"""V2 도구 어댑터가 공유하는 결과 저장과 소스 파싱 기능."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .docker_backend import CommandResult, DockerBackend
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json


@dataclass(slots=True)
class ToolOutcome:
    exit_code: int
    summary: str
    item_count: int = 0
    skipped: bool = False
    error: str = ""


def _unique_lines(text: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and line not in seen:
            seen.add(line)
            result.append(line)
    return result


HTTPX_SAFE_FIELDS = (
    "input", "url", "final_url", "status_code", "content_type", "content_length",
    "method", "host", "port", "scheme", "error",
)


def _httpx_records(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


def _response_body(record: dict[str, Any]) -> str:
    for key in ("body", "response_body"):
        value = record.get(key)
        if isinstance(value, str):
            return value
    response = record.get("response")
    if isinstance(response, dict):
        for key in ("body", "data", "content"):
            value = response.get(key)
            if isinstance(value, str):
                return value
        return ""
    if not isinstance(response, str):
        return ""
    for separator in ("\r\n\r\n", "\n\n"):
        if separator in response:
            return response.split(separator, 1)[1]
    return response


def _sanitized_httpx_stdout(records: list[dict[str, Any]]) -> str:
    lines = []
    for record in records:
        safe = {key: record[key] for key in HTTPX_SAFE_FIELDS if key in record}
        lines.append(json.dumps(safe, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def _extract_c_style_comments(source: str, language: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    index = 0
    quote: str | None = None
    while index < len(source):
        character = source[index]
        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            index += 1
            continue
        if language != "css" and source.startswith("//", index):
            end = source.find("\n", index + 2)
            if end < 0:
                end = len(source)
            comments.append(
                {
                    "line": source.count("\n", 0, index) + 1,
                    "syntax": f"{language}-line",
                    "text": source[index + 2:end],
                }
            )
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            content_end = len(source) if end < 0 else end
            comments.append(
                {
                    "line": source.count("\n", 0, index) + 1,
                    "syntax": f"{language}-block",
                    "text": source[index + 2:content_end],
                }
            )
            index = len(source) if end < 0 else end + 2
            continue
        index += 1
    return comments


def _extract_html_comments(source: str) -> list[dict[str, Any]]:
    comments: list[dict[str, Any]] = []
    for match in re.finditer(r"<!--(.*?)-->", source, flags=re.DOTALL):
        comments.append(
            {
                "line": source.count("\n", 0, match.start()) + 1,
                "syntax": "html",
                "text": match.group(1),
            }
        )
    for tag, language in (("script", "javascript"), ("style", "css")):
        for match in re.finditer(
            rf"<{tag}\b[^>]*>(.*?)</{tag}\s*>", source,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            line_offset = source.count("\n", 0, match.start(1))
            for comment in _extract_c_style_comments(match.group(1), language):
                comment["line"] += line_offset
                comments.append(comment)
    return comments


ENDPOINT_PATTERNS = (
    ("api-path", re.compile(r'''["'`]((?:/(?:api|rest|graphql|v\d+))(?:[/?][^"'`\s<>\\]*)?)["'`]''', re.I)),
    ("form-action", re.compile(r'''\baction\s*=\s*["'`]([^"'`\s<>]+)["'`]''', re.I)),
    ("action-id", re.compile(r'''\b(?:action[-_]?id|next-action)\b\s*[:=]\s*["'`]([^"'`\s<>]+)["'`]''', re.I)),
)
REQUEST_PATTERN = re.compile(
    r'''\b(fetch|axios(?:\.(get|post|put|patch|delete|request))?)\s*\(\s*["'`]((?:https?://|/)[^"'`\s<>\\]+)["'`]''',
    re.I,
)


def _extract_source_endpoints(source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for match in REQUEST_PATTERN.finditer(source):
        value = match.group(3)
        line_start = source.rfind("\n", 0, match.start()) + 1
        line_end = source.find("\n", match.end())
        context = source[line_start:len(source) if line_end < 0 else line_end].strip()
        explicit_method = match.group(2)
        if explicit_method and explicit_method.lower() != "request":
            method = explicit_method.upper()
        else:
            option = re.search(
                r'''\bmethod\s*:\s*["'`](get|post|put|patch|delete)["'`]''',
                context,
                re.I,
            )
            method = option.group(1).upper() if option else "GET"
        key = ("request", method, value)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            {
                "kind": "request",
                "value": value,
                "method": method,
                "line": source.count("\n", 0, match.start()) + 1,
                "context": context,
            }
        )
    for kind, pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(source):
            value = match.group(1)
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.end())
            context = source[line_start:len(source) if line_end < 0 else line_end].strip()
            item = {
                "kind": kind,
                "value": value,
                "line": source.count("\n", 0, match.start()) + 1,
                "context": context,
            }
            if kind == "form-action":
                method = re.search(r'''\bmethod\s*=\s*["'`](get|post)["'`]''', context, re.I)
                item["method"] = method.group(1).upper() if method else "GET"
            findings.append(item)
    return findings


def _candidate_source_urls(policy: ScopePolicy, urls: list[str]) -> list[str]:
    accepted = {"", ".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp", ".css", ".js", ".mjs", ".cjs", ".jsx"}
    candidates: list[str] = []
    for value in urls:
        parsed = urlsplit(value)
        if Path(parsed.path).suffix.lower() not in accepted:
            continue
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
        try:
            policy.validate_url(clean)
        except PolicyError:
            continue
        if clean not in candidates:
            candidates.append(clean)
    return candidates


class ToolRunner:
    def __init__(self, backend: DockerBackend, store: RunStore) -> None:
        self.backend = backend
        self.store = store

    def run(self, tool: str, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        method = getattr(self, f"run_{tool}", None)
        if method is None:
            raise ValueError(f"No adapter for tool: {tool}")
        return method(policy, state)

    def _write_result(
        self,
        state: dict[str, Any],
        tool: str,
        result: CommandResult,
        *,
        extension: str = "log",
        stdout: str | None = None,
    ) -> None:
        run_dir = self.store.run_dir(state["run_id"])
        stdout_path = run_dir / "raw" / f"{tool}.{extension}"
        stderr_path = run_dir / "raw" / f"{tool}.stderr.log"
        stdout_path.write_text(
            result.stdout if stdout is None else stdout,
            encoding="utf-8",
            newline="\n",
        )
        stderr_path.write_text(result.stderr, encoding="utf-8", newline="\n")
        self.store.add_artifact(state, stdout_path, "raw", tool)
        if result.stderr:
            self.store.add_artifact(state, stderr_path, "stderr", tool)

    def _write_sanitized_httpx_result(
        self, state: dict[str, Any], tool: str, result: CommandResult
    ) -> list[dict[str, Any]]:
        records = _httpx_records(result.stdout)
        self._write_result(
            state, tool, result, extension="jsonl",
            stdout=_sanitized_httpx_stdout(records),
        )
        return records

    def _copy_lines_input(self, state: dict[str, Any], name: str, lines: list[str]) -> str:
        run_dir = self.store.run_dir(state["run_id"])
        local = run_dir / "raw" / name
        local.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        remote_dir = self.backend.prepare_remote_dir(state["run_id"])
        remote = f"{remote_dir}/{name}"
        self.backend.copy_to(local, remote)
        return remote

    def _live_urls(self, policy: ScopePolicy, state: dict[str, Any]) -> list[str]:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "alive-urls.txt"
        accepted: list[str] = []
        for value in _unique_lines(path.read_text(encoding="utf-8")) if path.exists() else []:
            try:
                policy.validate_url(value)
            except PolicyError:
                continue
            if value not in accepted:
                accepted.append(value)
        return accepted

    def run_robots_txt(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        targets: list[str] = []
        for value in self._live_urls(policy, state):
            parsed = urlsplit(value)
            target = urlunsplit((parsed.scheme, parsed.netloc, "/robots.txt", "", ""))
            try:
                policy.validate_url(target)
            except PolicyError:
                continue
            if target not in targets:
                targets.append(target)
        if not targets:
            return ToolOutcome(0, "robots.txt skipped because no live origin exists", skipped=True)
        remote = self._copy_lines_input(state, "robots-input.txt", targets)
        result = self.backend.run(
            ["httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl", "-irr", "-duc"],
            process_timeout=120 if policy.profile == "fast" else 300,
        )
        records = self._write_sanitized_httpx_result(state, "robots_txt", result)
        documents: list[dict[str, Any]] = []
        count = 0
        for record in records:
            url = str(record.get("url") or record.get("input") or "")
            try:
                policy.validate_url(url)
                status_code = int(record.get("status_code") or 0)
            except (PolicyError, TypeError, ValueError):
                continue
            body = _response_body(record) if 200 <= status_code < 300 else ""
            directives = []
            for line_number, raw_line in enumerate(body.splitlines(), start=1):
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                name, separator, value = raw_line.partition(":")
                if separator and name.strip():
                    directives.append(
                        {"line": line_number, "name": name.strip().lower(), "value": value.strip()}
                    )
            count += len(directives)
            documents.append(
                {"url": url, "status_code": status_code, "content_type": record.get("content_type"), "directives": directives}
            )
        path = self.store.run_dir(state["run_id"]) / "parsed" / "robots.json"
        atomic_write_json(path, documents)
        self.store.add_artifact(state, path, "parsed", "robots_txt")
        return ToolOutcome(
            result.exit_code,
            f"Recorded {count} robots directives across {len(documents)} origins",
            count,
            error=result.stderr.strip(),
        )

    def run_nuclei(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        targets = self._live_urls(policy, state)
        if not targets:
            return ToolOutcome(0, "Nuclei skipped because no live origin exists", skipped=True)
        remote = self._copy_lines_input(state, "nuclei-input.txt", targets)
        result = self.backend.run(
            [
                "nuclei", "-list", remote, "-templates", "/opt/nuclei-templates",
                "-jsonl", "-silent", "-no-color", "-omit-template", "-disable-update-check",
            ],
            process_timeout=21600,
        )
        self._write_result(state, "nuclei", result, extension="jsonl")
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for line_number, line in enumerate(result.stdout.splitlines(), start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            template_id = str(record.get("template-id") or "unknown")
            matched_at = str(record.get("matched-at") or record.get("host") or "")
            matcher = str(record.get("matcher-name") or "")
            key = (template_id, matched_at, matcher)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                {
                    "template_id": template_id,
                    "name": str(info.get("name") or template_id),
                    "severity": str(info.get("severity") or "unknown").lower(),
                    "matched_at": matched_at,
                    "matcher_name": matcher,
                    "evidence": f"raw/nuclei.jsonl:{line_number}",
                }
            )
        path = self.store.run_dir(state["run_id"]) / "parsed" / "nuclei-findings.json"
        atomic_write_json(path, findings)
        self.store.add_artifact(state, path, "findings", "nuclei")
        return ToolOutcome(
            result.exit_code,
            f"Recorded {len(findings)} Nuclei findings",
            len(findings),
            error=result.stderr.strip(),
        )
