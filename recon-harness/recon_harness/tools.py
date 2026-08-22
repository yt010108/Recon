"""Fixed-command adapters and lightweight result parsers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from .docker_backend import CommandResult, DockerBackend
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json


@dataclass(slots=True)
class ToolOutcome:
    tool: str
    exit_code: int
    summary: str
    raw_files: list[Path] = field(default_factory=list)
    parsed_files: list[Path] = field(default_factory=list)
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


_HTTPX_SAFE_FIELDS = (
    "input",
    "url",
    "final_url",
    "status_code",
    "content_type",
    "content_length",
    "method",
    "host",
    "port",
    "scheme",
    "error",
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
        safe = {key: record[key] for key in _HTTPX_SAFE_FIELDS if key in record}
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
                    "text": source[index + 2 : end],
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
                    "text": source[index + 2 : content_end],
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
        pattern = rf"<{tag}\b[^>]*>(.*?)</{tag}\s*>"
        for match in re.finditer(pattern, source, flags=re.IGNORECASE | re.DOTALL):
            line_offset = source.count("\n", 0, match.start(1))
            for comment in _extract_c_style_comments(match.group(1), language):
                comment["line"] += line_offset
                comments.append(comment)
    return comments


def _source_kind(url: str, record: dict[str, Any]) -> str | None:
    content_type = str(record.get("content_type") or "").lower()
    suffix = Path(urlsplit(url).path).suffix.lower()
    if "html" in content_type or suffix in {".html", ".htm", ".xhtml", ".php", ".asp", ".aspx", ".jsp"}:
        return "html"
    if "css" in content_type or suffix == ".css":
        return "css"
    if "javascript" in content_type or "ecmascript" in content_type or suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript"
    if not suffix and (not content_type or content_type.startswith("text/")):
        return "html"
    return None


def _candidate_source_urls(policy: ScopePolicy, urls: list[str]) -> list[str]:
    candidates: list[str] = []
    accepted = {
        "",
        ".html",
        ".htm",
        ".xhtml",
        ".php",
        ".asp",
        ".aspx",
        ".jsp",
        ".css",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
    }
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


def _katana_scope_regexes(policy: ScopePolicy) -> list[str]:
    if policy.base_urls:
        patterns = []
        for value in policy.base_urls:
            parsed = urlsplit(value)
            prefix = parsed.path or "/"
            patterns.append(
                rf"^{re.escape(parsed.scheme)}://{re.escape(parsed.netloc)}{re.escape(prefix)}"
            )
        return patterns

    if policy.domains:
        ports = "|".join(str(port) for port in sorted(set(policy.allowed_ports)))
        patterns = []
        for domain in policy.domains:
            base = re.escape(domain.removeprefix("*.").rstrip("."))
            host = rf"(?:[a-zA-Z0-9-]+\.)*{base}"
            for scheme, default_port in (("http", 80), ("https", 443)):
                port = rf"(?::(?:{ports}))?" if default_port in policy.allowed_ports else rf":(?:{ports})"
                patterns.append(rf"^{scheme}://{host}{port}(?:/|$)")
        return patterns

    parsed = urlsplit(policy.base_url)
    return [rf"^{re.escape(parsed.scheme)}://{re.escape(parsed.netloc)}(?:/|$)"]


def _katana_exclude_regexes(policy: ScopePolicy) -> list[str]:
    patterns = []
    for host in policy.excluded_hosts:
        base = re.escape(host.removeprefix("*.").rstrip("."))
        patterns.append(rf"^https?://(?:[a-zA-Z0-9-]+\.)*{base}(?::\d+)?(?:/|$)")
    if policy.excluded_paths:
        paths = "|".join(re.escape(path) for path in policy.excluded_paths)
        patterns.append(rf"^https?://[^/?#]+(?:{paths})(?:/|\?|#|$)")
    return patterns


class ToolRunner:
    def __init__(
        self,
        backend: DockerBackend,
        store: RunStore,
        project_root: Path,
    ) -> None:
        self.backend = backend
        self.store = store
        self.project_root = project_root.resolve()

    def _write_result(
        self,
        state: dict[str, Any],
        tool: str,
        result: CommandResult,
        *,
        extension: str = "log",
    ) -> tuple[Path, Path]:
        run_dir = self.store.run_dir(state["run_id"])
        stdout_path = run_dir / "raw" / f"{tool}.{extension}"
        stderr_path = run_dir / "raw" / f"{tool}.stderr.log"
        stdout_path.write_text(result.stdout, encoding="utf-8", newline="\n")
        stderr_path.write_text(result.stderr, encoding="utf-8", newline="\n")
        self.store.add_artifact(state, stdout_path, "raw", tool)
        if result.stderr:
            self.store.add_artifact(state, stderr_path, "stderr", tool)
        return stdout_path, stderr_path

    def _write_sanitized_httpx_result(
        self,
        state: dict[str, Any],
        tool: str,
        result: CommandResult,
    ) -> tuple[Path, list[dict[str, Any]]]:
        """Store HTTPX metadata while keeping fetched bodies in parsed artifacts only."""
        records = _httpx_records(result.stdout)
        safe_result = CommandResult(
            command=result.command,
            exit_code=result.exit_code,
            stdout=_sanitized_httpx_stdout(records),
            stderr=result.stderr,
            timed_out=result.timed_out,
        )
        raw, _ = self._write_result(state, tool, safe_result, extension="jsonl")
        return raw, records

    def _copy_lines_input(
        self, state: dict[str, Any], name: str, lines: list[str]
    ) -> str:
        run_dir = self.store.run_dir(state["run_id"])
        local = run_dir / "raw" / name
        local.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        remote_dir = self.backend.prepare_remote_dir(state["run_id"])
        remote = f"{remote_dir}/{name}"
        self.backend.copy_to(local, remote)
        return remote

    def _filtered_container_wordlist(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        container_path: str,
        output_name: str,
    ) -> str:
        result = self.backend.run(["cat", container_path], process_timeout=60)
        if result.exit_code != 0:
            raise PolicyError(f"Cannot read container wordlist: {container_path}")
        candidates: list[str] = []
        for line in _unique_lines(result.stdout):
            candidate_path = "/" + line.lstrip("/")
            if any(
                candidate_path == excluded
                or candidate_path.startswith(excluded.rstrip("/") + "/")
                for excluded in policy.excluded_paths
            ):
                continue
            candidates.append(line)
        return self._copy_lines_input(state, output_name, candidates)

    def run(self, tool: str, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        method = getattr(self, f"run_{tool}", None)
        if method is None:
            raise ValueError(f"No adapter for tool: {tool}")
        return method(policy, state)

    @staticmethod
    def _host_in_scope(policy: ScopePolicy, host: str) -> bool:
        """Check hostname scope membership without failing on non-default ports."""
        port = policy.allowed_ports[0]
        for scheme in ("https", "http"):
            try:
                policy.validate_url(f"{scheme}://{host}:{port}")
                return True
            except PolicyError:
                continue
        return False

    def _merge_hosts(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        tool: str,
        discovered: list[str],
    ) -> list[str]:
        """Merge validated hosts into parsed/hosts.txt, sorted and deduplicated.

        This is the harness equivalent of `sort -u`: every collect-stage host
        source writes through this helper, so the file is always the union of
        all in-scope candidates regardless of adapter execution order.
        """
        hosts_path = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        existing = _unique_lines(hosts_path.read_text(encoding="utf-8")) if hosts_path.exists() else []
        merged: set[str] = {policy.root_domain}
        for candidate in existing + discovered:
            host = candidate.strip().lower().removeprefix("*.").rstrip(".")
            if not host or any(character in host for character in "/@? #"):
                continue
            if not self._host_in_scope(policy, host):
                continue
            merged.add(host)
        ordered = sorted(merged)
        hosts_path.parent.mkdir(parents=True, exist_ok=True)
        hosts_path.write_text("\n".join(ordered) + "\n", encoding="utf-8", newline="\n")
        self.store.add_artifact(state, hosts_path, "hosts", tool)
        return ordered

    def run_subfinder(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        result = self.backend.run(
            ["subfinder", "-d", policy.root_domain, "-silent"], process_timeout=240
        )
        raw, _ = self._write_result(state, "subfinder", result)
        hosts = self._merge_hosts(policy, state, "subfinder", _unique_lines(result.stdout))
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        return ToolOutcome(
            "subfinder", result.exit_code, f"Collected {len(hosts)} in-scope hosts", [raw], [parsed], len(hosts), error=result.stderr.strip()
        )

    def run_assetfinder(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        result = self.backend.run(
            ["assetfinder", "--subs-only", policy.root_domain], process_timeout=240
        )
        raw, _ = self._write_result(state, "assetfinder", result)
        hosts = self._merge_hosts(policy, state, "assetfinder", _unique_lines(result.stdout))
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        return ToolOutcome(
            "assetfinder",
            result.exit_code,
            f"Collected {len(hosts)} in-scope hosts (merged with prior collect results)",
            [raw],
            [parsed],
            len(hosts),
            error=result.stderr.strip(),
        )

    def run_amass_enum(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        """Passive-only Amass enumeration; active DNS contact is not allowed here.

        Without -passive Amass resolves discovered names against the target's
        nameservers, which is direct target traffic. That belongs to the
        approval-gated discovery stage, never to automatic collect.
        """
        result = self.backend.run(
            ["amass", "enum", "-passive", "-d", policy.root_domain],
            process_timeout=1800,
        )
        raw, _ = self._write_result(state, "amass_enum", result)
        hosts = self._merge_hosts(policy, state, "amass_enum", _unique_lines(result.stdout))
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        return ToolOutcome(
            "amass_enum",
            result.exit_code,
            f"Collected {len(hosts)} in-scope hosts (merged with prior collect results)",
            [raw],
            [parsed],
            len(hosts),
            error=result.stderr.strip(),
        )

    def run_waybackurls(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        result = self.backend.run(
            ["waybackurls"], input_text=policy.root_domain + "\n", process_timeout=300
        )
        raw, _ = self._write_result(state, "waybackurls", result)
        urls: list[str] = []
        for url in _unique_lines(result.stdout):
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            urls.append(url)
        urls = sorted(set(urls))
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "wayback-urls.txt"
        parsed.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8", newline="\n")
        self.store.add_artifact(state, parsed, "urls", "waybackurls")
        return ToolOutcome(
            "waybackurls", result.exit_code, f"Collected {len(urls)} in-scope historical URLs", [raw], [parsed], len(urls), error=result.stderr.strip()
        )

    def run_httpx(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        hosts_path = self.store.run_dir(state["run_id"]) / "parsed" / "hosts.txt"
        hosts = _unique_lines(hosts_path.read_text(encoding="utf-8")) if hosts_path.exists() else []
        if policy.base_url not in hosts:
            hosts.append(policy.base_url)
        remote = self._copy_lines_input(state, "httpx-input.txt", hosts)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-title", "-td",
                "-rl", str(policy.rate_limit), "-t", str(policy.concurrency),
                "-timeout", str(policy.timeout_seconds), "-duc",
            ],
            process_timeout=600,
        )
        raw, _ = self._write_result(state, "httpx", result, extension="jsonl")
        records: list[dict[str, Any]] = []
        urls: list[str] = []
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = str(record.get("url") or record.get("input") or "")
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            records.append(record)
            urls.append(url)
        run_dir = self.store.run_dir(state["run_id"])
        alive = run_dir / "parsed" / "alive-urls.txt"
        alive.write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""), encoding="utf-8", newline="\n")
        details = run_dir / "parsed" / "httpx.json"
        atomic_write_json(details, records)
        self.store.add_artifact(state, alive, "urls", "httpx")
        self.store.add_artifact(state, details, "parsed", "httpx")
        return ToolOutcome(
            "httpx", result.exit_code, f"Confirmed {len(set(urls))} live in-scope URLs", [raw], [alive, details], len(set(urls)), error=result.stderr.strip()
        )

    def run_robots_txt(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        targets: list[str] = []
        for value in self._live_urls(policy, state):
            parsed_url = urlsplit(value)
            target = urlunsplit(
                (parsed_url.scheme, parsed_url.netloc, "/robots.txt", "", "")
            )
            try:
                policy.validate_url(target)
            except PolicyError:
                continue
            if target not in targets:
                targets.append(target)
        if not targets:
            return ToolOutcome(
                "robots_txt",
                0,
                "robots.txt skipped because no in-scope origin permits /robots.txt",
                skipped=True,
            )

        remote = self._copy_lines_input(state, "robots-input.txt", targets)
        max_bytes = max(
            1024, min(1_048_576, int(policy.options.get("robots_max_bytes", 262_144)))
        )
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl",
                "-irr", "-rstr", str(max_bytes), "-rl", str(policy.rate_limit),
                "-t", str(policy.concurrency), "-timeout", str(policy.timeout_seconds),
                "-duc",
            ],
            process_timeout=600,
        )
        raw, records = self._write_sanitized_httpx_result(
            state, "robots_txt", result
        )
        documents: list[dict[str, Any]] = []
        directive_count = 0
        comment_count = 0
        for record in records:
            url = str(record.get("url") or record.get("input") or "")
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            try:
                status_code = int(record.get("status_code") or 0)
            except (TypeError, ValueError):
                status_code = 0
            body = _response_body(record) if 200 <= status_code < 300 else ""
            directives: list[dict[str, Any]] = []
            comments: list[dict[str, Any]] = []
            for line_number, raw_line in enumerate(body.splitlines(), start=1):
                stripped = raw_line.strip()
                if not stripped:
                    continue
                if stripped.startswith("#"):
                    comments.append(
                        {"line": line_number, "text": raw_line[raw_line.index("#") + 1 :]}
                    )
                    continue
                name, separator, value = raw_line.partition(":")
                if not separator or not name.strip():
                    continue
                directive: dict[str, Any] = {
                    "line": line_number,
                    "name": name.strip().lower(),
                    "value": value.strip(),
                }
                if directive["name"] == "sitemap":
                    try:
                        policy.validate_url(directive["value"])
                    except PolicyError:
                        directive["in_scope"] = False
                    else:
                        directive["in_scope"] = True
                directives.append(directive)
            directive_count += len(directives)
            comment_count += len(comments)
            documents.append(
                {
                    "url": url,
                    "status_code": status_code or record.get("status_code"),
                    "content_type": record.get("content_type"),
                    "body": body,
                    "directives": directives,
                    "comments": comments,
                }
            )

        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "robots.json"
        atomic_write_json(parsed, documents)
        self.store.add_artifact(state, parsed, "parsed", "robots_txt")
        summary = (
            f"Reviewed {len(documents)} robots.txt responses; recorded "
            f"{directive_count} directives and {comment_count} comments"
        )
        return ToolOutcome(
            "robots_txt",
            result.exit_code,
            summary,
            [raw],
            [parsed],
            directive_count + comment_count,
            error=result.stderr.strip(),
        )

    def _live_urls(self, policy: ScopePolicy, state: dict[str, Any]) -> list[str]:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "alive-urls.txt"
        urls = _unique_lines(path.read_text(encoding="utf-8")) if path.exists() else []
        return urls or [policy.base_url]

    def run_katana(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        remote = self._copy_lines_input(state, "katana-input.txt", self._live_urls(policy, state))
        depth = max(1, min(5, int(policy.options.get("crawl_depth", 2))))
        args = ["katana", "-list", remote, "-silent", "-d", str(depth), "-jc", "-rl", str(policy.rate_limit)]
        for pattern in _katana_scope_regexes(policy):
            args.extend(["-cs", pattern])
        for pattern in _katana_exclude_regexes(policy):
            args.extend(["-cos", pattern])
        result = self.backend.run(
            args,
            process_timeout=900,
        )
        raw, _ = self._write_result(state, "katana", result)
        urls: list[str] = []
        for url in _unique_lines(result.stdout):
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            urls.append(url)
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "katana-urls.txt"
        parsed.write_text("\n".join(sorted(set(urls))) + ("\n" if urls else ""), encoding="utf-8", newline="\n")
        self.store.add_artifact(state, parsed, "urls", "katana")
        return ToolOutcome(
            "katana", result.exit_code, f"Crawled {len(set(urls))} in-scope URLs", [raw], [parsed], len(set(urls)), error=result.stderr.strip()
        )

    def run_source_comments(
        self, policy: ScopePolicy, state: dict[str, Any]
    ) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        urls = self._live_urls(policy, state)
        katana_urls = run_dir / "parsed" / "katana-urls.txt"
        if katana_urls.exists():
            urls.extend(_unique_lines(katana_urls.read_text(encoding="utf-8")))
        candidates = _candidate_source_urls(policy, urls)
        max_files = max(
            1, min(500, int(policy.options.get("comment_max_files", 100)))
        )
        max_bytes = max(
            1024,
            min(2_097_152, int(policy.options.get("comment_max_bytes", 1_048_576))),
        )
        max_per_file = max(
            1, min(500, int(policy.options.get("comment_max_per_file", 100)))
        )
        candidates = candidates[:max_files]
        if not candidates:
            return ToolOutcome(
                "source_comments",
                0,
                "Source comment review skipped because no in-scope source URLs were found",
                skipped=True,
            )

        remote = self._copy_lines_input(state, "source-comments-input.txt", candidates)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl",
                "-irr", "-rstr", str(max_bytes), "-rl", str(policy.rate_limit),
                "-t", str(policy.concurrency), "-timeout", str(policy.timeout_seconds),
                "-duc",
            ],
            process_timeout=900,
        )
        raw, records = self._write_sanitized_httpx_result(
            state, "source_comments", result
        )
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str, str]] = set()
        reviewed = 0
        for record in records:
            url = str(record.get("url") or record.get("input") or "")
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            kind = _source_kind(url, record)
            body = _response_body(record)
            if kind is None or not body:
                continue
            reviewed += 1
            if kind == "html":
                comments = _extract_html_comments(body)
            else:
                comments = _extract_c_style_comments(body, kind)
            for comment in comments[:max_per_file]:
                text = str(comment["text"])
                key = (url, int(comment["line"]), str(comment["syntax"]), text)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {
                        "url": url,
                        "content_type": record.get("content_type"),
                        "kind": kind,
                        "line": comment["line"],
                        "syntax": comment["syntax"],
                        "text": text,
                    }
                )

        parsed = run_dir / "parsed" / "source-comments.json"
        atomic_write_json(parsed, findings)
        self.store.add_artifact(state, parsed, "parsed", "source_comments")
        return ToolOutcome(
            "source_comments",
            result.exit_code,
            f"Reviewed {reviewed} source responses and recorded {len(findings)} comments",
            [raw],
            [parsed],
            len(findings),
            error=result.stderr.strip(),
        )

    def run_gobuster_dir(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        wordlist = str(policy.options.get("gobuster_wordlist", "/opt/recon-wordlists/web-common.txt"))
        wordlist = self._filtered_container_wordlist(
            policy, state, wordlist, "gobuster-filtered.txt"
        )
        args = [
            "gobuster", "dir", "-u", policy.base_url, "-w", wordlist,
            "-q", "-t", str(policy.concurrency), "--timeout", f"{policy.timeout_seconds}s",
        ]
        configured_lengths = str(policy.options.get("gobuster_exclude_lengths", "")).strip()
        if configured_lengths:
            if not re.fullmatch(r"[0-9,-]+", configured_lengths):
                raise PolicyError("gobuster_exclude_lengths must be a numeric list or range")
            args.extend(["--exclude-length", configured_lengths])

        result = self.backend.run(args, process_timeout=1200)
        # SPAs commonly return the same 200 response for every unknown route. Gobuster
        # reports that body length during its preflight and exits before enumeration.
        # Retry once while excluding only that exact length instead of using --force,
        # which would fill the result set with wildcard false positives.
        wildcard_match = re.search(
            r"non existing urls?.*?\(Length:\s*(\d+)\)",
            result.stderr,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if result.exit_code != 0 and not configured_lengths and wildcard_match:
            args.extend(["--exclude-length", wildcard_match.group(1)])
            result = self.backend.run(args, process_timeout=1200)
        raw, _ = self._write_result(state, "gobuster_dir", result)
        records: list[dict[str, Any]] = []
        pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
        for line in result.stdout.splitlines():
            match = pattern.search(line.strip())
            if match:
                records.append({"path": match.group(1), "status": int(match.group(2)), "size": int(match.group(3)) if match.group(3) else None})
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "gobuster-dir.json"
        atomic_write_json(parsed, records)
        self.store.add_artifact(state, parsed, "parsed", "gobuster_dir")
        return ToolOutcome(
            "gobuster_dir", result.exit_code, f"Found {len(records)} content paths", [raw], [parsed], len(records), error=result.stderr.strip()
        )

    def run_gobuster_dns(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        if "." not in policy.root_domain or not policy.permissions.get("allow_dns_bruteforce", False):
            return ToolOutcome("gobuster_dns", 0, "DNS brute force skipped by scope policy", skipped=True)
        wordlist = str(policy.options.get("dns_wordlist", "/opt/recon-wordlists/dns-5000.txt"))
        result = self.backend.run(
            ["gobuster", "dns", "-d", policy.root_domain, "-w", wordlist, "-q", "-t", str(policy.concurrency)],
            process_timeout=1200,
        )
        raw, _ = self._write_result(state, "gobuster_dns", result)
        records = _unique_lines(result.stdout)
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "gobuster-dns.txt"
        parsed.write_text("\n".join(records) + ("\n" if records else ""), encoding="utf-8", newline="\n")
        self.store.add_artifact(state, parsed, "parsed", "gobuster_dns")
        return ToolOutcome(
            "gobuster_dns", result.exit_code, f"Recorded {len(records)} DNS results", [raw], [parsed], len(records), error=result.stderr.strip()
        )

    def run_parameth(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        target = str(policy.options.get("parameter_url", policy.base_url))
        policy.validate_url(target)
        wordlist = str(policy.options.get("parameth_wordlist", "project:wordlists/params-small.txt"))
        if wordlist.startswith("project:"):
            local = (self.project_root / wordlist.removeprefix("project:")).resolve()
            if self.project_root not in local.parents or not local.is_file():
                raise PolicyError("Invalid project Parameth wordlist")
            remote_dir = self.backend.prepare_remote_dir(state["run_id"])
            remote_wordlist = f"{remote_dir}/parameth-wordlist.txt"
            self.backend.copy_to(local, remote_wordlist)
            wordlist = remote_wordlist
        delay = max(0, min(10, int(policy.options.get("parameth_delay", 1))))
        threads = max(1, min(policy.concurrency, int(policy.options.get("parameth_threads", 3))))
        result = self.backend.run(
            ["parameth", "-u", target, "-p", wordlist, "-t", str(threads), "-T", str(delay)],
            process_timeout=1800,
        )
        raw, _ = self._write_result(state, "parameth", result)
        findings = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("[") or "parameter" in line.lower()]
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "parameth.json"
        atomic_write_json(parsed, {"target": target, "interesting_lines": findings})
        self.store.add_artifact(state, parsed, "parsed", "parameth")
        return ToolOutcome(
            "parameth", result.exit_code, f"Recorded {len(findings)} parameter result lines", [raw], [parsed], len(findings), error=result.stderr.strip()
        )
