"""허용된 도구의 고정 명령과 최소 결과 파서."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .docker_backend import CommandResult, DockerBackend
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json
from dorkgen import generate_dorks


@dataclass(slots=True)
class ToolOutcome:
    exit_code: int
    summary: str
    item_count: int = 0
    skipped: bool = False
    error: str = ""


def run_local_dorkgen(
    policy: ScopePolicy, state: dict[str, Any], store: RunStore
) -> ToolOutcome:
    """Google에 접속하지 않고 검색식만 run 아티팩트로 생성한다."""
    dorks = generate_dorks(policy.root_domain)
    destination = store.run_dir(state["run_id"]) / "parsed" / "google-dorks.txt"
    destination.write_text("\n".join(dorks) + "\n", encoding="utf-8", newline="\n")
    store.add_artifact(state, destination, "queries", "dorkgen")
    return ToolOutcome(0, f"Generated {len(dorks)} Google dork queries offline", len(dorks))


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
    # 정규식 하나로 처리하면 문자열 안의 https://를 주석으로 오인하므로 따옴표를 추적한다.
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


# 이미 받은 소스만 검사한다. 이 패턴들은 새 URL에 요청을 보내지 않는다.
_ENDPOINT_PATTERNS = (
    ("api-path", re.compile(r'''["'`]((?:/(?:api|rest|graphql|v\d+))(?:[/?][^"'`\s<>\\]*)?)["'`]''', re.IGNORECASE)),
    ("request", re.compile(r'''(fetch|axios(?:\.(?:get|post|put|patch|delete|request))?)\s*\(\s*["'`]((?:https?://|/)[^"'`\s<>\\]+)["'`]''', re.IGNORECASE)),
    ("action-id", re.compile(r'''\b(?:action[-_]?id|next-action)\b\s*[:=]\s*["'`]([^"'`\s<>]+)["'`]''', re.IGNORECASE)),
)


class _FormParser(HTMLParser):
    """HTML form의 전송 위치와 named control을 네트워크 요청 없이 수집한다."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        lowered = tag.lower()
        if lowered == "form":
            method = values.get("method", "GET").strip().upper() or "GET"
            self.current = {
                "kind": "form-action",
                "value": values.get("action", "").strip(),
                "method": method,
                "content_type": values.get("enctype", "application/x-www-form-urlencoded"),
                "line": self.getpos()[0],
                "context": self.get_starttag_text() or "<form>",
                "form_fields": [],
            }
            self.forms.append(self.current)
            return
        if self.current is None or lowered not in {"input", "select", "textarea", "button"}:
            return
        name = values.get("name", "").strip()
        if not name:
            return
        self.current["form_fields"].append(
            {
                "name": name,
                "type": values.get("type", lowered).strip().lower() or lowered,
                "required": "required" in values,
            }
        )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self.current = None


def _extract_html_forms(source: str) -> list[dict[str, Any]]:
    parser = _FormParser()
    try:
        parser.feed(source)
    except Exception:
        return []
    for form in parser.forms:
        names = list(dict.fromkeys(str(item["name"]) for item in form["form_fields"]))
        if form["method"] == "GET":
            form["query_parameters"] = names
            form["body_parameters"] = []
        else:
            form["query_parameters"] = []
            form["body_parameters"] = names
    return parser.forms


def _request_metadata(source: str, match: re.Match[str], call: str, value: str) -> dict[str, Any]:
    """일반적인 fetch/Axios 호출에서 보수적으로 메서드와 입력 키를 추출한다."""
    lowered = call.lower()
    method = "GET"
    if "." in lowered and lowered.rsplit(".", 1)[1] != "request":
        method = lowered.rsplit(".", 1)[1].upper()

    # 한 호출의 가까운 옵션만 본다. 전체 파일을 대상으로 하면 다른 요청의 키가 섞인다.
    tail = source[match.end() : match.end() + 1200]
    close = tail.find(");")
    if close >= 0:
        tail = tail[:close]
    method_match = re.search(
        r'''\bmethod\s*:\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']''',
        tail,
        flags=re.IGNORECASE,
    )
    if method_match:
        method = method_match.group(1).upper()

    content_type = ""
    content_type_match = re.search(
        r'''["']?content-type["']?\s*:\s*["']([^"']+)["']''',
        tail,
        flags=re.IGNORECASE,
    )
    if content_type_match:
        content_type = content_type_match.group(1).strip()

    body_region = ""
    body_match = re.search(
        r'''\b(?:body|data)\s*:\s*(?:JSON\.stringify\s*\()?\s*\{(.*?)\}''',
        tail,
        flags=re.IGNORECASE | re.DOTALL,
    )
    if body_match:
        body_region = body_match.group(1)
    elif method in {"POST", "PUT", "PATCH"} and lowered.startswith("axios."):
        payload_match = re.search(r'''^\s*,\s*\{(.*?)\}''', tail, flags=re.DOTALL)
        if payload_match:
            body_region = payload_match.group(1)
    body_parameters = list(
        dict.fromkeys(
            match.group(1) or match.group(2)
            for match in re.finditer(
                r'''(?:^|,)\s*(?:["']([^"']+)["']|([A-Za-z_$][\w$]*))\s*:''',
                body_region,
            )
        )
    )
    query_parameters = list(
        dict.fromkeys(name for name, _ in parse_qsl(urlsplit(value).query, keep_blank_values=True))
    )
    return {
        "method": method,
        "content_type": content_type,
        "query_parameters": query_parameters,
        "body_parameters": body_parameters,
        "form_fields": [],
    }


def _extract_source_endpoints(source: str) -> list[dict[str, Any]]:
    """소스의 경로와 action ID 후보를 출처 위치와 함께 중복 제거한다."""
    findings: list[dict[str, Any]] = _extract_html_forms(source)
    seen: set[tuple[str, str]] = set()
    for kind, pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(source):
            value = match.group(2) if kind == "request" else match.group(1)
            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.end())
            context = source[line_start : len(source) if line_end < 0 else line_end].strip()
            finding = {
                "kind": kind,
                "value": value,
                "line": source.count("\n", 0, match.start()) + 1,
                "context": context,
            }
            if kind == "request":
                finding.update(_request_metadata(source, match, match.group(1), value))
            findings.append(finding)
    return findings


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
    ports = "|".join(str(port) for port in policy.allowed_ports)
    base = re.escape(policy.domain)
    host = rf"(?:[a-zA-Z0-9-]+\.)*{base}"
    patterns = []
    for scheme, default_port in (("http", 80), ("https", 443)):
        port = rf"(?::(?:{ports}))?" if default_port in policy.allowed_ports else rf":(?:{ports})"
        patterns.append(rf"^{scheme}://{host}{port}(?:/|$)")
    return patterns


class ToolRunner:
    def __init__(
        self,
        backend: DockerBackend,
        store: RunStore,
    ) -> None:
        self.backend = backend
        self.store = store

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
        self,
        state: dict[str, Any],
        tool: str,
        result: CommandResult,
    ) -> list[dict[str, Any]]:
        """본문은 parsed 증거에만 두고 raw HTTPX 로그에는 안전한 메타데이터만 남긴다."""
        records = _httpx_records(result.stdout)
        self._write_result(
            state,
            tool,
            result,
            extension="jsonl",
            stdout=_sanitized_httpx_stdout(records),
        )
        return records

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

    def run(self, tool: str, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        method = getattr(self, f"run_{tool}", None)
        if method is None:
            raise ValueError(f"No adapter for tool: {tool}")
        return method(policy, state)

    def run_dorkgen(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        return run_local_dorkgen(policy, state, self.store)

    @staticmethod
    def _host_in_scope(policy: ScopePolicy, host: str) -> bool:
        """허용 포트 중 하나를 붙여 호스트가 스코프에 속하는지 확인한다."""
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
        """각 수집기의 결과를 검증한 뒤 hosts.txt 하나로 정렬·중복 제거한다."""
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
        self._write_result(state, "subfinder", result)
        hosts = self._merge_hosts(policy, state, "subfinder", _unique_lines(result.stdout))
        return ToolOutcome(
            result.exit_code,
            f"Collected {len(hosts)} in-scope hosts",
            len(hosts),
            error=result.stderr.strip(),
        )

    def run_assetfinder(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        result = self.backend.run(
            ["assetfinder", "--subs-only", policy.root_domain], process_timeout=240
        )
        self._write_result(state, "assetfinder", result)
        hosts = self._merge_hosts(policy, state, "assetfinder", _unique_lines(result.stdout))
        return ToolOutcome(
            result.exit_code,
            f"Collected {len(hosts)} in-scope hosts (merged with prior collect results)",
            len(hosts),
            error=result.stderr.strip(),
        )

    def run_amass_enum(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        """자동 수집에서는 대상 DNS에 접촉하지 않도록 Amass를 passive로 고정한다."""
        result = self.backend.run(
            ["amass", "enum", "-passive", "-d", policy.root_domain],
            process_timeout=1800,
        )
        self._write_result(state, "amass_enum", result)
        hosts = self._merge_hosts(policy, state, "amass_enum", _unique_lines(result.stdout))
        return ToolOutcome(
            result.exit_code,
            f"Collected {len(hosts)} in-scope hosts (merged with prior collect results)",
            len(hosts),
            error=result.stderr.strip(),
        )

    def run_waybackurls(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        result = self.backend.run(
            ["waybackurls"], input_text=policy.root_domain + "\n", process_timeout=300
        )
        self._write_result(state, "waybackurls", result)
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
            result.exit_code,
            f"Collected {len(urls)} in-scope historical URLs",
            len(urls),
            error=result.stderr.strip(),
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
                "-duc",
            ],
            process_timeout=600,
        )
        self._write_result(state, "httpx", result, extension="jsonl")
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
            result.exit_code,
            f"Confirmed {len(set(urls))} live in-scope URLs",
            len(set(urls)),
            error=result.stderr.strip(),
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
                0,
                "robots.txt skipped because no in-scope origin permits /robots.txt",
                skipped=True,
            )

        remote = self._copy_lines_input(state, "robots-input.txt", targets)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl",
                "-irr", "-duc",
            ],
            process_timeout=600,
        )
        records = self._write_sanitized_httpx_result(state, "robots_txt", result)
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
            result.exit_code,
            summary,
            directive_count + comment_count,
            error=result.stderr.strip(),
        )

    def run_nuclei(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        """핀한 템플릿 전체로 활성 URL을 검사한다."""
        targets: list[str] = []
        for value in self._live_urls(policy, state):
            try:
                policy.validate_url(value)
            except PolicyError:
                continue
            if value not in targets:
                targets.append(value)
        if not targets:
            return ToolOutcome(0, "Nuclei skipped because no in-scope URL exists", skipped=True)

        remote = self._copy_lines_input(state, "nuclei-input.txt", targets)
        result = self.backend.run(
            [
                "nuclei",
                "-list", remote,
                "-templates", "/opt/nuclei-templates",
                "-jsonl",
                "-silent",
                "-no-color",
                "-omit-template",
                "-disable-update-check",
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
            matched_at = str(record.get("matched-at") or record.get("host") or "")
            response = record.get("response")
            info = record.get("info") if isinstance(record.get("info"), dict) else {}
            template_id = str(record.get("template-id") or "unknown")
            matcher_name = str(record.get("matcher-name") or "")
            key = (template_id, matched_at, matcher_name)
            if key in seen:
                continue
            seen.add(key)
            status_match = (
                re.search(r"(?m)^HTTP/\S+\s+(\d{3})\b", response)
                if isinstance(response, str)
                else None
            )
            findings.append(
                {
                    "template_id": template_id,
                    "name": str(info.get("name") or template_id),
                    "severity": str(info.get("severity") or "unknown").lower(),
                    "type": str(record.get("type") or "http"),
                    "matched_at": matched_at,
                    "matcher_name": matcher_name,
                    "status_code": int(status_match.group(1)) if status_match else None,
                    "timestamp": str(record.get("timestamp") or ""),
                    "evidence": f"raw/nuclei.jsonl:{line_number}",
                }
            )

        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "nuclei-findings.json"
        atomic_write_json(parsed, findings)
        self.store.add_artifact(state, parsed, "findings", "nuclei")
        return ToolOutcome(
            result.exit_code,
            f"Recorded {len(findings)} Nuclei findings",
            len(findings),
            error=result.stderr.strip(),
        )

    def _live_urls(self, policy: ScopePolicy, state: dict[str, Any]) -> list[str]:
        path = self.store.run_dir(state["run_id"]) / "parsed" / "alive-urls.txt"
        urls = _unique_lines(path.read_text(encoding="utf-8")) if path.exists() else []
        return urls or [policy.base_url]

    def run_katana(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        remote = self._copy_lines_input(state, "katana-input.txt", self._live_urls(policy, state))
        depth = 2
        args = ["katana", "-list", remote, "-silent", "-d", str(depth), "-jc"]
        for pattern in _katana_scope_regexes(policy):
            args.extend(["-cs", pattern])
        result = self.backend.run(
            args,
            process_timeout=900,
        )
        self._write_result(state, "katana", result)
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
            result.exit_code,
            f"Crawled {len(set(urls))} in-scope URLs",
            len(set(urls)),
            error=result.stderr.strip(),
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
        if not candidates:
            return ToolOutcome(
                0,
                "Source comment review skipped because no in-scope source URLs were found",
                skipped=True,
            )

        remote = self._copy_lines_input(state, "source-comments-input.txt", candidates)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl",
                "-irr", "-duc",
            ],
            process_timeout=900,
        )
        records = self._write_sanitized_httpx_result(state, "source_comments", result)
        findings: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        seen: set[tuple[str, int, str, str]] = set()
        seen_endpoints: set[tuple[str, str, str]] = set()
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
            for candidate in _extract_source_endpoints(body):
                endpoint = None
                if candidate["kind"] != "action-id":
                    endpoint = urlunsplit(urlsplit(urljoin(url, candidate["value"]))._replace(fragment=""))
                    try:
                        policy.validate_url(endpoint)
                    except PolicyError:
                        continue
                key = (url, candidate["kind"], endpoint or candidate["value"])
                if key in seen_endpoints:
                    continue
                seen_endpoints.add(key)
                endpoints.append({"source": url, "endpoint": endpoint, **candidate})
            for comment in comments:
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
        endpoint_path = run_dir / "parsed" / "source-endpoints.json"
        atomic_write_json(endpoint_path, endpoints)
        self.store.add_artifact(state, endpoint_path, "parsed", "source_comments")
        return ToolOutcome(
            result.exit_code,
            f"Reviewed {reviewed} source responses; recorded {len(findings)} comments and {len(endpoints)} endpoint/action candidates",
            len(findings) + len(endpoints),
            error=result.stderr.strip(),
        )

    def run_gobuster_dir(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        wordlist = "/opt/recon-wordlists/web-common.txt"
        args = [
            "gobuster", "dir", "-u", policy.base_url, "-w", wordlist,
            "-q",
        ]
        result = self.backend.run(args, process_timeout=1200)
        # SPA가 모든 경로에 같은 200 본문을 반환하면 그 길이만 제외해 한 번 재시도한다.
        # --force는 와일드카드 오탐을 대량 생성하므로 사용하지 않는다.
        wildcard_match = re.search(
            r"non existing urls?.*?\(Length:\s*(\d+)\)",
            result.stderr,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if result.exit_code != 0 and wildcard_match:
            args.extend(["--exclude-length", wildcard_match.group(1)])
            result = self.backend.run(args, process_timeout=1200)
        self._write_result(state, "gobuster_dir", result)
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
            result.exit_code,
            f"Found {len(records)} content paths",
            len(records),
            error=result.stderr.strip(),
        )

    def run_parameth(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        target = policy.base_url
        policy.validate_url(target)
        wordlist = "/opt/recon-wordlists/params-small.txt"
        result = self.backend.run(
            ["parameth", "-u", target, "-p", wordlist],
            process_timeout=1800,
        )
        self._write_result(state, "parameth", result)
        findings = [line.strip() for line in result.stdout.splitlines() if line.strip().startswith("[") or "parameter" in line.lower()]
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "parameth.json"
        atomic_write_json(parsed, {"target": target, "interesting_lines": findings})
        self.store.add_artifact(state, parsed, "parsed", "parameth")
        return ToolOutcome(
            result.exit_code,
            f"Recorded {len(findings)} parameter result lines",
            len(findings),
            error=result.stderr.strip(),
        )
