"""더 깊은 Katana 크롤링과 정적 프런트엔드 자산 분석."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json
from .tools import (
    ToolOutcome,
    ToolRunner,
    _candidate_source_urls,
    _extract_c_style_comments,
    _extract_html_comments,
    _extract_source_endpoints,
    _katana_scope_regexes,
    _response_body,
    _unique_lines,
)


KATANA_DEPTH = 4

_JS_ASSIGNMENT_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)"
)
_JS_CALL_RE = re.compile(
    r"\b(fetch|import|axios(?:\.(?:get|post|put|patch|delete|request))?)\s*\(",
    re.IGNORECASE,
)
_SOURCE_MAP_RE = re.compile(r"(?:[#@]\s*)?sourceMappingURL\s*=\s*([^\s*]+)", re.IGNORECASE)
_QUOTED_ASSET_RE = re.compile(
    r'''["'`]([^"'`\s<>]*(?:/_next/static/|static/chunks/)[^"'`\s<>]*|[^"'`\s<>]+(?:\.js|\.mjs|\.cjs|\.map)(?:[?#][^"'`\s<>]*)?|[^"'`\s<>]*(?:_buildManifest|_ssgManifest|build-manifest|app-build-manifest|react-loadable-manifest|routes-manifest|prerender-manifest|middleware-manifest|webpack-runtime|webpack)[^"'`\s<>]*(?:\.js|\.json)?)["'`]''',
    re.IGNORECASE,
)
_MANIFEST_NAME_RE = re.compile(
    r"(?:_buildManifest|_ssgManifest|build-manifest|app-build-manifest|react-loadable-manifest|routes-manifest|prerender-manifest|middleware-manifest|webpack)",
    re.IGNORECASE,
)


class _SourceHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.assets: list[tuple[str, str]] = []
        self._next_data = False
        self.next_data_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value or "" for name, value in attrs}
        lowered = tag.lower()
        if lowered == "script":
            if values.get("src"):
                self.assets.append(("script-src", values["src"]))
            if values.get("id") == "__NEXT_DATA__":
                self._next_data = True
        elif lowered == "link" and values.get("href"):
            href = values["href"]
            rel = values.get("rel", "").lower()
            if "preload" in rel or "modulepreload" in rel or _looks_like_asset(href):
                self.assets.append(("link-asset", href))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._next_data:
            self._next_data = False

    def handle_data(self, data: str) -> None:
        if self._next_data:
            self.next_data_parts.append(data)


def _looks_like_asset(value: str) -> bool:
    path = urlsplit(value).path.lower()
    if path.endswith((".js", ".mjs", ".cjs", ".map")):
        return True
    return bool(_MANIFEST_NAME_RE.search(path))


def _line_context(source: str, offset: int) -> tuple[int, str]:
    start = source.rfind("\n", 0, offset) + 1
    end = source.find("\n", offset)
    if end < 0:
        end = len(source)
    return source.count("\n", 0, offset) + 1, source[start:end].strip()


def _decode_literal(value: str) -> str | None:
    value = value.strip()
    if len(value) < 2 or value[0] not in {"'", '"'} or value[-1] != value[0]:
        return None
    body = value[1:-1]
    replacements = {
        r"\\": "\\",
        r"\n": "\n",
        r"\r": "\r",
        r"\t": "\t",
        r"\'": "'",
        r'\"': '"',
        r"\/": "/",
    }
    for old, new in replacements.items():
        body = body.replace(old, new)
    return body


def _split_top_level_plus(expr: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    template_expr_depth = 0
    for index, char in enumerate(expr):
        if escaped:
            escaped = False
            continue
        if quote is not None:
            if char == "\\":
                escaped = True
                continue
            if quote == "`" and char == "$" and index + 1 < len(expr) and expr[index + 1] == "{":
                template_expr_depth += 1
                continue
            if quote == "`" and template_expr_depth:
                if char == "{":
                    template_expr_depth += 1
                elif char == "}":
                    template_expr_depth -= 1
                continue
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}" and depth:
            depth -= 1
            continue
        if char == "+" and depth == 0:
            parts.append(expr[start:index].strip())
            start = index + 1
    parts.append(expr[start:].strip())
    return parts


def _eval_static_string(expr: str, bindings: dict[str, str]) -> str | None:
    expr = expr.strip()
    while len(expr) >= 2 and expr[0] == "(" and expr[-1] == ")":
        expr = expr[1:-1].strip()

    parts = _split_top_level_plus(expr)
    if len(parts) > 1:
        values = [_eval_static_string(part, bindings) for part in parts]
        return "".join(values) if all(value is not None for value in values) else None

    if expr in bindings:
        return bindings[expr]
    literal = _decode_literal(expr)
    if literal is not None:
        return literal
    if len(expr) >= 2 and expr[0] == "`" and expr[-1] == "`":
        body = expr[1:-1]

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in bindings:
                raise KeyError(name)
            return bindings[name]

        try:
            return re.sub(r"\$\{\s*([A-Za-z_$][\w$]*)\s*\}", replace, body)
        except KeyError:
            return None
    return None


def _collect_static_bindings(source: str) -> dict[str, str]:
    assignments = list(_JS_ASSIGNMENT_RE.finditer(source))
    bindings: dict[str, str] = {}
    for _ in range(4):
        changed = False
        for match in assignments:
            value = _eval_static_string(match.group(2), bindings)
            if value is not None and bindings.get(match.group(1)) != value:
                bindings[match.group(1)] = value
                changed = True
        if not changed:
            break
    return bindings


def _first_call_argument(source: str, opening_paren: int) -> str:
    start = opening_paren + 1
    quote: str | None = None
    escaped = False
    depth = 0
    template_expr_depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if escaped:
            escaped = False
            continue
        if quote is not None:
            if char == "\\":
                escaped = True
                continue
            if quote == "`" and char == "$" and index + 1 < len(source) and source[index + 1] == "{":
                template_expr_depth += 1
                continue
            if quote == "`" and template_expr_depth:
                if char == "{":
                    template_expr_depth += 1
                elif char == "}":
                    template_expr_depth -= 1
                continue
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            depth += 1
            continue
        if char in ")]}":
            if depth == 0 and char == ")":
                return source[start:index].strip()
            if depth:
                depth -= 1
            continue
        if char == "," and depth == 0:
            return source[start:index].strip()
    return ""


def _extract_static_calls(source: str) -> list[dict[str, Any]]:
    bindings = _collect_static_bindings(source)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for match in _JS_CALL_RE.finditer(source):
        expr = _first_call_argument(source, match.end() - 1)
        value = _eval_static_string(expr, bindings)
        if not value:
            continue
        call = match.group(1).lower()
        kind = "dynamic-import" if call == "import" else "request-static"
        key = (kind, value)
        if key in seen:
            continue
        seen.add(key)
        line, context = _line_context(source, match.start())
        findings.append({"kind": kind, "value": value, "line": line, "context": context})
    return findings


def _extract_html_assets(source: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    parser = _SourceHTMLParser()
    try:
        parser.feed(source)
    except Exception:
        return [], None
    assets = [
        {"kind": kind, "value": value, "line": 0, "context": "HTML attribute"}
        for kind, value in parser.assets
    ]
    next_data: dict[str, Any] | None = None
    if parser.next_data_parts:
        try:
            parsed = json.loads("".join(parser.next_data_parts))
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            next_data = parsed
    return assets, next_data


def _walk_strings(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, str):
        strings.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            strings.extend(_walk_strings(item))
    elif isinstance(value, list):
        for item in value:
            strings.extend(_walk_strings(item))
    return strings


def _extract_next_data_assets(next_data: dict[str, Any], source_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    build_id = next_data.get("buildId")
    if isinstance(build_id, str) and build_id:
        parsed = urlsplit(source_url)
        origin = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        for name in ("_buildManifest.js", "_ssgManifest.js"):
            findings.append(
                {
                    "kind": "next-manifest",
                    "value": urljoin(origin, f"/_next/static/{build_id}/{name}"),
                    "line": 0,
                    "context": f"__NEXT_DATA__.buildId={build_id}",
                }
            )
    for value in _walk_strings(next_data):
        if value.startswith(("/", "http://", "https://")) and (
            _looks_like_asset(value) or value.startswith("/_next/")
        ):
            findings.append(
                {"kind": "next-data-asset", "value": value, "line": 0, "context": "__NEXT_DATA__"}
            )
    return findings


def _extract_source_assets(source: str, kind: str, source_url: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if kind == "html":
        html_assets, next_data = _extract_html_assets(source)
        findings.extend(html_assets)
        if next_data is not None:
            findings.extend(_extract_next_data_assets(next_data, source_url))
    if kind in {"html", "javascript"}:
        for candidate in _extract_static_calls(source):
            if candidate["kind"] == "dynamic-import" or _looks_like_asset(str(candidate["value"])):
                findings.append(candidate)
        for match in _SOURCE_MAP_RE.finditer(source):
            line, context = _line_context(source, match.start())
            findings.append(
                {"kind": "source-map", "value": match.group(1).strip("'\""), "line": line, "context": context}
            )
        for match in _QUOTED_ASSET_RE.finditer(source):
            line, context = _line_context(source, match.start())
            findings.append(
                {"kind": "js-asset", "value": match.group(1), "line": line, "context": context}
            )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in findings:
        key = (str(item["kind"]), str(item["value"]))
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _resolve_in_scope(policy: ScopePolicy, source_url: str, value: str) -> str | None:
    raw = value.strip()
    if not raw or raw.startswith(("data:", "blob:", "javascript:", "mailto:", "webpack:", "node:")):
        return None
    if "${" in raw:
        return None
    resolved = urlunsplit(urlsplit(urljoin(source_url, raw))._replace(fragment=""))
    try:
        policy.validate_url(resolved)
    except PolicyError:
        return None
    return resolved


def _record_kind(url: str, record: dict[str, Any]) -> str | None:
    content_type = str(record.get("content_type") or "").lower()
    suffix = Path(urlsplit(url).path).suffix.lower()
    if suffix == ".map":
        return "sourcemap"
    if suffix == ".json" or "json" in content_type:
        return "json"
    if "html" in content_type or suffix in {"", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp"}:
        return "html"
    if "javascript" in content_type or "ecmascript" in content_type or suffix in {".js", ".mjs", ".cjs", ".jsx"}:
        return "javascript"
    if "css" in content_type or suffix == ".css":
        return "css"
    return None


def _manifest_candidates(body: str) -> list[str]:
    values: list[str] = []
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = None
    if payload is not None:
        values.extend(_walk_strings(payload))
    else:
        for match in re.finditer(r'''["']([^"'\s<>]+)["']''', body):
            values.append(match.group(1))
    return [
        value
        for value in values
        if value.startswith(("/", "http://", "https://")) or _looks_like_asset(value)
    ]


def _sourcemap_sources(body: str) -> tuple[list[str], list[str]]:
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return [], []
    if not isinstance(payload, dict):
        return [], []
    sources = [str(value) for value in payload.get("sources", []) if isinstance(value, str)]
    contents = [str(value) for value in payload.get("sourcesContent", []) if isinstance(value, str)]
    return sources, contents


class DeepDiscoveryToolRunner(ToolRunner):
    """기본 ToolRunner에 깊은 크롤링과 정적 프런트엔드 자산 추적을 추가한다."""

    def run_katana(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        remote = self._copy_lines_input(state, "katana-input.txt", self._live_urls(policy, state))
        args = [
            "katana", "-list", remote, "-silent", "-d", str(KATANA_DEPTH),
            "-jc",
        ]
        for pattern in _katana_scope_regexes(policy):
            args.extend(["-cs", pattern])
        result = self.backend.run(args, process_timeout=1200)
        self._write_result(state, "katana", result)
        urls: list[str] = []
        for url in _unique_lines(result.stdout):
            try:
                policy.validate_url(url)
            except PolicyError:
                continue
            urls.append(url)
        parsed = self.store.run_dir(state["run_id"]) / "parsed" / "katana-urls.txt"
        parsed.write_text(
            "\n".join(sorted(set(urls))) + ("\n" if urls else ""),
            encoding="utf-8",
            newline="\n",
        )
        self.store.add_artifact(state, parsed, "urls", "katana")
        return ToolOutcome(
            result.exit_code,
            f"Crawled {len(set(urls))} in-scope URLs at depth {KATANA_DEPTH}",
            len(set(urls)),
            error=result.stderr.strip(),
        )

    def _fetch_source_records(
        self,
        state: dict[str, Any],
        policy: ScopePolicy,
        urls: list[str],
        tool_name: str,
    ) -> tuple[Any, list[dict[str, Any]]]:
        remote = self._copy_lines_input(state, f"{tool_name}-input.txt", urls)
        result = self.backend.run(
            [
                "httpx", "-l", remote, "-silent", "-j", "-sc", "-ct", "-cl",
                "-irr", "-duc",
            ],
            process_timeout=900,
        )
        return result, self._write_sanitized_httpx_result(state, tool_name, result)

    def run_source_comments(self, policy: ScopePolicy, state: dict[str, Any]) -> ToolOutcome:
        run_dir = self.store.run_dir(state["run_id"])
        urls = self._live_urls(policy, state)
        katana_urls = run_dir / "parsed" / "katana-urls.txt"
        if katana_urls.exists():
            urls.extend(_unique_lines(katana_urls.read_text(encoding="utf-8")))
        candidates = _candidate_source_urls(policy, urls)
        if not candidates:
            return ToolOutcome(
                0,
                "Source review skipped because no in-scope source URLs were found",
                skipped=True,
            )

        initial_result, initial_records = self._fetch_source_records(
            state, policy, candidates, "source_comments"
        )
        comments: list[dict[str, Any]] = []
        endpoints: list[dict[str, Any]] = []
        assets: list[dict[str, Any]] = []
        seen_comments: set[tuple[str, int, str, str]] = set()
        seen_endpoints: set[tuple[str, str, str]] = set()
        seen_assets: set[tuple[str, str, str]] = set()
        reviewed_urls: set[str] = set()
        discovered_urls: list[str] = []

        def add_endpoint(source_url: str, candidate: dict[str, Any], value: str | None = None) -> None:
            raw_value = str(value if value is not None else candidate.get("value", ""))
            endpoint = None
            if candidate.get("kind") != "action-id":
                endpoint = _resolve_in_scope(policy, source_url, raw_value)
                if endpoint is None:
                    return
            key = (source_url, str(candidate.get("kind")), endpoint or raw_value)
            if key in seen_endpoints:
                return
            seen_endpoints.add(key)
            endpoints.append({"source": source_url, "endpoint": endpoint, **candidate, "value": raw_value})

        def add_asset(source_url: str, candidate: dict[str, Any]) -> None:
            raw_value = str(candidate.get("value", ""))
            resolved = _resolve_in_scope(policy, source_url, raw_value)
            key = (source_url, str(candidate.get("kind")), resolved or raw_value)
            if key in seen_assets:
                return
            seen_assets.add(key)
            entry = {"source": source_url, "url": resolved, **candidate, "value": raw_value}
            assets.append(entry)
            if resolved is not None:
                add_endpoint(source_url, candidate, raw_value)
                if resolved not in discovered_urls and resolved not in candidates:
                    discovered_urls.append(resolved)

        def process_record(record: dict[str, Any], *, allow_discovery: bool) -> None:
            source_url = str(record.get("url") or record.get("input") or "")
            try:
                policy.validate_url(source_url)
            except PolicyError:
                return
            body = _response_body(record)
            kind = _record_kind(source_url, record)
            if kind is None or not body:
                return
            reviewed_urls.add(source_url)

            if kind == "html":
                extracted_comments = _extract_html_comments(body)
            elif kind in {"javascript", "css"}:
                extracted_comments = _extract_c_style_comments(body, kind)
            else:
                extracted_comments = []
            for comment in extracted_comments:
                text = str(comment["text"])
                key = (source_url, int(comment["line"]), str(comment["syntax"]), text)
                if key in seen_comments:
                    continue
                seen_comments.add(key)
                comments.append(
                    {
                        "url": source_url,
                        "content_type": record.get("content_type"),
                        "kind": kind,
                        "line": comment["line"],
                        "syntax": comment["syntax"],
                        "text": text,
                    }
                )

            if kind in {"html", "javascript"}:
                for candidate in _extract_source_endpoints(body):
                    add_endpoint(source_url, candidate)
                for candidate in _extract_static_calls(body):
                    if candidate["kind"] == "request-static":
                        add_endpoint(source_url, candidate)
                if allow_discovery:
                    for candidate in _extract_source_assets(body, kind, source_url):
                        add_asset(source_url, candidate)

            if kind == "sourcemap":
                source_names, source_contents = _sourcemap_sources(body)
                for name in source_names:
                    candidate = {"kind": "source-map-source", "value": name, "line": 0, "context": "sources[]"}
                    key = (source_url, candidate["kind"], name)
                    if key not in seen_assets:
                        seen_assets.add(key)
                        assets.append({"source": source_url, "url": None, **candidate})
                for embedded in source_contents:
                    for candidate in _extract_source_endpoints(embedded):
                        add_endpoint(source_url, {**candidate, "kind": f"sourcemap-{candidate['kind']}"})
                    for candidate in _extract_static_calls(embedded):
                        if candidate["kind"] == "request-static":
                            add_endpoint(source_url, {**candidate, "kind": "sourcemap-request"})

            if kind in {"json", "javascript"} and _MANIFEST_NAME_RE.search(urlsplit(source_url).path):
                for value in _manifest_candidates(body):
                    candidate_kind = "manifest-asset" if _looks_like_asset(value) else "manifest-route"
                    candidate = {"kind": candidate_kind, "value": value, "line": 0, "context": "manifest"}
                    if candidate_kind == "manifest-asset" and allow_discovery:
                        add_asset(source_url, candidate)
                    else:
                        add_endpoint(source_url, candidate)

        for record in initial_records:
            process_record(record, allow_discovery=True)

        secondary_result = None
        secondary_urls = discovered_urls
        if secondary_urls:
            secondary_result, secondary_records = self._fetch_source_records(
                state, policy, secondary_urls, "source_assets"
            )
            for record in secondary_records:
                process_record(record, allow_discovery=False)

        atomic_write_json(run_dir / "parsed" / "source-comments.json", comments)
        self.store.add_artifact(state, run_dir / "parsed" / "source-comments.json", "parsed", "source_comments")
        atomic_write_json(run_dir / "parsed" / "source-endpoints.json", endpoints)
        self.store.add_artifact(state, run_dir / "parsed" / "source-endpoints.json", "parsed", "source_comments")
        atomic_write_json(run_dir / "parsed" / "source-assets.json", assets)
        self.store.add_artifact(state, run_dir / "parsed" / "source-assets.json", "parsed", "source_comments")

        exit_code = initial_result.exit_code
        errors = [initial_result.stderr.strip()] if initial_result.stderr.strip() else []
        if secondary_result is not None:
            exit_code = exit_code or secondary_result.exit_code
            if secondary_result.stderr.strip():
                errors.append(secondary_result.stderr.strip())
        return ToolOutcome(
            exit_code,
            (
                f"Reviewed {len(reviewed_urls)} source responses; recorded {len(comments)} comments, "
                f"{len(endpoints)} endpoint/action candidates and {len(assets)} JS/manifest/sourcemap assets"
            ),
            len(comments) + len(endpoints) + len(assets),
            error="\n".join(errors),
        )
