"""도구 관찰값을 기능 단위 route와 작은 검토 Queue로 정규화한다."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit, urlunsplit

from .policy import PolicyError, ScopePolicy
from .storage import RunStore, atomic_write_json, atomic_write_text
from .tools import ToolOutcome


MAX_CANDIDATES = 20
STATIC_SUFFIXES = {
    ".avi", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map",
    ".mjs", ".mov", ".mp3", ".mp4", ".pdf", ".png", ".svg", ".ttf",
    ".webm", ".webp", ".woff", ".woff2",
}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

ROLE_HINTS = {
    "인증": {"login", "logout", "signin", "signup", "register", "auth", "oauth", "sso", "password", "reset"},
    "관리": {"admin", "manage", "dashboard", "console", "panel"},
    "API": {"api", "graphql", "swagger", "openapi", "rpc"},
    "파일": {"upload", "download", "export", "import", "attachment", "file"},
    "검색": {"search", "query", "find", "filter"},
    "객체": {"user", "account", "profile", "order", "invoice", "item", "document", "id"},
    "운영": {"debug", "dev", "test", "internal", "health", "metrics", "actuator"},
}
SINK_HINTS = {
    "파일 입력": {"upload", "import", "file", "attachment", "path", "filename"},
    "외부 URL": {"url", "uri", "redirect", "return", "next", "callback", "webhook"},
    "명령·템플릿": {"cmd", "command", "exec", "template", "render"},
    "객체 식별자": {"id", "user", "account", "order", "document", "item", "seq"},
    "인증 입력": {"login", "auth", "token", "password", "reset", "oauth"},
}

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
DATE_RE = re.compile(r"^\d{4}[-_.]\d{1,2}(?:[-_.]\d{1,2})?$")
HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.I)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,}={0,2}$")


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _lines(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _origin(url: str) -> str:
    parsed = urlsplit(url)
    port = parsed.port
    default = 443 if parsed.scheme == "https" else 80
    netloc = str(parsed.hostname or "") if port in {None, default} else f"{parsed.hostname}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def _path_segment(value: str) -> str:
    if value.isdigit():
        return "{int}"
    if UUID_RE.fullmatch(value):
        return "{uuid}"
    if DATE_RE.fullmatch(value):
        return "{date}"
    if HEX_RE.fullmatch(value) or TOKEN_RE.fullmatch(value):
        return "{token}"
    return value


def normalize_path(path: str) -> str:
    decoded = unquote(path or "/")
    parts = [_path_segment(part) for part in decoded.split("/")]
    normalized = "/".join(parts)
    return normalized if normalized.startswith("/") else "/" + normalized


def _tokens(*values: str) -> set[str]:
    result: set[str] = set()
    for value in values:
        camel = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
        result.update(
            token.lower()
            for token in re.split(r"[^A-Za-z0-9]+", camel)
            if token
        )
    return result


def _labels(tokens: set[str], hints: dict[str, set[str]]) -> list[str]:
    return [label for label, words in hints.items() if tokens & words]


def _evidence_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("tool"), item.get("artifact"), item.get("source"),
        item.get("line"), item.get("kind"),
    )


def _route_id(signature: str) -> str:
    return "route-" + hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12]


def _priority(entry: dict[str, Any]) -> tuple[str | None, int, list[str]]:
    score = 0
    reasons: list[str] = []
    method = entry["method"]
    parameters = [*entry["query_parameters"], *entry["body_parameters"]]
    roles = entry["roles"]
    sinks = entry["sink_hints"]
    evidence_tools = {item.get("tool") for item in entry["evidence"]}

    if method in STATE_CHANGING:
        score += 3
        reasons.append(f"상태 변경 method {method}")
    if parameters:
        score += 2
        reasons.append("이름이 확인된 입력값")
    valuable_roles = set(roles) & {"인증", "관리", "API", "파일", "운영"}
    if valuable_roles:
        score += 2
        reasons.append("기능 분류: " + ", ".join(sorted(valuable_roles)))
    if sinks:
        score += 2
        reasons.append("검토 입력: " + ", ".join(sinks))
    if "source_comments" in evidence_tools:
        score += 1
        reasons.append("소스 위치 확인")
    if len(evidence_tools) >= 2:
        score += 1
        reasons.append("복수 도구 근거")

    if score < 2:
        return None, score, reasons
    priority = "P1" if score >= 6 else "P2" if score >= 4 else "P3"
    return priority, score, reasons


def _next_action(entry: dict[str, Any]) -> str:
    roles = set(entry["roles"])
    sinks = set(entry["sink_hints"])
    if "인증" in roles:
        return "인증 전후 요청, 세션과 오류 응답을 비교한다."
    if "관리" in roles:
        return "비인증·일반 사용자 접근 통제와 연결 기능을 확인한다."
    if "파일 입력" in sinks or "파일" in roles:
        return "허용 형식, 저장 위치와 다운로드 권한을 확인한다."
    if "외부 URL" in sinks:
        return "URL 검증, 리다이렉트와 서버 측 요청 여부를 확인한다."
    if "API" in roles:
        return "요청 스키마, method와 인증 요구사항을 확인한다."
    if "객체 식별자" in sinks or "객체" in roles:
        return "식별자 변경 시 객체 권한 검사가 적용되는지 확인한다."
    return "정상·비정상 입력의 상태 코드와 응답 차이를 확인한다."


def build_surface(store: RunStore, state: dict[str, Any]) -> dict[str, Any]:
    run_dir = store.run_dir(state["run_id"])
    policy = ScopePolicy.load(run_dir / "scope.toml")
    parsed_dir = run_dir / "parsed"
    normalized_dir = run_dir / "normalized"
    normalized_dir.mkdir(parents=True, exist_ok=True)

    origins = _json(normalized_dir / "origins.json", [])
    if not isinstance(origins, list):
        origins = []
    origins = list(
        {
            str(item.get("url")): item
            for item in origins
            if isinstance(item, dict) and item.get("url")
        }.values()
    )

    routes: dict[str, dict[str, Any]] = {}

    def add(
        url: str,
        *,
        method: str = "GET",
        query_parameters: list[str] | None = None,
        body_parameters: list[str] | None = None,
        evidence: dict[str, Any],
    ) -> None:
        if not url.startswith(("http://", "https://")):
            return
        try:
            policy.validate_url(url)
        except PolicyError:
            return
        parsed = urlsplit(url)
        suffix = Path(parsed.path).suffix.lower()
        if suffix in STATIC_SUFFIXES:
            return
        origin = _origin(url)
        path = normalize_path(parsed.path)
        query = list(dict.fromkeys(
            [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
            + list(query_parameters or [])
        ))
        body = list(dict.fromkeys(body_parameters or []))
        method = (method or "GET").upper()
        signature = "|".join(
            [origin, method, path, ",".join(sorted(query)), ",".join(sorted(body))]
        )
        entry = routes.setdefault(
            signature,
            {
                "route_id": _route_id(signature),
                "origin": origin,
                "method": method,
                "path": path,
                "query_parameters": sorted(query),
                "body_parameters": sorted(body),
                "evidence": [],
            },
        )
        if _evidence_key(evidence) not in {_evidence_key(item) for item in entry["evidence"]}:
            entry["evidence"].append(evidence)

    for url in _lines(parsed_dir / "alive-urls.txt"):
        add(url, evidence={"tool": "httpx", "artifact": "parsed/alive-urls.txt"})
    for url in _lines(parsed_dir / "katana-urls.txt"):
        add(url, evidence={"tool": "katana", "artifact": "parsed/katana-urls.txt"})

    for document in _json(parsed_dir / "robots.json", []):
        if not isinstance(document, dict):
            continue
        base = str(document.get("url") or "")
        for directive in document.get("directives", []):
            if not isinstance(directive, dict):
                continue
            value = str(directive.get("value") or "")
            if value.startswith("/"):
                add(
                    urljoin(base, value),
                    evidence={"tool": "robots_txt", "artifact": "parsed/robots.json", "line": directive.get("line")},
                )

    for item in _json(parsed_dir / "source-endpoints.json", []):
        if not isinstance(item, dict) or not item.get("endpoint"):
            continue
        query_parameters = item.get("query_parameters")
        body_parameters = item.get("body_parameters")
        add(
            str(item["endpoint"]),
            method=str(item.get("method") or "GET"),
            query_parameters=[
                str(value) for value in query_parameters
            ] if isinstance(query_parameters, list) else [],
            body_parameters=[
                str(value) for value in body_parameters
            ] if isinstance(body_parameters, list) else [],
            evidence={
                "tool": "source_comments",
                "artifact": "parsed/source-endpoints.json",
                "source": item.get("source"),
                "line": item.get("line"),
                "kind": item.get("kind"),
            },
        )

    for item in _json(parsed_dir / "gobuster-dir.json", []):
        if isinstance(item, dict) and item.get("url"):
            add(
                str(item["url"]),
                evidence={"tool": "gobuster_dir", "artifact": item.get("evidence") or "parsed/gobuster-dir.json"},
            )

    ordered_routes: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    previous = {
        item.get("route_id"): item
        for item in _json(normalized_dir / "candidates.json", [])
        if isinstance(item, dict) and item.get("route_id")
    }
    for entry in routes.values():
        token_values = [
            entry["path"], *entry["query_parameters"], *entry["body_parameters"]
        ]
        tokens = _tokens(*token_values)
        entry["roles"] = _labels(tokens, ROLE_HINTS)
        entry["sink_hints"] = _labels(tokens, SINK_HINTS)
        priority, score, reasons = _priority(entry)
        entry["priority"] = priority
        entry["priority_score"] = score
        ordered_routes.append(entry)
        if priority is None:
            continue
        old = previous.get(entry["route_id"], {})
        candidates.append(
            {
                "route_id": entry["route_id"],
                "priority": priority,
                "priority_score": score,
                "method": entry["method"],
                "route": entry["origin"] + entry["path"],
                "query_parameters": entry["query_parameters"],
                "body_parameters": entry["body_parameters"],
                "roles": entry["roles"],
                "sink_hints": entry["sink_hints"],
                "reasons": reasons,
                "next_action": _next_action(entry),
                "evidence": entry["evidence"],
                "status": old.get("status", "unverified"),
                "notes": old.get("notes", ""),
            }
        )

    ordered_routes.sort(key=lambda item: (item["origin"], item["path"], item["method"]))
    candidates.sort(key=lambda item: (-item["priority_score"], item["route"], item["method"]))
    candidates = candidates[:MAX_CANDIDATES]

    failures: list[dict[str, Any]] = []
    for stage_name, stage in state.get("stages", {}).items():
        if not isinstance(stage, dict):
            continue
        for tool, result in stage.get("tools", {}).items():
            if isinstance(result, dict) and result.get("status") == "failed":
                failures.append(
                    {
                        "stage": stage_name,
                        "tool": tool,
                        "error": result.get("error") or result.get("summary") or "unknown",
                    }
                )
    coverage = {
        "status": state.get("status"),
        "profile": state.get("scope", {}).get("profile", "fast"),
        "origins": len(origins),
        "routes": len(ordered_routes),
        "candidates": len(candidates),
        "failures": failures,
        "stages": {
            name: item.get("status")
            for name, item in state.get("stages", {}).items()
            if isinstance(item, dict)
        },
    }

    origins_path = normalized_dir / "origins.json"
    routes_path = normalized_dir / "routes.jsonl"
    candidates_path = normalized_dir / "candidates.json"
    coverage_path = normalized_dir / "coverage.json"
    atomic_write_json(origins_path, origins)
    atomic_write_text(
        routes_path,
        "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in ordered_routes)
        + ("\n" if ordered_routes else ""),
    )
    atomic_write_json(candidates_path, candidates)
    atomic_write_json(coverage_path, coverage)
    for path, kind in (
        (origins_path, "origins"),
        (routes_path, "routes"),
        (candidates_path, "candidates"),
        (coverage_path, "coverage"),
    ):
        store.add_artifact(state, path, kind, "surface")
    store.save(state)
    return {
        "origins": origins,
        "routes": ordered_routes,
        "candidates": candidates,
        "coverage": coverage,
    }


def run_local_surface(state: dict[str, Any], store: RunStore) -> ToolOutcome:
    result = build_surface(store, state)
    return ToolOutcome(
        0,
        f"Normalized {len(result['routes'])} routes and selected {len(result['candidates'])} candidates",
        len(result["candidates"]),
    )
