"""전체 수집 결과를 보존하고 첫 화면에는 검토 후보만 보여준다."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from .policy import ScopePolicy
from .storage import RunStore, atomic_write_text
from .surface import build_surface


IMPORTANT_TERMS = (
    "admin", "api", "auth", "credential", "debug", "internal", "key",
    "login", "password", "secret", "token", "todo", "upload",
)
SENSITIVE_VALUE_RE = re.compile(
    r"(?i)\b(token|api[-_ ]?key|secret|password|credential)\b(\s*[:=]\s*)([^\s,;]+)"
)


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _lines(path: Path) -> list[str]:
    try:
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []


def _jsonl(path: Path) -> list[dict[str, Any]]:
    items = []
    for line in _lines(path):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            items.append(item)
    return items


def _cell(value: Any) -> str:
    rendered = "-" if value is None or value == "" else str(value)
    return rendered.replace("|", "\\|").replace("\n", " ")


def _terms(value: Any) -> list[str]:
    text = str(value).lower()
    return [term for term in IMPORTANT_TERMS if term in text]


def _important_endpoints(items: Any) -> list[dict[str, Any]]:
    ranked = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("endpoint") or item.get("value") or "")
        method = str(item.get("method") or "GET").upper()
        labels = _terms(" ".join((value, str(item.get("kind") or ""), str(item.get("context") or ""))))
        score = len(labels) * 3 + (2 if "?" in value else 0)
        score += 3 if method in {"POST", "PUT", "PATCH", "DELETE"} else 0
        score += 1 if item.get("kind") in {"request", "request-static", "form-action", "action-id"} else 0
        if score:
            ranked.append((score, value, {**item, "report_method": method, "report_labels": labels}))
    return [item for _score, _value, item in sorted(ranked, key=lambda row: (-row[0], row[1]))[:20]]


def _important_comments(items: Any) -> list[dict[str, Any]]:
    ranked = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "")
        labels = _terms(text)
        if labels:
            safe_text = SENSITIVE_VALUE_RE.sub(r"\1\2[REDACTED]", text)
            ranked.append((len(labels), {**item, "report_labels": labels, "report_text": safe_text[:180]}))
    return [item for _score, item in sorted(ranked, key=lambda row: -row[0])[:10]]


def _important_assets(items: Any) -> list[dict[str, Any]]:
    priorities = ("sourcemap", "source-map", "manifest", "dynamic-import", "chunk")
    ranked = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").lower()
        value = str(item.get("url") or item.get("value") or "")
        score = sum(term in f"{kind} {value.lower()}" for term in priorities)
        if score:
            ranked.append((score, value, item))
    return [item for _score, _value, item in sorted(ranked, key=lambda row: (-row[0], row[1]))[:10]]


def _important_routes(items: Any) -> list[dict[str, Any]]:
    routes = [
        item for item in items if isinstance(item, dict) and int(item.get("priority_score") or 0) >= 2
    ]
    return sorted(
        routes,
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            str(item.get("origin") or ""),
            str(item.get("path") or ""),
            str(item.get("method") or ""),
        ),
    )[:50]


def _route_meta(routes: list[dict[str, Any]]) -> str:
    labels = []
    for route in sorted(routes, key=lambda item: str(item.get("method") or "")):
        score = int(route.get("priority_score") or 0)
        priority = "P1" if score >= 6 else "P2" if score >= 4 else "P3"
        params = route.get("query_parameters") or []
        suffix = f" params={','.join(map(str, params))}" if params else ""
        labels.append(f"{route.get('method') or 'GET'} {priority}{suffix}")
    return f" [{'; '.join(labels)}]" if labels else ""


def _sitemap_lines(routes: list[dict[str, Any]]) -> list[str]:
    by_origin: dict[str, dict[str, Any]] = {}
    for route in routes:
        tree = by_origin.setdefault(str(route.get("origin") or "unknown"), {"routes": [], "children": {}})
        parts = [part for part in str(route.get("path") or "/").split("/") if part] or ["/"]
        node = tree
        for part in parts:
            node = node["children"].setdefault(part, {"routes": [], "children": {}})
        node["routes"].append(route)

    lines: list[str] = []

    def render(node: dict[str, Any], prefix: str) -> None:
        children = sorted(node["children"].items())
        for index, (name, child) in enumerate(children):
            last = index == len(children) - 1
            connector = "└── " if last else "├── "
            label = "/" if name == "/" else f"/{name}"
            lines.append(f"{prefix}{connector}{label}{_route_meta(child['routes'])}")
            render(child, prefix + ("    " if last else "│   "))

    for index, origin in enumerate(sorted(by_origin)):
        if index:
            lines.append("")
        lines.append(origin)
        render(by_origin[origin], "")
    return lines


def _route_from_url(value: str, *, params: list[str] | None = None) -> dict[str, Any] | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None
    except ValueError:
        return None
    origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    query = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True)})
    query.extend(name for name in params or [] if name not in query)
    return {
        "origin": origin,
        "path": parsed.path or "/",
        "method": "GET",
        "query_parameters": query,
        "priority_score": 2,
    }


def _discovery_routes(run_dir: Path, policy: ScopePolicy) -> list[dict[str, Any]]:
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    parameth = _json(run_dir / "discovery" / "parameth.json", {})
    param_by_target: dict[str, list[str]] = {}
    for record in parameth if isinstance(parameth, list) else []:
        if not isinstance(record, dict) or not record.get("target"):
            continue
        target = str(record["target"])
        names = []
        for line in record.get("interesting_lines") or []:
            names.extend(
                re.findall(
                    r"(?i)(?:parameter|param)(?:\s+found)?\s*[:=]\s*([a-zA-Z0-9_.-]+)",
                    str(line),
                )
            )
        param_by_target[target.split("?", 1)[0]] = sorted(set(names))

    values = [str(item.get("url") or "") for item in _jsonl(run_dir / "discovery" / "url-queue.jsonl")]
    for item in _json(run_dir / "discovery" / "gobuster-dir.json", []):
        if isinstance(item, dict) and item.get("path"):
            values.append(urljoin(policy.base_url.rstrip("/") + "/", str(item["path"]).lstrip("/")))
    for value in values:
        extra = param_by_target.get(value.split("?", 1)[0], [])
        route = _route_from_url(value, params=extra)
        if route is None:
            continue
        key = (route["origin"], route["path"])
        existing = routes.setdefault(key, route)
        existing["query_parameters"] = sorted(
            set(existing["query_parameters"]) | set(route["query_parameters"])
        )
    for param_target, param_names in param_by_target.items():
        route = _route_from_url(param_target, params=param_names)
        if route is not None:
            key = (route["origin"], route["path"])
            existing = routes.setdefault(key, route)
            existing["query_parameters"] = sorted(
                set(existing["query_parameters"]) | set(param_names)
            )
    return sorted(routes.values(), key=lambda item: (item["origin"], item["path"]))


def _write_parameth_targets(
    store: RunStore,
    state: dict[str, Any],
    routes: list[dict[str, Any]],
) -> Path:
    static_suffixes = {
        ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".mjs",
        ".png", ".svg", ".webp", ".woff", ".woff2",
    }
    targets = []
    for route in routes:
        path = str(route.get("path") or "/")
        if path == "/" or Path(path).suffix.lower() in static_suffixes:
            continue
        params = route.get("query_parameters") or []
        query = "&".join(f"{name}=" for name in params)
        target = f"{route['origin']}{path}" + (f"?{query}" if query else "")
        if target not in targets:
            targets.append(target)
    destination = store.run_dir(state["run_id"]) / "discovery" / "parameth-targets.txt"
    atomic_write_text(destination, "\n".join(targets) + ("\n" if targets else ""))
    store.add_artifact(state, destination, "targets", "parameth")
    return destination


def build_stage_report(store: RunStore, state: dict[str, Any], stage: str) -> Path:
    run_dir = store.run_dir(state["run_id"])
    policy = ScopePolicy.load(run_dir / "scope.toml")
    stage_state = state["stages"][stage]
    lines = [
        f"# {stage.title()} report: {policy.base_url}", "",
        f"- 상태: `{stage_state['status']}`", "",
        "## 도구 결과", "", "| 도구 | 상태 | 결과 수 | 요약 |", "|---|---|---:|---|",
    ]
    for tool, result in stage_state.get("tools", {}).items():
        lines.append(
            f"| {_cell(tool)} | {_cell(result.get('status'))} | {_cell(result.get('item_count'))} | {_cell(result.get('summary'))} |"
        )
    if not stage_state.get("tools"):
        lines.append("| - | 결과 없음 | - | - |")

    if stage == "collect":
        domains = _lines(run_dir / "collect" / "domains.txt")
        lines.extend(["", "## 수집 도메인", "", f"전체 `{len(domains)}`개 (`collect/domains.txt`)", ""])
        lines.extend(f"- `{domain}`" for domain in domains[:100])
    elif stage == "probe":
        services = _json(run_dir / "probe" / "httpx.json", [])
        lines.extend(["", "## 활성 서비스와 기술", "", "| URL | 상태 | 제목 | 기술 |", "|---|---:|---|---|"])
        for item in services if isinstance(services, list) else []:
            if isinstance(item, dict):
                tech = item.get("tech") or item.get("technologies") or []
                tech = ", ".join(map(str, tech)) if isinstance(tech, list) else tech
                lines.append(
                    f"| {_cell(item.get('url') or item.get('input'))} | {_cell(item.get('status_code'))} | {_cell(item.get('title'))} | {_cell(tech)} |"
                )
    elif stage == "crawl":
        routes = [
            route for value in _lines(run_dir / "crawl" / "katana-urls.txt")
            if (route := _route_from_url(value)) is not None
        ]
        lines.extend(["", "## Crawl 사이트맵", "", "```text"])
        lines.extend(_sitemap_lines(routes) or ["수집 URL 없음"])
        lines.append("```")
        lines.extend([
            "", "## 소스 분석 개수", "",
            f"- 주석: `{len(_json(run_dir / 'crawl' / 'source-comments.json', []))}`",
            f"- 엔드포인트: `{len(_json(run_dir / 'crawl' / 'source-endpoints.json', []))}`",
            f"- 소스 자산: `{len(_json(run_dir / 'crawl' / 'source-assets.json', []))}`",
        ])
    elif stage == "discovery":
        routes = _discovery_routes(run_dir, policy)
        targets_path = _write_parameth_targets(store, state, routes)
        target_count = len(_lines(targets_path))
        lines.extend([
            "", "## Discovery 통합 사이트맵", "",
            f"URL Discovery와 실행된 선택 도구 결과를 합친 `{len(routes)}`개 route", "", "```text",
        ])
        lines.extend(_sitemap_lines(routes) or ["수집 route 없음"])
        lines.append("```")
        lines.extend([
            "", "## Parameth 실행 후보", "",
            f"동적 실행 후보 `{target_count}`개 (`discovery/parameth-targets.txt`)",
            "Pi에서 사용자가 URL을 선택했을 때만 Parameth를 실행한다.",
        ])
    elif stage == "normalize":
        coverage = _json(run_dir / "normalize" / "coverage.json", {})
        lines.extend([
            "", "## 정규화 결과", "",
            f"- Route: `{coverage.get('routes', 0)}`",
            f"- 후보: `{coverage.get('candidates', 0)}`",
            "- 최종 보고서: `../report.md`",
        ])

    destination = run_dir / stage / "report.md"
    atomic_write_text(destination, "\n".join(lines) + "\n")
    store.add_artifact(state, destination, "stage_report", stage)
    store.save(state)
    return destination


def build_report(store: RunStore, state: dict[str, Any]) -> Path:
    run_dir = store.run_dir(state["run_id"])
    policy = ScopePolicy.load(run_dir / "scope.toml")
    surface = build_surface(policy, state, store)
    services = _json(run_dir / "probe" / "httpx.json", [])
    nuclei = _json(run_dir / "probe" / "nuclei-findings.json", [])
    domains = _lines(run_dir / "collect" / "domains.txt")
    dorks = _lines(run_dir / "collect" / "google-dorks.txt")
    source_endpoints = _json(run_dir / "crawl" / "source-endpoints.json", [])
    source_comments = _json(run_dir / "crawl" / "source-comments.json", [])
    source_assets = _json(run_dir / "crawl" / "source-assets.json", [])
    important_endpoints = _important_endpoints(source_endpoints)
    important_comments = _important_comments(source_comments)
    important_assets = _important_assets(source_assets)
    important_routes = _important_routes(surface["routes"])
    failures = [
        (stage, tool, result.get("error") or result.get("summary"))
        for stage, stage_state in state["stages"].items()
        for tool, result in stage_state.get("tools", {}).items()
        if result.get("status") == "failed"
    ]
    lines = [
        f"# Recon: {policy.base_url}", "", f"- 상태: `{state['status']}`",
        f"- 수집 도메인: `{len(domains)}`", f"- 활성 서비스: `{len(services)}`",
        f"- 원본 URL 관찰: `{surface['coverage']['observations']}`",
        f"- 기능 단위 route: `{len(surface['routes'])}`",
        f"- 사이트맵 중요 route: `{len(important_routes)}` / 최대 50",
        f"- Nuclei 후보: `{len(nuclei)}`", f"- 실패 도구: `{len(failures)}`", "",
        "## 중요 사이트맵", "",
        "표시 정보: HTTP Method, 중요도, 파라미터", "", "```text",
    ]
    lines.extend(_sitemap_lines(important_routes) or ["중요 route 없음"])
    lines.append("```")
    lines.extend([
        "", "## 중요 소스 정보", "",
        f"- 엔드포인트: `{len(source_endpoints)}`개 중 `{len(important_endpoints)}`개 표시 (`crawl/source-endpoints.json`)",
        f"- 주석: `{len(source_comments)}`개 중 `{len(important_comments)}`개 표시 (`crawl/source-comments.json`)",
        f"- 소스 자산: `{len(source_assets)}`개 중 `{len(important_assets)}`개 표시 (`crawl/source-assets.json`)",
        "", "### 중요 엔드포인트", "",
        "| Method | 엔드포인트 | 분류 | 출처 | 줄 |", "|---|---|---|---|---:|",
    ])
    for item in important_endpoints:
        lines.append(
            f"| {_cell(item['report_method'])} | {_cell(item.get('endpoint') or item.get('value'))} | "
            f"{_cell(', '.join(item['report_labels']))} | {_cell(item.get('source'))} | {_cell(item.get('line'))} |"
        )
    if not important_endpoints:
        lines.append("| - | 중요 엔드포인트 없음 | - | - | - |")
    lines.extend(["", "### 중요 주석", "", "| 분류 | 출처 | 줄 | 내용 |", "|---|---|---:|---|"])
    for item in important_comments:
        lines.append(
            f"| {_cell(', '.join(item['report_labels']))} | {_cell(item.get('url'))} | "
            f"{_cell(item.get('line'))} | {_cell(item['report_text'])} |"
        )
    if not important_comments:
        lines.append("| - | 중요 주석 없음 | - | - |")
    lines.extend(["", "### 중요 소스 자산", "", "| 종류 | 자산 | 출처 |", "|---|---|---|"])
    for item in important_assets:
        lines.append(
            f"| {_cell(item.get('kind'))} | {_cell(item.get('url') or item.get('value'))} | {_cell(item.get('source'))} |"
        )
    if not important_assets:
        lines.append("| - | 중요 소스 자산 없음 | - |")
    lines.extend(["", "## 활성 서비스", "", "| URL | 상태 | 제목 | 기술 |", "|---|---:|---|---|"])
    for item in services[:30]:
        tech = item.get("tech") or item.get("technologies") or []
        tech = ", ".join(map(str, tech)) if isinstance(tech, list) else tech
        lines.append(f"| {_cell(item.get('url') or item.get('input'))} | {_cell(item.get('status_code'))} | {_cell(item.get('title'))} | {_cell(tech)} |")
    if not services:
        lines.append("| - | - | 활성 서비스 없음 | - |")
    lines.extend(["", "## 실패 도구", ""])
    if failures:
        lines.extend(["| 단계 | 도구 | 원인 |", "|---|---|---|"])
        lines.extend(f"| {_cell(stage)} | {_cell(tool)} | {_cell(str(error)[:180])} |" for stage, tool, error in failures)
    else:
        lines.append("기록된 실패가 없다.")
    lines.extend([
        "", "## 전체 결과 위치", "", "- 단계별 원본 출력: `<단계>/raw/`",
        "- 단계별 결과: `<단계>/`", "- 전체 route: `normalize/routes.jsonl`",
        "- 상위 후보: `normalize/candidates.json`", "- 수행 범위: `normalize/coverage.json`",
        f"- Google Dork: `{len(dorks)}`개 (`collect/google-dorks.txt`)", "",
    ])
    destination = run_dir / "report.md"
    atomic_write_text(destination, "\n".join(lines))
    store.add_artifact(state, destination, "report", "surface")
    store.save(state)
    return destination
