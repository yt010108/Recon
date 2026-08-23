"""수집 결과에서 자산, 엔드포인트 역할, 입력 지점 후보를 요약한다."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from .storage import RunStore


ROLE_HINTS = {
    "인증": ("login", "logout", "signin", "signup", "register", "auth", "oauth", "sso", "password"),
    "관리": ("admin", "manage", "dashboard", "console", "panel"),
    "API": ("api", "graphql", "swagger", "openapi", "rpc"),
    "파일 처리": ("upload", "download", "export", "import", "attachment", "file"),
    "검색": ("search", "query", "find", "filter"),
    "사용자/객체": ("user", "account", "profile", "order", "invoice", "item", "document"),
    "개발/운영": ("debug", "dev", "test", "internal", "health", "metrics", "actuator"),
}

SINK_HINTS = {
    "파일 입력": ("upload", "import", "file", "attachment", "path", "filename"),
    "외부 URL/이동": ("url", "uri", "redirect", "return", "next", "callback", "webhook"),
    "명령·템플릿 입력": ("cmd", "command", "exec", "template", "render"),
    "조회·식별자 입력": ("id", "user", "account", "order", "document", "item"),
    "검색·필터 입력": ("search", "query", "q", "filter", "sort"),
    "인증 입력": ("login", "auth", "token", "password", "reset", "oauth"),
}


def _lines(path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()] if path.exists() else []


def _json(path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _cell(value: Any) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", " ")


def _matches(url: str, hints: dict[str, tuple[str, ...]]) -> list[str]:
    path = urlsplit(url).path.lower()
    params = [name.lower() for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    return [name for name, words in hints.items() if any(word in value for value in [path, *params] for word in words)]


def _urls(run_dir, base_url: str) -> list[str]:
    values: set[str] = set()
    for name in ("wayback-urls.txt", "alive-urls.txt", "katana-urls.txt"):
        values.update(_lines(run_dir / "parsed" / name))
    for item in _json(run_dir / "parsed" / "gobuster-dir.json", []):
        if item.get("path"):
            values.add(urljoin(base_url.rstrip("/") + "/", str(item["path"]).lstrip("/")))
    for item in _json(run_dir / "parsed" / "source-endpoints.json", []):
        if item.get("endpoint"):
            values.add(str(item["endpoint"]))
    return sorted(value for value in values if value.startswith(("http://", "https://")))


def build_report(store: RunStore, state: dict[str, Any]):
    run_dir = store.run_dir(state["run_id"])
    base_url = state["scope"]["base_url"]
    services = _json(run_dir / "parsed" / "httpx.json", [])
    source_endpoints = _json(run_dir / "parsed" / "source-endpoints.json", [])
    dorks = _lines(run_dir / "parsed" / "google-dorks.txt")
    nuclei_findings = _json(run_dir / "parsed" / "nuclei-findings.json", [])
    urls = _urls(run_dir, base_url)
    endpoints = [(url, _matches(url, ROLE_HINTS)) for url in urls]
    endpoints = [(url, roles or ["일반 웹"]) for url, roles in endpoints if roles or urlsplit(url).query]
    sinks = [(url, reasons) for url in urls if (reasons := _matches(url, SINK_HINTS))]

    lines = [
        f"# Recon: {base_url}", "",
        f"- 상태: `{state['status']}`",
        f"- 호스트: `{len(_lines(run_dir / 'parsed' / 'hosts.txt'))}`",
        f"- 활성 서비스: `{len(services)}`",
        f"- 수집 URL: `{len(urls)}`",
        f"- Nuclei 발견 후보: `{len(nuclei_findings)}`",
        f"- 검토할 입력 지점: `{len(sinks)}`", "",
        "## 자산", "", "| URL | 상태 | 제목 | 기술 |", "|---|---:|---|---|",
    ]
    for item in services[:30]:
        tech = item.get("tech") or item.get("technologies") or []
        tech = ", ".join(map(str, tech)) if isinstance(tech, list) else tech
        lines.append(f"| {_cell(item.get('url') or item.get('input'))} | {_cell(item.get('status_code'))} | {_cell(item.get('title'))} | {_cell(tech)} |")
    if not services:
        lines.append("| - | - | 활성 서비스 없음 | - |")

    lines.extend(["", "## 주요 엔드포인트", "", "| 역할 | URL |", "|---|---|"])
    lines.extend(f"| {_cell(', '.join(roles))} | {_cell(url)} |" for url, roles in endpoints[:50])
    if not endpoints:
        lines.append("| - | 역할을 추정할 엔드포인트 없음 |")

    lines.extend(["", "## 소스에서 찾은 경로와 액션", "", "| 유형 | 값 | 출처 |", "|---|---|---|"])
    for item in source_endpoints[:50]:
        lines.append(f"| {_cell(item.get('kind'))} | {_cell(item.get('endpoint') or item.get('value'))} | {_cell(item.get('source'))}:{_cell(item.get('line'))} |")
    if not source_endpoints:
        lines.append("| - | 발견된 후보 없음 | - |")

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
        "unknown": 5,
    }
    nuclei_findings = sorted(
        nuclei_findings,
        key=lambda item: (
            severity_order.get(str(item.get("severity", "unknown")).lower(), 5),
            str(item.get("template_id", "")),
            str(item.get("matched_at", "")),
        ),
    )
    lines.extend([
        "", "## Nuclei 발견 후보", "",
        "공식 서명 HTTP 템플릿의 자동 탐지 결과이며 취약점 확정이 아니다.", "",
        "| 심각도 | 템플릿 | 매처 | 이름 | 대상 | HTTP | 근거 |",
        "|---|---|---|---|---|---:|---|",
    ])
    for item in nuclei_findings[:100]:
        lines.append(
            f"| {_cell(item.get('severity'))} | {_cell(item.get('template_id'))} | "
            f"{_cell(item.get('matcher_name'))} | {_cell(item.get('name'))} | "
            f"{_cell(item.get('matched_at'))} | "
            f"{_cell(item.get('status_code'))} | `{_cell(item.get('evidence'))}` |"
        )
    if not nuclei_findings:
        lines.append("| - | - | - | 근거가 확인된 발견 후보 없음 | - | - | - |")

    lines.extend(["", "## 우선 검토할 입력 지점", "", "경로명과 쿼리 파라미터에 따른 후보이며 취약점 판정이 아니다.", "", "| 후보 유형 | URL | 파라미터 |", "|---|---|---|"])
    for url, reasons in sinks[:50]:
        params = ", ".join(name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)) or "-"
        lines.append(f"| {_cell(', '.join(reasons))} | {_cell(url)} | {_cell(params)} |")
    if not sinks:
        lines.append("| - | 발견된 후보 없음 | - |")

    lines.extend([
        "", "## Google Dorks", "",
        f"Google 요청 없이 검색식 `{len(dorks)}`개를 생성했다: `parsed/google-dorks.txt`"
        if dorks else "생성된 검색식이 없다.",
    ])

    lines.extend(["", "## 증거", "", "원문은 `raw/`, 정리된 결과는 `parsed/`에 있다.", ""])
    destination = run_dir / "report.md"
    destination.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    store.add_artifact(state, destination, "report", "harness")
    store.save(state)
    return destination
