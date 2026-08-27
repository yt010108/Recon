"""수집 결과에서 자산, 엔드포인트 역할, 입력 지점과 발견 위치를 요약한다."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from .storage import RunStore, atomic_write_json


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
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ] if path.exists() else []


def _json(path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _cell(value: Any) -> str:
    return str(value or "-").replace("|", "\\|").replace("\n", " ")


def _matches(url: str, hints: dict[str, tuple[str, ...]]) -> list[str]:
    path = urlsplit(url).path.lower()
    params = [
        name.lower()
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
    ]
    values = [path, *params]
    return [
        name
        for name, words in hints.items()
        if any(word in value for value in values for word in words)
    ]


def _add_evidence(
    mapping: dict[str, list[dict[str, Any]]],
    url: str,
    evidence: dict[str, Any],
) -> None:
    if not url.startswith(("http://", "https://")):
        return
    items = mapping.setdefault(url, [])
    if evidence not in items:
        items.append(evidence)


def _url_evidence(run_dir, base_url: str) -> dict[str, list[dict[str, Any]]]:
    mapping: dict[str, list[dict[str, Any]]] = {}

    line_sources = (
        ("wayback-urls.txt", "waybackurls"),
        ("alive-urls.txt", "httpx"),
        ("katana-urls.txt", "katana"),
    )
    for name, tool in line_sources:
        for url in _lines(run_dir / "parsed" / name):
            _add_evidence(
                mapping,
                url,
                {"tool": tool, "artifact": f"parsed/{name}"},
            )

    for item in _json(run_dir / "parsed" / "gobuster-dir.json", []):
        if not isinstance(item, dict):
            continue
        url = str(item.get("url") or "")
        if not url and item.get("path") and base_url:
            url = urljoin(base_url.rstrip("/") + "/", str(item["path"]).lstrip("/"))
        if url:
            _add_evidence(
                mapping,
                url,
                {
                    "tool": "gobuster_dir",
                    "artifact": str(item.get("evidence") or "parsed/gobuster-dir.json"),
                    "source": item.get("base_url") or base_url or None,
                },
            )

    for item in _json(run_dir / "parsed" / "source-endpoints.json", []):
        if not isinstance(item, dict) or not item.get("endpoint"):
            continue
        _add_evidence(
            mapping,
            str(item["endpoint"]),
            {
                "tool": "source_comments",
                "artifact": "parsed/source-endpoints.json",
                "source": item.get("source"),
                "line": item.get("line"),
                "context": item.get("context"),
                "kind": item.get("kind"),
            },
        )

    return mapping


def _urls(run_dir, base_url: str) -> list[str]:
    """기존 호출자를 위해 URL 목록 인터페이스를 유지한다."""
    return sorted(_url_evidence(run_dir, base_url))


def _evidence_label(items: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    for item in items:
        source = item.get("source")
        line = item.get("line")
        if source:
            label = str(source)
            if line not in {None, "", 0, "0"}:
                label += f":{line}"
            kind = item.get("kind")
            if kind:
                label += f" ({kind})"
        else:
            label = str(item.get("artifact") or item.get("tool") or "unknown")
        if label not in labels:
            labels.append(label)
    if not labels:
        return "-"
    if len(labels) > 3:
        return "; ".join(labels[:3]) + f"; +{len(labels) - 3} more"
    return "; ".join(labels)


def _attack_surface(
    state: dict[str, Any],
    services: list[dict[str, Any]],
    network_services: list[dict[str, Any]],
    evidence: dict[str, list[dict[str, Any]]],
    nuclei_findings: list[dict[str, Any]],
    source_endpoints: list[dict[str, Any]],
    parameter_findings: Any,
) -> dict[str, Any]:
    endpoints: list[dict[str, Any]] = []
    for url in sorted(evidence):
        parameters = [
            name
            for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ]
        endpoints.append(
            {
                "url": url,
                "roles": _matches(url, ROLE_HINTS),
                "sink_hints": _matches(url, SINK_HINTS),
                "parameters": parameters,
                "evidence": evidence[url],
            }
        )
    return {
        "scope": state["scope"],
        "network_services": network_services,
        "web_services": services,
        "endpoints": endpoints,
        "source_endpoints": source_endpoints,
        "parameter_findings": parameter_findings,
        "nuclei_findings": nuclei_findings,
    }


def build_report(store: RunStore, state: dict[str, Any]):
    run_dir = store.run_dir(state["run_id"])
    scope = state["scope"]
    mode = str(scope.get("mode", "internet"))
    base_url = str(scope.get("base_url") or "")
    target_label = str(scope.get("target_label") or base_url or scope.get("name") or "scope")

    services = _json(run_dir / "parsed" / "httpx.json", [])
    if not isinstance(services, list):
        services = []
    network_services = _json(run_dir / "parsed" / "network-services.json", [])
    if not isinstance(network_services, list):
        network_services = []
    source_endpoints = _json(run_dir / "parsed" / "source-endpoints.json", [])
    if not isinstance(source_endpoints, list):
        source_endpoints = []
    dorks = _lines(run_dir / "parsed" / "google-dorks.txt")
    parameter_findings = _json(run_dir / "parsed" / "parameth.json", [])
    nuclei_findings = _json(run_dir / "parsed" / "nuclei-findings.json", [])
    if not isinstance(nuclei_findings, list):
        nuclei_findings = []

    evidence = _url_evidence(run_dir, base_url)
    urls = sorted(evidence)
    endpoints = [(url, _matches(url, ROLE_HINTS)) for url in urls]
    endpoints = [
        (url, roles or ["일반 웹"])
        for url, roles in endpoints
        if roles or urlsplit(url).query
    ]
    sinks = [
        (url, reasons, evidence.get(url, []))
        for url in urls
        if (reasons := _matches(url, SINK_HINTS))
    ]

    attack_surface = _attack_surface(
        state,
        services,
        network_services,
        evidence,
        nuclei_findings,
        source_endpoints,
        parameter_findings,
    )
    attack_surface_path = run_dir / "parsed" / "attack-surface.json"
    atomic_write_json(attack_surface_path, attack_surface)
    store.add_artifact(state, attack_surface_path, "attack-surface", "harness")

    lines = [
        f"# Recon: {target_label}",
        "",
        f"- 모드: `{mode}`",
        f"- 상태: `{state['status']}`",
        f"- 호스트: `{len(_lines(run_dir / 'parsed' / 'hosts.txt'))}`",
        f"- 스코프 열린 포트: `{len(network_services)}`",
        f"- 활성 웹 서비스: `{len(services)}`",
        f"- 수집 URL: `{len(urls)}`",
        f"- Nuclei 발견 후보: `{len(nuclei_findings)}`",
        f"- 검토할 입력 지점: `{len(sinks)}`",
        "",
        "## 자산",
        "",
        "| URL | 상태 | 제목 | 기술 |",
        "|---|---:|---|---|",
    ]
    for item in services:
        tech = item.get("tech") or item.get("technologies") or []
        tech = ", ".join(map(str, tech)) if isinstance(tech, list) else tech
        lines.append(
            f"| {_cell(item.get('url') or item.get('input'))} | "
            f"{_cell(item.get('status_code'))} | {_cell(item.get('title'))} | {_cell(tech)} |"
        )
    if not services:
        lines.append("| - | - | 활성 웹 서비스 없음 | - |")

    if network_services:
        lines.extend([
            "",
            "## 내부망 열린 포트",
            "",
            "| 호스트 | 포트 | 프로토콜 | 서비스 | 근거 |",
            "|---|---:|---|---|---|",
        ])
        for item in network_services:
            lines.append(
                f"| {_cell(item.get('host'))} | {_cell(item.get('port'))} | "
                f"{_cell(item.get('protocol'))} | {_cell(item.get('service'))} | "
                f"`{_cell(item.get('evidence'))}` |"
            )

    lines.extend(["", "## 주요 엔드포인트", "", "| 역할 | URL |", "|---|---|"])
    lines.extend(
        f"| {_cell(', '.join(roles))} | {_cell(url)} |"
        for url, roles in endpoints
    )
    if not endpoints:
        lines.append("| - | 역할을 추정할 엔드포인트 없음 |")

    lines.extend([
        "",
        "## 소스에서 찾은 경로와 액션",
        "",
        "| 유형 | 값 | 출처 |",
        "|---|---|---|",
    ])
    for item in source_endpoints:
        lines.append(
            f"| {_cell(item.get('kind'))} | {_cell(item.get('endpoint') or item.get('value'))} | "
            f"{_cell(item.get('source'))}:{_cell(item.get('line'))} |"
        )
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
        "",
        "## Nuclei 발견 후보",
        "",
        "Nuclei 템플릿의 자동 탐지 결과이며 취약점 확정이 아니다.",
        "",
        "| 심각도 | 템플릿 | 매처 | 이름 | 대상 | HTTP | 근거 |",
        "|---|---|---|---|---|---:|---|",
    ])
    for item in nuclei_findings:
        lines.append(
            f"| {_cell(item.get('severity'))} | {_cell(item.get('template_id'))} | "
            f"{_cell(item.get('matcher_name'))} | {_cell(item.get('name'))} | "
            f"{_cell(item.get('matched_at'))} | {_cell(item.get('status_code'))} | "
            f"`{_cell(item.get('evidence'))}` |"
        )
    if not nuclei_findings:
        lines.append("| - | - | - | 근거가 확인된 발견 후보 없음 | - | - | - |")

    lines.extend([
        "",
        "## 우선 검토할 입력 지점",
        "",
        "경로명과 쿼리 파라미터에 따른 후보이며 취약점 판정이 아니다. 발견 위치는 후보가 어떤 도구/소스에서 들어왔는지 보여준다.",
        "",
        "| 후보 유형 | URL | 파라미터 | 발견 위치 |",
        "|---|---|---|---|",
    ])
    for url, reasons, sink_evidence in sinks:
        params = ", ".join(
            name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
        ) or "-"
        lines.append(
            f"| {_cell(', '.join(reasons))} | {_cell(url)} | {_cell(params)} | "
            f"{_cell(_evidence_label(sink_evidence))} |"
        )
    if not sinks:
        lines.append("| - | 발견된 후보 없음 | - | - |")

    lines.extend(["", "## Google Dorks", ""])
    if mode == "competition":
        lines.append("Competition 모드에서는 인터넷 과거/검색 수집을 실행하지 않는다.")
    else:
        lines.append(
            f"Google 요청 없이 검색식 `{len(dorks)}`개를 생성했다: `parsed/google-dorks.txt`"
            if dorks else "생성된 검색식이 없다."
        )

    lines.extend([
        "",
        "## 증거",
        "",
        "원문은 `raw/`, 정리된 결과는 `parsed/`에 있다.",
        "Agent 입력용 통합 표면은 `parsed/attack-surface.json`에 있다.",
        "",
    ])
    destination = run_dir / "report.md"
    destination.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    store.add_artifact(state, destination, "report", "harness")
    store.save(state)
    return destination
