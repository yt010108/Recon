"""수집 결과에서 자산, 엔드포인트 역할, 입력 지점과 발견 위치를 요약한다."""

from __future__ import annotations

import hashlib
import json
import re
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


def _tokens(value: str) -> set[str]:
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    tokens = {
        token.lower()
        for token in re.split(r"[^A-Za-z0-9]+", camel_split)
        if token
    }
    tokens.update(token[:-1] for token in list(tokens) if len(token) > 3 and token.endswith("s"))
    return tokens


def _matches(
    url: str,
    hints: dict[str, tuple[str, ...]],
    extra_values: list[str] | None = None,
) -> list[str]:
    parsed = urlsplit(url)
    values = [parsed.path, *(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))]
    values.extend(extra_values or [])
    tokens = set().union(*(_tokens(value) for value in values)) if values else set()
    return [
        name
        for name, words in hints.items()
        if any(word.lower() in tokens for word in words)
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

    for item in _json(run_dir / "parsed" / "parameth.json", []):
        if not isinstance(item, dict) or not item.get("target"):
            continue
        _add_evidence(
            mapping,
            str(item["target"]),
            {
                "tool": "parameth",
                "artifact": str(item.get("evidence") or "parsed/parameth.json"),
                "parameters": item.get("parameters") or [],
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
    by_url: dict[str, dict[str, Any]] = {}

    def endpoint_for(url: str) -> dict[str, Any]:
        item = by_url.setdefault(
            url,
            {
                "url": url,
                "methods": [],
                "query_parameters": [],
                "body_parameters": [],
                "form_fields": [],
                "content_types": [],
                "evidence": list(evidence.get(url, [])),
            },
        )
        return item

    for url in evidence:
        item = endpoint_for(url)
        for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            if name not in item["query_parameters"]:
                item["query_parameters"].append(name)

    for source in source_endpoints:
        if not isinstance(source, dict) or not source.get("endpoint"):
            continue
        url = str(source["endpoint"])
        item = endpoint_for(url)
        method = str(source.get("method") or "").upper()
        if method and method not in item["methods"]:
            item["methods"].append(method)
        content_type = str(source.get("content_type") or "").strip()
        if content_type and content_type not in item["content_types"]:
            item["content_types"].append(content_type)
        for key in ("query_parameters", "body_parameters"):
            values = source.get(key) if isinstance(source.get(key), list) else []
            for value in values:
                name = str(value).strip()
                if name and name not in item[key]:
                    item[key].append(name)
        fields = source.get("form_fields") if isinstance(source.get("form_fields"), list) else []
        for field in fields:
            if isinstance(field, dict) and field not in item["form_fields"]:
                item["form_fields"].append(field)

    for finding in parameter_findings if isinstance(parameter_findings, list) else []:
        if not isinstance(finding, dict) or not finding.get("target"):
            continue
        item = endpoint_for(str(finding["target"]))
        for value in finding.get("parameters", []):
            name = str(value).strip()
            if name and name not in item["query_parameters"]:
                item["query_parameters"].append(name)

    endpoints: list[dict[str, Any]] = []
    for url, item in sorted(by_url.items()):
        input_names = [*item["query_parameters"], *item["body_parameters"]]
        input_names.extend(
            str(field.get("name") or "")
            for field in item["form_fields"]
            if isinstance(field, dict)
        )
        item["roles"] = _matches(url, ROLE_HINTS, input_names)
        item["sink_hints"] = _matches(url, SINK_HINTS, input_names)
        # 기존 소비자를 위한 전체 파라미터 필드는 유지한다.
        item["parameters"] = list(dict.fromkeys(input_names))

        score = 0.15
        reasons = ["scoped endpoint"]
        if item["evidence"]:
            score += 0.15
            reasons.append("discovery evidence")
        if any(entry.get("source") for entry in item["evidence"] if isinstance(entry, dict)):
            score += 0.15
            reasons.append("source provenance")
        if item["methods"]:
            score += 0.1
            reasons.append("HTTP method observed")
        if any(method in {"POST", "PUT", "PATCH", "DELETE"} for method in item["methods"]):
            score += 0.1
            reasons.append("state-changing method")
        if item["parameters"]:
            score += 0.15
            reasons.append("named input")
        if item["sink_hints"]:
            score += 0.15
            reasons.append("sink token")
        item["confidence"] = round(min(score, 0.95), 2)
        item["confidence_reasons"] = reasons
        item["validation_status"] = "unverified"
        endpoints.append(item)
    return {
        "scope": state["scope"],
        "network_services": network_services,
        "web_services": services,
        "endpoints": endpoints,
        "source_endpoints": source_endpoints,
        "parameter_findings": parameter_findings,
        "nuclei_findings": nuclei_findings,
    }


def _finding_id(url: str) -> str:
    return "candidate-" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]


def _merge_findings(run_dir, endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    existing_raw = _json(run_dir / "parsed" / "findings.json", [])
    existing = {
        str(item.get("finding_id")): item
        for item in existing_raw
        if isinstance(item, dict) and item.get("finding_id")
    }
    findings: list[dict[str, Any]] = []
    for endpoint in endpoints:
        methods = [str(value) for value in endpoint.get("methods", [])]
        candidate_types = [str(value) for value in endpoint.get("sink_hints", [])]
        has_inputs = bool(endpoint.get("parameters") or endpoint.get("form_fields"))
        changes_state = any(value in {"POST", "PUT", "PATCH", "DELETE"} for value in methods)
        if not candidate_types and not has_inputs and not changes_state:
            continue
        identifier = _finding_id(str(endpoint["url"]))
        previous = existing.get(identifier, {})
        finding = {
            **previous,
            "finding_id": identifier,
            "status": previous.get("status", "unverified"),
            "url": endpoint["url"],
            "methods": methods,
            "candidate_types": candidate_types,
            "confidence": endpoint.get("confidence", 0),
            "confidence_reasons": endpoint.get("confidence_reasons", []),
            "parameters": endpoint.get("parameters", []),
            "evidence": endpoint.get("evidence", []),
            "notes": previous.get("notes", ""),
            "request_artifact": previous.get("request_artifact"),
            "response_artifact": previous.get("response_artifact"),
        }
        endpoint["finding_id"] = identifier
        endpoint["validation_status"] = finding["status"]
        findings.append(finding)
    return sorted(findings, key=lambda item: (-float(item["confidence"]), str(item["url"])))


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
    attack_surface = _attack_surface(
        state,
        services,
        network_services,
        evidence,
        nuclei_findings,
        source_endpoints,
        parameter_findings,
    )
    surface_endpoints = attack_surface["endpoints"]
    findings = _merge_findings(run_dir, surface_endpoints)
    findings_path = run_dir / "parsed" / "findings.json"
    atomic_write_json(findings_path, findings)
    store.add_artifact(state, findings_path, "findings-queue", "harness")

    attack_surface_path = run_dir / "parsed" / "attack-surface.json"
    atomic_write_json(attack_surface_path, attack_surface)
    store.add_artifact(state, attack_surface_path, "attack-surface", "harness")

    urls = [str(item["url"]) for item in surface_endpoints]
    endpoints = [
        item for item in surface_endpoints if item.get("roles") or item.get("parameters")
    ]
    sinks = [item for item in surface_endpoints if item.get("finding_id")]

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
        f"- 검토할 입력 지점: `{len(findings)}`",
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

    lines.extend(["", "## 주요 엔드포인트", "", "| 역할 | 메서드 | URL | 입력 |", "|---|---|---|---|"])
    lines.extend(
        f"| {_cell(', '.join(item.get('roles') or ['일반 웹']))} | "
        f"{_cell(', '.join(item.get('methods') or []))} | {_cell(item.get('url'))} | "
        f"{_cell(', '.join(item.get('parameters') or []))} |"
        for item in endpoints
    )
    if not endpoints:
        lines.append("| - | - | 역할을 추정할 엔드포인트 없음 | - |")

    lines.extend([
        "",
        "## 소스에서 찾은 경로와 액션",
        "",
        "| 유형 | 메서드 | 값 | 입력 | 출처 |",
        "|---|---|---|---|---|",
    ])
    for item in source_endpoints:
        lines.append(
            f"| {_cell(item.get('kind'))} | {_cell(item.get('method'))} | "
            f"{_cell(item.get('endpoint') or item.get('value'))} | "
            f"{_cell(', '.join([*(item.get('query_parameters') or []), *(item.get('body_parameters') or [])]))} | "
            f"{_cell(item.get('source'))}:{_cell(item.get('line'))} |"
        )
    if not source_endpoints:
        lines.append("| - | - | 발견된 후보 없음 | - | - |")

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
        "토큰, 관찰된 메서드와 named input에 따른 검증 큐이며 취약점 판정이 아니다.",
        "",
        "| ID | 상태 | 신뢰도 | 후보 유형 | 메서드 | URL | 파라미터 | 발견 위치 |",
        "|---|---|---:|---|---|---|---|---|",
    ])
    for item in sinks:
        lines.append(
            f"| {_cell(item.get('finding_id'))} | {_cell(item.get('validation_status'))} | "
            f"{_cell(item.get('confidence'))} | {_cell(', '.join(item.get('sink_hints') or []))} | "
            f"{_cell(', '.join(item.get('methods') or []))} | {_cell(item.get('url'))} | "
            f"{_cell(', '.join(item.get('parameters') or []))} | "
            f"{_cell(_evidence_label(item.get('evidence') or []))} |"
        )
    if not sinks:
        lines.append("| - | - | - | 발견된 후보 없음 | - | - | - | - |")

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
        "수동 검증 상태와 메모는 `parsed/findings.json`에 있다.",
        "",
    ])
    destination = run_dir / "report.md"
    destination.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    store.add_artifact(state, destination, "report", "harness")
    store.save(state)
    return destination
