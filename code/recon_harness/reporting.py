"""정규화된 웹 표면에서 사람이 바로 읽을 작은 요약을 만든다."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .storage import RunStore, atomic_write_text
from .surface import build_surface


def _json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _cell(value: Any) -> str:
    rendered = "-" if value is None or value == "" else str(value)
    return rendered.replace("|", "\\|").replace("\n", " ")


def _evidence(items: list[dict[str, Any]]) -> str:
    labels: list[str] = []
    for item in items:
        source = item.get("source")
        label = str(source or item.get("artifact") or item.get("tool") or "unknown")
        if source and item.get("line"):
            label += f":{item['line']}"
        if label not in labels:
            labels.append(label)
    return "; ".join(labels[:2]) + (f"; +{len(labels) - 2}" if len(labels) > 2 else "")


def build_report(store: RunStore, state: dict[str, Any]) -> Path:
    run_dir = store.run_dir(state["run_id"])
    surface = build_surface(store, state)
    origins = surface["origins"]
    routes = surface["routes"]
    candidates = surface["candidates"]
    coverage = surface["coverage"]
    scope = state["scope"]
    nuclei = _json(run_dir / "parsed" / "nuclei-findings.json", [])

    lines = [
        f"# Competition Web Recon: {scope.get('target_label', '-')}",
        "",
        f"- 상태: `{state.get('status', '-')}`",
        f"- 프로필: `{scope.get('profile', 'fast')}`",
        f"- 활성 origin: `{len(origins)}`",
        f"- 기능 단위 route: `{len(routes)}`",
        f"- 우선 검토 후보: `{len(candidates)}` / 최대 20",
        f"- 실패 도구: `{len(coverage['failures'])}`",
        "",
        "## 활성 웹 서비스",
        "",
        "| URL | 상태 | 제목 | 서버 | 기술 |",
        "|---|---:|---|---|---|",
    ]
    for item in origins[:30]:
        technologies = item.get("technologies") or []
        if isinstance(technologies, list):
            technologies = ", ".join(map(str, technologies))
        lines.append(
            f"| {_cell(item.get('url'))} | {_cell(item.get('status_code'))} | "
            f"{_cell(item.get('title'))} | {_cell(item.get('web_server'))} | {_cell(technologies)} |"
        )
    if not origins:
        lines.append("| - | - | 활성 웹 서비스 없음 | - | - |")

    lines.extend(
        [
            "",
            "## 우선 검토 후보",
            "",
            "| 우선 | Method | Route | 입력 | 이유 | 근거 |",
            "|---|---|---|---|---|---|",
        ]
    )
    for item in candidates:
        inputs = list(dict.fromkeys([*item["query_parameters"], *item["body_parameters"]]))
        lines.append(
            f"| {_cell(item['priority'])} | {_cell(item['method'])} | {_cell(item['route'])} | "
            f"{_cell(', '.join(inputs))} | {_cell('; '.join(item['reasons']))} | "
            f"{_cell(_evidence(item['evidence']))} |"
        )
        lines.append(f"|  |  | 다음 행동 |  | {_cell(item['next_action'])} |  |")
    if not candidates:
        lines.append("| - | - | 검토 후보 없음 | - | - | - |")

    lines.extend(["", "## 실패 및 미확인 영역", ""])
    if coverage["failures"]:
        lines.extend(["| 단계 | 도구 | 원인 |", "|---|---|---|"])
        for item in coverage["failures"]:
            error = str(item["error"])
            if len(error) > 180:
                error = error[:177] + "..."
            lines.append(f"| {_cell(item['stage'])} | {_cell(item['tool'])} | {_cell(error)} |")
    else:
        lines.append("기록된 도구 실패가 없다.")

    lines.extend(["", "## Nuclei", ""])
    lines.append(
        f"별도 실행 결과 `{len(nuclei)}`건. 자동 탐지는 취약점 확정이 아니다."
        if nuclei else "Nuclei는 실행되지 않았거나 발견 결과가 없다."
    )
    lines.extend(
        [
            "",
            "## 증거 위치",
            "",
            "- 원본 도구 출력: `raw/`",
            "- 도구별 중간 결과: `parsed/`",
            "- 활성 origin: `normalized/origins.json`",
            "- 전체 기능 route: `normalized/routes.jsonl`",
            "- 상위 후보: `normalized/candidates.json`",
            "- 수행 범위와 실패: `normalized/coverage.json`",
            "",
        ]
    )
    destination = run_dir / "summary.md"
    atomic_write_text(destination, "\n".join(lines))
    store.add_artifact(state, destination, "summary", "surface")
    store.save(state)
    return destination
