"""전체 수집 결과를 보존하고 첫 화면에는 검토 후보만 보여준다."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .policy import ScopePolicy
from .storage import RunStore, atomic_write_text
from .surface import build_surface


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


def _cell(value: Any) -> str:
    rendered = "-" if value is None or value == "" else str(value)
    return rendered.replace("|", "\\|").replace("\n", " ")


def build_report(store: RunStore, state: dict[str, Any]) -> Path:
    run_dir = store.run_dir(state["run_id"])
    policy = ScopePolicy.load(run_dir / "scope.toml")
    surface = build_surface(policy, state, store)
    services = _json(run_dir / "parsed" / "httpx.json", [])
    nuclei = _json(run_dir / "parsed" / "nuclei-findings.json", [])
    hosts = _lines(run_dir / "parsed" / "hosts.txt")
    dorks = _lines(run_dir / "parsed" / "google-dorks.txt")
    failures = [
        (stage, tool, result.get("error") or result.get("summary"))
        for stage, stage_state in state["stages"].items()
        for tool, result in stage_state.get("tools", {}).items()
        if result.get("status") == "failed"
    ]
    lines = [
        f"# Recon: {policy.base_url}", "", f"- 상태: `{state['status']}`",
        f"- 수집 호스트: `{len(hosts)}`", f"- 활성 서비스: `{len(services)}`",
        f"- 원본 URL 관찰: `{surface['coverage']['observations']}`",
        f"- 기능 단위 route: `{len(surface['routes'])}`",
        f"- 우선 검토 후보: `{len(surface['candidates'])}` / 최대 20",
        f"- Nuclei 후보: `{len(nuclei)}`", f"- 실패 도구: `{len(failures)}`", "",
        "## 우선 검토 후보", "",
        "| 우선 | Method | Route | 입력 | 분류 | 다음 행동 |", "|---|---|---|---|---|---|",
    ]
    for item in surface["candidates"]:
        labels = ", ".join([*item["roles"], *item["sink_hints"]])
        lines.append(f"| {_cell(item['priority'])} | {_cell(item['method'])} | {_cell(item['route'])} | {_cell(', '.join(item['query_parameters']))} | {_cell(labels)} | {_cell(item['next_action'])} |")
    if not surface["candidates"]:
        lines.append("| - | - | 검토 후보 없음 | - | - | - |")
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
        "", "## 전체 결과 위치", "", "- 원본 출력: `raw/`",
        "- 도구별 파싱 결과: `parsed/`", "- 전체 route: `normalized/routes.jsonl`",
        "- 상위 후보: `normalized/candidates.json`", "- 수행 범위: `normalized/coverage.json`",
        f"- Google Dork: `{len(dorks)}`개 (`parsed/google-dorks.txt`)", "",
    ])
    destination = run_dir / "report.md"
    atomic_write_text(destination, "\n".join(lines))
    store.add_artifact(state, destination, "report", "surface")
    store.save(state)
    return destination
