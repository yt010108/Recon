"""state.json에서 짧은 리콘 요약 보고서를 만든다."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .models import STAGE_ORDER
from .storage import RunStore


def build_report(store: RunStore, state: dict[str, Any]) -> Path:
    scope = state["scope"]
    dos_tools_used = bool(
        scope["permissions"].get("allow_dos_tools")
        or {"gobuster_dir", "parameth"} & state["stages"]["discovery"]["tools"].keys()
    )
    lines = [
        f"# Recon summary: {scope['base_url']}",
        "",
        f"- Run: `{state['run_id']}`",
        f"- Status: `{state['status']}`",
        f"- Gobuster/Parameth: `{'enabled' if dos_tools_used else 'disabled'}`",
        "",
        "## Results",
        "",
        "| Stage | Tool | Status | Items | Summary |",
        "|---|---|---|---:|---|",
    ]

    for stage in STAGE_ORDER:
        stage_state = state["stages"][stage]
        if not stage_state["tools"]:
            lines.append(f"| {stage} | - | {stage_state['status']} | 0 | - |")
            continue
        for tool, result in stage_state["tools"].items():
            summary = str(result["summary"]).replace("|", "\\|").replace("\n", " ")
            lines.append(
                f"| {stage} | {tool} | {result['status']} | "
                f"{result['item_count']} | {summary} |"
            )

    errors = [
        f"- `{stage}/{tool}`: {result['error']}"
        for stage in STAGE_ORDER
        for tool, result in state["stages"][stage]["tools"].items()
        if result.get("error")
    ]
    if errors:
        lines.extend(["", "## Errors", "", *errors])

    lines.extend(
        [
            "",
            "## Evidence",
            "",
            "원본 출력과 robots.txt·HTML/CSS/JS 주석은 이 런의 `raw/`와 `parsed/`에 저장되어 있다.",
            "스크린샷은 `screenshots/`에 저장한다.",
            "",
        ]
    )

    destination = store.run_dir(state["run_id"]) / "report.md"
    destination.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    store.add_artifact(state, destination, "report", "harness")
    store.save(state)
    return destination
