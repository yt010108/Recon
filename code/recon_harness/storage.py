"""events.jsonl에 상태를 보존하고 progress.md 요약을 만든다."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .events import append_event, latest_state, read_events
from .models import STAGE_ORDER


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9.-]+", "-", value).strip("-.").lower()
    return normalized[:48] or "scope"


def atomic_write_text(path: Path, text: str) -> None:
    """중단 중에도 진행 파일이 반쯤 쓰이지 않도록 원자적으로 교체한다."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, payload: Any) -> None:
    """파싱 결과 JSON도 같은 방식으로 안전하게 기록한다."""
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


class RunStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def create(self, scope_path: Path, scope_snapshot: dict[str, Any]) -> dict[str, Any]:
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        run_id = f"{stamp}-{_slug(scope_snapshot['name'])}-{uuid.uuid4().hex[:6]}"
        run_dir = self.root / run_id
        (run_dir / "raw").mkdir(parents=True)
        (run_dir / "parsed").mkdir()
        (run_dir / "screenshots").mkdir()
        state = {
            "run_id": run_id,
            "status": "ready",
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "scope": scope_snapshot,
            "stages": {
                stage: {
                    "status": "pending",
                    "started_at": None,
                    "finished_at": None,
                    "tools": {},
                    "error": None,
                }
                for stage in STAGE_ORDER
            },
            "artifacts": [],
        }
        shutil.copyfile(scope_path, run_dir / "scope.toml")
        self.save(state)
        return state

    def run_dir(self, run_id: str) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", run_id):
            raise ValueError("Invalid run id")
        path = (self.root / run_id).resolve()
        if path.parent != self.root:
            raise ValueError("Run path escapes the run root")
        return path

    def load(self, run_id: str) -> dict[str, Any]:
        run_dir = self.run_dir(run_id)
        state = latest_state(run_dir / "events.jsonl")
        if state is not None:
            return state

        # 기존 run은 progress.md를 한 번 읽은 뒤 다음 save부터 events.jsonl로 전환한다.
        path = run_dir / "progress.md"
        try:
            text = path.read_text(encoding="utf-8")
            payload = text.split("<!-- recon-state\n", 1)[1].split("\n-->", 1)[0]
            return json.loads(payload)
        except (OSError, IndexError, json.JSONDecodeError) as exc:
            raise FileNotFoundError(f"Unknown run: {run_id}") from exc

    def save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        append_event(
            self.run_dir(state["run_id"]) / "events.jsonl",
            "state",
            state=state,
        )
        self._write_progress(state)

    def append_event(self, state: dict[str, Any], event_type: str, **payload: Any) -> None:
        append_event(
            self.run_dir(state["run_id"]) / "events.jsonl",
            event_type,
            **payload,
        )

    def events(self, run_id: str):
        return read_events(self.run_dir(run_id) / "events.jsonl")

    def _write_progress(self, state: dict[str, Any]) -> None:
        next_stage = next(
            (
                stage
                for stage in STAGE_ORDER
                if state["stages"][stage]["status"]
                in {"pending", "running", "partial", "failed"}
            ),
            "complete",
        )
        lines = [
            f"# Recon progress: {state['run_id']}",
            "",
            f"- Target: `{state['scope']['base_url']}`",
            f"- Status: `{state['status']}`",
            f"- Updated: `{state['updated_at']}`",
            f"- Artifacts: `{len(state['artifacts'])}`",
            f"- Next: `{next_stage}`",
            "",
        ]
        discovery = state.get("discovery")
        if isinstance(discovery, dict):
            lines.extend(
                [
                    (
                        f"- Discovery: {discovery.get('rounds', 0)}/2 rounds, "
                        f"{discovery.get('urls', 0)} URLs, "
                        f"{discovery.get('queued', 0)} queued, "
                        f"{discovery.get('stop_reason', '-')}"
                    ),
                    "",
                ]
            )
        lines.extend(["| Stage | Status | Tools |", "|---|---|---|"])
        for stage in STAGE_ORDER:
            item = state["stages"][stage]
            tools = ", ".join(item["tools"]) if item["tools"] else "-"
            lines.append(f"| {stage} | {item['status']} | {tools} |")
        lines.extend(["", "이 요약은 `events.jsonl`에서 생성한다.", ""])
        atomic_write_text(
            self.run_dir(state["run_id"]) / "progress.md", "\n".join(lines)
        )

    def add_artifact(self, state: dict[str, Any], path: Path, kind: str, tool: str) -> None:
        relative = path.resolve().relative_to(self.run_dir(state["run_id"]))
        entry = {"path": relative.as_posix(), "kind": kind, "tool": tool}
        if entry not in state["artifacts"]:
            state["artifacts"].append(entry)

    def list_runs(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        run_dirs = {
            path.parent for path in self.root.glob("*/events.jsonl")
        } | {
            path.parent for path in self.root.glob("*/progress.md")
        }
        for run_dir in run_dirs:
            try:
                results.append(self.load(run_dir.name))
            except FileNotFoundError:
                continue
        return sorted(results, key=lambda item: item.get("created_at", ""), reverse=True)
