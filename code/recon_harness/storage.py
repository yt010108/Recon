"""런별 상태, 감사 이벤트, 아티팩트를 파일로 보존한다."""

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

from .models import STAGE_ORDER


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9.-]+", "-", value).strip("-.").lower()
    return normalized[:48] or "scope"


def atomic_write_json(path: Path, payload: Any) -> None:
    # 중단 시 state.json이 반쯤 쓰인 상태로 남지 않도록 같은 디렉터리에서 교체한다.
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


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
        self.append_event(run_id, "run_created", {"scope": scope_snapshot["name"]})
        return state

    def run_dir(self, run_id: str) -> Path:
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", run_id):
            raise ValueError("Invalid run id")
        path = (self.root / run_id).resolve()
        if path.parent != self.root:
            raise ValueError("Run path escapes the run root")
        return path

    def load(self, run_id: str) -> dict[str, Any]:
        path = self.run_dir(run_id) / "state.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FileNotFoundError(f"Unknown run: {run_id}") from exc

    def save(self, state: dict[str, Any]) -> None:
        state["updated_at"] = utc_now()
        atomic_write_json(self.run_dir(state["run_id"]) / "state.json", state)
        self._write_progress(state)

    def _write_progress(self, state: dict[str, Any]) -> None:
        next_stage = next(
            (
                stage
                for stage in STAGE_ORDER
                if state["stages"][stage]["status"] in {"pending", "failed"}
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
            "| Stage | Status | Tools |",
            "|---|---|---|",
        ]
        for stage in STAGE_ORDER:
            item = state["stages"][stage]
            tools = ", ".join(item["tools"]) if item["tools"] else "-"
            lines.append(f"| {stage} | {item['status']} | {tools} |")
        lines.extend(["", "Pi는 `state.json`과 `events.jsonl`을 기준으로 이 실행을 재개한다.", ""])
        (self.run_dir(state["run_id"]) / "progress.md").write_text(
            "\n".join(lines), encoding="utf-8", newline="\n"
        )

    def append_event(self, run_id: str, event_type: str, data: dict[str, Any]) -> None:
        record = {"time": utc_now(), "type": event_type, "data": data}
        path = self.run_dir(run_id) / "events.jsonl"
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    def add_artifact(self, state: dict[str, Any], path: Path, kind: str, tool: str) -> None:
        relative = path.resolve().relative_to(self.run_dir(state["run_id"]))
        entry = {"path": relative.as_posix(), "kind": kind, "tool": tool}
        if entry not in state["artifacts"]:
            state["artifacts"].append(entry)

    def list_runs(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for state_path in self.root.glob("*/state.json"):
            try:
                results.append(json.loads(state_path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError):
                continue
        return sorted(results, key=lambda item: item.get("created_at", ""), reverse=True)
