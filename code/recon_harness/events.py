"""Append-only run event log."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator


def _repair_tail(path: Path) -> None:
    """Drop only a crash-truncated final record before the next append."""
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open("rb+") as stream:
        end = stream.seek(0, os.SEEK_END)
        stream.seek(end - 1)
        if stream.read(1) == b"\n":
            return
        start = 0
        position = end
        while position:
            size = min(position, 4096)
            position -= size
            stream.seek(position)
            chunk = stream.read(size)
            newline = chunk.rfind(b"\n")
            if newline >= 0:
                start = position + newline + 1
                break
        stream.seek(start)
        try:
            json.loads(stream.read().decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            stream.seek(start)
            stream.truncate()
        else:
            stream.seek(0, os.SEEK_END)
            stream.write(b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def append_event(path: Path, event_type: str, **payload: Any) -> dict[str, Any]:
    event = {
        "type": event_type,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        **payload,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    _repair_tail(path)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return event


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    try:
        lines = path.read_bytes().splitlines()
    except FileNotFoundError:
        return
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        try:
            event = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            if index == len(lines) - 1:
                return
            raise
        if isinstance(event, dict):
            yield event


def latest_state(path: Path) -> dict[str, Any] | None:
    state = None
    for event in read_events(path):
        candidate = event.get("state")
        if event.get("type") == "state" and isinstance(candidate, dict):
            state = candidate
    return state
