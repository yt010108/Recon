#!/usr/bin/env python3
"""Reject staged run artifacts and common credential formats before commit."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import PurePosixPath


PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("OpenAI-style key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("authorization bearer", re.compile(r"(?i)\bauthorization\s*[:=]\s*[\"']?bearer\s+[A-Za-z0-9._~+/=-]{8,}")),
)
ASSIGNMENT = re.compile(
    r"(?im)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|client[_-]?secret|secret|password|passwd)"
    r"\b\s*[:=]\s*[\"']?([A-Za-z0-9_./+=:@-]{8,})"
)
PLACEHOLDERS = ("example", "sample", "changeme", "replace", "placeholder", "your_", "your-")


def findings(path: str, text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    for label, pattern in PATTERNS:
        for match in pattern.finditer(text):
            result.append((text.count("\n", 0, match.start()) + 1, label))
    for match in ASSIGNMENT.finditer(text):
        value = match.group(1).lower()
        if any(marker in value for marker in PLACEHOLDERS):
            continue
        result.append((text.count("\n", 0, match.start()) + 1, "credential assignment"))
    return sorted(set(result))


def _git(*args: str, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], capture_output=True, text=text, check=False
    )


def staged_files() -> list[str]:
    result = _git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace").strip())
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in result.stdout.split(b"\0")
        if item
    ]


def staged_text(path: str) -> str | None:
    result = _git("show", f":{path}")
    if result.returncode != 0 or b"\0" in result.stdout[:8192]:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def main() -> int:
    try:
        paths = staged_files()
    except (OSError, RuntimeError) as exc:
        print(f"secret guard: cannot inspect Git index: {exc}", file=sys.stderr)
        return 2

    blocked: list[tuple[str, int | None, str]] = []
    for raw_path in paths:
        path = PurePosixPath(raw_path.replace("\\", "/"))
        parts = tuple(part.lower() for part in path.parts)
        if "runs" in parts:
            blocked.append((raw_path, None, "run artifact must never be committed"))
            continue
        name = path.name.lower()
        if (name == ".env" or name.startswith(".env.")) and name not in {
            ".env.example",
            ".env.sample",
        }:
            blocked.append((raw_path, None, "environment secret file"))
            continue
        text = staged_text(raw_path)
        if text is None:
            continue
        blocked.extend((raw_path, line, label) for line, label in findings(raw_path, text))

    if not blocked:
        print("secret guard: staged files passed")
        return 0
    print("secret guard: commit blocked; sensitive staged content was detected:", file=sys.stderr)
    for path, line, label in blocked:
        location = f"{path}:{line}" if line is not None else path
        print(f"  - {location} ({label})", file=sys.stderr)
    print("Move the value to an ignored local file and stage a safe placeholder instead.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
