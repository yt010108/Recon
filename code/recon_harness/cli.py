"""Pi와 사람이 호출하는 최소 CLI."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

from . import __version__
from .docker_backend import DEFAULT_IMAGE, NUCLEI_IMAGE, BackendError, DockerBackend
from .models import LOCAL_TOOLS, STAGE_ORDER, TOOL_NAMES
from .policy import PolicyError, ScopePolicy
from .reporting import build_report
from .runner import HarnessRunner
from .storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def normalize_domain(value: str) -> str:
    """URL이나 경로가 들어와도 호스트 이름만 남긴다."""
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    domain = (parsed.hostname or "").rstrip(".").lower()
    if not domain or parsed.username or parsed.password:
        raise ValueError("A valid domain is required")
    return domain


def render_scope_toml(domain: str) -> str:
    """새 런에는 허용된 도메인 하나만 저장한다."""
    return "\n".join([
        "[scope]",
        f"domain = {json.dumps(normalize_domain(domain), ensure_ascii=False)}",
        "",
    ])


def _store() -> RunStore:
    return RunStore(PROJECT_ROOT / "runs")


def _emit(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _state_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": state["run_id"],
        "status": state["status"],
        "target": state["scope"]["base_url"],
        "stages": {
            name: {
                "status": item["status"],
                "tools": item["tools"],
                "error": item["error"],
            }
            for name, item in state["stages"].items()
        },
        "artifacts": state["artifacts"],
    }


def _create_run(domain: str) -> tuple[RunStore, dict[str, Any]]:
    store = _store()
    with tempfile.TemporaryDirectory(prefix="recon-scope-") as temporary:
        scope_path = Path(temporary) / "scope.toml"
        scope_path.write_text(
            render_scope_toml(domain),
            encoding="utf-8",
            newline="\n",
        )
        policy = ScopePolicy.load(scope_path)
        state = store.create(policy.path, policy.snapshot())
    return store, state


def _emit_with_report(store: RunStore, state: dict[str, Any]) -> int:
    report = build_report(store, state)
    summary = _state_summary(store.load(state["run_id"]))
    summary["report"] = str(report)
    _emit(summary)
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    _store_value, state = _create_run(args.domain)
    _emit(_state_summary(state))
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    store, state = _create_run(args.domain)

    state = HarnessRunner(store).run_all(state["run_id"])
    return _emit_with_report(store, state)


def cmd_stage(args: argparse.Namespace) -> int:
    store = _store()
    state = HarnessRunner(store).run_stage(args.run, args.stage)
    return _emit_with_report(store, state)


def cmd_tool(args: argparse.Namespace) -> int:
    store = _store()
    state = HarnessRunner(store).run_tool(args.run, args.tool)
    return _emit_with_report(store, state)


def cmd_report(args: argparse.Namespace) -> int:
    store = _store()
    return _emit_with_report(store, store.load(args.run))


def cmd_list(_args: argparse.Namespace) -> int:
    _emit([_state_summary(item) for item in _store().list_runs()])
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    _emit(_state_summary(_store().load(args.run)))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    backend = DockerBackend(args.image)
    status = backend.doctor()
    nuclei_backend = DockerBackend(NUCLEI_IMAGE)
    nuclei_status = nuclei_backend.doctor()
    tools: dict[str, dict[str, Any]] = {}

    if status["ready"]:
        command_names = {
            "gobuster_dir": "gobuster",
            "robots_txt": "httpx",
            "source_comments": "httpx",
            "amass_enum": "amass",
        }
        base_tools = TOOL_NAMES - LOCAL_TOOLS - {"nuclei"}
        for name in sorted({command_names.get(tool, tool) for tool in base_tools}):
            result = backend.run(["which", name], process_timeout=20)
            tools[name] = {
                "available": result.exit_code == 0,
                "path": result.stdout.strip(),
            }

    if nuclei_status["ready"]:
        result = nuclei_backend.run(["which", "nuclei"], process_timeout=20)
        tools["nuclei"] = {
            "available": result.exit_code == 0,
            "path": result.stdout.strip(),
        }

    ready = (
        bool(status["ready"])
        and bool(nuclei_status["ready"])
        and all(item["available"] for item in tools.values())
        and "nuclei" in tools
    )
    _emit({"backend": status, "nuclei_backend": nuclei_status, "tools": tools})
    return 0 if ready else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-harness")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start", help="Run recon for one allowed domain")
    start.add_argument("domain")
    start.set_defaults(handler=cmd_start)

    create = commands.add_parser("create", help="Create a run without network requests")
    create.add_argument("domain")
    create.set_defaults(handler=cmd_create)

    stage = commands.add_parser("stage", help="Run one stage in an existing run")
    stage.add_argument("--run", required=True)
    stage.add_argument("stage", choices=STAGE_ORDER)
    stage.set_defaults(handler=cmd_stage)

    tool = commands.add_parser("tool", help="Run one tool in an existing run")
    tool.add_argument("--run", required=True)
    tool.add_argument("tool", choices=sorted(TOOL_NAMES))
    tool.set_defaults(handler=cmd_tool)

    report = commands.add_parser("report", help="Rebuild one run report offline")
    report.add_argument("--run", required=True)
    report.set_defaults(handler=cmd_report)

    listing = commands.add_parser("list", help="List runs")
    listing.set_defaults(handler=cmd_list)

    status = commands.add_parser("status", help="Show run state")
    status.add_argument("--run", required=True)
    status.set_defaults(handler=cmd_status)

    doctor = commands.add_parser("doctor", help="Check Docker and tools")
    doctor.add_argument("--image", default=DEFAULT_IMAGE)
    doctor.set_defaults(handler=cmd_doctor)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except PolicyError as exc:
        print(json.dumps({"error": "policy", "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 3
    except BackendError as exc:
        print(json.dumps({"error": "backend", "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 4
    except (FileNotFoundError, ValueError) as exc:
        print(json.dumps({"error": "input", "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(json.dumps({"error": "cancelled", "message": "Interrupted by user"}), file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
