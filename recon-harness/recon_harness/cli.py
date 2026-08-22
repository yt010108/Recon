"""Command-line interface used by humans and the Pi extension."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .docker_backend import DEFAULT_IMAGE, BackendError, DockerBackend
from .models import APPROVAL_STAGES, STAGE_ORDER, TOOL_SPECS
from .policy import PolicyError, ScopePolicy
from .reporting import build_report
from .runner import HarnessRunner
from .storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _store() -> RunStore:
    return RunStore(PROJECT_ROOT / "runs")


def _emit(payload: Any, as_json: bool = True) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(payload)


def _state_summary(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": state["run_id"],
        "status": state["status"],
        "target": state["scope"]["base_url"],
        "scope": state["scope"]["name"],
        "created_at": state["created_at"],
        "updated_at": state["updated_at"],
        "stages": {
            name: {
                "status": item["status"],
                "approved_by": item["approved_by"],
                "tools": item["tools"],
                "error": item["error"],
            }
            for name, item in state["stages"].items()
        },
        "artifacts": state["artifacts"],
    }


def cmd_init(args: argparse.Namespace) -> int:
    policy = ScopePolicy.load(args.scope)
    state = _store().create(policy.path, policy.snapshot())
    _emit(_state_summary(state))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    _emit([_state_summary(item) for item in _store().list_runs()])
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    _emit(_state_summary(_store().load(args.run)))
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    state = _store().load(args.run)
    policy = ScopePolicy.load(_store().run_dir(args.run) / state["frozen_scope_file"])
    plan = []
    for stage in STAGE_ORDER:
        tools = [
            spec.name for spec in TOOL_SPECS.values()
            if spec.stage == stage and policy.is_tool_enabled(spec.name)
        ]
        plan.append(
            {
                "stage": stage,
                "requires_approval": stage in APPROVAL_STAGES,
                "enabled": policy.permissions.get(
                    {
                        "collect": "allow_passive_collection",
                        "probe": "allow_http_probing",
                        "crawl": "allow_crawling",
                        "discovery": "allow_content_discovery",
                    }[stage],
                    False,
                ),
                "tools": tools,
            }
        )
    _emit({"run_id": args.run, "target": policy.base_url, "plan": plan})
    return 0


def cmd_run_auto(args: argparse.Namespace) -> int:
    store = _store()
    state = HarnessRunner(PROJECT_ROOT, store).run_automatic(args.run)
    build_report(store, state)
    _emit(_state_summary(store.load(args.run)))
    return 0


def cmd_run_stage(args: argparse.Namespace) -> int:
    store = _store()
    state = HarnessRunner(PROJECT_ROOT, store).run_stage(
        args.run,
        args.stage,
        approved=args.approve,
        approved_by=args.approved_by if args.approve else None,
    )
    build_report(store, state)
    _emit(_state_summary(store.load(args.run)))
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    store = _store()
    state = store.load(args.run)
    destination = build_report(store, state)
    _emit({"run_id": args.run, "report": str(destination)})
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    policy = ScopePolicy.load(args.scope) if args.scope else None
    image = policy.worker_image if policy else args.image
    network = policy.docker_network if policy else args.network
    backend = DockerBackend(image, network=network)
    status = backend.doctor()
    tools: dict[str, dict[str, Any]] = {}
    if status["ready"]:
        with tempfile.TemporaryDirectory(prefix="hermes-recon-doctor-") as temporary:
            workspace = Path(temporary) / "run"
            workspace.mkdir()
            local_probe = Path(temporary) / "mount-probe.txt"
            local_probe.write_text("worker-input-mount-ok\n", encoding="utf-8")
            mount_backend = DockerBackend(
                image,
                workspace_dir=workspace,
                network=network,
                run_id="doctor",
            )
            remote_dir = mount_backend.prepare_remote_dir("doctor")
            remote_probe = f"{remote_dir}/mount-probe.txt"
            mount_backend.copy_to(local_probe, remote_probe)
            mount_result = mount_backend.run(["cat", remote_probe], process_timeout=20)
            status["input_mount_available"] = (
                mount_result.exit_code == 0
                and mount_result.stdout.strip() == "worker-input-mount-ok"
            )
            if not status["input_mount_available"]:
                status["error"] = (
                    str(status["error"])
                    + ("; " if status["error"] else "")
                    + (mount_result.stderr.strip() or "Worker input mount check failed")
                )
        command_for_tool = {
            "gobuster_dir": "gobuster",
            "gobuster_dns": "gobuster",
            "robots_txt": "httpx",
            "source_comments": "httpx",
            "amass_enum": "amass",
        }
        required = {
            command_for_tool.get(spec.name, spec.name) for spec in TOOL_SPECS.values()
        }
        required.add("chromium")
        for name in sorted(required):
            result = backend.run(["which", name], process_timeout=20)
            tools[name] = {
                "available": result.exit_code == 0,
                "path": result.stdout.strip(),
            }
    _emit({"backend": status, "tools": tools})
    return 0 if (
        status["ready"]
        and status.get("input_mount_available", False)
        and all(item["available"] for item in tools.values())
    ) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon-harness",
        description="Policy-gated bug bounty reconnaissance harness",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="Create a run from a frozen scope file")
    init_parser.add_argument("--scope", required=True)
    init_parser.set_defaults(handler=cmd_init)

    list_parser = sub.add_parser("list", help="List stored runs")
    list_parser.set_defaults(handler=cmd_list)

    status_parser = sub.add_parser("status", help="Show run state")
    status_parser.add_argument("--run", required=True)
    status_parser.set_defaults(handler=cmd_status)

    plan_parser = sub.add_parser("plan", help="Show the fixed stage plan")
    plan_parser.add_argument("--run", required=True)
    plan_parser.set_defaults(handler=cmd_plan)

    auto_parser = sub.add_parser("run-auto", help="Run collect and probe stages")
    auto_parser.add_argument("--run", required=True)
    auto_parser.set_defaults(handler=cmd_run_auto)

    stage_parser = sub.add_parser("run-stage", help="Run one stage")
    stage_parser.add_argument("--run", required=True)
    stage_parser.add_argument("--stage", required=True, choices=STAGE_ORDER)
    stage_parser.add_argument("--approve", action="store_true")
    stage_parser.add_argument("--approved-by", default="cli-user")
    stage_parser.set_defaults(handler=cmd_run_stage)

    report_parser = sub.add_parser("report", help="Generate a Markdown report")
    report_parser.add_argument("--run", required=True)
    report_parser.set_defaults(handler=cmd_report)

    doctor_parser = sub.add_parser("doctor", help="Check the worker image, network, and tools")
    doctor_parser.add_argument("--scope")
    doctor_parser.add_argument("--image", default=DEFAULT_IMAGE)
    doctor_parser.add_argument("--network")
    doctor_parser.set_defaults(handler=cmd_doctor)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
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
