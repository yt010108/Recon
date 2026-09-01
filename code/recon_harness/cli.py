"""대회용 웹 Recon V2 CLI."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .docker_backend import DEFAULT_IMAGE, NUCLEI_IMAGE, BackendError, DockerBackend
from .models import PROFILES, STAGE_ORDER, TOOL_NAMES
from .policy import DEFAULT_COMPETITION_PORTS, PolicyError, ScopePolicy
from .reporting import build_report
from .runner import HarnessRunner
from .storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def normalize_targets(values: Sequence[str]) -> list[str]:
    targets: list[str] = []
    for raw in values:
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError as exc:
            raise ValueError(f"Target must be an IPv4 address or CIDR: {candidate}") from exc
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Competition Recon currently supports IPv4 only")
        normalized = str(network.network_address) if network.prefixlen == 32 else str(network)
        if normalized not in targets:
            targets.append(normalized)
    if not targets:
        raise ValueError("At least one IPv4 target or CIDR is required")
    return targets


def parse_ports(value: str | None) -> list[int]:
    if value is None or not value.strip():
        return list(DEFAULT_COMPETITION_PORTS)
    ports: list[int] = []
    for raw in value.split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            port = int(candidate)
        except ValueError as exc:
            raise ValueError(f"Invalid port: {candidate}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("At least one port is required")
    return sorted(ports)


def render_scope_toml(
    targets: Sequence[str],
    ports: Sequence[int] | None = None,
    *,
    profile: str = "fast",
    budget_minutes: int | None = None,
    tls_verify: bool = False,
) -> str:
    normalized_targets = normalize_targets(targets)
    normalized_ports = sorted(set(int(port) for port in (ports or DEFAULT_COMPETITION_PORTS)))
    default_budget = 3 if profile == "fast" else 15
    return "\n".join(
        [
            "[scope]",
            f"targets = {json.dumps(normalized_targets)}",
            f"ports = {json.dumps(normalized_ports)}",
            f"tls_verify = {str(bool(tls_verify)).lower()}",
            "",
            "[run]",
            f"profile = {json.dumps(profile)}",
            f"budget_minutes = {int(budget_minutes or default_budget)}",
            "",
        ]
    )


def _store() -> RunStore:
    return RunStore(PROJECT_ROOT / "runs")


def _emit(payload: Any) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def _state_summary(state: dict[str, Any]) -> dict[str, Any]:
    scope = state["scope"]
    return {
        "run_id": state["run_id"],
        "status": state["status"],
        "target": scope.get("target_label"),
        "profile": scope.get("profile", "fast"),
        "budget_minutes": scope.get("budget_minutes"),
        "stages": {
            name: {
                "status": item.get("status"),
                "tools": item.get("tools", {}),
                "error": item.get("error"),
            }
            for name, item in state.get("stages", {}).items()
        },
        "artifacts": state.get("artifacts", []),
    }


def _create_run(args: argparse.Namespace) -> tuple[RunStore, dict[str, Any]]:
    rendered = render_scope_toml(
        args.targets,
        parse_ports(args.ports),
        profile=args.profile,
        budget_minutes=args.budget_minutes,
        tls_verify=args.tls_verify,
    )
    store = _store()
    with tempfile.TemporaryDirectory(prefix="recon-scope-") as temporary:
        scope_path = Path(temporary) / "scope.toml"
        scope_path.write_text(rendered, encoding="utf-8", newline="\n")
        policy = ScopePolicy.load(scope_path)
        state = store.create(policy.path, policy.snapshot())
    return store, state


def _emit_with_report(store: RunStore, state: dict[str, Any]) -> int:
    summary_path = build_report(store, state)
    refreshed = store.load(state["run_id"])
    payload = _state_summary(refreshed)
    payload["summary"] = str(summary_path)
    payload["routes"] = str(store.run_dir(state["run_id"]) / "normalized" / "routes.jsonl")
    payload["candidates"] = str(store.run_dir(state["run_id"]) / "normalized" / "candidates.json")
    _emit(payload)
    return 0 if refreshed["status"] in {"success", "no_signal", "partial"} else 1


def cmd_create(args: argparse.Namespace) -> int:
    _store_value, state = _create_run(args)
    _emit(_state_summary(state))
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    store, state = _create_run(args)
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
    tools: dict[str, dict[str, Any]] = {}
    if status["ready"]:
        for name in ("gobuster", "httpx", "katana", "nmap"):
            result = backend.run(["which", name], process_timeout=20)
            tools[name] = {"available": result.exit_code == 0, "path": result.stdout.strip()}
    nuclei_status = DockerBackend(NUCLEI_IMAGE).doctor()
    ready = bool(status["ready"]) and all(item["available"] for item in tools.values())
    _emit({"backend": status, "tools": tools, "optional_nuclei": nuclei_status})
    return 0 if ready else 1


def _add_scope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="+", help="Allowed IPv4 addresses or CIDRs")
    parser.add_argument("--ports", help="Comma-separated allowed TCP ports")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="fast")
    parser.add_argument("--budget-minutes", type=int)
    parser.add_argument(
        "--tls-verify",
        action="store_true",
        help="Require valid TLS certificates (default accepts competition certificates)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-harness")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    start = commands.add_parser("start", help="Run competition web Recon V2")
    _add_scope_arguments(start)
    start.set_defaults(handler=cmd_start)

    create = commands.add_parser("create", help="Create a run without network requests")
    _add_scope_arguments(create)
    create.set_defaults(handler=cmd_create)

    # 기존 Competition 명령은 같은 동작의 호환 alias로 둔다.
    competition_start = commands.add_parser("competition-start", help=argparse.SUPPRESS)
    _add_scope_arguments(competition_start)
    competition_start.set_defaults(handler=cmd_start)
    competition_create = commands.add_parser("competition-create", help=argparse.SUPPRESS)
    _add_scope_arguments(competition_create)
    competition_create.set_defaults(handler=cmd_create)

    stage = commands.add_parser("stage", help="Run one V2 stage")
    stage.add_argument("--run", required=True)
    stage.add_argument("stage", choices=STAGE_ORDER)
    stage.set_defaults(handler=cmd_stage)

    tool = commands.add_parser("tool", help="Run one tool in an existing run")
    tool.add_argument("--run", required=True)
    tool.add_argument("tool", choices=sorted(TOOL_NAMES))
    tool.set_defaults(handler=cmd_tool)

    report = commands.add_parser("report", help="Rebuild normalized output offline")
    report.add_argument("--run", required=True)
    report.set_defaults(handler=cmd_report)

    listing = commands.add_parser("list", help="List runs")
    listing.set_defaults(handler=cmd_list)
    status = commands.add_parser("status", help="Show run state")
    status.add_argument("--run", required=True)
    status.set_defaults(handler=cmd_status)
    doctor = commands.add_parser("doctor", help="Check Docker and required tools")
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
