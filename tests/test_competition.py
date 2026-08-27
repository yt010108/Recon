from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_competition_scope_toml
from recon_harness.competition_tools import CompetitionToolRunner
from recon_harness.docker_backend import CommandResult
from recon_harness.models import stage_for_tool, tools_for_stage
from recon_harness.policy import PolicyError, ScopePolicy
from recon_harness.reporting import build_report
from recon_harness.storage import RunStore


class FakeBackend:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.commands: list[list[str]] = []

    def prepare_remote_dir(self, _run_id: str) -> str:
        return "/work/run/.worker-inputs"

    def copy_to(self, _local: Path, _remote: str) -> None:
        return None

    def run(self, command: list[str], **_kwargs: object) -> CommandResult:
        self.commands.append(command)
        return self.results.pop(0)


class CompetitionScopeTests(unittest.TestCase):
    def _policy(self, targets=None, ports=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "scope.toml"
        path.write_text(
            render_competition_scope_toml(
                targets or ["10.20.30.0/24"],
                ports or [80, 8080],
            ),
            encoding="utf-8",
        )
        return ScopePolicy.load(path)

    def test_competition_scope_uses_network_and_port_boundaries(self) -> None:
        policy = self._policy()
        self.assertEqual(policy.mode, "competition")
        self.assertEqual(policy.targets, ["10.20.30.0/24"])
        self.assertEqual(policy.allowed_ports, [80, 8080])
        self.assertEqual(
            policy.validate_url("http://10.20.30.55:8080/api"),
            "http://10.20.30.55:8080/api",
        )
        with self.assertRaises(PolicyError):
            policy.validate_url("http://10.20.31.55:8080/api")
        with self.assertRaises(PolicyError):
            policy.validate_url("http://10.20.30.55:9000/api")

    def test_competition_scope_rejects_large_ranges(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "scope.toml"
        path.write_text(
            '[scope]\nmode="competition"\ntargets=["10.0.0.0/19"]\nports=[80]\n',
            encoding="utf-8",
        )
        with self.assertRaises(PolicyError):
            ScopePolicy.load(path)

    def test_competition_stage_mapping_skips_internet_osint(self) -> None:
        self.assertEqual(tools_for_stage("collect", "competition"), ("network_discovery",))
        self.assertEqual(stage_for_tool("httpx", "competition"), "probe")
        with self.assertRaises(ValueError):
            stage_for_tool("waybackurls", "competition")


class CompetitionAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.scope_path = root / "scope.toml"
        self.scope_path.write_text(
            render_competition_scope_toml(["10.20.30.0/24"], [80, 8080]),
            encoding="utf-8",
        )
        self.policy = ScopePolicy.load(self.scope_path)
        self.store = RunStore(root / "runs")
        self.state = self.store.create(self.scope_path, self.policy.snapshot())

    def test_network_discovery_parses_only_scoped_open_ports(self) -> None:
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/><address addr="10.20.30.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
    </ports>
  </host>
  <host><status state="up"/><address addr="10.20.31.5" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
  </host>
</nmaprun>"""
        backend = FakeBackend(CommandResult(0, xml, ""))
        outcome = CompetitionToolRunner(backend, self.store).run_network_discovery(
            self.policy, self.state
        )
        run_dir = self.store.run_dir(self.state["run_id"])
        services = json.loads(
            (run_dir / "parsed" / "network-services.json").read_text(encoding="utf-8")
        )
        self.assertEqual(outcome.item_count, 2)
        self.assertEqual({(item["host"], item["port"]) for item in services}, {
            ("10.20.30.5", 80),
            ("10.20.30.5", 8080),
        })
        self.assertIn("-sT", backend.commands[0])
        self.assertIn("--open", backend.commands[0])

    def test_katana_scope_is_restricted_to_confirmed_origins(self) -> None:
        run_dir = self.store.run_dir(self.state["run_id"])
        (run_dir / "parsed" / "alive-urls.txt").write_text(
            "http://10.20.30.5:8080\n",
            encoding="utf-8",
        )
        backend = FakeBackend(CommandResult(0, "", ""))
        CompetitionToolRunner(backend, self.store).run_katana(self.policy, self.state)
        command = backend.commands[0]
        scope_value = command[command.index("-cs") + 1]
        self.assertIn("10\\.20\\.30\\.5:8080", scope_value)
        self.assertNotIn("10.20.30.0/24", scope_value)

    def test_report_and_attack_surface_show_sink_provenance(self) -> None:
        run_dir = self.store.run_dir(self.state["run_id"])
        endpoint = "http://10.20.30.5:8080/api/users?id=1"
        (run_dir / "parsed" / "alive-urls.txt").write_text(
            "http://10.20.30.5:8080\n",
            encoding="utf-8",
        )
        (run_dir / "parsed" / "source-endpoints.json").write_text(
            json.dumps([
                {
                    "source": "http://10.20.30.5:8080/static/app.js",
                    "endpoint": endpoint,
                    "kind": "request-static",
                    "value": "/api/users?id=1",
                    "line": 42,
                    "context": "fetch('/api/users?id=1')",
                }
            ]),
            encoding="utf-8",
        )
        report_path = build_report(self.store, self.state)
        report = report_path.read_text(encoding="utf-8")
        self.assertIn("static/app.js:42", report)
        self.assertIn("발견 위치", report)

        surface = json.loads(
            (run_dir / "parsed" / "attack-surface.json").read_text(encoding="utf-8")
        )
        item = next(value for value in surface["endpoints"] if value["url"] == endpoint)
        self.assertIn("조회·식별자 입력", item["sink_hints"])
        self.assertEqual(item["parameters"], ["id"])
        self.assertEqual(item["evidence"][0]["line"], 42)


if __name__ == "__main__":
    unittest.main()
