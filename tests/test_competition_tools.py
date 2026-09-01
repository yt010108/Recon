from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.competition_tools import CompetitionToolRunner
from recon_harness.docker_backend import CommandResult
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore
from recon_harness.tools import _extract_source_endpoints


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


class CompetitionToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(
            render_scope_toml(["10.20.30.5"], [443], profile="deep", budget_minutes=30),
            encoding="utf-8",
        )
        self.policy = ScopePolicy.load(scope_path)
        self.store = RunStore(root / "runs")
        self.state = self.store.create(scope_path, self.policy.snapshot())

    def test_network_discovery_keeps_only_allowed_open_services(self) -> None:
        xml = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="10.20.30.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https" product="nginx" version="1.24"/></port></ports></host></nmaprun>"""
        backend = FakeBackend(CommandResult(0, xml, ""))
        outcome = CompetitionToolRunner(backend, self.store).run_network_discovery(
            self.policy, self.state
        )
        services = json.loads(
            (self.store.run_dir(self.state["run_id"]) / "parsed" / "network-services.json").read_text(encoding="utf-8")
        )
        self.assertEqual(outcome.item_count, 1)
        self.assertEqual(services[0]["product"], "nginx")
        self.assertIn("--version-light", backend.commands[0])

    def test_https_gobuster_accepts_competition_certificates_by_default(self) -> None:
        run_dir = self.store.run_dir(self.state["run_id"])
        (run_dir / "parsed" / "alive-urls.txt").write_text(
            "https://10.20.30.5\n", encoding="utf-8"
        )
        backend = FakeBackend(CommandResult(0, "admin (Status: 200) [Size: 12]\n", ""))
        outcome = CompetitionToolRunner(backend, self.store).run_gobuster_dir(
            self.policy, self.state
        )
        self.assertIn("-k", backend.commands[0])
        self.assertEqual(outcome.item_count, 1)

    def test_source_requests_keep_observed_method(self) -> None:
        findings = _extract_source_endpoints(
            'axios.post("/api/upload", payload)\nfetch("/api/reset", {method: "DELETE"})\n'
            'axios.get("/api/upload")'
        )
        methods = {
            (item["value"], item["method"])
            for item in findings if item["kind"] == "request"
        }
        self.assertIn(("/api/upload", "POST"), methods)
        self.assertIn(("/api/upload", "GET"), methods)
        self.assertIn(("/api/reset", "DELETE"), methods)


if __name__ == "__main__":
    unittest.main()
