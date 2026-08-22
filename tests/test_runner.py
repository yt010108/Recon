from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.runner import HarnessRunner
from recon_harness.storage import RunStore


class RunnerSelectionTests(unittest.TestCase):
    def _run(self, dos_allowed: bool) -> tuple[list[str], dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(
            render_scope_toml("example.com", dos_allowed), encoding="utf-8"
        )
        policy = ScopePolicy.load(scope_path)
        store = RunStore(root / "runs")
        state = store.create(scope_path, policy.snapshot())
        runner = HarnessRunner(store)
        called: list[str] = []

        def complete(run_id: str, stage: str) -> dict:
            called.append(stage)
            current = store.load(run_id)
            current["stages"][stage]["status"] = "completed"
            store.save(current)
            return current

        with patch.object(runner, "_run_stage", side_effect=complete):
            finished = runner.run_all(state["run_id"])
        return called, finished

    def test_crawl_runs_without_dos_tools(self) -> None:
        called, state = self._run(False)
        self.assertEqual(called, ["collect", "probe", "crawl"])
        self.assertEqual(state["stages"]["discovery"]["status"], "skipped")

    def test_discovery_runs_when_dos_tools_are_allowed(self) -> None:
        called, _state = self._run(True)
        self.assertEqual(called, ["collect", "probe", "crawl", "discovery"])


if __name__ == "__main__":
    unittest.main()
