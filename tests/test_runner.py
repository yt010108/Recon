from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.runner import HarnessRunner
from recon_harness.storage import RunStore, atomic_write_json
from recon_harness.tools import ToolOutcome


class RunnerTests(unittest.TestCase):
    def _created(self, profile: str = "fast"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(
            render_scope_toml(["10.20.30.5"], [443], profile=profile, budget_minutes=30),
            encoding="utf-8",
        )
        policy = ScopePolicy.load(scope_path)
        store = RunStore(root / "runs")
        state = store.create(scope_path, policy.snapshot())
        return store, state

    def test_fast_profile_finishes_without_deep_tools(self) -> None:
        store, state = self._created("fast")
        runner = HarnessRunner(store)
        calls: list[str] = []

        def fake(_policy, current, tool):
            calls.append(tool)
            if tool == "httpx":
                atomic_write_json(
                    store.run_dir(current["run_id"]) / "normalized" / "origins.json",
                    [{"url": "https://10.20.30.5"}],
                )
            return ToolOutcome(0, f"{tool} ok", 1)

        with patch.object(runner, "_run_tool_adapter", side_effect=fake):
            result = runner.run_all(state["run_id"])
        self.assertEqual(result["status"], "success")
        self.assertNotIn("source_comments", calls)
        self.assertNotIn("gobuster_dir", calls)
        self.assertEqual(result["stages"]["expansion"]["status"], "skipped")

    def test_tool_failure_is_visible_as_partial(self) -> None:
        store, state = self._created("fast")
        runner = HarnessRunner(store)

        def fake(_policy, current, tool):
            if tool == "httpx":
                atomic_write_json(
                    store.run_dir(current["run_id"]) / "normalized" / "origins.json",
                    [{"url": "https://10.20.30.5"}],
                )
            if tool == "katana":
                return ToolOutcome(1, "katana failed", 0, error="timeout")
            return ToolOutcome(0, f"{tool} ok", 1)

        with patch.object(runner, "_run_tool_adapter", side_effect=fake):
            result = runner.run_all(state["run_id"])
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["stages"]["mapping"]["status"], "partial")
        self.assertEqual(result["stages"]["mapping"]["tools"]["katana"]["status"], "failed")

    def test_optional_nuclei_does_not_complete_deep_expansion(self) -> None:
        store, state = self._created("deep")
        runner = HarnessRunner(store)
        with patch.object(
            runner,
            "_run_tool_adapter",
            return_value=ToolOutcome(0, "nuclei ok", 1),
        ):
            result = runner.run_tool(state["run_id"], "nuclei")
        self.assertEqual(result["stages"]["expansion"]["status"], "partial")
        self.assertEqual(result["stages"]["expansion"]["tools"]["nuclei"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
