from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.runner import HarnessRunner
from recon_harness.storage import RunStore
from recon_harness.tools import ToolOutcome


class RunnerSelectionTests(unittest.TestCase):
    def _created_run(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(render_scope_toml("example.com"), encoding="utf-8")
        policy = ScopePolicy.load(scope_path)
        store = RunStore(root / "runs")
        state = store.create(scope_path, policy.snapshot())
        return store, state

    def _run(self) -> tuple[list[str], dict]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(render_scope_toml("example.com"), encoding="utf-8")
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

    def test_all_stages_run(self) -> None:
        called, _state = self._run()
        self.assertEqual(called, ["collect", "probe", "crawl", "discovery", "normalize"])

    def test_failed_tool_is_preserved_in_overall_status(self) -> None:
        store, state = self._created_run()
        runner = HarnessRunner(store)
        for stage in ("collect", "probe", "crawl", "normalize"):
            state["stages"][stage]["status"] = "completed"
        store.save(state)

        with (
            patch.object(runner, "_backend_for_tool", return_value=object()),
            patch("recon_harness.runner.DeepDiscoveryToolRunner") as tools,
        ):
            tools.return_value.run.side_effect = [
                ToolOutcome(0, "url discovery", 1),
                ToolOutcome(1, "gobuster failed", 0, error="failed"),
                ToolOutcome(0, "parameth", 1),
            ]
            finished = runner.run_stage(state["run_id"], "discovery")

        self.assertEqual(
            finished["stages"]["discovery"]["status"],
            "completed_with_errors",
        )
        self.assertEqual(finished["status"], "completed_with_errors")

    def test_one_stage_can_run_without_previous_stage(self) -> None:
        store, state = self._created_run()
        runner = HarnessRunner(store)
        with patch.object(runner, "_run_stage", return_value=state) as selected:
            runner.run_stage(state["run_id"], "crawl")
        selected.assert_called_once_with(state["run_id"], "crawl", require_previous=False)

    def test_one_tool_is_recorded_as_partial_stage(self) -> None:
        store, state = self._created_run()
        runner = HarnessRunner(store)
        with (
            patch("recon_harness.runner.DockerBackend") as backend,
            patch("recon_harness.runner.DeepDiscoveryToolRunner") as tools,
        ):
            backend.return_value.require_ready.return_value = None
            tools.return_value.run.return_value = ToolOutcome(0, "one host", 1)
            result = runner.run_tool(state["run_id"], "subfinder")
        self.assertEqual(result["stages"]["collect"]["status"], "partial")
        self.assertEqual(result["stages"]["collect"]["tools"]["subfinder"]["item_count"], 1)

    def test_dorkgen_individual_run_does_not_start_docker(self) -> None:
        store, state = self._created_run()
        with patch("recon_harness.runner.DockerBackend") as backend:
            result = HarnessRunner(store).run_tool(state["run_id"], "dorkgen")
        backend.assert_not_called()
        self.assertEqual(result["stages"]["collect"]["tools"]["dorkgen"]["status"], "completed")

    def test_nuclei_individual_run_uses_dedicated_image(self) -> None:
        store, state = self._created_run()
        runner = HarnessRunner(store)
        with (
            patch("recon_harness.runner.DockerBackend") as backend,
            patch("recon_harness.runner.DeepDiscoveryToolRunner") as tools,
        ):
            backend.return_value.require_ready.return_value = None
            tools.return_value.run.return_value = ToolOutcome(0, "one finding", 1)
            runner.run_tool(state["run_id"], "nuclei")
        self.assertEqual(backend.call_args.args[0], "local/hermes-recon-nuclei:0.1")


if __name__ == "__main__":
    unittest.main()
