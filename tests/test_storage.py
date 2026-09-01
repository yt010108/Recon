from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore


class RunStoreTests(unittest.TestCase):
    def test_state_json_is_canonical_and_progress_is_derived(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope_path = root / "scope.toml"
            scope_path.write_text(render_scope_toml(["10.20.30.5"], [443]), encoding="utf-8")
            policy = ScopePolicy.load(scope_path)
            store = RunStore(root / "runs")
            state = store.create(scope_path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            self.assertTrue((run_dir / "state.json").is_file())
            self.assertTrue((run_dir / "normalized").is_dir())
            self.assertEqual(store.load(state["run_id"])["schema_version"], 2)
            progress = (run_dir / "progress.md").read_text(encoding="utf-8")
            self.assertIn("정식 상태는 `state.json`", progress)

    def test_invalid_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(Path(temporary) / "runs")
            with self.assertRaises(ValueError):
                store.run_dir("../escape")


if __name__ == "__main__":
    unittest.main()
