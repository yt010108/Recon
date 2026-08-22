from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.policy import ScopePolicy
from recon_harness.reporting import build_report
from recon_harness.storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class RunStoreTests(unittest.TestCase):
    def test_create_freezes_scope_and_persists_events(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            self.assertTrue((run_dir / "scope.toml").is_file())
            self.assertTrue((run_dir / "events.jsonl").is_file())
            self.assertTrue((run_dir / "screenshots").is_dir())
            self.assertTrue((run_dir / "progress.md").is_file())
            loaded = store.load(state["run_id"])
            self.assertEqual(loaded["scope"]["name"], "recon-juice-shop")

    def test_report_is_created_and_registered(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            (store.run_dir(state["run_id"]) / "parsed" / "source-comments.json").write_text(
                json.dumps(
                    [
                        {
                            "url": "http://recon-juice-shop:3000/app.js",
                            "kind": "javascript",
                            "line": 4,
                            "text": "token=SAMPLE-ORIGINAL-VALUE\n``` still verbatim",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            report = build_report(store, state)
            self.assertTrue(report.is_file())
            loaded = store.load(state["run_id"])
            self.assertTrue(any(item["path"] == "report.md" for item in loaded["artifacts"]))
            text = report.read_text(encoding="utf-8")
            self.assertIn("http://recon-juice-shop:3000", text)
            self.assertIn("## Evidence", text)
            self.assertNotIn("SAMPLE-ORIGINAL-VALUE", text)

    def test_invalid_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            with self.assertRaises(ValueError):
                store.run_dir("../escape")


if __name__ == "__main__":
    unittest.main()
