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
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "juice-shop.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            self.assertTrue((run_dir / "scope.toml").is_file())
            self.assertTrue((run_dir / "events.jsonl").is_file())
            loaded = store.load(state["run_id"])
            self.assertEqual(loaded["scope"]["name"], "Local OWASP Juice Shop")

    def test_report_is_created_and_registered(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "juice-shop.toml")
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
            self.assertIn("Local OWASP Juice Shop", report.read_text(encoding="utf-8"))
            self.assertIn(
                "token=SAMPLE-ORIGINAL-VALUE\n``` still verbatim",
                report.read_text(encoding="utf-8"),
            )

    def test_invalid_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            with self.assertRaises(ValueError):
                store.run_dir("../escape")


if __name__ == "__main__":
    unittest.main()
