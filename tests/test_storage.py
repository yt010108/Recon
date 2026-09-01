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
    def test_create_freezes_scope_and_persists_progress(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            self.assertTrue((run_dir / "scope.toml").is_file())
            self.assertFalse((run_dir / "state.json").exists())
            self.assertFalse((run_dir / "events.jsonl").exists())
            self.assertTrue((run_dir / "screenshots").is_dir())
            for stage in ("collect", "probe", "crawl", "discovery", "normalize"):
                self.assertTrue((run_dir / stage / "raw").is_dir())
            self.assertFalse((run_dir / "raw").exists())
            self.assertFalse((run_dir / "parsed").exists())
            self.assertFalse((run_dir / "normalized").exists())
            self.assertTrue((run_dir / "progress.md").is_file())
            loaded = store.load(state["run_id"])
            self.assertEqual(loaded["scope"]["name"], "recon-juice-shop")

    def test_report_is_created_and_registered(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            (run_dir / "crawl" / "source-comments.json").write_text(
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
            (run_dir / "collect" / "domains.txt").write_text(
                "recon-juice-shop\n", encoding="utf-8"
            )
            (run_dir / "crawl" / "katana-urls.txt").write_text(
                "http://recon-juice-shop:3000/api/orders?id=1\n",
                encoding="utf-8",
            )
            (run_dir / "discovery" / "url-queue.jsonl").write_text(
                json.dumps(
                    {
                        "url": "http://recon-juice-shop:3000/admin?debug=1",
                        "sources": ["robots"],
                        "status": "queued",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (run_dir / "collect" / "google-dorks.txt").write_text(
                "site:recon-juice-shop\n", encoding="utf-8"
            )
            (run_dir / "probe" / "nuclei-findings.json").write_text(
                json.dumps(
                    [
                        {
                            "template_id": "test-header",
                            "name": "Test Header",
                            "severity": "low",
                            "matched_at": "http://recon-juice-shop:3000/",
                            "status_code": 200,
                            "evidence": "probe/raw/nuclei.jsonl:1",
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
            self.assertIn("http://recon-juice-shop:3000/admin", text)
            self.assertIn("## 우선 검토 후보", text)
            self.assertIn("admin, operation", text)
            self.assertIn("Google Dork: `1`개", text)
            self.assertIn("Nuclei 후보: `1`", text)
            self.assertTrue((run_dir / "normalize" / "routes.jsonl").is_file())
            self.assertTrue((run_dir / "normalize" / "candidates.json").is_file())
            self.assertNotIn("SAMPLE-ORIGINAL-VALUE", text)

    def test_invalid_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            with self.assertRaises(ValueError):
                store.run_dir("../escape")


if __name__ == "__main__":
    unittest.main()
