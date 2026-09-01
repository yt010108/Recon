from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.policy import ScopePolicy
from recon_harness.reporting import build_report, build_stage_report
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
            (run_dir / "crawl" / "source-endpoints.json").write_text(
                json.dumps(
                    [
                        {
                            "source": "http://recon-juice-shop:3000/app.js",
                            "endpoint": "http://recon-juice-shop:3000/api/admin?debug=1",
                            "kind": "request",
                            "line": 8,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / "crawl" / "source-assets.json").write_text(
                json.dumps(
                    [
                        {
                            "source": "http://recon-juice-shop:3000/",
                            "url": "http://recon-juice-shop:3000/app.js.map",
                            "kind": "source-map",
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
            self.assertIn("/admin [GET P2 params=debug]", text)
            self.assertIn("## 중요 사이트맵", text)
            self.assertIn("/admin [GET P2 params=debug]", text)
            sitemap = text.split("## 중요 사이트맵", 1)[1].split("## 중요 소스 정보", 1)[0]
            self.assertNotIn("source", sitemap.lower())
            self.assertIn("Google Dork: `1`개", text)
            self.assertIn("Nuclei 후보: `1`", text)
            self.assertIn("## 중요 소스 정보", text)
            self.assertIn("/api/admin?debug=1", text)
            self.assertIn("app.js.map", text)
            self.assertIn("token=[REDACTED]", text)
            self.assertTrue((run_dir / "normalize" / "routes.jsonl").is_file())
            self.assertTrue((run_dir / "normalize" / "candidates.json").is_file())
            self.assertNotIn("SAMPLE-ORIGINAL-VALUE", text)

    def test_invalid_run_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            with self.assertRaises(ValueError):
                store.run_dir("../escape")

    def test_discovery_report_merges_url_gobuster_and_parameth_as_tree(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            (run_dir / "discovery" / "url-queue.jsonl").write_text(
                json.dumps({"url": "http://recon-juice-shop:3000/api/users?id=1"}) + "\n",
                encoding="utf-8",
            )
            (run_dir / "discovery" / "gobuster-dir.json").write_text(
                json.dumps([{"path": "/admin", "status": 200}]),
                encoding="utf-8",
            )
            (run_dir / "discovery" / "parameth.json").write_text(
                json.dumps(
                    [{
                        "target": "http://recon-juice-shop:3000/",
                        "interesting_lines": ["parameter: token"],
                    }]
                ),
                encoding="utf-8",
            )
            report = build_stage_report(store, state, "discovery")
            text = report.read_text(encoding="utf-8")
            tree = text.split("```text", 1)[1].split("```", 1)[0]
            self.assertIn("/api", tree)
            self.assertIn("/users [GET P3 params=id]", tree)
            self.assertIn("/admin [GET P3]", tree)
            self.assertIn("/ [GET P3 params=token]", tree)
            self.assertNotIn("gobuster", tree.lower())
            self.assertNotIn("source", tree.lower())
            targets = (run_dir / "discovery" / "parameth-targets.txt").read_text(encoding="utf-8")
            self.assertIn("/api/users?id=", targets)
            self.assertIn("/admin", targets)

    def test_probe_report_shows_httpx_technology_detection(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(temporary)
            state = store.create(policy.path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            (run_dir / "probe" / "httpx.json").write_text(
                json.dumps(
                    [
                        {
                            "url": "http://recon-juice-shop:3000/",
                            "status_code": 200,
                            "title": "Juice Shop",
                            "tech": ["Express", "Angular"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            text = build_stage_report(store, state, "probe").read_text(encoding="utf-8")
            self.assertIn("활성 서비스와 기술", text)
            self.assertIn("Express, Angular", text)


if __name__ == "__main__":
    unittest.main()
