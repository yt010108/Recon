from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.reporting import build_report
from recon_harness.storage import RunStore, atomic_write_json
from recon_harness.surface import build_surface, normalize_path


class SurfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        scope_path = root / "scope.toml"
        scope_path.write_text(render_scope_toml(["10.20.30.5"], [443]), encoding="utf-8")
        policy = ScopePolicy.load(scope_path)
        self.store = RunStore(root / "runs")
        self.state = self.store.create(scope_path, policy.snapshot())
        self.run_dir = self.store.run_dir(self.state["run_id"])
        atomic_write_json(
            self.run_dir / "normalized" / "origins.json",
            [{"url": "https://10.20.30.5", "status_code": 200, "title": "Portal"}],
        )

    def test_query_values_collapse_and_static_assets_are_removed(self) -> None:
        urls = [f"https://10.20.30.5/view?seq={value}" for value in range(100)]
        urls.append("https://10.20.30.5/static/common.js")
        (self.run_dir / "parsed" / "katana-urls.txt").write_text("\n".join(urls), encoding="utf-8")
        result = build_surface(self.store, self.state)
        view_routes = [item for item in result["routes"] if item["path"] == "/view"]
        self.assertEqual(len(view_routes), 1)
        self.assertEqual(view_routes[0]["query_parameters"], ["seq"])
        self.assertFalse(any(item["path"].endswith("common.js") for item in result["routes"]))

    def test_numeric_path_segments_are_normalized(self) -> None:
        self.assertEqual(normalize_path("/users/1234/orders/99"), "/users/{int}/orders/{int}")

    def test_candidates_are_capped_and_manual_state_is_preserved(self) -> None:
        endpoints = [
            {
                "source": "https://10.20.30.5/app",
                "endpoint": f"https://10.20.30.5/api/type{index}/items?id={index}",
                "method": "POST",
                "query_parameters": ["id"],
                "body_parameters": ["name"],
                "line": index + 1,
                "kind": "form-action",
            }
            for index in range(30)
        ]
        atomic_write_json(self.run_dir / "parsed" / "source-endpoints.json", endpoints)
        first = build_surface(self.store, self.state)
        self.assertEqual(len(first["candidates"]), 20)
        saved = first["candidates"]
        saved[0]["status"] = "confirmed"
        saved[0]["notes"] = "manual check"
        atomic_write_json(self.run_dir / "normalized" / "candidates.json", saved)
        second = build_surface(self.store, self.state)
        matching = next(item for item in second["candidates"] if item["route_id"] == saved[0]["route_id"])
        self.assertEqual(matching["status"], "confirmed")
        self.assertEqual(matching["notes"], "manual check")

    def test_summary_does_not_dump_every_route(self) -> None:
        (self.run_dir / "parsed" / "katana-urls.txt").write_text(
            "\n".join(f"https://10.20.30.5/view?seq={value}" for value in range(100)),
            encoding="utf-8",
        )
        summary = build_report(self.store, self.state)
        text = summary.read_text(encoding="utf-8")
        self.assertIn("우선 검토 후보", text)
        self.assertLess(len(text), 20_000)


if __name__ == "__main__":
    unittest.main()
