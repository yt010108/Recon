from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore
from recon_harness.surface import build_surface


class SurfaceTests(unittest.TestCase):
    def test_query_values_collapse_and_candidates_are_capped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scope_path = root / "scope.toml"
            scope_path.write_text(render_scope_toml("example.com"), encoding="utf-8")
            policy = ScopePolicy.load(scope_path)
            store = RunStore(root / "runs")
            state = store.create(scope_path, policy.snapshot())
            run_dir = store.run_dir(state["run_id"])
            urls = [f"https://example.com/api/type{index}?id={value}" for index in range(30) for value in range(2)]
            urls.append("https://example.com/static/app.js")
            (run_dir / "crawl" / "katana-urls.txt").write_text("\n".join(urls), encoding="utf-8")
            (run_dir / "discovery" / "parameth.json").write_text(
                json.dumps(
                    [
                        {
                            "target": "https://example.com/search",
                            "interesting_lines": ["[+] parameter found: debug"],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            result = build_surface(policy, state, store)
        self.assertEqual(len(result["routes"]), 31)
        self.assertEqual(len(result["candidates"]), 20)
        self.assertFalse(any(item["path"].endswith(".js") for item in result["routes"]))
        parameth_route = next(item for item in result["routes"] if item["path"] == "/search")
        self.assertEqual(parameth_route["query_parameters"], ["debug"])
        self.assertEqual(parameth_route["evidence"][0]["tool"], "parameth")


if __name__ == "__main__":
    unittest.main()
