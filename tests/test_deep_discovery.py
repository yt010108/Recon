from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.deep_discovery import (
    KATANA_DEPTH,
    DeepDiscoveryToolRunner,
    _collect_static_bindings,
    _extract_source_assets,
    _extract_static_calls,
    _sourcemap_sources,
)
from recon_harness.docker_backend import CommandResult
from recon_harness.policy import ScopePolicy
from recon_harness.storage import RunStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class FakeBackend:
    def __init__(self, *results: CommandResult) -> None:
        self.results = list(results)
        self.commands: list[list[str]] = []

    def prepare_remote_dir(self, _run_id: str) -> str:
        return "/work/run/.worker-inputs"

    def copy_to(self, _local: Path, _remote: str) -> None:
        return None

    def run(self, command: list[str], **_kwargs: object) -> CommandResult:
        self.commands.append(command)
        return self.results.pop(0)


class StaticDiscoveryTests(unittest.TestCase):
    def test_static_string_evaluation_resolves_concat_and_template(self) -> None:
        source = """
const base = "/api";
const version = "v1";
const endpoint = base + "/" + version + "/users";
const chunk = `/_next/static/chunks/${version}.js`;
fetch(endpoint);
import(chunk);
"""
        bindings = _collect_static_bindings(source)
        self.assertEqual(bindings["endpoint"], "/api/v1/users")
        self.assertEqual(bindings["chunk"], "/_next/static/chunks/v1.js")
        calls = {(item["kind"], item["value"]) for item in _extract_static_calls(source)}
        self.assertIn(("request-static", "/api/v1/users"), calls)
        self.assertIn(("dynamic-import", "/_next/static/chunks/v1.js"), calls)

    def test_static_fetch_and_axios_calls_keep_method_and_inputs(self) -> None:
        source = """
const endpoint = "/api/users?id=7";
fetch(endpoint, {method: "PUT", headers: {"Content-Type": "application/json"}, body: JSON.stringify({displayName: "A", enabled: true})});
axios.post("/api/upload", {filename: "a.txt", path: "/tmp"});
"""
        calls = _extract_static_calls(source)
        fetch = next(item for item in calls if item["value"].startswith("/api/users"))
        self.assertEqual(fetch["method"], "PUT")
        self.assertEqual(fetch["query_parameters"], ["id"])
        self.assertEqual(fetch["body_parameters"], ["displayName", "enabled"])
        upload = next(item for item in calls if item["value"] == "/api/upload")
        self.assertEqual(upload["method"], "POST")
        self.assertEqual(upload["body_parameters"], ["filename", "path"])

    def test_next_data_script_chunks_and_manifests_are_discovered(self) -> None:
        source = """
<script id="__NEXT_DATA__" type="application/json">{"buildId":"build123","page":"/home"}</script>
<script src="/_next/static/chunks/main-a1b2.js"></script>
"""
        assets = _extract_source_assets(source, "html", "https://example.com/")
        values = {item["value"] for item in assets}
        self.assertIn("/_next/static/chunks/main-a1b2.js", values)
        self.assertIn("https://example.com/_next/static/build123/_buildManifest.js", values)
        self.assertIn("https://example.com/_next/static/build123/_ssgManifest.js", values)

    def test_sourcemap_sources_and_embedded_contents_are_read_offline(self) -> None:
        body = '{"version":3,"sources":["webpack://src/api.js"],"sourcesContent":["fetch(\\"/api/from-map\\")"]}'
        sources, contents = _sourcemap_sources(body)
        self.assertEqual(sources, ["webpack://src/api.js"])
        self.assertEqual(contents, ['fetch("/api/from-map")'])


class KatanaTests(unittest.TestCase):
    def test_katana_depth_is_four(self) -> None:
        self.assertEqual(KATANA_DEPTH, 4)
        with tempfile.TemporaryDirectory() as temporary:
            store = RunStore(Path(temporary) / "runs")
            policy = ScopePolicy.load(PROJECT_ROOT / "tests" / "lab" / "scope.toml")
            state = store.create(policy.path, policy.snapshot())
            backend = FakeBackend(CommandResult(0, "http://recon-juice-shop:3000/\n", ""))
            DeepDiscoveryToolRunner(backend, store).run_katana(policy, state)
            command = backend.commands[0]
            depth_index = command.index("-d") + 1
            self.assertEqual(command[depth_index], "4")


if __name__ == "__main__":
    unittest.main()
