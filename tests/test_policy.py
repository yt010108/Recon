from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.models import STAGE_ORDER, TOOL_NAMES, stage_for_tool, tools_for_stage
from recon_harness.policy import PolicyError, ScopePolicy


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCOPE = PROJECT_ROOT / "tests" / "fixtures" / "example.toml"
LAB_SCOPE = PROJECT_ROOT / "tests" / "lab" / "scope.toml"


class ScopePolicyTests(unittest.TestCase):
    def test_example_scope_allows_root_and_subdomain(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        self.assertEqual(policy.worker_image, "local/hermes-recon-web:0.1")
        self.assertIsNone(policy.docker_network)
        self.assertEqual(policy.validate_url("https://example.com/"), "https://example.com/")
        self.assertEqual(
            policy.validate_url("https://api.example.com/v1"),
            "https://api.example.com/v1",
        )

    def test_example_scope_blocks_unrelated_domain(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        with self.assertRaises(PolicyError):
            policy.validate_url("https://example.net/")

    def test_every_recon_stage_is_available(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        self.assertEqual(policy.validate_stage("discovery"), "discovery")
        self.assertEqual(policy.validate_stage("crawl"), "crawl")
        juice = ScopePolicy.load(LAB_SCOPE)
        self.assertEqual(juice.docker_network, "recon-lab")
        self.assertEqual(juice.validate_stage("discovery"), "discovery")

    def test_scan_stage_is_not_part_of_recon(self) -> None:
        self.assertEqual(STAGE_ORDER, ("collect", "probe", "crawl", "discovery", "normalize"))
        policy = ScopePolicy.load(LAB_SCOPE)
        with self.assertRaises(ValueError):
            policy.validate_stage("scan")

    def test_tool_maps_to_its_stage(self) -> None:
        self.assertEqual(stage_for_tool("httpx"), "probe")
        self.assertEqual(stage_for_tool("nuclei"), "probe")
        self.assertEqual(stage_for_tool("source_comments"), "crawl")
        self.assertIn("url_discovery", tools_for_stage("discovery"))
        self.assertNotIn("url_discovery", TOOL_NAMES)
        with self.assertRaises(ValueError):
            stage_for_tool("url_discovery")
        self.assertNotIn("nuclei", tools_for_stage("probe"))

    def test_url_scope_preserves_base_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.toml"
            rendered = render_scope_toml("https://Example.com/path")
            path.write_text(rendered, encoding="utf-8")
            policy = ScopePolicy.load(path)
        self.assertIn("domain_timeout = 180", rendered)
        self.assertEqual(policy.domain_timeout, 180)
        self.assertEqual(policy.name, "example.com")
        self.assertEqual(policy.base_url, "https://Example.com/path")

    def test_ip_target_is_supported_without_domain_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.toml"
            path.write_text(render_scope_toml("https://10.20.30.5:8443"), encoding="utf-8")
            policy = ScopePolicy.load(path)
        self.assertTrue(policy.is_ip)
        self.assertEqual(policy.validate_url("https://10.20.30.5:8443/admin"), "https://10.20.30.5:8443/admin")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://10.20.30.6:8443/admin")

    def test_domain_timeout_can_be_overridden(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.toml"
            path.write_text(render_scope_toml("example.com", 45), encoding="utf-8")
            policy = ScopePolicy.load(path)
        self.assertEqual(policy.domain_timeout, 45)


if __name__ == "__main__":
    unittest.main()
