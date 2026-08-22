from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.models import STAGE_ORDER
from recon_harness.policy import PolicyError, ScopePolicy


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_SCOPE = PROJECT_ROOT / "tests" / "fixtures" / "example.toml"
LAB_SCOPE = PROJECT_ROOT / "tests" / "lab" / "scope.toml"


class ScopePolicyTests(unittest.TestCase):
    def test_example_scope_allows_root_and_subdomain(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        self.assertEqual(policy.worker_image, "local/hermes-recon-web:0.1")
        self.assertTrue(policy.is_tool_enabled("robots_txt"))
        self.assertTrue(policy.is_tool_enabled("source_comments"))
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

    def test_stage_permission_is_enforced(self) -> None:
        policy = ScopePolicy.load(EXAMPLE_SCOPE)
        with self.assertRaises(PolicyError):
            policy.validate_stage("discovery")
        self.assertEqual(policy.validate_stage("crawl"), "crawl")
        juice = ScopePolicy.load(LAB_SCOPE)
        self.assertEqual(juice.docker_network, "recon-lab")
        self.assertEqual(juice.validate_stage("discovery"), "discovery")

    def test_scan_stage_is_not_part_of_recon(self) -> None:
        self.assertEqual(STAGE_ORDER, ("collect", "probe", "crawl", "discovery"))
        policy = ScopePolicy.load(LAB_SCOPE)
        with self.assertRaises(ValueError):
            policy.validate_stage("scan")

    def test_pi_scope_contains_only_domain_and_dos_choice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.toml"
            rendered = render_scope_toml("https://Example.com/path", True)
            path.write_text(rendered, encoding="utf-8")
            policy = ScopePolicy.load(path)
        self.assertEqual(rendered.count("="), 2)
        self.assertEqual(policy.name, "example.com")
        self.assertTrue(policy.permissions["allow_crawling"])
        self.assertTrue(policy.permissions["allow_dos_tools"])
        self.assertTrue(policy.is_tool_enabled("gobuster_dir"))

    def test_crawler_stays_enabled_when_dos_tools_are_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "scope.toml"
            path.write_text(render_scope_toml("example.com", False), encoding="utf-8")
            policy = ScopePolicy.load(path)
        self.assertTrue(policy.is_tool_enabled("katana"))
        self.assertTrue(policy.is_tool_enabled("source_comments"))
        self.assertFalse(policy.is_tool_enabled("gobuster_dir"))
        self.assertFalse(policy.is_tool_enabled("parameth"))


if __name__ == "__main__":
    unittest.main()
