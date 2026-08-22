from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.models import STAGE_ORDER
from recon_harness.policy import PolicyError, ScopePolicy


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ScopePolicyTests(unittest.TestCase):
    def test_example_scope_allows_root_and_subdomain(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "example.toml")
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
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "example.toml")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://example.net/")

    def test_example_scope_blocks_excluded_host_and_path(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "example.toml")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://status.example.com/")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://example.com/logout")

    def test_active_stage_requires_approval_and_permission(self) -> None:
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "example.toml")
        with self.assertRaises(PolicyError):
            policy.validate_stage("crawl", approved=True)
        juice = ScopePolicy.load(PROJECT_ROOT / "scopes" / "juice-shop.toml")
        self.assertEqual(juice.docker_network, "recon-lab")
        with self.assertRaises(PolicyError):
            juice.validate_stage("crawl", approved=False)
        self.assertEqual(juice.validate_stage("crawl", approved=True), "crawl")

    def test_scan_stage_is_not_part_of_recon(self) -> None:
        self.assertEqual(STAGE_ORDER, ("collect", "probe", "crawl", "discovery"))
        policy = ScopePolicy.load(PROJECT_ROOT / "scopes" / "juice-shop.toml")
        with self.assertRaises(ValueError):
            policy.validate_stage("scan", approved=True)

    def test_scope_requires_authorization_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.toml"
            path.write_text(
                "[scope]\nname='bad'\n[targets]\nbase_url='https://example.com'\ndomains=['example.com']\n",
                encoding="utf-8",
            )
            with self.assertRaises(PolicyError):
                ScopePolicy.load(path)


if __name__ == "__main__":
    unittest.main()
