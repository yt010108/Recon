from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from recon_harness.cli import render_scope_toml
from recon_harness.models import STAGE_ORDER, tools_for_stage
from recon_harness.policy import PolicyError, ScopePolicy


class ScopePolicyTests(unittest.TestCase):
    def _load(self, text: str) -> ScopePolicy:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "scope.toml"
        path.write_text(text, encoding="utf-8")
        return ScopePolicy.load(path)

    def test_competition_scope_allows_only_configured_ipv4_and_ports(self) -> None:
        policy = self._load(
            render_scope_toml(
                ["10.20.30.0/24"], [443, 8443],
                profile="deep", budget_minutes=12,
            )
        )
        self.assertEqual(policy.profile, "deep")
        self.assertEqual(policy.budget_minutes, 12)
        self.assertEqual(policy.validate_url("https://10.20.30.5:8443/login"), "https://10.20.30.5:8443/login")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://10.20.31.5:8443/login")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://10.20.30.5:9443/login")
        with self.assertRaises(PolicyError):
            policy.validate_url("https://example.com/login")

    def test_profiles_change_only_expensive_stages(self) -> None:
        self.assertEqual(STAGE_ORDER, ("inventory", "mapping", "normalize", "expansion"))
        self.assertNotIn("source_comments", tools_for_stage("mapping", "fast"))
        self.assertIn("source_comments", tools_for_stage("mapping", "deep"))
        self.assertEqual(tools_for_stage("expansion", "fast"), ())
        self.assertEqual(tools_for_stage("expansion", "deep"), ("gobuster_dir",))


if __name__ == "__main__":
    unittest.main()
