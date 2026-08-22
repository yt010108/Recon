from __future__ import annotations

import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SecretGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = runpy.run_path(str(PROJECT_ROOT / "scripts" / "check-secrets.py"))

    def test_detects_credential_without_echoing_value(self) -> None:
        detected = self.module["findings"](
            "config.txt", "password=" + "correct-horse-battery-staple"
        )
        self.assertEqual(detected, [(1, "credential assignment")])

    def test_scanner_does_not_flag_its_own_pattern_source(self) -> None:
        source = (PROJECT_ROOT / "scripts" / "check-secrets.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(self.module["findings"]("check-secrets.py", source), [])

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_staged_secret_is_blocked_without_printing_its_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(
                ["git", "init", "-q"], cwd=root, check=True, capture_output=True
            )
            secret = "ghp_" + ("A" * 36)
            (root / "config.txt").write_text("token=" + secret, encoding="utf-8")
            subprocess.run(
                ["git", "add", "config.txt"], cwd=root, check=True, capture_output=True
            )
            result = subprocess.run(
                [sys.executable, str(PROJECT_ROOT / "scripts" / "check-secrets.py")],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertNotIn(secret, result.stderr)


if __name__ == "__main__":
    unittest.main()
