from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from recon_harness.docker_backend import (
    DEFAULT_IMAGE,
    REMOTE_INPUT_DIR,
    BackendError,
    DockerBackend,
)


def completed(
    returncode: int = 0, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class DockerBackendTests(unittest.TestCase):
    def test_doctor_checks_image_and_requested_network(self) -> None:
        with (
            patch("recon_harness.docker_backend.shutil.which", return_value="docker"),
            patch.object(
                DockerBackend, "_completed", side_effect=[completed(), completed()]
            ) as mocked,
        ):
            status = DockerBackend(DEFAULT_IMAGE, network="recon-lab").doctor()

        self.assertTrue(status["ready"])
        self.assertEqual(status["mode"], "ephemeral-container-per-command")
        self.assertEqual(mocked.call_args_list[0].args[0], ["docker", "image", "inspect", DEFAULT_IMAGE])
        self.assertEqual(mocked.call_args_list[1].args[0], ["docker", "network", "inspect", "recon-lab"])

    def test_run_builds_locked_ephemeral_container_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "run"
            workspace.mkdir()
            with (
                patch("recon_harness.docker_backend.shutil.which", return_value="docker"),
                patch("recon_harness.docker_backend.subprocess.run", return_value=completed(stdout="ok\n")) as mocked,
            ):
                backend = DockerBackend(
                    DEFAULT_IMAGE,
                    workspace_dir=workspace,
                    network="recon-lab",
                    run_id="run-123",
                )
                result = backend.run(
                    ["which", "httpx"],
                    input_text="input\n",
                    process_timeout=30,
                    environment={"TEST_MODE": "1"},
                )

        command = mocked.call_args.args[0]
        self.assertEqual(result.stdout, "ok\n")
        self.assertIn("--rm", command)
        self.assertIn("--read-only", command)
        self.assertIn("--pull=never", command)
        self.assertIn("no-new-privileges:true", command)
        self.assertIn("--network", command)
        self.assertIn("recon-lab", command)
        self.assertIn("TEST_MODE=1", command)
        self.assertTrue(any(REMOTE_INPUT_DIR in item and "readonly" in item for item in command))
        self.assertEqual(command[-6:], [DEFAULT_IMAGE, "timeout", "--signal=TERM", "30s", "which", "httpx"])

    def test_copy_to_maps_only_the_worker_input_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "run"
            workspace.mkdir()
            source = root / "input.txt"
            source.write_text("one\ntwo\n", encoding="utf-8")
            with patch("recon_harness.docker_backend.shutil.which", return_value="docker"):
                backend = DockerBackend(DEFAULT_IMAGE, workspace_dir=workspace, run_id="run-123")
                backend.copy_to(source, f"{REMOTE_INPUT_DIR}/targets/input.txt")
                copied = workspace / ".worker-inputs" / "targets" / "input.txt"
                self.assertEqual(copied.read_text(encoding="utf-8"), "one\ntwo\n")
                with self.assertRaises(BackendError):
                    backend.copy_to(source, "/tmp/outside.txt")

    def test_host_timeout_force_removes_only_the_named_temporary_container(self) -> None:
        timeout = subprocess.TimeoutExpired(["docker", "run"], 21)
        with (
            patch("recon_harness.docker_backend.shutil.which", return_value="docker"),
            patch(
                "recon_harness.docker_backend.subprocess.run",
                side_effect=[timeout, completed()],
            ) as mocked,
        ):
            result = DockerBackend(DEFAULT_IMAGE, run_id="run-123").run(
                ["which", "httpx"], process_timeout=1
            )

        self.assertEqual(result.exit_code, 124)
        cleanup = mocked.call_args_list[1].args[0]
        self.assertEqual(cleanup[:3], ["docker", "rm", "-f"])
        self.assertTrue(cleanup[3].startswith("hermes-recon-run-123-"))


if __name__ == "__main__":
    unittest.main()
