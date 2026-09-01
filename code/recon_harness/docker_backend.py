"""도구 명령마다 제한된 일회용 Docker 컨테이너를 실행한다."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Sequence


DEFAULT_IMAGE = "local/hermes-recon-web:0.1"
NUCLEI_IMAGE = "local/hermes-recon-nuclei:0.1"
REMOTE_INPUT_DIR = "/work/run/.worker-inputs"


class BackendError(RuntimeError):
    """Raised when Docker or the configured worker image is unavailable."""


@dataclass(slots=True)
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


class DockerBackend:
    """Run each fixed tool command in a new, locked-down container."""

    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        *,
        workspace_dir: Path | None = None,
        network: str | None = None,
        run_id: str | None = None,
    ) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,254}", image):
            raise BackendError(f"Invalid worker image: {image!r}")
        if network and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", network):
            raise BackendError(f"Invalid Docker network: {network!r}")
        if run_id and not re.fullmatch(r"[a-zA-Z0-9._-]+", run_id):
            raise BackendError(f"Invalid run id: {run_id!r}")

        self.image = image
        self.network = network
        self.run_id = run_id
        self.workspace_dir = workspace_dir.resolve() if workspace_dir else None
        self.docker = shutil.which("docker")
        if not self.docker:
            raise BackendError("docker was not found on PATH")

    @staticmethod
    def _completed(command: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )

    def doctor(self) -> dict[str, object]:
        image_result = self._completed([self.docker, "image", "inspect", self.image])
        image_available = image_result.returncode == 0

        network_available = True
        network_error = ""
        if self.network:
            network_result = self._completed(
                [self.docker, "network", "inspect", self.network]
            )
            network_available = network_result.returncode == 0
            network_error = network_result.stderr.strip() if not network_available else ""

        errors = []
        if not image_available:
            errors.append(image_result.stderr.strip() or f"Image {self.image!r} is unavailable")
        if not network_available:
            errors.append(network_error or f"Network {self.network!r} is unavailable")
        return {
            "docker": self.docker,
            "mode": "ephemeral-container-per-command",
            "image": self.image,
            "image_available": image_available,
            "network": self.network or "default",
            "network_available": network_available,
            "ready": image_available and network_available,
            "error": "; ".join(item for item in errors if item),
        }

    def require_ready(self) -> None:
        status = self.doctor()
        if not status["ready"]:
            raise BackendError(f"Worker is not ready: {status['error']}")

    def _input_dir(self) -> Path:
        if self.workspace_dir is None:
            raise BackendError("This worker command requires a run workspace")
        destination = self.workspace_dir / ".worker-inputs"
        destination.mkdir(parents=True, exist_ok=True)
        return destination.resolve()

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        process_timeout: int = 900,
        environment: dict[str, str] | None = None,
    ) -> CommandResult:
        if not args or any("\x00" in str(item) for item in args):
            raise BackendError("Invalid empty command or NUL byte")
        safe_timeout = max(1, process_timeout)
        name_suffix = uuid.uuid4().hex[:12]
        run_prefix = (self.run_id or "doctor")[-32:]
        container_name = f"hermes-recon-{run_prefix}-{name_suffix}".lower()
        command = [
            self.docker,
            "run",
            "--rm",
            "--name",
            container_name,
            "--pull=never",
        ]
        if input_text is not None:
            command.append("-i")
        if self.network:
            command.extend(["--network", self.network])
        if self.workspace_dir is not None:
            # 필요한 입력 파일만 컨테이너에 노출한다.
            input_dir = self._input_dir()
            command.extend(
                [
                    "--mount",
                    f"type=bind,source={input_dir},target={REMOTE_INPUT_DIR}",
                ]
            )
        for key, value in (environment or {}).items():
            if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
                raise BackendError(f"Invalid environment variable name: {key}")
            command.extend(["-e", f"{key}={value}"])
        command.extend(
            [
                self.image,
                "timeout",
                "--signal=TERM",
                f"{safe_timeout}s",
                *[str(item) for item in args],
            ]
        )

        try:
            completed = subprocess.run(
                command,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=safe_timeout + 20,
                check=False,
                env=os.environ.copy(),
            )
            return CommandResult(
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            # 호스트 타임아웃이 Docker의 timeout보다 먼저 발생한 경우 이 컨테이너만 정리한다.
            subprocess.run(
                [self.docker, "rm", "-f", container_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                check=False,
            )
            return CommandResult(
                exit_code=124,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            )

    def prepare_remote_dir(self, run_id: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", run_id):
            raise BackendError("Invalid run id for worker input directory")
        if self.run_id is not None and run_id != self.run_id:
            raise BackendError("Run id does not match the worker workspace")
        self._input_dir()
        return REMOTE_INPUT_DIR

    def copy_to(self, source: Path, remote_path: str) -> None:
        source = source.resolve()
        if not source.is_file():
            raise BackendError(f"Worker input does not exist: {source}")

        remote = PurePosixPath(remote_path)
        remote_base = PurePosixPath(REMOTE_INPUT_DIR)
        try:
            relative = remote.relative_to(remote_base)
        except ValueError as exc:
            raise BackendError("Refusing to copy outside the worker input directory") from exc
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise BackendError("Invalid worker input path")

        input_dir = self._input_dir()
        destination = (input_dir / Path(*relative.parts)).resolve()
        if input_dir not in destination.parents:
            raise BackendError("Worker input path escapes its directory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
