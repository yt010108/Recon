"""run-local scope.toml의 도메인 경계를 검증한다."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_backend import DEFAULT_IMAGE, NUCLEI_IMAGE
from .models import STAGE_PERMISSIONS, TOOL_NAMES, validate_stage


class PolicyError(ValueError):
    """스코프 밖의 대상이나 비활성 단계를 요청했을 때 발생한다."""


def _domain_matches(host: str, domain: str) -> bool:
    host = host.rstrip(".").lower()
    return host == domain or host.endswith(f".{domain}")


@dataclass(slots=True)
class ScopePolicy:
    path: Path
    domain: str
    dos_allowed: bool
    base_url: str
    docker_network: str | None = None
    worker_image: str = DEFAULT_IMAGE
    nuclei_image: str = NUCLEI_IMAGE
    rate_limit: int = 5
    concurrency: int = 2
    timeout_seconds: int = 10
    domains: list[str] = field(init=False)
    allowed_ports: list[int] = field(init=False)
    permissions: dict[str, bool] = field(init=False)
    enabled_tools: list[str] = field(init=False)

    def __post_init__(self) -> None:
        self.domains = [self.domain]
        parsed = urlsplit(self.base_url)
        if parsed.port is not None:
            self.allowed_ports = [parsed.port]
        else:
            self.allowed_ports = [80, 443]
        self.permissions = {
            "allow_passive_collection": True,
            "allow_http_probing": True,
            "allow_crawling": True,
            "allow_dos_tools": self.dos_allowed,
        }
        conditional = {"gobuster_dir", "parameth"}
        self.enabled_tools = sorted(
            tool for tool in TOOL_NAMES if self.dos_allowed or tool not in conditional
        )

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        source = Path(path).expanduser().resolve()
        try:
            raw = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"Cannot load scope file {source}: {exc}") from exc

        scope = raw.get("scope", {})
        domain = str(scope.get("domain", "")).strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain):
            raise PolicyError("[scope].domain must be a valid hostname")

        base_url = str(scope.get("base_url", f"https://{domain}")).strip()
        network = str(scope.get("network", "")).strip() or None
        policy = cls(
            path=source,
            domain=domain,
            dos_allowed=bool(scope.get("dos_allowed", False)),
            base_url=base_url,
            docker_network=network,
        )
        policy.validate_url(base_url)
        return policy

    @property
    def name(self) -> str:
        return self.domain

    @property
    def root_domain(self) -> str:
        return self.domain

    def validate_url(self, value: str) -> str:
        # 모든 네트워크 어댑터가 요청 직전에 이 경계를 다시 검사한다.
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise PolicyError(f"Invalid target URL: {value}") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyError(f"Only absolute HTTP(S) URLs are allowed: {value}")
        if parsed.username or parsed.password:
            raise PolicyError("Credentials in target URLs are not allowed")
        if not _domain_matches(parsed.hostname, self.domain):
            raise PolicyError(f"Target is outside the configured domain: {parsed.hostname}")
        effective_port = port or (443 if parsed.scheme == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise PolicyError(f"Port {effective_port} is outside the configured scope")
        return value

    def validate_stage(self, stage: str) -> str:
        normalized = validate_stage(stage)
        permission = STAGE_PERMISSIONS[normalized]
        if not self.permissions[permission]:
            raise PolicyError(f"Stage {normalized!r} is disabled")
        return normalized

    def is_tool_enabled(self, tool: str) -> bool:
        return tool in self.enabled_tools

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "domains": self.domains,
            "allowed_ports": self.allowed_ports,
            "worker_image": self.worker_image,
            "nuclei_image": self.nuclei_image,
            "docker_network": self.docker_network,
            "rate_limit": self.rate_limit,
            "concurrency": self.concurrency,
            "timeout_seconds": self.timeout_seconds,
            "enabled_tools": self.enabled_tools,
            "permissions": self.permissions,
        }
