"""run-local scope.toml의 도메인 경계를 검증한다."""

from __future__ import annotations

import re
import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_backend import DEFAULT_IMAGE
from .models import validate_stage


DEFAULT_DOMAIN_TIMEOUT = 180


class PolicyError(ValueError):
    """스코프 밖의 대상을 요청했을 때 발생한다."""


def _domain_matches(host: str, domain: str) -> bool:
    host = host.rstrip(".").lower()
    return host == domain or host.endswith(f".{domain}")


@dataclass(slots=True)
class ScopePolicy:
    path: Path
    domain: str
    base_url: str
    docker_network: str | None = None
    worker_image: str = DEFAULT_IMAGE
    domain_timeout: int = DEFAULT_DOMAIN_TIMEOUT
    run_gobuster: bool = False
    domains: list[str] = field(init=False)
    allowed_ports: list[int] = field(init=False)
    is_ip: bool = field(init=False)
    is_domain: bool = field(init=False)

    def __post_init__(self) -> None:
        self.domains = [self.domain]
        try:
            ipaddress.ip_address(self.domain)
            self.is_ip = True
        except ValueError:
            self.is_ip = False
        self.is_domain = not self.is_ip
        try:
            self.domain_timeout = int(self.domain_timeout)
        except (TypeError, ValueError) as exc:
            raise PolicyError(f"Invalid domain timeout: {self.domain_timeout}") from exc
        if not 1 <= self.domain_timeout <= 180:
            raise PolicyError("Domain timeout must be between 1 and 180 seconds")
        parsed = urlsplit(self.base_url)
        if parsed.port is not None:
            self.allowed_ports = [parsed.port]
        else:
            self.allowed_ports = [80, 443]

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        source = Path(path).expanduser().resolve()
        try:
            raw = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"Cannot load scope file {source}: {exc}") from exc

        scope = raw.get("scope", {})
        domain = str(scope.get("domain", "")).strip().lower().rstrip(".")
        try:
            ipaddress.ip_address(domain)
            valid_target = True
        except ValueError:
            valid_target = bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", domain))
        if not valid_target:
            raise PolicyError("[scope].domain must be a valid hostname or IP address")

        base_url = str(scope.get("base_url", f"https://{domain}")).strip()
        network = str(scope.get("network", "")).strip() or None
        policy = cls(
            path=source,
            domain=domain,
            base_url=base_url,
            docker_network=network,
            domain_timeout=scope.get("domain_timeout", DEFAULT_DOMAIN_TIMEOUT),
            run_gobuster=scope.get("run_gobuster", False),
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
        return validate_stage(stage)

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "domains": self.domains,
            "allowed_ports": self.allowed_ports,
            "target_type": "ip" if self.is_ip else "domain",
            "domain_timeout": self.domain_timeout,
            "run_gobuster": self.run_gobuster,
            "worker_image": self.worker_image,
            "docker_network": self.docker_network,
        }
