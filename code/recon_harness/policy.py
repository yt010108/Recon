"""대회에서 명시적으로 허용된 IPv4/CIDR과 포트를 검증한다."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_backend import DEFAULT_IMAGE
from .models import validate_profile, validate_stage


MAX_COMPETITION_ADDRESSES = 4096
DEFAULT_COMPETITION_PORTS = [80, 443, 3000, 5000, 8000, 8080, 8081, 8443, 8888, 9000]


class PolicyError(ValueError):
    """스코프 밖의 대상을 요청했을 때 발생한다."""


@dataclass(slots=True)
class ScopePolicy:
    path: Path
    targets: list[str]
    allowed_ports: list[int]
    profile: str = "fast"
    budget_minutes: int = 3
    tls_verify: bool = False
    docker_network: str | None = None
    worker_image: str = DEFAULT_IMAGE
    mode: str = field(init=False, default="competition")
    base_url: str = field(init=False, default="")
    domain: None = field(init=False, default=None)
    domains: list[str] = field(init=False, default_factory=list)
    network_scopes: list[ipaddress.IPv4Network] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.profile = validate_profile(self.profile)
        if not 1 <= int(self.budget_minutes) <= 120:
            raise PolicyError("[run].budget_minutes must be between 1 and 120")
        self.budget_minutes = int(self.budget_minutes)
        if not self.targets:
            raise PolicyError("competition scope requires at least one IPv4 target or CIDR")

        self.network_scopes = []
        normalized_targets: list[str] = []
        total_addresses = 0
        for value in self.targets:
            try:
                network = ipaddress.ip_network(str(value).strip(), strict=False)
            except ValueError as exc:
                raise PolicyError(f"Target must be an IPv4 address or CIDR: {value}") from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise PolicyError("competition scope currently supports IPv4 only")
            total_addresses += network.num_addresses
            if total_addresses > MAX_COMPETITION_ADDRESSES:
                raise PolicyError(
                    f"Scope is too large; maximum {MAX_COMPETITION_ADDRESSES} IPv4 addresses per run"
                )
            normalized = str(network.network_address) if network.prefixlen == 32 else str(network)
            if normalized not in normalized_targets:
                normalized_targets.append(normalized)
                self.network_scopes.append(network)
        self.targets = normalized_targets

        ports: list[int] = []
        for value in self.allowed_ports or DEFAULT_COMPETITION_PORTS:
            try:
                port = int(value)
            except (TypeError, ValueError) as exc:
                raise PolicyError(f"Invalid port: {value!r}") from exc
            if not 1 <= port <= 65535:
                raise PolicyError(f"Port out of range: {port}")
            if port not in ports:
                ports.append(port)
        self.allowed_ports = sorted(ports)

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        source = Path(path).expanduser().resolve()
        try:
            raw = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"Cannot load scope file {source}: {exc}") from exc

        scope = raw.get("scope", {})
        run = raw.get("run", {})
        targets = scope.get("targets", [])
        ports = scope.get("ports", DEFAULT_COMPETITION_PORTS)
        if not isinstance(targets, list):
            raise PolicyError("[scope].targets must be an array")
        if not isinstance(ports, list):
            raise PolicyError("[scope].ports must be an array")
        tls_verify = scope.get("tls_verify", False)
        if not isinstance(tls_verify, bool):
            raise PolicyError("[scope].tls_verify must be true or false")
        network = str(scope.get("network", "")).strip() or None
        profile = str(run.get("profile", "fast"))
        default_budget = 3 if profile.strip().lower() == "fast" else 15
        return cls(
            path=source,
            targets=[str(value) for value in targets],
            allowed_ports=list(ports),
            profile=profile,
            budget_minutes=int(run.get("budget_minutes", default_budget)),
            tls_verify=tls_verify,
            docker_network=network,
        )

    @property
    def name(self) -> str:
        return f"competition-{self.targets[0]}"

    @property
    def target_label(self) -> str:
        return ", ".join(self.targets)

    @property
    def root_domain(self) -> str:
        raise PolicyError("competition scope has no root domain")

    def validate_host(self, value: str) -> str:
        host = value.strip().strip("[]")
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise PolicyError(f"Target must remain on an allowed IPv4 address: {host}") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise PolicyError("competition scope currently supports IPv4 only")
        if not any(address in network for network in self.network_scopes):
            raise PolicyError(f"Target is outside the configured scope: {host}")
        return host

    def validate_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise PolicyError(f"Invalid target URL: {value}") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyError(f"Only absolute HTTP(S) URLs are allowed: {value}")
        if parsed.username or parsed.password:
            raise PolicyError("Credentials in target URLs are not allowed")
        self.validate_host(parsed.hostname)
        effective_port = port or (443 if parsed.scheme == "https" else 80)
        if effective_port not in self.allowed_ports:
            raise PolicyError(f"Port {effective_port} is outside the configured scope")
        return value

    def validate_stage(self, stage: str) -> str:
        return validate_stage(stage)

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "mode": self.mode,
            "target_label": self.target_label,
            "targets": self.targets,
            "allowed_ports": self.allowed_ports,
            "profile": self.profile,
            "budget_minutes": self.budget_minutes,
            "tls_verify": self.tls_verify,
            "worker_image": self.worker_image,
            "docker_network": self.docker_network,
        }
