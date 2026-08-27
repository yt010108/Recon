"""run-local scope.toml의 인터넷 도메인/대회 내부망 경계를 검증한다."""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_backend import DEFAULT_IMAGE
from .models import validate_mode, validate_stage


MAX_COMPETITION_ADDRESSES = 4096

DEFAULT_COMPETITION_PORTS = [
    80,
    81,
    443,
    3000,
    3001,
    4000,
    5000,
    7001,
    8000,
    8008,
    8080,
    8081,
    8088,
    8443,
    8888,
    9000,
    9090,
    9200,
    9443,
]


class PolicyError(ValueError):
    """스코프 밖의 대상을 요청했을 때 발생한다."""


def _domain_matches(host: str, domain: str) -> bool:
    host = host.rstrip(".").lower()
    return host == domain or host.endswith(f".{domain}")


def _valid_hostname(value: str) -> bool:
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value))


@dataclass(slots=True)
class ScopePolicy:
    path: Path
    mode: str
    domain: str | None
    base_url: str
    docker_network: str | None = None
    worker_image: str = DEFAULT_IMAGE
    targets: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    domains: list[str] = field(init=False)
    network_scopes: list[ipaddress.IPv4Network] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.mode = validate_mode(self.mode)
        self.domains = [self.domain] if self.domain else []
        self.network_scopes = []

        if self.mode == "internet":
            if not self.domain:
                raise PolicyError("internet mode requires [scope].domain")
            parsed = urlsplit(self.base_url)
            if parsed.port is not None:
                self.allowed_ports = [parsed.port]
            else:
                self.allowed_ports = [80, 443]
            return

        if self.domain is not None:
            raise PolicyError("competition mode does not use [scope].domain")
        if not self.targets:
            raise PolicyError("competition mode requires at least one IPv4 target or CIDR")

        normalized_targets: list[str] = []
        total_addresses = 0
        for value in self.targets:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise PolicyError(
                    f"Competition target must be an IPv4 address or CIDR: {value}"
                ) from exc
            if not isinstance(network, ipaddress.IPv4Network):
                raise PolicyError("competition mode currently supports IPv4 targets only")
            total_addresses += network.num_addresses
            if total_addresses > MAX_COMPETITION_ADDRESSES:
                raise PolicyError(
                    f"Competition scope is too large; maximum {MAX_COMPETITION_ADDRESSES} IPv4 addresses per run"
                )
            normalized = str(network.network_address) if network.prefixlen == 32 else str(network)
            if normalized not in normalized_targets:
                normalized_targets.append(normalized)
                self.network_scopes.append(network)
        self.targets = normalized_targets

        if not self.allowed_ports:
            self.allowed_ports = list(DEFAULT_COMPETITION_PORTS)
        normalized_ports: list[int] = []
        for value in self.allowed_ports:
            try:
                port = int(value)
            except (TypeError, ValueError) as exc:
                raise PolicyError(f"Invalid competition port: {value!r}") from exc
            if not 1 <= port <= 65535:
                raise PolicyError(f"Competition port out of range: {port}")
            if port not in normalized_ports:
                normalized_ports.append(port)
        self.allowed_ports = sorted(normalized_ports)

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        source = Path(path).expanduser().resolve()
        try:
            raw = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"Cannot load scope file {source}: {exc}") from exc

        scope = raw.get("scope", {})
        mode = validate_mode(str(scope.get("mode", "internet")))
        network = str(scope.get("network", "")).strip() or None

        if mode == "internet":
            domain = str(scope.get("domain", "")).strip().lower().rstrip(".")
            if not _valid_hostname(domain):
                raise PolicyError("[scope].domain must be a valid hostname")
            base_url = str(scope.get("base_url", f"https://{domain}")).strip()
            policy = cls(
                path=source,
                mode=mode,
                domain=domain,
                base_url=base_url,
                docker_network=network,
            )
            policy.validate_url(base_url)
            return policy

        targets_raw = scope.get("targets", [])
        if not isinstance(targets_raw, list):
            raise PolicyError("[scope].targets must be an array")
        ports_raw = scope.get("ports", DEFAULT_COMPETITION_PORTS)
        if not isinstance(ports_raw, list):
            raise PolicyError("[scope].ports must be an array")
        base_url = str(scope.get("base_url", "")).strip()
        policy = cls(
            path=source,
            mode=mode,
            domain=None,
            base_url=base_url,
            docker_network=network,
            targets=[str(value).strip() for value in targets_raw if str(value).strip()],
            allowed_ports=list(ports_raw),
        )
        if base_url:
            policy.validate_url(base_url)
        return policy

    @property
    def name(self) -> str:
        if self.mode == "internet":
            return str(self.domain)
        return f"competition-{self.targets[0]}"

    @property
    def root_domain(self) -> str:
        if not self.domain:
            raise PolicyError("competition scope has no root domain")
        return self.domain

    @property
    def target_label(self) -> str:
        if self.mode == "internet":
            return self.base_url
        return ", ".join(self.targets)

    def validate_host(self, value: str) -> str:
        host = value.strip().strip("[]")
        if self.mode == "internet":
            if not self.domain or not _domain_matches(host, self.domain):
                raise PolicyError(f"Target is outside the configured domain: {host}")
            return host
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise PolicyError(
                f"Competition targets must remain on configured IPv4 addresses: {host}"
            ) from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise PolicyError("competition mode currently supports IPv4 targets only")
        if not any(address in network for network in self.network_scopes):
            raise PolicyError(f"Target is outside the configured competition scope: {host}")
        return host

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
            "base_url": self.base_url,
            "target_label": self.target_label,
            "targets": self.targets,
            "domains": self.domains,
            "allowed_ports": self.allowed_ports,
            "worker_image": self.worker_image,
            "docker_network": self.docker_network,
        }
