"""Scope parsing and target authorization checks."""

from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .docker_backend import DEFAULT_IMAGE
from .models import APPROVAL_STAGES, STAGE_ORDER, TOOL_SPECS, validate_stage


class PolicyError(ValueError):
    """Raised when a scope or requested action violates policy."""


def _domain_matches(host: str, allowed: str) -> bool:
    host = host.rstrip(".").lower()
    allowed = allowed.removeprefix("*.").rstrip(".").lower()
    return host == allowed or host.endswith(f".{allowed}")


def _port_for_url(parsed: Any) -> int:
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


@dataclass(slots=True)
class ScopePolicy:
    path: Path
    name: str
    kind: str
    authorization_reference: str
    base_url: str
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    base_urls: list[str] = field(default_factory=list)
    excluded_hosts: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443])
    worker_image: str = DEFAULT_IMAGE
    docker_network: str | None = None
    rate_limit: int = 20
    concurrency: int = 10
    timeout_seconds: int = 10
    enabled_tools: list[str] = field(default_factory=lambda: list(TOOL_SPECS))
    permissions: dict[str, bool] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        source = Path(path).expanduser().resolve()
        try:
            raw = tomllib.loads(source.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise PolicyError(f"Cannot load scope file {source}: {exc}") from exc

        scope = raw.get("scope", {})
        targets = raw.get("targets", {})
        limits = raw.get("limits", {})
        permissions = raw.get("permissions", {})
        tools = raw.get("tools", {})
        worker = raw.get("worker", {})

        name = str(scope.get("name", "")).strip()
        authorization = str(scope.get("authorization_reference", "")).strip()
        base_url = str(targets.get("base_url", "")).strip()
        if not name:
            raise PolicyError("[scope].name is required")
        if not authorization:
            raise PolicyError("[scope].authorization_reference is required")
        if not base_url:
            raise PolicyError("[targets].base_url is required")

        requested_tools = [str(item) for item in tools.get("enabled", list(TOOL_SPECS))]
        # Frozen runs from the first prototype may still mention the retired scan
        # tools. Ignore those two names while continuing to reject real typos.
        enabled_tools = [item for item in requested_tools if item not in {"nuclei", "nmap"}]
        unknown_tools = sorted(set(enabled_tools) - set(TOOL_SPECS))
        if unknown_tools:
            raise PolicyError(f"Unknown enabled tools: {', '.join(unknown_tools)}")

        policy = cls(
            path=source,
            name=name,
            kind=str(scope.get("kind", "bugbounty")),
            authorization_reference=authorization,
            base_url=base_url,
            domains=[str(item).lower() for item in targets.get("domains", [])],
            cidrs=[str(item) for item in targets.get("cidrs", [])],
            base_urls=[str(item) for item in targets.get("base_urls", [])],
            excluded_hosts=[str(item).lower() for item in targets.get("excluded_hosts", [])],
            excluded_paths=[str(item) for item in targets.get("excluded_paths", [])],
            allowed_ports=[int(item) for item in targets.get("allowed_ports", [80, 443])],
            worker_image=str(worker.get("image", DEFAULT_IMAGE)).strip(),
            docker_network=str(worker.get("network", "")).strip() or None,
            rate_limit=max(1, int(limits.get("rate_limit", 20))),
            concurrency=max(1, int(limits.get("concurrency", 10))),
            timeout_seconds=max(1, int(limits.get("timeout_seconds", 10))),
            enabled_tools=enabled_tools,
            permissions={str(key): bool(value) for key, value in permissions.items()},
            options={str(key): value for key, value in tools.items() if key != "enabled"},
        )
        policy.validate_url(policy.base_url)
        for cidr in policy.cidrs:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise PolicyError(f"Invalid CIDR in scope: {cidr}") from exc
        return policy

    @property
    def root_domain(self) -> str:
        if self.domains:
            return self.domains[0].removeprefix("*.")
        parsed = urlsplit(self.base_url)
        return parsed.hostname or ""

    def validate_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise PolicyError(f"Invalid target URL: {value}") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise PolicyError(f"Only absolute HTTP(S) URLs are allowed: {value}")
        if parsed.username is not None or parsed.password is not None:
            raise PolicyError("Credentials in target URLs are not allowed")

        host = parsed.hostname.rstrip(".").lower()
        if any(_domain_matches(host, blocked) for blocked in self.excluded_hosts):
            raise PolicyError(f"Host is explicitly excluded by scope: {host}")

        host_allowed = any(_domain_matches(host, domain) for domain in self.domains)
        if not host_allowed:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None
            if address is not None:
                host_allowed = any(
                    address in ipaddress.ip_network(cidr, strict=False) for cidr in self.cidrs
                )

        if self.base_urls:
            prefix_allowed = False
            for prefix in self.base_urls:
                allowed = urlsplit(prefix)
                if (
                    parsed.scheme == allowed.scheme
                    and parsed.hostname == allowed.hostname
                    and _port_for_url(parsed) == _port_for_url(allowed)
                    and (parsed.path or "/").startswith(allowed.path or "/")
                ):
                    prefix_allowed = True
                    break
            host_allowed = host_allowed and prefix_allowed

        if not host_allowed:
            raise PolicyError(f"Target is outside the configured scope: {host}")

        if _port_for_url(parsed) not in self.allowed_ports:
            raise PolicyError(f"Port {_port_for_url(parsed)} is outside the configured scope")
        path = parsed.path or "/"
        if any(path.startswith(prefix) for prefix in self.excluded_paths):
            raise PolicyError(f"Path is explicitly excluded by scope: {path}")
        return value

    def validate_stage(self, stage: str, approved: bool = False) -> str:
        normalized = validate_stage(stage)
        permission_name = {
            "collect": "allow_passive_collection",
            "probe": "allow_http_probing",
            "crawl": "allow_crawling",
            "discovery": "allow_content_discovery",
        }[normalized]
        if not self.permissions.get(permission_name, False):
            raise PolicyError(f"Scope policy disables stage {normalized!r} ({permission_name})")
        if normalized in APPROVAL_STAGES and not approved:
            raise PolicyError(f"Stage {normalized!r} requires explicit user approval")
        return normalized

    def is_tool_enabled(self, tool: str) -> bool:
        return tool in self.enabled_tools

    def snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "authorization_reference": self.authorization_reference,
            "base_url": self.base_url,
            "domains": self.domains,
            "cidrs": self.cidrs,
            "base_urls": self.base_urls,
            "excluded_hosts": self.excluded_hosts,
            "excluded_paths": self.excluded_paths,
            "allowed_ports": self.allowed_ports,
            "worker_image": self.worker_image,
            "docker_network": self.docker_network,
            "rate_limit": self.rate_limit,
            "concurrency": self.concurrency,
            "timeout_seconds": self.timeout_seconds,
            "enabled_tools": self.enabled_tools,
            "permissions": self.permissions,
            "options": self.options,
            "stages": list(STAGE_ORDER),
        }
