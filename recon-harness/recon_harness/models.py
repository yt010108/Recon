"""Shared stage and tool metadata."""

from __future__ import annotations

from dataclasses import dataclass


STAGE_ORDER = ("collect", "probe", "crawl", "discovery")
AUTOMATIC_STAGES = frozenset({"collect", "probe"})
APPROVAL_STAGES = frozenset({"crawl", "discovery"})


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    stage: str
    description: str
    active: bool


TOOL_SPECS: dict[str, ToolSpec] = {
    "subfinder": ToolSpec(
        "subfinder", "collect", "Passive subdomain candidate collection", False
    ),
    "assetfinder": ToolSpec(
        "assetfinder", "collect", "Passive subdomain candidates from CT logs and archives", False
    ),
    "amass_enum": ToolSpec(
        "amass_enum", "collect", "Passive-only OWASP Amass enumeration (-passive)", False
    ),
    "waybackurls": ToolSpec(
        "waybackurls", "collect", "Historical URL collection", False
    ),
    "httpx": ToolSpec("httpx", "probe", "HTTP service probing", True),
    "robots_txt": ToolSpec(
        "robots_txt", "probe", "robots.txt directives and comments", True
    ),
    "katana": ToolSpec("katana", "crawl", "Live web crawling", True),
    "source_comments": ToolSpec(
        "source_comments", "crawl", "HTML, CSS, and JavaScript comment review", True
    ),
    "gobuster_dir": ToolSpec(
        "gobuster_dir", "discovery", "Web content discovery", True
    ),
    "gobuster_dns": ToolSpec(
        "gobuster_dns", "discovery", "DNS candidate brute force", True
    ),
    "parameth": ToolSpec(
        "parameth", "discovery", "GET/POST parameter discovery", True
    ),
}


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower()
    if normalized not in STAGE_ORDER:
        choices = ", ".join(STAGE_ORDER)
        raise ValueError(f"Unknown stage {stage!r}; expected one of: {choices}")
    return normalized


def tools_for_stage(stage: str) -> list[ToolSpec]:
    normalized = validate_stage(stage)
    return [spec for spec in TOOL_SPECS.values() if spec.stage == normalized]
