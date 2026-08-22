"""리콘 단계, 권한, 도구의 고정 관계."""

STAGE_ORDER = ("collect", "probe", "crawl", "discovery")

# 단계별 정책 키와 도구를 한곳에 둬 실행기와 CLI의 판단이 어긋나지 않게 한다.
STAGE_PERMISSIONS = {
    "collect": "allow_passive_collection",
    "probe": "allow_http_probing",
    "crawl": "allow_crawling",
    "discovery": "allow_dos_tools",
}

STAGE_TOOLS = {
    "collect": ("subfinder", "assetfinder", "amass_enum", "waybackurls"),
    "probe": ("httpx", "robots_txt"),
    "crawl": ("katana", "source_comments"),
    "discovery": ("gobuster_dir", "parameth"),
}

TOOL_NAMES = frozenset(tool for tools in STAGE_TOOLS.values() for tool in tools)


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower()
    if normalized not in STAGE_ORDER:
        choices = ", ".join(STAGE_ORDER)
        raise ValueError(f"Unknown stage {stage!r}; expected one of: {choices}")
    return normalized


def tools_for_stage(stage: str) -> tuple[str, ...]:
    return STAGE_TOOLS[validate_stage(stage)]
