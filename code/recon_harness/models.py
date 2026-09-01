"""리콘 단계와 도구의 고정 관계."""

STAGE_ORDER = ("collect", "probe", "crawl", "discovery", "normalize")

STAGE_TOOLS = {
    "collect": ("dorkgen", "subfinder", "assetfinder", "amass_enum", "waybackurls"),
    "probe": ("httpx", "robots_txt"),
    "crawl": ("katana", "source_comments"),
    "discovery": ("url_discovery", "gobuster_dir"),
    "normalize": ("surface",),
}

# Nuclei는 전체 recon에 자동 포함하지 않고 필요할 때만 단독 실행한다.
TOOL_STAGES = {
    tool: stage for stage, tools in STAGE_TOOLS.items() for tool in tools
}
TOOL_STAGES["nuclei"] = "probe"
TOOL_STAGES["parameth"] = "discovery"
INTERNAL_TOOLS = frozenset({"url_discovery"})
TOOL_NAMES = frozenset(TOOL_STAGES) - INTERNAL_TOOLS
LOCAL_TOOLS = frozenset({"dorkgen", "surface"})


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower()
    if normalized not in STAGE_ORDER:
        choices = ", ".join(STAGE_ORDER)
        raise ValueError(f"Unknown stage {stage!r}; expected one of: {choices}")
    return normalized


def tools_for_stage(stage: str) -> tuple[str, ...]:
    return STAGE_TOOLS[validate_stage(stage)]


def stage_for_tool(tool: str) -> str:
    normalized = tool.strip().lower()
    if normalized in TOOL_STAGES:
        return TOOL_STAGES[normalized]
    choices = ", ".join(sorted(TOOL_NAMES))
    raise ValueError(f"Unknown tool {tool!r}; expected one of: {choices}")
