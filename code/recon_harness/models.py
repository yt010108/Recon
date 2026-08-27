"""리콘 모드별 단계와 도구의 고정 관계."""

STAGE_ORDER = ("collect", "probe", "crawl", "discovery")
MODES = frozenset({"internet", "competition"})

INTERNET_STAGE_TOOLS = {
    "collect": ("dorkgen", "subfinder", "assetfinder", "amass_enum", "waybackurls"),
    "probe": ("httpx", "robots_txt"),
    "crawl": ("katana", "source_comments"),
    "discovery": ("gobuster_dir", "parameth"),
}

COMPETITION_STAGE_TOOLS = {
    "collect": ("network_discovery",),
    "probe": ("httpx", "robots_txt"),
    "crawl": ("katana", "source_comments"),
    "discovery": ("gobuster_dir", "parameth"),
}

MODE_STAGE_TOOLS = {
    "internet": INTERNET_STAGE_TOOLS,
    "competition": COMPETITION_STAGE_TOOLS,
}

# Nuclei는 전체 recon에 자동 포함하지 않고 필요할 때만 단독 실행한다.
TOOL_STAGES = {
    tool: stage
    for mapping in MODE_STAGE_TOOLS.values()
    for stage, tools in mapping.items()
    for tool in tools
}
TOOL_STAGES["nuclei"] = "probe"
TOOL_NAMES = frozenset(TOOL_STAGES)
LOCAL_TOOLS = frozenset({"dorkgen"})


def validate_mode(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized not in MODES:
        choices = ", ".join(sorted(MODES))
        raise ValueError(f"Unknown mode {mode!r}; expected one of: {choices}")
    return normalized


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower()
    if normalized not in STAGE_ORDER:
        choices = ", ".join(STAGE_ORDER)
        raise ValueError(f"Unknown stage {stage!r}; expected one of: {choices}")
    return normalized


def tools_for_stage(stage: str, mode: str = "internet") -> tuple[str, ...]:
    normalized_stage = validate_stage(stage)
    normalized_mode = validate_mode(mode)
    return MODE_STAGE_TOOLS[normalized_mode][normalized_stage]


def stage_for_tool(tool: str, mode: str = "internet") -> str:
    normalized_tool = tool.strip().lower()
    normalized_mode = validate_mode(mode)
    allowed = set().union(*MODE_STAGE_TOOLS[normalized_mode].values()) | {"nuclei"}
    if normalized_tool in allowed:
        return TOOL_STAGES[normalized_tool]
    choices = ", ".join(sorted(allowed))
    raise ValueError(
        f"Tool {tool!r} is not available in {normalized_mode!r} mode; expected one of: {choices}"
    )
