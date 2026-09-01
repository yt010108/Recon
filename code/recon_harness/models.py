"""대회용 웹 Recon V2의 단계와 도구 관계."""

STAGE_ORDER = ("inventory", "mapping", "normalize", "expansion")
PROFILES = frozenset({"fast", "deep"})

PROFILE_STAGE_TOOLS = {
    "fast": {
        "inventory": ("network_discovery", "httpx"),
        "mapping": ("robots_txt", "katana"),
        "normalize": ("surface",),
        "expansion": (),
    },
    "deep": {
        "inventory": ("network_discovery", "httpx"),
        "mapping": ("robots_txt", "katana", "source_comments"),
        "normalize": ("surface",),
        "expansion": ("gobuster_dir",),
    },
}

TOOL_STAGES = {
    tool: stage
    for mapping in PROFILE_STAGE_TOOLS.values()
    for stage, tools in mapping.items()
    for tool in tools
}
TOOL_STAGES["nuclei"] = "expansion"
TOOL_NAMES = frozenset(TOOL_STAGES)
LOCAL_TOOLS = frozenset({"surface"})


def validate_profile(profile: str) -> str:
    normalized = profile.strip().lower()
    if normalized not in PROFILES:
        choices = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile {profile!r}; expected one of: {choices}")
    return normalized


def validate_stage(stage: str) -> str:
    normalized = stage.strip().lower()
    if normalized not in STAGE_ORDER:
        choices = ", ".join(STAGE_ORDER)
        raise ValueError(f"Unknown stage {stage!r}; expected one of: {choices}")
    return normalized


def tools_for_stage(stage: str, profile: str = "fast") -> tuple[str, ...]:
    return PROFILE_STAGE_TOOLS[validate_profile(profile)][validate_stage(stage)]


def stage_for_tool(tool: str) -> str:
    normalized = tool.strip().lower()
    if normalized in TOOL_STAGES:
        return TOOL_STAGES[normalized]
    choices = ", ".join(sorted(TOOL_NAMES))
    raise ValueError(f"Unknown tool {tool!r}; expected one of: {choices}")
