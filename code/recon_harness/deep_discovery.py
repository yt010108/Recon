"""URL discovery를 기존 ToolRunner에 연결한다."""

from __future__ import annotations

from typing import Any

from .policy import ScopePolicy
from .tools import ToolOutcome, ToolRunner


class DeepDiscoveryToolRunner(ToolRunner):
    """기본 도구 구현은 상속하고 URL discovery만 추가한다."""

    def run_url_discovery(
        self, policy: ScopePolicy, state: dict[str, Any]
    ) -> ToolOutcome:
        from .discovery import DiscoveryRunner

        return DiscoveryRunner(self, self.store).run(policy, state)
