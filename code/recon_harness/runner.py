"""대회용 웹 Recon V2의 단계와 상태를 실행한다."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .competition_tools import CompetitionToolRunner
from .docker_backend import NUCLEI_IMAGE, DockerBackend
from .models import LOCAL_TOOLS, STAGE_ORDER, stage_for_tool, tools_for_stage, validate_stage
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, utc_now
from .surface import run_local_surface


TERMINAL_STAGE_STATES = {"success", "partial", "no_signal", "skipped"}


class HarnessRunner:
    def __init__(self, store: RunStore) -> None:
        self.store = store

    def policy_for_run(self, state: dict[str, Any]) -> ScopePolicy:
        return ScopePolicy.load(self.store.run_dir(state["run_id"]) / "scope.toml")

    def _backend_for_tool(self, policy: ScopePolicy, run_id: str, tool: str) -> DockerBackend:
        image = NUCLEI_IMAGE if tool == "nuclei" else policy.worker_image
        backend = DockerBackend(
            image,
            workspace_dir=self.store.run_dir(run_id),
            network=policy.docker_network,
            run_id=run_id,
        )
        backend.require_ready()
        return backend

    def _run_tool_adapter(
        self,
        policy: ScopePolicy,
        state: dict[str, Any],
        tool: str,
    ):
        if tool in LOCAL_TOOLS:
            return run_local_surface(state, self.store)
        backend = self._backend_for_tool(policy, state["run_id"], tool)
        return CompetitionToolRunner(backend, self.store).run(tool, policy, state)

    @staticmethod
    def _budget_exhausted(state: dict[str, Any], policy: ScopePolicy) -> bool:
        started_at = state.get("budget_started_at")
        if not started_at:
            return False
        try:
            started = datetime.fromisoformat(str(started_at))
            elapsed = (datetime.fromisoformat(utc_now()) - started).total_seconds()
        except (TypeError, ValueError):
            return False
        return elapsed >= policy.budget_minutes * 60

    @staticmethod
    def _stage_result(stage_state: dict[str, Any]) -> str:
        statuses = [
            item.get("status")
            for item in stage_state.get("tools", {}).values()
            if isinstance(item, dict)
        ]
        if any(status == "failed" for status in statuses):
            return "partial"
        if any(status == "success" for status in statuses):
            return "success"
        if statuses and all(status == "skipped" for status in statuses):
            return "skipped"
        return "no_signal"

    def _set_run_status(self, state: dict[str, Any]) -> None:
        statuses = [state["stages"][name]["status"] for name in STAGE_ORDER]
        if not all(status in TERMINAL_STAGE_STATES for status in statuses):
            state["status"] = "partial"
            return
        if any(status == "partial" for status in statuses):
            state["status"] = "partial"
            return
        profile = state.get("scope", {}).get("profile", "fast")
        if any(
            state["stages"][name]["status"] == "skipped"
            and tools_for_stage(name, profile)
            for name in STAGE_ORDER
        ):
            state["status"] = "partial"
            return
        origins_path = self.store.run_dir(state["run_id"]) / "normalized" / "origins.json"
        try:
            origins = json.loads(origins_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            origins = []
        state["status"] = "success" if origins else "no_signal"

    def _run_stage(
        self,
        run_id: str,
        stage: str,
        *,
        require_previous: bool = True,
    ) -> dict[str, Any]:
        normalized = validate_stage(stage)
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)
        stage_state = state["stages"][normalized]
        if stage_state["status"] in {"success", "no_signal", "skipped"}:
            return state

        stage_index = STAGE_ORDER.index(normalized)
        if require_previous and stage_index > 0:
            previous_name = STAGE_ORDER[stage_index - 1]
            previous = state["stages"][previous_name]["status"]
            if previous not in TERMINAL_STAGE_STATES:
                raise PolicyError(f"Previous stage {previous_name!r} is not complete")

        stage_state.update(
            {
                "status": "running",
                "started_at": stage_state.get("started_at") or utc_now(),
                "finished_at": None,
                "error": None,
            }
        )
        state["budget_started_at"] = state.get("budget_started_at") or utc_now()
        state["status"] = "running"
        self.store.save(state)
        tools = tools_for_stage(normalized, policy.profile)
        if not tools:
            stage_state.update({"status": "skipped", "finished_at": utc_now()})
            self._set_run_status(state)
            self.store.save(state)
            return state

        try:
            for tool in tools:
                existing = stage_state["tools"].get(tool, {})
                if existing.get("status") in {"success", "no_signal", "skipped"}:
                    continue
                if self._budget_exhausted(state, policy):
                    stage_state["tools"][tool] = {
                        "status": "skipped",
                        "exit_code": None,
                        "summary": "Skipped because the run time budget was exhausted",
                        "item_count": 0,
                        "error": "",
                    }
                    continue
                outcome = self._run_tool_adapter(policy, state, tool)
                status = (
                    "skipped" if outcome.skipped else
                    "failed" if outcome.exit_code != 0 else
                    "no_signal" if outcome.item_count == 0 else
                    "success"
                )
                stage_state["tools"][tool] = {
                    "status": status,
                    "exit_code": outcome.exit_code,
                    "summary": outcome.summary,
                    "item_count": outcome.item_count,
                    "error": outcome.error,
                }
                self.store.save(state)
        except (Exception, KeyboardInterrupt) as exc:
            stage_state.update(
                {"status": "failed", "error": str(exc), "finished_at": utc_now()}
            )
            state["status"] = "failed"
            self.store.save(state)
            raise

        stage_state["status"] = self._stage_result(stage_state)
        stage_state["finished_at"] = utc_now()
        self._set_run_status(state)
        self.store.save(state)
        return state

    def run_stage(self, run_id: str, stage: str) -> dict[str, Any]:
        return self._run_stage(run_id, stage, require_previous=True)

    def run_tool(self, run_id: str, tool: str) -> dict[str, Any]:
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)
        stage = stage_for_tool(tool)
        stage_state = state["stages"][stage]
        previous_stage_status = stage_state.get("status", "pending")
        stage_state.update(
            {
                "status": "running",
                "started_at": stage_state.get("started_at") or utc_now(),
                "error": None,
            }
        )
        state["budget_started_at"] = state.get("budget_started_at") or utc_now()
        state["status"] = "running"
        self.store.save(state)
        try:
            outcome = self._run_tool_adapter(policy, state, tool)
        except (Exception, KeyboardInterrupt) as exc:
            stage_state.update(
                {"status": "failed", "finished_at": utc_now(), "error": str(exc)}
            )
            state["status"] = "failed"
            self.store.save(state)
            raise

        status = (
            "skipped" if outcome.skipped else
            "failed" if outcome.exit_code != 0 else
            "no_signal" if outcome.item_count == 0 else
            "success"
        )
        stage_state["tools"][tool] = {
            "status": status,
            "exit_code": outcome.exit_code,
            "summary": outcome.summary,
            "item_count": outcome.item_count,
            "error": outcome.error,
        }
        required_tools = tools_for_stage(stage, policy.profile)
        if tool not in required_tools:
            stage_state["status"] = (
                previous_stage_status
                if previous_stage_status in TERMINAL_STAGE_STATES
                else "partial"
            )
        elif all(name in stage_state["tools"] for name in required_tools):
            stage_state["status"] = self._stage_result(stage_state)
        else:
            stage_state["status"] = "partial"
        stage_state["finished_at"] = utc_now()
        self._set_run_status(state)
        self.store.save(state)
        return state

    def run_all(self, run_id: str) -> dict[str, Any]:
        state = self.store.load(run_id)
        for stage in STAGE_ORDER:
            state = self._run_stage(run_id, stage)
        self._set_run_status(state)
        self.store.save(state)
        return state
