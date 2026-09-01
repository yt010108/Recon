"""일반 Recon 수집 단계와 최종 정규화를 실행한다."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .deep_discovery import DeepDiscoveryToolRunner
from .docker_backend import NUCLEI_IMAGE, DockerBackend
from .models import LOCAL_TOOLS, STAGE_ORDER, stage_for_tool, tools_for_stage, validate_stage
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, utc_now
from .surface import run_local_surface
from .tools import run_local_dorkgen


class HarnessRunner:
    def __init__(self, store: RunStore) -> None:
        self.store = store
        self._io_lock = threading.RLock()

    def _run_remote_tool(self, tool: str, policy: ScopePolicy, state: dict[str, Any]):
        return DeepDiscoveryToolRunner(
            self._backend_for_tool(policy, state["run_id"], tool),
            self.store,
            self._io_lock,
        ).run(tool, policy, state)

    def policy_for_run(self, state: dict[str, Any]) -> ScopePolicy:
        return ScopePolicy.load(self.store.run_dir(state["run_id"]) / "scope.toml")

    def _backend_for_tool(
        self, policy: ScopePolicy, run_id: str, tool: str
    ) -> DockerBackend:
        image = NUCLEI_IMAGE if tool == "nuclei" else policy.worker_image
        backend = DockerBackend(
            image,
            workspace_dir=self.store.run_dir(run_id),
            network=policy.docker_network,
            run_id=run_id,
        )
        backend.require_ready()
        return backend

    def _run_local_tool(
        self, tool: str, policy: ScopePolicy, state: dict[str, Any]
    ):
        if tool == "dorkgen":
            return run_local_dorkgen(policy, state, self.store)
        if tool == "surface":
            return run_local_surface(policy, state, self.store)
        raise ValueError(f"Unknown local tool: {tool}")

    def _run_stage(
        self, run_id: str, stage: str, *, require_previous: bool = True
    ) -> dict[str, Any]:
        normalized = validate_stage(stage)
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)
        policy.validate_stage(normalized)

        stage_state = state["stages"][normalized]
        # 완료 단계는 재실행하지 않는다. 실패 단계만 감사 기록을 보존한 채 재시도한다.
        if stage_state["status"] == "completed":
            return state
        stage_index = STAGE_ORDER.index(normalized)
        if require_previous and stage_index > 0:
            previous = state["stages"][STAGE_ORDER[stage_index - 1]]["status"]
            if previous not in {"completed", "completed_with_errors", "skipped"}:
                raise PolicyError(
                    f"Previous stage {STAGE_ORDER[stage_index - 1]!r} is not complete"
                )

        stage_state.update(
            {
                "status": "running",
                "started_at": utc_now(),
                "finished_at": None,
                "error": None,
            }
        )
        state["status"] = "running"
        self.store.save(state)
        failures = 0
        try:
            pending_tools = [
                tool for tool in tools_for_stage(normalized)
                if stage_state["tools"].get(tool, {}).get("status") != "completed"
            ]
            outcomes = []
            if normalized == "collect" and "dorkgen" in pending_tools:
                outcomes.append(("dorkgen", self._run_local_tool("dorkgen", policy, state)))
                pending_tools.remove("dorkgen")
            if normalized == "collect" and pending_tools:
                with ThreadPoolExecutor(max_workers=len(pending_tools)) as executor:
                    futures = {
                        executor.submit(self._run_remote_tool, tool, policy, state): tool
                        for tool in pending_tools
                    }
                    outcomes.extend((futures[future], future.result()) for future in as_completed(futures))
            else:
                outcomes.extend(
                    (
                        tool,
                        self._run_local_tool(tool, policy, state)
                        if tool in LOCAL_TOOLS
                        else self._run_remote_tool(tool, policy, state),
                    )
                    for tool in pending_tools
                )

            for tool, outcome in outcomes:
                tool_status = "skipped" if outcome.skipped else (
                    "completed" if outcome.exit_code == 0 else "failed"
                )
                if tool_status == "failed":
                    failures += 1
                stage_state["tools"][tool] = {
                    "status": tool_status,
                    "exit_code": outcome.exit_code,
                    "summary": outcome.summary,
                    "item_count": outcome.item_count,
                    "error": outcome.error,
                }
                self.store.save(state)
        except (Exception, KeyboardInterrupt) as exc:
            stage_state["status"] = "failed"
            stage_state["error"] = str(exc)
            stage_state["finished_at"] = utc_now()
            state["status"] = "failed"
            self.store.save(state)
            raise

        stage_state["status"] = "completed_with_errors" if failures else "completed"
        stage_state["finished_at"] = utc_now()
        completed = all(
            state["stages"][stage]["status"]
            in {"completed", "completed_with_errors", "skipped"}
            for stage in STAGE_ORDER
        )
        has_errors = any(
            state["stages"][stage]["status"] == "completed_with_errors"
            for stage in STAGE_ORDER
        )
        state["status"] = (
            "completed_with_errors" if completed and has_errors
            else "completed" if completed
            else "ready"
        )
        self.store.save(state)
        return state

    def run_stage(self, run_id: str, stage: str) -> dict[str, Any]:
        """선택한 단계만 실행한다. 필요한 입력이 없으면 각 도구의 안전한 기본값을 쓴다."""
        return self._run_stage(run_id, stage, require_previous=False)

    def run_tool(self, run_id: str, tool: str) -> dict[str, Any]:
        """선택한 도구 하나만 실행하고 같은 run에 결과를 누적한다."""
        stage = stage_for_tool(tool)
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)

        backend = (
            None
            if tool in LOCAL_TOOLS
            else self._backend_for_tool(policy, run_id, tool)
        )
        stage_state = state["stages"][stage]
        stage_state.update({"status": "running", "started_at": stage_state["started_at"] or utc_now(), "error": None})
        state["status"] = "running"
        self.store.save(state)
        try:
            outcome = (
                self._run_local_tool(tool, policy, state)
                if tool in LOCAL_TOOLS
                else DeepDiscoveryToolRunner(backend, self.store, self._io_lock).run(tool, policy, state)
            )
        except (Exception, KeyboardInterrupt) as exc:
            stage_state.update({"status": "failed", "finished_at": utc_now(), "error": str(exc)})
            state["status"] = "failed"
            self.store.save(state)
            raise

        status = "skipped" if outcome.skipped else ("completed" if outcome.exit_code == 0 else "failed")
        stage_state["tools"][tool] = {
            "status": status,
            "exit_code": outcome.exit_code,
            "summary": outcome.summary,
            "item_count": outcome.item_count,
            "error": outcome.error,
        }
        enabled = list(tools_for_stage(stage))
        recorded = [stage_state["tools"].get(name, {}).get("status") for name in enabled]
        if all(value in {"completed", "skipped"} for value in recorded):
            stage_state["status"] = "completed"
            stage_state["finished_at"] = utc_now()
        elif status == "failed":
            stage_state["status"] = "completed_with_errors"
        else:
            stage_state["status"] = "partial"
        state["status"] = "ready"
        self.store.save(state)
        return state

    def run_all(self, run_id: str) -> dict[str, Any]:
        state = self.store.load(run_id)
        for stage in STAGE_ORDER:
            state = self._run_stage(run_id, stage)
        return state
