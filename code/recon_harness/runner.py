"""정책과 승인을 적용해 네 단계만 순서대로 실행한다."""

from __future__ import annotations

from typing import Any

from .docker_backend import DockerBackend
from .models import STAGE_ORDER, STAGE_PERMISSIONS, tools_for_stage, validate_stage
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, utc_now
from .tools import ToolRunner


class HarnessRunner:
    def __init__(self, store: RunStore) -> None:
        self.store = store

    def policy_for_run(self, state: dict[str, Any]) -> ScopePolicy:
        return ScopePolicy.load(self.store.run_dir(state["run_id"]) / "scope.toml")

    def _run_stage(self, run_id: str, stage: str) -> dict[str, Any]:
        normalized = validate_stage(stage)
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)
        policy.validate_stage(normalized)

        stage_state = state["stages"][normalized]
        # 완료 단계는 재실행하지 않는다. 실패 단계만 감사 기록을 보존한 채 재시도한다.
        if stage_state["status"] == "completed":
            return state
        stage_index = STAGE_ORDER.index(normalized)
        if stage_index > 0:
            previous = state["stages"][STAGE_ORDER[stage_index - 1]]["status"]
            if previous not in {"completed", "completed_with_errors", "skipped"}:
                raise PolicyError(
                    f"Previous stage {STAGE_ORDER[stage_index - 1]!r} is not complete"
                )

        backend = DockerBackend(
            policy.worker_image,
            workspace_dir=self.store.run_dir(run_id),
            network=policy.docker_network,
            run_id=run_id,
        )
        backend.require_ready()
        tool_runner = ToolRunner(backend, self.store)
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
        self.store.append_event(
            run_id,
            "stage_started",
            {"stage": normalized},
        )

        failures = 0
        enabled = [tool for tool in tools_for_stage(normalized) if policy.is_tool_enabled(tool)]
        if not enabled:
            stage_state["status"] = "skipped"
            stage_state["finished_at"] = utc_now()
            self.store.append_event(run_id, "stage_skipped", {"stage": normalized})
            self.store.save(state)
            return state

        try:
            for tool in enabled:
                self.store.append_event(run_id, "tool_started", {"tool": tool})
                outcome = tool_runner.run(tool, policy, state)
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
                self.store.append_event(
                    run_id,
                    "tool_finished",
                    {
                        "tool": tool,
                        "status": tool_status,
                        "exit_code": outcome.exit_code,
                        "item_count": outcome.item_count,
                    },
                )
                self.store.save(state)
        except (Exception, KeyboardInterrupt) as exc:
            stage_state["status"] = "failed"
            stage_state["error"] = str(exc)
            stage_state["finished_at"] = utc_now()
            state["status"] = "failed"
            self.store.append_event(
                run_id, "stage_failed", {"stage": normalized, "error": str(exc)}
            )
            self.store.save(state)
            raise

        stage_state["status"] = "completed_with_errors" if failures else "completed"
        stage_state["finished_at"] = utc_now()
        completed = all(
            state["stages"][stage]["status"]
            in {"completed", "completed_with_errors", "skipped"}
            for stage in STAGE_ORDER
        )
        state["status"] = "completed" if completed else "ready"
        self.store.append_event(
            run_id,
            "stage_finished",
            {"stage": normalized, "status": stage_state["status"]},
        )
        self.store.save(state)
        return state

    def run_all(self, run_id: str) -> dict[str, Any]:
        state = self.store.load(run_id)
        for stage in STAGE_ORDER:
            policy = self.policy_for_run(state)
            if not policy.permissions.get(STAGE_PERMISSIONS[stage], False):
                item = state["stages"][stage]
                item["status"] = "skipped"
                item["finished_at"] = utc_now()
                self.store.append_event(run_id, "stage_skipped", {"stage": stage})
                self.store.save(state)
                continue
            state = self._run_stage(run_id, stage)
        if all(
            item["status"] in {"completed", "completed_with_errors", "skipped"}
            for item in state["stages"].values()
        ):
            state["status"] = "completed"
            self.store.save(state)
        return state
