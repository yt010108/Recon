"""Stage orchestration with policy and approval enforcement."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .docker_backend import DockerBackend
from .models import AUTOMATIC_STAGES, STAGE_ORDER, tools_for_stage, validate_stage
from .policy import PolicyError, ScopePolicy
from .storage import RunStore, utc_now
from .tools import ToolRunner


class HarnessRunner:
    def __init__(self, project_root: Path, store: RunStore) -> None:
        self.project_root = project_root.resolve()
        self.store = store

    def policy_for_run(self, state: dict[str, Any]) -> ScopePolicy:
        frozen = self.store.run_dir(state["run_id"]) / state["frozen_scope_file"]
        return ScopePolicy.load(frozen)

    def run_stage(
        self,
        run_id: str,
        stage: str,
        *,
        approved: bool = False,
        approved_by: str | None = None,
    ) -> dict[str, Any]:
        normalized = validate_stage(stage)
        state = self.store.load(run_id)
        policy = self.policy_for_run(state)
        policy.validate_stage(normalized, approved=approved)

        stage_state = state["stages"][normalized]
        # A cleanly completed stage is idempotent. A failed or partially failed
        # stage may be invoked again (and active stages still require a fresh
        # approval), which makes tool/config fixes recoverable without discarding
        # the run's audit trail.
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
        tool_runner = ToolRunner(backend, self.store, self.project_root)
        stage_state.update(
            {
                "status": "running",
                "started_at": utc_now(),
                "finished_at": None,
                "approved_by": approved_by if approved else None,
                "error": None,
            }
        )
        state["status"] = "running"
        self.store.save(state)
        self.store.append_event(
            run_id,
            "stage_started",
            {"stage": normalized, "approved_by": stage_state["approved_by"]},
        )

        failures = 0
        enabled = [
            spec for spec in tools_for_stage(normalized) if policy.is_tool_enabled(spec.name)
        ]
        if not enabled:
            stage_state["status"] = "skipped"
            stage_state["finished_at"] = utc_now()
            self.store.append_event(run_id, "stage_skipped", {"stage": normalized})
            self.store.save(state)
            return state

        try:
            for spec in enabled:
                self.store.append_event(run_id, "tool_started", {"tool": spec.name})
                outcome = tool_runner.run(spec.name, policy, state)
                tool_status = "skipped" if outcome.skipped else (
                    "completed" if outcome.exit_code == 0 else "failed"
                )
                if tool_status == "failed":
                    failures += 1
                stage_state["tools"][spec.name] = {
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
                        "tool": spec.name,
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

    def run_automatic(self, run_id: str) -> dict[str, Any]:
        state = self.store.load(run_id)
        for stage in STAGE_ORDER:
            if stage not in AUTOMATIC_STAGES:
                break
            state = self.run_stage(run_id, stage)
        return state
