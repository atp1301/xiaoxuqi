from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

from .agents import make_agents
from .checkpoint import load_checkpoint, write_checkpoint
from .llm import LLMClient
from .models import AgentResult, AgentStatus, PlanStep, RunState, RunStatus
from .policy import PolicyEngine, parse_target
from .report import write_report
from .tools import DemoLabAdapter, HttpLabAdapter, KnowledgeBase


ProgressCallback = Callable[[RunState, list[dict[str, Any]]], None]


class Orchestrator:
    """Plan, execute, persist and resume a bounded agent run."""

    def __init__(
        self,
        policy: PolicyEngine | None = None,
        adapter: DemoLabAdapter | HttpLabAdapter | Any | None = None,
        kb: KnowledgeBase | None = None,
        mode: str = "auto",
        llm: LLMClient | None = None,
    ) -> None:
        self.policy = policy or PolicyEngine()
        self._adapter_injected = adapter is not None
        self.adapter = adapter or DemoLabAdapter(self.policy)
        self.kb = kb or KnowledgeBase()
        if mode not in {"auto", "deterministic", "llm"}:
            raise ValueError("mode must be auto, deterministic or llm")
        self.mode = mode
        candidate = llm or LLMClient()
        if mode == "llm" and not candidate.config.configured:
            raise ValueError("LLM mode requires HARNESS_LLM_API_KEY")
        self.llm = candidate if mode == "llm" else None
        if mode == "auto" and candidate.config.configured:
            candidate.config = type(candidate.config)(
                api_key=candidate.config.api_key,
                base_url=candidate.config.base_url,
                model=candidate.config.model,
                provider="auto-fallback",
            )
            self.llm = candidate
        self.agents = make_agents(self.adapter, self.policy, self.kb, self.llm)

    def plan(self) -> list[PlanStep]:
        return [
            PlanStep("discover attack surface", "recon"),
            PlanStep("analyze observations", "vuln"),
            PlanStep("validate in lab", "exploit"),
            PlanStep("assemble report", "report"),
        ]

    @staticmethod
    def _plan_dicts(plan: list[PlanStep]) -> list[dict[str, Any]]:
        return [step.__dict__.copy() for step in plan]

    @staticmethod
    def _validate_checkpoint_plan(
        payload: dict[str, Any], plan: list[PlanStep]
    ) -> list[dict[str, Any]]:
        expected = Orchestrator._plan_dicts(plan)
        if payload.get("plan") != expected:
            raise ValueError("checkpoint plan does not match current plan")
        next_step_index = payload.get("next_step_index")
        if not isinstance(next_step_index, int) or not (0 <= next_step_index <= len(plan)):
            raise ValueError("checkpoint next_step_index is invalid")
        statuses = payload.get("step_statuses")
        if not isinstance(statuses, list) or len(statuses) != len(plan):
            raise ValueError("checkpoint step status list does not match current plan")
        allowed = {"pending", "running", "success", "skipped", "failed"}
        normalized: list[dict[str, Any]] = []
        for step, record in zip(plan, statuses):
            if not isinstance(record, dict) or record.get("agent") != step.agent:
                raise ValueError("checkpoint step identity does not match current plan")
            status = record.get("status", "pending")
            if status not in allowed:
                raise ValueError(f"unsupported checkpoint step status: {status}")
            try:
                attempts = int(record.get("attempts", 0))
            except (TypeError, ValueError) as exc:
                raise ValueError("checkpoint attempts must be an integer") from exc
            if attempts < 0:
                raise ValueError("checkpoint attempts cannot be negative")
            normalized.append({"agent": step.agent, "status": status, "attempts": attempts})
        return normalized

    @staticmethod
    def _first_incomplete(statuses: list[dict[str, Any]]) -> int | None:
        for index, record in enumerate(statuses):
            if record.get("status") not in {"success", "skipped"}:
                return index
        return None

    @staticmethod
    def _invalidate_dependent_state(state: RunState, first_index: int) -> None:
        if first_index <= 0:
            for key in (
                "endpoints",
                "raw_evidence",
                "reachable",
                "sqlite_sqli_validation",
                "sqlite_sqli_validation_error",
            ):
                state.facts.pop(key, None)
        if first_index <= 1:
            state.findings = []
        if first_index <= 2:
            state.exploit_results = []
        if first_index <= 3:
            state.report_paths = {}

    def _select_adapter(self, scenario: str) -> None:
        if self._adapter_injected:
            return
        self.adapter = HttpLabAdapter(self.policy) if scenario == "local-web" else DemoLabAdapter(self.policy)
        self.agents = make_agents(self.adapter, self.policy, self.kb, self.llm)

    @staticmethod
    def _notify(
        callback: ProgressCallback | None,
        state: RunState,
        statuses: list[dict[str, Any]],
    ) -> None:
        if callback is not None:
            callback(deepcopy(state), deepcopy(statuses))

    def run(
        self,
        target: str = "demo.local",
        scenario: str = "demo",
        output_dir: str | Path = "out",
        resume_from: str | Path | None = None,
        checkpoint_path: str | Path | None = None,
        progress_callback: ProgressCallback | None = None,
        run_id: str | None = None,
    ) -> RunState:
        if resume_from and checkpoint_path:
            if Path(resume_from).resolve() != Path(checkpoint_path).resolve():
                raise ValueError("resume_from and checkpoint_path refer to different files")

        # resume_from explicitly reads a checkpoint. For compatibility, an
        # existing checkpoint_path is also treated as a read source; a missing
        # checkpoint_path is used as the write destination.
        resume_path: Path | None = Path(resume_from).expanduser().resolve() if resume_from else None
        if resume_path is None and checkpoint_path and Path(checkpoint_path).is_file():
            resume_path = Path(checkpoint_path).expanduser().resolve()
        payload = load_checkpoint(resume_path) if resume_path else None

        if payload is not None:
            state = RunState.from_dict(payload["state"])
            if not state.run_id:
                raise ValueError("checkpoint state has no run_id")
            parsed = self.policy.require_target(state.target)
            scenario = state.scenario
        else:
            parsed = self.policy.require_target(parse_target(target))
            if scenario not in {"demo", "local-web"}:
                raise ValueError(f"unsupported scenario: {scenario}")
            state = RunState(target=parsed, scenario=scenario, run_id=run_id or uuid4().hex[:12])

        if scenario not in {"demo", "local-web"}:
            raise ValueError(f"unsupported scenario: {scenario}")
        self._select_adapter(scenario)

        plan = self.plan()
        plan_dicts = self._plan_dicts(plan)
        if payload is not None:
            statuses = self._validate_checkpoint_plan(payload, plan)
            first_incomplete = self._first_incomplete(statuses)
            if first_incomplete is not None:
                self._invalidate_dependent_state(state, first_incomplete)
                # A resume gets a fresh bounded budget for the first failed
                # step and all dependent steps. Historical attempts remain in
                # state.agent_results, errors and events.
                for record in statuses[first_incomplete:]:
                    record["status"] = "pending"
                    record["attempts"] = 0
        else:
            first_incomplete = 0
            statuses = [
                {"agent": step.agent, "status": "pending", "attempts": 0}
                for step in plan
            ]
            state.facts["agent_mode"] = self.mode if self.llm is None else "llm-advisory"
            state.facts["plan"] = plan_dicts
            state.add_event("plan", "created bounded agent plan", steps=[step.agent for step in plan])

        state.facts["plan"] = plan_dicts
        checkpoint_destination = (
            Path(resume_path).resolve()
            if resume_path
            else Path(checkpoint_path).expanduser().resolve()
            if checkpoint_path
            else Path(output_dir).expanduser().resolve() / ".checkpoints" / f"{state.run_id}.json"
        )
        state.checkpoint_path = str(checkpoint_destination)
        state.status = RunStatus.RUNNING
        resume_index = len(plan) if first_incomplete is None else first_incomplete
        write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, resume_index)
        self._notify(progress_callback, state, statuses)

        for index, step in enumerate(plan):
            record = statuses[index]
            if payload is not None and record.get("status") in {"success", "skipped"}:
                state.add_event(step.agent, "skipped; restored from checkpoint", checkpoint=str(checkpoint_destination))
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index + 1)
                self._notify(progress_callback, state, statuses)
                continue

            agent = self.agents[step.agent]
            first_attempt = int(record.get("attempts", 0)) + 1
            if first_attempt > step.max_attempts:
                first_attempt = 1
                record["attempts"] = 0
            last_result: AgentResult | None = None

            for attempt in range(first_attempt, step.max_attempts + 1):
                record["status"] = "running"
                record["attempts"] = attempt
                state.add_event(step.agent, "agent started", attempt=attempt)
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index)
                self._notify(progress_callback, state, statuses)
                try:
                    result = agent.run(state)
                except Exception as exc:
                    result = AgentResult(agent.name, AgentStatus.FAILED, f"{agent.name} failed", errors=[str(exc)])
                last_result = result
                state.agent_results.append(result)
                if result.status != AgentStatus.FAILED:
                    record["status"] = result.status.value
                    state.add_event(step.agent, result.status.value, summary=result.summary)
                    write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index + 1)
                    self._notify(progress_callback, state, statuses)
                    break

                state.errors.extend(result.errors)
                record["status"] = "failed"
                state.add_event(
                    step.agent,
                    "agent failed; retrying" if attempt < step.max_attempts else "agent failed; retry limit reached",
                    errors=result.errors,
                )
                state.add_event(step.agent, result.status.value, summary=result.summary)
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index)
                self._notify(progress_callback, state, statuses)

            if last_result is None:
                last_result = AgentResult(
                    step.agent,
                    AgentStatus.FAILED,
                    f"{step.agent} has no executable attempt",
                    errors=["checkpoint did not contain a runnable attempt"],
                )
                state.agent_results.append(last_result)
                state.errors.extend(last_result.errors)
                record["status"] = "failed"
                state.add_event(step.agent, "retry limit reached; step remains failed")

            if last_result.status == AgentStatus.FAILED and step.agent == "recon":
                state.facts["endpoints"] = []
                state.add_event("react", "recon failed; continued with empty attack surface")
            if last_result.status == AgentStatus.FAILED and step.agent in {"vuln", "exploit"}:
                state.add_event(step.agent, f"{step.agent} failed; report will include the failure")
            next_index = index + 1 if last_result.status != AgentStatus.FAILED else index
            write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, next_index)
            self._notify(progress_callback, state, statuses)

        latest_results: dict[str, AgentResult] = {}
        for result in state.agent_results:
            latest_results[result.agent] = result
        state.status = (
            RunStatus.COMPLETED
            if not any(result.status == AgentStatus.FAILED for result in latest_results.values())
            else RunStatus.FAILED
        )
        try:
            state.report_paths = write_report(state, output_dir)
        except Exception as exc:
            state.status = RunStatus.FAILED
            state.errors.append(f"report write failed: {exc}")
            state.add_event("report", "report write failed", error=str(exc))
        remaining_index = self._first_incomplete(statuses)
        write_checkpoint(
            state,
            checkpoint_destination,
            plan_dicts,
            statuses,
            len(plan) if remaining_index is None else remaining_index,
        )
        self._notify(progress_callback, state, statuses)
        return state
