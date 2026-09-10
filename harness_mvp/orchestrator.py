from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any
from uuid import uuid4

from .agents import make_agents
from .checkpoint import load_checkpoint, write_checkpoint
from .llm import LLMClient
from .models import OPERATOR_GOAL, AgentResult, AgentStatus, PlanStep, RunState, RunStatus
from .policy import PolicyEngine, parse_target
from .report import write_report
from .complex_lab import ComplexWebAdapter
from .tools import DemoLabAdapter, HttpLabAdapter, KnowledgeBase


ProgressCallback = Callable[[RunState, list[dict[str, Any]]], None]

OPERATOR_ROLE = "\u534f\u8c03\u667a\u80fd\u4f53 Operator\uff1a\u63a5\u6536\u5404 Agent \u6c47\u62a5 \u2192 \u7efc\u5408 \u2192 \u5206\u914d\u4efb\u52a1"

_THOUGHTS = {
    "recon": "The goal is an authorized attack-chain assessment. Start with recon of training paths.",
    "code_audit": "Recon recorded endpoints. Scan lab source for regex sinks; demo-level taint only.",
    "env_repro": "Read the lab manifest and emit start/reset/cleanup reproduction steps.",
    "vuln": "Combine recon and code-audit observations, then retrieve CVE/TTP/payload/case knowledge.",
    "exploit": "Validate recorded findings in policy scope. Demo stays simulated; labs use fixed probes.",
    "post_exploit": "Plan lateral movement from the foothold, but only record a simulated hop.",
    "report": "Synthesize agent reports, evidence, and failures into an auditable report.",
}

_RECON_FACT_KEYS = (
    "endpoints",
    "raw_evidence",
    "reachable",
    "sqlite_sqli_validation",
    "sqlite_sqli_validation_error",
    "sqlite_sqli_differential",
    "complex_sqli_validation",
    "complex_sqli_validation_error",
    "complex_sqli_differential",
    "complex_chain",
    "raw_http_evidence",
    "test_evidence",
)


class Orchestrator:
    """Operator coordinator: receive agent reports, synthesize, assign the next task.

    Plan-and-Execute builds a task tree; each specialist step is wrapped in a
    ReAct Thought -> Action -> Observation record. The Operator never calls
    exploit tools itself.
    """

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
            PlanStep("discover attack surface", "recon", "recon", "goal", []),
            PlanStep("static code audit", "code_audit", "code_audit", "goal", ["recon"]),
            PlanStep("reproduce lab environment", "env_repro", "env_repro", "goal", []),
            PlanStep("analyze observations", "vuln", "vuln", "goal", ["recon", "code_audit"]),
            PlanStep("validate in lab", "exploit", "exploit", "goal", ["vuln"]),
            PlanStep("simulate post-exploit movement", "post_exploit", "post_exploit", "goal", ["exploit"]),
            PlanStep("assemble report", "report", "report", "goal", ["exploit", "post_exploit", "env_repro"]),
        ]

    def task_tree(self) -> list[PlanStep]:
        return [OPERATOR_GOAL, *self.plan()]

    @staticmethod
    def _plan_dicts(plan: list[PlanStep]) -> list[dict[str, Any]]:
        return [step.to_dict() for step in plan]

    def build_progress(self, plan: list[PlanStep], statuses: list[dict[str, Any]]) -> dict[str, Any]:
        derived = "pending"
        if any(item.get("status") == "failed" for item in statuses):
            derived = "failed"
        elif any(item.get("status") == "running" for item in statuses):
            derived = "running"
        elif statuses and all(item.get("status") in {"success", "skipped"} for item in statuses):
            derived = "success"
        tree = [
            {
                "step_id": OPERATOR_GOAL.step_id,
                "parent_id": None,
                "name": OPERATOR_GOAL.name,
                "agent": OPERATOR_GOAL.agent,
                "status": derived,
                "depends_on": [],
            }
        ]
        steps: list[dict[str, Any]] = []
        for step, record in zip(plan, statuses):
            node = {
                "step_id": step.step_id or step.agent,
                "parent_id": step.parent_id,
                "name": step.name,
                "agent": step.agent,
                "status": str(record.get("status", "pending")),
                "depends_on": list(step.depends_on),
                "attempts": int(record.get("attempts", 0) or 0),
            }
            tree.append(node)
            steps.append(node)
        completed = sum(1 for item in statuses if item.get("status") in {"success", "skipped"})
        return {
            "steps": steps,
            "tree": tree,
            "completed": completed,
            "total": len(plan),
            "operator": OPERATOR_ROLE,
        }

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
            normalized.append(
                {
                    "agent": step.agent,
                    "name": step.name,
                    "step_id": step.step_id or step.agent,
                    "parent_id": step.parent_id,
                    "depends_on": list(step.depends_on),
                    "status": status,
                    "attempts": attempts,
                }
            )
        return normalized

    @staticmethod
    def _first_incomplete(statuses: list[dict[str, Any]]) -> int | None:
        for index, record in enumerate(statuses):
            if record.get("status") not in {"success", "skipped"}:
                return index
        return None

    def _invalidate_dependent_state(self, state: RunState, first_index: int) -> None:
        remaining = {step.agent for step in self.plan()[first_index:]}
        if "recon" in remaining:
            for key in _RECON_FACT_KEYS:
                state.facts.pop(key, None)
        if "code_audit" in remaining:
            state.facts.pop("code_audit", None)
        if "env_repro" in remaining:
            state.facts.pop("env_repro", None)
        if "vuln" in remaining:
            state.findings = []
            state.facts.pop("llm_advisory", None)
        if "exploit" in remaining:
            state.exploit_results = []
            state.facts.pop("complex_chain", None)
            state.facts.pop("raw_http_evidence", None)
            state.facts.pop("test_evidence", None)
        if "post_exploit" in remaining:
            state.facts.pop("post_exploit", None)
        if "report" in remaining:
            state.report_paths = {}

    def _select_adapter(self, scenario: str) -> None:
        if self._adapter_injected:
            return
        if scenario == "local-web":
            self.adapter = HttpLabAdapter(self.policy)
        elif scenario == "complex-web":
            self.adapter = ComplexWebAdapter(self.policy)
        else:
            self.adapter = DemoLabAdapter(self.policy)
        self.agents = make_agents(self.adapter, self.policy, self.kb, self.llm)

    @staticmethod
    def _notify(
        callback: ProgressCallback | None,
        state: RunState,
        statuses: list[dict[str, Any]],
    ) -> None:
        if callback is not None:
            callback(deepcopy(state), deepcopy(statuses))

    def _think(self, state: RunState, step: PlanStep, attempt: int) -> str:
        prefix = f"{OPERATOR_ROLE} [{step.agent} attempt {attempt}] "
        return prefix + _THOUGHTS.get(step.agent, step.name)

    def _synthesize(self, state: RunState, step: PlanStep, result: AgentResult) -> None:
        names = [item.agent for item in self.plan()]
        try:
            nxt = names[names.index(step.agent) + 1]
        except (ValueError, IndexError):
            nxt = None
        brief = f"{step.agent} -> {result.status.value}: {result.summary}"
        reports = [
            f"{item.agent}:{item.status.value}"
            for item in state.agent_results
            if item.agent in names
        ]
        state.working_memory["operator"] = OPERATOR_ROLE
        state.working_memory["current_goal"] = OPERATOR_GOAL.name
        state.working_memory["current_action"] = step.agent
        state.working_memory["last_report"] = brief
        state.working_memory["next_assignment"] = nxt
        state.working_memory["received_reports"] = reports[-8:]
        state.add_event(
            "operator",
            "received agent report and assigned next task",
            agent=step.agent,
            next_assignment=nxt,
            summary=result.summary,
        )

    def _status_record(self, step: PlanStep, status: str = "pending", attempts: int = 0) -> dict[str, Any]:
        return {
            "agent": step.agent,
            "name": step.name,
            "step_id": step.step_id or step.agent,
            "parent_id": step.parent_id,
            "depends_on": list(step.depends_on),
            "status": status,
            "attempts": attempts,
        }

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
            if scenario not in {"demo", "local-web", "complex-web"}:
                raise ValueError(f"unsupported scenario: {scenario}")
            state = RunState(target=parsed, scenario=scenario, run_id=run_id or uuid4().hex[:12])

        if scenario not in {"demo", "local-web", "complex-web"}:
            raise ValueError(f"unsupported scenario: {scenario}")
        self._select_adapter(scenario)

        plan = self.plan()
        plan_dicts = self._plan_dicts(plan)
        tree_dicts = self._plan_dicts(self.task_tree())
        if payload is not None:
            statuses = self._validate_checkpoint_plan(payload, plan)
            first_incomplete = self._first_incomplete(statuses)
            if first_incomplete is not None:
                self._invalidate_dependent_state(state, first_incomplete)
                for record in statuses[first_incomplete:]:
                    record["status"] = "pending"
                    record["attempts"] = 0
        else:
            first_incomplete = 0
            statuses = [self._status_record(step) for step in plan]
            state.working_memory["agent_mode"] = self.mode if self.llm is None else "llm-advisory"
            state.working_memory["plan"] = plan_dicts
            state.working_memory["task_tree"] = tree_dicts
            state.working_memory["operator"] = OPERATOR_ROLE
            state.working_memory["current_goal"] = OPERATOR_GOAL.name
            state.working_memory["current_action"] = None
            state.add_event("plan", "created bounded agent plan", steps=[step.agent for step in plan])

        state.working_memory["plan"] = plan_dicts
        state.working_memory["task_tree"] = tree_dicts
        state.working_memory["operator"] = OPERATOR_ROLE
        state.working_memory["current_goal"] = OPERATOR_GOAL.name
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
        write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, resume_index, task_tree=tree_dicts)
        self._notify(progress_callback, state, statuses)

        for index, step in enumerate(plan):
            record = statuses[index]
            if payload is not None and record.get("status") in {"success", "skipped"}:
                state.add_event(step.agent, "skipped; restored from checkpoint", checkpoint=str(checkpoint_destination))
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index + 1, task_tree=tree_dicts)
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
                thought = self._think(state, step, attempt)
                action = f"invoke {step.agent}"
                state.working_memory["current_action"] = step.agent
                state.working_memory["current_agent"] = step.agent
                state.add_event("thought", thought, agent=step.agent, attempt=attempt)
                state.add_event("action", action, agent=step.agent, attempt=attempt, tool=step.agent)
                state.add_event(step.agent, "agent started", attempt=attempt)
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index, task_tree=tree_dicts)
                self._notify(progress_callback, state, statuses)
                try:
                    result = agent.run(state)
                except Exception as exc:
                    result = AgentResult(agent.name, AgentStatus.FAILED, f"{agent.name} failed", errors=[str(exc)])
                last_result = result
                state.agent_results.append(result)
                state.add_event(
                    "observation",
                    result.summary,
                    agent=step.agent,
                    status=result.status.value,
                    observations=result.observations,
                )
                state.record_episode(step.agent, thought, action, result.summary, result.status.value, attempt=attempt)
                self._synthesize(state, step, result)
                if result.status != AgentStatus.FAILED:
                    record["status"] = result.status.value
                    state.add_event(step.agent, result.status.value, summary=result.summary)
                    write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index + 1, task_tree=tree_dicts)
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
                write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, index, task_tree=tree_dicts)
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
            write_checkpoint(state, checkpoint_destination, plan_dicts, statuses, next_index, task_tree=tree_dicts)
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
            task_tree=tree_dicts,
        )
        self._notify(progress_callback, state, statuses)
        return state
