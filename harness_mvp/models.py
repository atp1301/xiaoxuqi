from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class RunStatus(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStatus(str, Enum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class Target:
    host: str
    port: int = 80
    scheme: str = "http"

    @property
    def address(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


@dataclass
class ProbeResponse:
    path: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    latency_ms: float = 0.0
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    description: str
    endpoint: str
    evidence: str
    remediation: str
    cwe: str = ""
    confidence: float = 0.0
    exploitable: bool = False
    source: str = "demo"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    agent: str
    status: AgentStatus
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)


@dataclass
class Event:
    timestamp: str
    phase: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanStep:
    name: str
    agent: str
    max_attempts: int = 2


@dataclass
class RunState:
    target: Target
    scenario: str = "demo"
    run_id: str = field(default_factory=lambda: uuid4().hex[:12])
    status: RunStatus = RunStatus.PLANNED
    facts: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    exploit_results: list[dict[str, Any]] = field(default_factory=list)
    agent_results: list[AgentResult] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    report_paths: dict[str, str] = field(default_factory=dict)
    checkpoint_path: str = ""

    def add_event(self, phase: str, message: str, **details: Any) -> None:
        self.events.append(Event(utc_now(), phase, message, details))

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)

        def normalize(item: Any) -> Any:
            if isinstance(item, Enum):
                return item.value
            if isinstance(item, dict):
                return {key: normalize(val) for key, val in item.items()}
            if isinstance(item, list):
                return [normalize(val) for val in item]
            return item

        return normalize(value)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunState":
        """Rehydrate a state saved by the checkpoint writer."""
        target_data = payload.get("target") or {}
        target = Target(
            host=str(target_data.get("host", "")),
            port=int(target_data.get("port", 80)),
            scheme=str(target_data.get("scheme", "http")),
        )
        findings = [Finding(**item) for item in payload.get("findings", [])]
        agent_results = [
            AgentResult(
                agent=str(item.get("agent", "")),
                status=AgentStatus(item.get("status", AgentStatus.FAILED.value)),
                summary=str(item.get("summary", "")),
                data=dict(item.get("data") or {}),
                errors=list(item.get("errors") or []),
                observations=list(item.get("observations") or []),
            )
            for item in payload.get("agent_results", [])
        ]
        events = [Event(**item) for item in payload.get("events", [])]
        return cls(
            target=target,
            scenario=str(payload.get("scenario", "demo")),
            run_id=str(payload.get("run_id") or uuid4().hex[:12]),
            status=RunStatus(payload.get("status", RunStatus.PLANNED.value)),
            facts=dict(payload.get("facts") or {}),
            findings=findings,
            exploit_results=list(payload.get("exploit_results") or []),
            agent_results=agent_results,
            events=events,
            errors=list(payload.get("errors") or []),
            report_paths=dict(payload.get("report_paths") or {}),
            checkpoint_path=str(payload.get("checkpoint_path", "")),
        )
