from __future__ import annotations
import re
from abc import ABC, abstractmethod
from typing import Any

from .models import AgentResult, AgentStatus, Finding, RunState
from .policy import PolicyEngine
from .report import build_report
from .tools import DemoLabAdapter, HttpLabAdapter, KnowledgeBase
from .llm import LLMClient


def _search_result_count(body: str) -> int | None:
    match = re.search(r"search results \((\d+)\)", body.lower())
    return int(match.group(1)) if match else None


def _sqlite_sqli_differential(validation: dict[str, Any]) -> dict[str, Any]:
    """Require baseline, positive, and negative response features together."""
    baseline = validation["baseline"]
    positive = validation["positive"]
    negative = validation["negative"]
    base_body = baseline.body_excerpt.lower()
    pos_body = positive.body_excerpt.lower()
    neg_body = negative.body_excerpt.lower()
    base_count = _search_result_count(base_body)
    pos_count = _search_result_count(pos_body)
    neg_count = _search_result_count(neg_body)
    proof_seen = "course-proof-sqli-v1" in pos_body
    public_seen = "public-training-record" in base_body
    verified = (
        base_count == 1
        and public_seen
        and pos_count is not None
        and pos_count > base_count
        and proof_seen
        and neg_count == 0
    )
    return {
        "verified": verified,
        "baseline_count": base_count,
        "positive_count": pos_count,
        "negative_count": neg_count,
        "proof_seen": proof_seen,
        "public_seen": public_seen,
        "positive_sha256": positive.metadata.get("body_sha256"),
        "negative_sha256": negative.metadata.get("body_sha256"),
        "baseline_sha256": baseline.metadata.get("body_sha256"),
    }


class Agent(ABC):
    name = "agent"

    @abstractmethod
    def run(self, state: RunState) -> AgentResult:
        raise NotImplementedError


class ReconAgent(Agent):
    name = "recon"

    def __init__(self, adapter: DemoLabAdapter | HttpLabAdapter) -> None:
        self.adapter = adapter

    def run(self, state: RunState) -> AgentResult:
        paths = ["/", "/login", "/search", "/admin", "/health"]
        responses = [self.adapter.probe(state.target, path) for path in paths]
        state.facts["endpoints"] = [response.__dict__ for response in responses]
        state.facts["raw_evidence"] = [
            {
                "path": r.path,
                "status_code": r.status_code,
                "body_excerpt": r.body_excerpt,
                "body_sha256": r.metadata.get("body_sha256"),
                "source": r.source,
            }
            for r in responses
        ]
        state.facts["reachable"] = any(response.status_code < 500 for response in responses)
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            f"probed {len(responses)} lab endpoints",
            {"responses": len(responses)},
            observations=[response.path for response in responses],
        )


class VulnAgent(Agent):
    name = "vuln"

    def __init__(
        self,
        kb: KnowledgeBase,
        llm: LLMClient | None = None,
        adapter: DemoLabAdapter | HttpLabAdapter | None = None,
    ) -> None:
        self.kb, self.llm, self.adapter = kb, llm, adapter

    def run(self, state: RunState) -> AgentResult:
        findings: list[Finding] = []
        endpoints = state.facts.get("endpoints", [])
        for endpoint in endpoints:
            path, body = endpoint["path"], endpoint.get("body_excerpt", "").lower()
            if endpoint.get("source") == "http-lab":
                if path == "/search" and isinstance(self.adapter, HttpLabAdapter):
                    try:
                        validation = self.adapter.validate_sqlite_sqli(state.target)
                        differential = _sqlite_sqli_differential(validation)
                        state.facts["sqlite_sqli_validation"] = {
                            key: {
                                "status_code": value.status_code,
                                "body_excerpt": value.body_excerpt,
                                "metadata": value.metadata,
                            }
                            for key, value in validation.items()
                        }
                        state.facts["sqlite_sqli_differential"] = differential
                        if differential["verified"]:
                            related = self.kb.search("SQLite SQL injection /search")
                            findings.append(
                                Finding(
                                    f"F-{len(findings)+1:03d}",
                                    "SQLite SQL injection",
                                    "high",
                                    "Controlled differential in the authorized local training service.",
                                    path,
                                    "Baseline/public, fixed positive, and fixed negative GET probes diverged only in the vulnerable branch.",
                                    "Use parameterized SQLite queries and validate search input.",
                                    "CWE-89",
                                    0.86,
                                    False,
                                    "http-lab",
                                    {
                                        "knowledge_base": [entry.entry_id for entry in related],
                                        "knowledge_matches": [
                                            {
                                                "entry_id": entry.entry_id,
                                                "score": entry.score,
                                                "retrieval": entry.metadata.get("retrieval"),
                                            }
                                            for entry in related
                                        ],
                                        "evidence_sha256": [
                                            differential["baseline_sha256"],
                                            differential["positive_sha256"],
                                            differential["negative_sha256"],
                                        ],
                                        "differential": differential,
                                    },
                                )
                            )
                    except Exception as exc:
                        state.facts["sqlite_sqli_validation_error"] = str(exc)
                continue
            # Demo mode retains its deterministic teaching indicators.
            if path == "/login" and "sql syntax" in body:
                title, cwe, severity, evidence, remediation = (
                    "SQL injection indicator",
                    "CWE-89",
                    "high",
                    "DemoLabAdapter returned a SQL syntax marker",
                    "Use parameterized queries and generic error responses.",
                )
            elif path == "/search" and "without output encoding" in body:
                title, cwe, severity, evidence, remediation = (
                    "Reflected XSS indicator",
                    "CWE-79",
                    "medium",
                    "DemoLabAdapter reported reflected input without output encoding",
                    "Context-encode reflected output and deploy a restrictive CSP.",
                )
            elif path == "/admin" and "authorization_required=false" in body:
                title, cwe, severity, evidence, remediation = (
                    "Missing authorization",
                    "CWE-862",
                    "critical",
                    "DemoLabAdapter exposed an admin route without authorization",
                    "Require authentication and enforce server-side authorization on the route.",
                )
            else:
                continue
            related = self.kb.search(f"{title} {path}")
            findings.append(
                Finding(
                    f"F-{len(findings)+1:03d}",
                    title,
                    severity,
                    f"The lab response indicates a {title.lower()} condition.",
                    path,
                    evidence,
                    remediation,
                    cwe,
                    0.65,
                    False,
                    "demo-simulated",
                    {
                        "knowledge_base": [entry.entry_id for entry in related],
                        "knowledge_matches": [
                            {
                                "entry_id": entry.entry_id,
                                "score": entry.score,
                                "retrieval": entry.metadata.get("retrieval"),
                            }
                            for entry in related
                        ],
                        "evidence_type": "fixed marker",
                    },
                )
            )
        state.findings = findings
        data: dict[str, Any] = {"finding_ids": [finding.finding_id for finding in findings]}
        observations = [finding.title for finding in findings]
        if self.llm is not None:
            try:
                advisory = self.llm.advisory(state.target.address, endpoints)
                state.facts["llm_advisory"] = advisory
                data["llm_advisory"] = advisory
                observations.append("model advisory recorded")
            except Exception:
                if self.llm.config.provider == "auto-fallback":
                    observations.append("model advisory unavailable; deterministic evidence retained")
                else:
                    raise
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            f"identified {len(findings)} findings",
            data,
            observations=observations,
        )


class ExploitAgent(Agent):
    name = "exploit"

    def __init__(self, policy: PolicyEngine) -> None:
        self.policy, self.adapter = policy, None

    def run(self, state: RunState) -> AgentResult:
        if not state.findings:
            return AgentResult(self.name, AgentStatus.SKIPPED, "no findings to validate")
        if state.scenario == "local-web" and any(
            finding.source == "http-lab" and finding.cwe == "CWE-89" for finding in state.findings
        ):
            self.policy.require_action("exploit_validate_sqlite", state.target)
            if not isinstance(self.adapter, HttpLabAdapter):
                return AgentResult(
                    self.name,
                    AgentStatus.FAILED,
                    "local SQLi adapter unavailable",
                    errors=["HttpLabAdapter required"],
                )
            try:
                validation = self.adapter.validate_sqlite_sqli(state.target)
                differential = _sqlite_sqli_differential(validation)
                status = "verified" if differential["verified"] else "failed"
                for finding in state.findings:
                    if finding.cwe == "CWE-89":
                        finding.exploitable = differential["verified"]
                        finding.confidence = 0.98 if differential["verified"] else 0.35
                        finding.metadata["validation"] = {
                            "status": status,
                            **differential,
                        }
                state.exploit_results = [
                    {
                        "finding_id": finding.finding_id,
                        "status": status if finding.cwe == "CWE-89" else "simulated",
                        "message": "Fixed baseline/positive/negative GET probes; no arbitrary payload accepted.",
                    }
                    for finding in state.findings
                ]
                # Completed validation is an agent success; the probe outcome stays in data.status.
                return AgentResult(
                    self.name,
                    AgentStatus.SUCCESS,
                    f"validated {status} for local SQLi",
                    {"validated": 1, "status": status, "differential": differential},
                )
            except Exception as exc:
                state.exploit_results = [
                    {
                        "finding_id": finding.finding_id,
                        "status": "failed",
                        "message": f"local SQLi validation raised: {exc}",
                    }
                    for finding in state.findings
                ]
                return AgentResult(
                    self.name,
                    AgentStatus.FAILED,
                    "local SQLi validation failed",
                    {"validated": 0, "status": "failed"},
                    errors=[str(exc)],
                )
        self.policy.require_action("exploit_simulate", state.target)
        state.exploit_results = [
            {
                "finding_id": finding.finding_id,
                "status": "simulated",
                "message": "Proof-of-concept was simulated; no payload was sent.",
            }
            for finding in state.findings
        ]
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            f"simulated validation for {len(state.findings)} findings",
            {"validated": len(state.findings)},
        )


class ReportAgent(Agent):
    name = "report"

    def run(self, state: RunState) -> AgentResult:
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            "assembled auditable report",
            {"finding_count": build_report(state)["summary"]["finding_count"]},
        )


def make_agents(
    adapter: DemoLabAdapter | HttpLabAdapter,
    policy: PolicyEngine,
    kb: KnowledgeBase,
    llm: LLMClient | None = None,
) -> dict[str, Agent]:
    exploit = ExploitAgent(policy)
    exploit.adapter = adapter
    return {
        "recon": ReconAgent(adapter),
        "vuln": VulnAgent(kb, llm, adapter),
        "exploit": exploit,
        "report": ReportAgent(),
    }
