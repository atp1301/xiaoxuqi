from __future__ import annotations
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
import json

from .models import AgentResult, AgentStatus, Finding, RunState
from .policy import PolicyEngine
from .report import build_report
from .complex_lab import ComplexWebAdapter, sqli_differential as _complex_sqli_differential
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

    def __init__(self, adapter: DemoLabAdapter | HttpLabAdapter | ComplexWebAdapter) -> None:
        self.adapter = adapter

    def run(self, state: RunState) -> AgentResult:
        paths = list(getattr(self.adapter, "recon_paths", ("/", "/login", "/search", "/admin", "/health")))
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
        adapter: DemoLabAdapter | HttpLabAdapter | ComplexWebAdapter | None = None,
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
            if endpoint.get("source") == "complex-web":
                if path == "/search" and isinstance(self.adapter, ComplexWebAdapter):
                    try:
                        validation = self.adapter.validate_sqli(state.target)
                        differential = _complex_sqli_differential(validation)
                        state.facts["complex_sqli_validation"] = {
                            key: {
                                "status_code": value.status_code,
                                "body_excerpt": value.body_excerpt,
                                "metadata": value.metadata,
                            }
                            for key, value in validation.items()
                        }
                        state.facts["complex_sqli_differential"] = differential
                        if differential["verified"]:
                            related = self.kb.search("SQLite SQL injection credential disclosure")
                            findings.append(
                                Finding(
                                    f"F-{len(findings)+1:03d}",
                                    "SQLite SQL injection with session disclosure",
                                    "high",
                                    "Controlled differential in the authorized multi-node complex-web lab leaked an internal session token.",
                                    path,
                                    "Baseline/public, fixed positive, and fixed negative GET probes diverged; the positive branch disclosed operator:lab-session-v1.",
                                    "Use parameterized SQLite queries, hide non-public rows, and keep internal-admin off the public edge.",
                                    "CWE-89",
                                    0.9,
                                    False,
                                    "complex-web",
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
                        state.facts["complex_sqli_validation_error"] = str(exc)
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
        if state.scenario == "complex-web" and any(
            finding.source == "complex-web" and finding.cwe == "CWE-89" for finding in state.findings
        ):
            self.policy.require_action("exploit_validate_complex", state.target)
            if not isinstance(self.adapter, ComplexWebAdapter):
                return AgentResult(
                    self.name,
                    AgentStatus.FAILED,
                    "complex-web adapter unavailable",
                    errors=["ComplexWebAdapter required"],
                )
            try:
                chain = self.adapter.validate_chain(state.target)
                status = chain["status"]
                state.facts["complex_chain"] = chain
                state.facts["raw_http_evidence"] = chain.get("raw_http", [])
                state.facts["test_evidence"] = {
                    "chain": ["discover", "verify", "constrained-shell-identity", "read-flag"],
                    "classification": "local-real-complex-web",
                    "shell_obtained": chain.get("shell_obtained"),
                    "shell_identity": chain.get("shell_identity"),
                    "flag": chain.get("flag"),
                    "flag_match": chain.get("flag_match"),
                    "flag_sha256": chain.get("flag_sha256"),
                    "session_token_seen": chain.get("session_token_seen"),
                }
                for finding in state.findings:
                    if finding.cwe == "CWE-89":
                        finding.exploitable = bool(chain.get("verified"))
                        finding.confidence = 0.99 if chain.get("verified") else 0.35
                        finding.metadata["validation"] = {
                            "status": status,
                            "shell_obtained": chain.get("shell_obtained"),
                            "flag_match": chain.get("flag_match"),
                            **chain.get("differential", {}),
                        }
                state.exploit_results = [
                    {
                        "finding_id": finding.finding_id,
                        "status": status if finding.cwe == "CWE-89" else "simulated",
                        "message": "Fixed GET probes only: SQLi differential, constrained id identity, and ground-truth flag read.",
                        "shell_obtained": chain.get("shell_obtained"),
                        "flag_match": chain.get("flag_match"),
                    }
                    for finding in state.findings
                ]
                return AgentResult(
                    self.name,
                    AgentStatus.SUCCESS,
                    f"validated {status} for complex-web chain",
                    {
                        "validated": 1,
                        "status": status,
                        "shell_obtained": chain.get("shell_obtained"),
                        "flag_match": chain.get("flag_match"),
                    },
                )
            except Exception as exc:
                state.exploit_results = [
                    {
                        "finding_id": finding.finding_id,
                        "status": "failed",
                        "message": f"complex-web validation raised: {exc}",
                    }
                    for finding in state.findings
                ]
                return AgentResult(
                    self.name,
                    AgentStatus.FAILED,
                    "complex-web validation failed",
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



ROOT = Path(__file__).resolve().parents[1]
_SINK_PATTERNS = (
    ("execute", re.compile(r"\b(?:connection\.)?execute\s*\(")),
    ("query", re.compile(r"\bquery\s*\(")),
    ("os.system", re.compile(r"\bos\.system\s*\(")),
    ("subprocess", re.compile(r"\bsubprocess\.(?:run|Popen|call|check_output|check_call)\s*\(")),
)
_TAINT_ASSIGN = re.compile(r"\b(statement|sql|query|cmd|command)\s*=\s*.*\+")


class CodeAuditAgent(Agent):
    """Regex sink scan plus a demo-level taint skeleton. Not a real dataflow engine."""

    name = "code_audit"

    def __init__(self, policy: PolicyEngine) -> None:
        self.policy = policy

    def run(self, state: RunState) -> AgentResult:
        self.policy.require_action("code_audit_scan", state.target)
        sources = self._sources(state.scenario)
        sinks: list[dict[str, Any]] = []
        errors: list[str] = []
        for source in sources:
            try:
                sinks.extend(self._audit_file(source))
            except OSError as exc:
                errors.append(f"{source}: {exc}")
        tainted = [item for item in sinks if item.get("tainted")]
        payload = {
            "method": "regex-sink-scan",
            "taint_model": "demo-skeleton",
            "files": [str(path.relative_to(ROOT)).replace("\\", "/") for path in sources],
            "sink_count": len(sinks),
            "tainted_count": len(tainted),
            "sinks": sinks[:20],
        }
        state.facts["code_audit"] = payload
        summary = f"scanned {len(sources)} lab source file(s); {len(tainted)} tainted sink(s)"
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            summary,
            payload,
            errors=errors,
            observations=[f"{item['sink']}:{item['file']}:{item['line']}" for item in sinks[:8]],
        )

    @staticmethod
    def _sources(scenario: str) -> list[Path]:
        if scenario == "complex-web":
            return [ROOT / "lab" / "complex_web" / "server.py"]
        return [ROOT / "lab" / "app.py"]

    def _audit_file(self, path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            raise FileNotFoundError(path)
        text = path.read_text(encoding="utf-8")
        if len(text) > 200_000:
            raise OSError("source file exceeds audit size limit")
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        tainted_vars: set[str] = set()
        sinks: list[dict[str, Any]] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            assigned = _TAINT_ASSIGN.search(line)
            if assigned:
                tainted_vars.add(assigned.group(1))
            for sink_name, pattern in _SINK_PATTERNS:
                if not pattern.search(line):
                    continue
                used = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", line))
                concat = bool(re.search(r"[\"'].*\+|\+\s*[\"']", line))
                sinks.append(
                    {
                        "file": relative,
                        "line": lineno,
                        "sink": sink_name,
                        "excerpt": line.strip()[:200],
                        "tainted": bool(used & tainted_vars) or concat,
                    }
                )
        return sinks


class EnvReproAgent(Agent):
    """Emit environment reproduction steps from the lab manifest. Does not start labs."""

    name = "env_repro"

    def __init__(self, policy: PolicyEngine) -> None:
        self.policy = policy

    def run(self, state: RunState) -> AgentResult:
        self.policy.require_action("env_repro_read", state.target)
        manifest_path = self._manifest_path(state.scenario)
        if manifest_path is None:
            payload = {
                "environment_id": "demo-in-process",
                "classification": "simulated",
                "start_command": "python -m harness_mvp --scenario demo --target demo.local",
                "reset_command": "none; DemoLabAdapter is process-local",
                "cleanup_command": "none",
                "source_revision": "workspace-demo",
                "steps": [
                    "Use DemoLabAdapter; no Docker or network start is required.",
                    "Reset by starting a new harness run.",
                    "Cleanup is process exit.",
                ],
            }
        else:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
            payload = {
                "environment_id": raw.get("environment_id"),
                "classification": raw.get("classification"),
                "target": raw.get("target"),
                "source_revision": raw.get("source_revision"),
                "start_command": raw.get("start_command"),
                "reset_command": raw.get("reset_command"),
                "cleanup_command": raw.get("cleanup_command"),
                "success_criteria": list(raw.get("success_criteria") or []),
                "manifest": str(manifest_path.relative_to(ROOT)).replace("\\", "/"),
                "steps": [
                    f"Start: {raw.get('start_command')}",
                    f"Reset: {raw.get('reset_command')}",
                    f"Cleanup: {raw.get('cleanup_command')}",
                ],
            }
        state.facts["env_repro"] = payload
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            f"reproduced environment plan for {payload.get('environment_id')}",
            payload,
            observations=list(payload.get("steps") or []),
        )

    @staticmethod
    def _manifest_path(scenario: str) -> Path | None:
        if scenario == "local-web":
            return ROOT / "lab" / "manifest.json"
        if scenario == "complex-web":
            return ROOT / "lab" / "complex_web" / "manifest.json"
        return None


class PostExploitAgent(Agent):
    """Simulated lateral movement only. Never executes commands or scans the network."""

    name = "post_exploit"

    def __init__(self, policy: PolicyEngine) -> None:
        self.policy = policy

    def run(self, state: RunState) -> AgentResult:
        self.policy.require_action("post_exploit_simulate", state.target)
        verified = any(item.get("status") == "verified" for item in state.exploit_results)
        exploitable = any(finding.exploitable for finding in state.findings)
        if not state.findings and not state.exploit_results:
            payload = {"simulated": True, "executed": False, "hops": []}
            state.facts["post_exploit"] = payload
            return AgentResult(self.name, AgentStatus.SKIPPED, "no validated foothold for lateral movement", payload)

        if state.scenario == "complex-web" and (verified or exploitable):
            hops = [
                {
                    "from": "app-api",
                    "to": "internal-admin",
                    "technique": "T1021",
                    "status": "simulated",
                    "message": "Would reuse the in-lab session toward internal-admin. Not executed by this agent.",
                }
            ]
            summary = "simulated app-api to internal-admin hop"
        elif state.scenario == "local-web" and (verified or exploitable):
            hops = [
                {
                    "from": "public /search",
                    "to": "same-process SQLite records",
                    "technique": "T1005",
                    "status": "simulated",
                    "message": "Would read non-public training rows already proven by the differential. No extra command issued.",
                }
            ]
            summary = "simulated same-host data access"
        elif state.findings:
            hops = [
                {
                    "from": "public edge",
                    "to": "/admin",
                    "technique": "T1190",
                    "status": "simulated",
                    "message": "Demo admin route is already unauthenticated; no additional hop executed.",
                }
            ]
            summary = "simulated admin reachability note"
        else:
            payload = {"simulated": True, "executed": False, "hops": []}
            state.facts["post_exploit"] = payload
            return AgentResult(self.name, AgentStatus.SKIPPED, "exploit did not yield a foothold", payload)

        payload = {
            "simulated": True,
            "executed": False,
            "boundary": "post-exploit is observational only; no shell, no nmap, no extra HTTP",
            "hops": hops,
        }
        state.facts["post_exploit"] = payload
        return AgentResult(
            self.name,
            AgentStatus.SUCCESS,
            summary,
            payload,
            observations=[item["message"] for item in hops],
        )


def make_agents(
    adapter: DemoLabAdapter | HttpLabAdapter | ComplexWebAdapter,
    policy: PolicyEngine,
    kb: KnowledgeBase,
    llm: LLMClient | None = None,
) -> dict[str, Agent]:
    exploit = ExploitAgent(policy)
    exploit.adapter = adapter
    return {
        "recon": ReconAgent(adapter),
        "code_audit": CodeAuditAgent(policy),
        "env_repro": EnvReproAgent(policy),
        "vuln": VulnAgent(kb, llm, adapter),
        "exploit": exploit,
        "post_exploit": PostExploitAgent(policy),
        "report": ReportAgent(),
    }
