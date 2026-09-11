from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from .checkpoint import SCHEMA_VERSION
from .models import Finding, RunState


MODEL_SECTION_DISCLAIMER = (
    "This section is written by a language model from the measured evidence above. "
    "It is interpretation, not evidence. Findings, `verified` verdicts and SHA-256 digests "
    "come from deterministic probing and are unaffected by anything written here."
)


def _as_float(value: Any, fallback: float = 0.0) -> float:
    """Coerce a stored confidence for display.

    A report must render even if a value was hand-edited or produced by an
    older schema; formatting a non-number used to raise and turn the whole run
    into a failure.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    number = float(value)
    return number if math.isfinite(number) else fallback


def _as_text(value: Any, fallback: str = "unknown") -> str:
    return value if isinstance(value, str) and value else fallback


def _interpretation_block(state: RunState) -> dict[str, Any]:
    """The two model-written facts, plus where every field came from."""
    return {
        "findings_interpretation": state.facts.get("llm_findings_interpretation"),
        "risk_brief": state.facts.get("llm_risk_brief"),
        "provenance": {
            "measured_sources": ["differential HTTP probes", "SHA-256 response digests", "ground-truth lab flag"],
            "model_written_fields": [
                "findings[].metadata.interpretation.narrative",
                "findings[].metadata.interpretation.confidence_raw",
                "findings[].severity when metadata.severity_source == 'model'",
                "interpretation.risk_brief.content",
            ],
            "model_cannot_write": [
                "findings[] existence",
                "findings[].exploitable",
                "findings[].metadata.validation",
                "exploit_results",
                "test_evidence",
            ],
        },
    }


def build_report(state: RunState) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for finding in state.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "run_id": state.run_id,
        "target": state.target.address,
        "scenario": state.scenario,
        "status": state.status.value,
        "summary": {"finding_count": len(state.findings), "severity_counts": counts},
        "agent_mode": state.working_memory.get("agent_mode"),
        "interpretation": _interpretation_block(state),
        "findings": [finding.__dict__ for finding in state.findings],
        "exploit_results": state.exploit_results,
        "agent_results": [result.__dict__ | {"status": result.status.value} for result in state.agent_results],
        "checkpoint": {
            "schema_version": SCHEMA_VERSION,
            "path": state.checkpoint_path,
            "resumable": bool(state.checkpoint_path),
        },
        "test_evidence": state.facts.get("test_evidence", {}),
        "facts": state.facts,
        "working_memory": {
            "current_goal": state.working_memory.get("current_goal"),
            "current_action": state.working_memory.get("current_action"),
            "operator": state.working_memory.get("operator"),
            "next_assignment": state.working_memory.get("next_assignment"),
            "received_reports": state.working_memory.get("received_reports", []),
        },
        "episodic_memory": state.episodic_memory,
        "task_tree": state.working_memory.get("task_tree", state.working_memory.get("plan", [])),
        "events": [event.__dict__ for event in state.events],
        "errors": state.errors,
    }


def _render_interpretation(report: dict[str, Any]) -> list[str]:
    """Render the model-written section, or say plainly why there is none."""
    block = report.get("interpretation") or {}
    interpretation = block.get("findings_interpretation")
    brief = block.get("risk_brief")
    lines: list[str] = ["## Model Interpretation", "", MODEL_SECTION_DISCLAIMER, ""]
    if not interpretation and not brief:
        lines.extend(["No model was invoked for this run.", ""])
        return lines

    if isinstance(interpretation, dict) and interpretation.get("available"):
        lines.extend([
            f"- Findings graded by model: `{interpretation.get('model') or 'n/a'}` "
            f"(prompt `{interpretation.get('prompt_version') or 'n/a'}`)",
            f"- Response SHA-256: `{interpretation.get('raw_sha256') or 'n/a'}`",
            f"- Brief SHA-256: `{interpretation.get('evidence_sha256') or 'n/a'}`",
            f"- Rejected items: `{len(interpretation.get('rejected') or [])}`",
            "",
        ])
    elif isinstance(interpretation, dict):
        lines.extend([
            f"- Model grading unavailable, deterministic grading retained: `{_as_text(interpretation.get('error'), 'unknown error')}`",
            "",
        ])

    if isinstance(brief, dict) and brief.get("available"):
        content = brief.get("content") or {}
        lines.extend([
            f"- Overall risk (model): **{_as_text(content.get('overall_risk'), 'n/a')}**",
            "",
            _as_text(content.get("executive_summary"), "(no summary returned)"),
            "",
        ])
        actions = content.get("prioritized_actions") or []
        if actions:
            lines.extend(["Priority actions as ranked by the model:", ""])
            lines.extend(f"{index}. {action}" for index, action in enumerate(actions, start=1))
            lines.append("")
        limitations = content.get("limitations") or []
        if limitations:
            lines.extend(["Stated limitations:", ""])
            lines.extend(f"- {item}" for item in limitations)
            lines.append("")
    elif isinstance(brief, dict):
        lines.extend([
            f"- Model risk brief unavailable: `{_as_text(brief.get('error'), 'unknown error')}`",
            "",
        ])
    provenance = block.get("provenance") or {}
    lines.extend([
        "Provenance: `measured_sources` = "
        + ", ".join(provenance.get("measured_sources") or [])
        + "; the model cannot write "
        + ", ".join(provenance.get("model_cannot_write") or [])
        + ".",
        "",
    ])
    return lines


def _agent_mode_line(report: dict[str, Any]) -> str:
    """State what actually happened, not what was requested.

    A run can ask for `llm` and still be deterministic end to end if every call
    failed, so the mode recorded at construction time is not sufficient. The
    outcome is read back from the two call-site facts.
    """
    mode = report.get("agent_mode")
    if not isinstance(mode, dict):
        return "- Agent mode: `unknown` (no mode was recorded for this run)"
    requested = _as_text(mode.get("requested"))
    if _as_text(mode.get("effective")) != "llm":
        return f"- Agent mode: `{requested}` (deterministic only — no model call was made)"

    block = report.get("interpretation") or {}
    call_sites = (
        ("findings grading", block.get("findings_interpretation")),
        ("risk brief", block.get("risk_brief")),
    )
    succeeded = [name for name, fact in call_sites if isinstance(fact, dict) and fact.get("available")]
    if not succeeded:
        return f"- Agent mode: `{requested}` (model was called but every call failed; this run is deterministic)"
    if len(succeeded) == 1:
        return (
            f"- Agent mode: `{requested}` (model participated partially — {succeeded[0]} only; "
            "the other call fell back to deterministic)"
        )
    return f"- Agent mode: `{requested}` (model participated; interpretation is labelled as such)"


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# Harness MVP Security Assessment",
        "",
        f"- Run: `{report['run_id']}`",
        f"- Target: `{report['target']}`",
        f"- Scenario: `{report['scenario']}`",
        f"- Status: **{report['status']}**",
        f"- Findings: **{summary['finding_count']}**",
        _agent_mode_line(report),
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings were produced.")
    for finding in report["findings"]:
        metadata = finding.get("metadata") or {}
        lines.extend([
            f"### {finding['finding_id']}: {finding['title']}",
            f"- Severity: **{finding['severity']}** | Confidence: `{_as_float(finding.get('confidence')):.0%}`",
            f"- Endpoint: `{finding['endpoint']}` | CWE: `{finding['cwe'] or 'n/a'}` | Source: `{finding.get('source', 'unknown')}`",
            f"- Evidence grade: **measured**" if metadata.get("differential") else "- Evidence grade: **indicator-only** (no differential probe)",
            f"- Description: {finding['description']}",
            f"- Evidence: `{finding['evidence']}`",
            f"- Remediation: {finding['remediation']}",
            "",
        ])
        if metadata.get("severity_source") == "model":
            baseline = metadata.get("severity_baseline", "unknown")
            lines.append(f"- Severity basis: model interpretation (measured baseline: `{baseline}`)")
        else:
            lines.append("- Severity basis: deterministic rule")
        interpretation = metadata.get("interpretation")
        if isinstance(interpretation, dict) and interpretation.get("narrative"):
            lines.append(f"- **[模型判读 / model interpretation — not evidence]** {_as_text(interpretation.get('narrative'), '')}")
            lines.append("")
        validation = metadata.get("validation")
        if validation:
            lines.append(f"- Validation: **{validation.get('status', 'unknown')}**")
            if validation.get("positive_sha256") and validation.get("negative_sha256"):
                lines.append("- Evidence hashes: positive and negative response SHA-256 values are stored in the JSON report.")
            lines.append("")
    lines.extend(_render_interpretation(report))
    lines.extend(["## Validation Results", "", "`verified` means the bounded local training check observed the expected differential; `simulated` means no payload was sent; complex-web also records constrained shell identity and flag match.", "", "```json", json.dumps(report["exploit_results"], ensure_ascii=False, indent=2), "```", ""])
    evidence = report.get("test_evidence") or {}
    if evidence.get("chain"):
        lines.extend([
            "## Attack Chain Evidence",
            "",
            f"- Chain: `{' -> '.join(evidence.get('chain', []))}`",
            f"- Shell identity: `{evidence.get('shell_identity') or 'n/a'}`",
            f"- Flag match: **{evidence.get('flag_match')}**",
            f"- Flag: `{evidence.get('flag') or 'n/a'}`",
            f"- Flag SHA-256: `{evidence.get('flag_sha256') or 'n/a'}`",
            "",
        ])
    tree = report.get("task_tree") or []
    if tree:
        lines.extend(["## Task Tree", ""])
        for node in tree:
            parent = node.get("parent_id") or "root"
            lines.append(f"- `{node.get('step_id')}` parent=`{parent}` agent=`{node.get('agent')}`: {node.get('name')}")
        lines.append("")
    memory = report.get("working_memory") or {}
    if memory.get("operator"):
        lines.extend([
            "## Operator Memory",
            "",
            f"- Operator: {memory.get('operator')}",
            f"- Current goal: `{memory.get('current_goal')}`",
            f"- Last action: `{memory.get('current_action')}`",
            "",
        ])
    lines.extend(["## Agent Results", "", "```json", json.dumps(report.get("agent_results", []), ensure_ascii=False, indent=2), "```", ""])
    checkpoint = report.get("checkpoint", {})
    lines.extend(["## Checkpoint", "", f"- Path: `{checkpoint.get('path') or 'n/a'}`", f"- Resumable: **{checkpoint.get('resumable', False)}**", ""])
    if report.get("test_evidence"):
        lines.extend(["## Test Evidence", "", "```json", json.dumps(report["test_evidence"], ensure_ascii=False, indent=2), "```", ""])
    return "\n".join(lines)


def write_report(state: RunState, output_dir: str | Path) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    report = build_report(state)
    json_path = output / f"{state.run_id}.json"
    md_path = output / f"{state.run_id}.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return {"json": str(json_path.resolve()), "markdown": str(md_path.resolve())}
