from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .checkpoint import SCHEMA_VERSION
from .models import Finding, RunState


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
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings were produced.")
    for finding in report["findings"]:
        lines.extend([
            f"### {finding['finding_id']}: {finding['title']}",
            f"- Severity: **{finding['severity']}** | Confidence: `{finding['confidence']:.0%}`",
            f"- Endpoint: `{finding['endpoint']}` | CWE: `{finding['cwe'] or 'n/a'}` | Source: `{finding.get('source', 'unknown')}`",
            f"- Description: {finding['description']}",
            f"- Evidence: `{finding['evidence']}`",
            f"- Remediation: {finding['remediation']}",
            "",
        ])
        validation = finding.get("metadata", {}).get("validation")
        if validation:
            lines.append(f"- Validation: **{validation.get('status', 'unknown')}**")
            if validation.get("positive_sha256") and validation.get("negative_sha256"):
                lines.append("- Evidence hashes: positive and negative response SHA-256 values are stored in the JSON report.")
            lines.append("")
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
