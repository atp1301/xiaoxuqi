"""Pure validation layer between model prose and the assessment record.

Nothing here performs I/O. The module exists so that the one structural
guarantee of this harness is testable in isolation: **model output is never
deserialised into a `Finding`**. A model response can only ever contribute
three scalars — `severity`, `confidence` and a narrative string — each of which
is checked and clamped against the measured evidence before it is stored.

Dependency direction is deliberate: `llm -> interpretation -> models`. The
validator never imports the client, so it cannot accidentally acquire the
ability to make a call.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .models import Finding


SEVERITY_ALLOWLIST: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
"""Ordered least-to-most severe; the index doubles as the ranking."""

SEVERITY_RANK: dict[str, int] = {name: index for index, name in enumerate(SEVERITY_ALLOWLIST)}

PROMPT_VERSION = "interpretation-v1"
BRIEF_VERSION = "risk-brief-v1"

MAX_NARRATIVE_CHARS = 600
MAX_SUMMARY_CHARS = 1500
MAX_ACTION_CHARS = 240
MAX_ACTIONS = 5
MAX_ITEMS = 64

# The three scalars a model may contribute to a finding. Anything else it sends
# is dropped before it reaches the record, which is what makes finding
# injection structurally impossible rather than merely discouraged.
INTERPRETATION_KEYS: tuple[str, ...] = ("finding_id", "severity", "confidence", "narrative")

# Which measured fields of a differential probe may be shown to the model.
_DIFFERENTIAL_KEYS: tuple[str, ...] = (
    "verified",
    "baseline_count",
    "positive_count",
    "negative_count",
    "proof_seen",
    "public_seen",
    "token_seen",
    "baseline_sha256",
    "positive_sha256",
    "negative_sha256",
)

MAX_EVIDENCE_CHARS = 900


@dataclass(frozen=True)
class Band:
    """The interval a confidence value is allowed to live in.

    Measured evidence fixes the band; the model only positions itself inside it.
    That ordering is what keeps a model from talking a verified exploit down to
    near-zero confidence, or an unconfirmed indicator up to near-certainty.
    """

    low: float
    high: float
    severities: tuple[str, ...]
    basis: str

    def contains(self, value: float) -> bool:
        return self.low <= value <= self.high

    def allows(self, severity: str) -> bool:
        return severity in self.severities


MEASURED_VERIFIED = Band(0.90, 0.99, ("high", "critical"), "measured_differential_verified")
MEASURED_FAILED = Band(0.30, 0.40, ("medium", "high"), "measured_differential_failed")
UNMEASURED = Band(0.40, 0.70, ("low", "medium", "high", "critical"), "no_differential_measurement")


def band_for(measured: bool, verified: bool | None) -> Band:
    """Pick the band implied by what was actually observed."""
    if not measured:
        return UNMEASURED
    return MEASURED_VERIFIED if verified else MEASURED_FAILED


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, -1)


# --- text hygiene -----------------------------------------------------------

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEADING_RE = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]*")
_QUOTE_RE = re.compile(r"(?m)^[ \t]{0,3}>[ \t]?")
_FENCE_RE = re.compile(r"`+")
_LINK_RE = re.compile(r"\]\(")
_WHITESPACE_RE = re.compile(r"\s+")


def safe_text(value: Any, cap: int) -> str:
    """Flatten model prose so it cannot masquerade as a measured section.

    Headings, block-quotes and code fences are stripped, markdown links are
    broken, and everything collapses to a single paragraph. Model text lands in
    the report next to deterministic evidence; without this it could render a
    heading that reads like a machine-generated finding.
    """
    if not isinstance(value, str):
        return ""
    text = _CONTROL_RE.sub(" ", value)
    text = _HEADING_RE.sub("", text)
    text = _QUOTE_RE.sub("", text)
    text = _FENCE_RE.sub("", text)
    text = _LINK_RE.sub("] ", text)
    text = _WHITESPACE_RE.sub(" ", text).strip()
    return text[:cap]


def safe_confidence(value: Any) -> float | None:
    """Return a finite float, or None for anything that is not a real number.

    `bool` is rejected explicitly because `isinstance(True, int)` is true in
    Python, and `"0.9"` is rejected rather than coerced so a malformed response
    degrades to the deterministic value instead of silently parsing.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return number


def apply_band(model_confidence: Any, band: Band, fallback: Any) -> float:
    """Clamp a model confidence into the measured band.

    Out-of-range values are clamped, not discarded: the model's *direction* is
    still informative, it just does not get to leave the interval the evidence
    established. A missing or unusable value falls back to the deterministic
    one, which is itself clamped so the "confidence lies in the band" invariant
    holds unconditionally.
    """
    candidate = safe_confidence(model_confidence)
    if candidate is None:
        candidate = safe_confidence(fallback)
    if candidate is None:
        candidate = band.low
    return round(min(max(candidate, band.low), band.high), 4)


# --- what the model is allowed to see ---------------------------------------


def _measured_block(finding: Finding) -> dict[str, Any] | None:
    """Extract the differential probe result from a finding's own metadata."""
    differential = finding.metadata.get("differential")
    if not isinstance(differential, Mapping):
        return None
    return {key: differential[key] for key in _DIFFERENTIAL_KEYS if key in differential}


def finding_brief(finding: Finding) -> dict[str, Any]:
    """The complete set of facts the model receives about one finding.

    Built from the finding, never from model output. `measured` is the finding's
    own differential result, so what the model reasons about is a real HTTP
    probe with real hashes rather than a restatement of its own prior output.
    """
    measured = _measured_block(finding)
    return {
        "finding_id": finding.finding_id,
        "title": safe_text(finding.title, 200),
        "cwe": safe_text(finding.cwe, 40),
        "endpoint": safe_text(finding.endpoint, 200),
        "source": safe_text(finding.source, 40),
        "severity_baseline": finding.severity if finding.severity in SEVERITY_RANK else "info",
        "confidence_baseline": safe_confidence(finding.confidence),
        "evidence": safe_text(finding.evidence, MAX_EVIDENCE_CHARS),
        "measured": measured,
        "measured_verified": None if measured is None else bool(measured.get("verified")),
    }


def finding_band(finding: Finding) -> Band:
    """The band implied by a finding's own measured evidence."""
    measured = _measured_block(finding)
    if measured is None:
        return band_for(measured=False, verified=None)
    return band_for(measured=True, verified=bool(measured.get("verified")))


def evidence_digest(payload: Any) -> str:
    """Stable sha256 over the exact brief that was sent to the model.

    Lets an auditor recompute what the model saw without storing it.
    """
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# --- validation -------------------------------------------------------------


def _reject(rejected: list[dict[str, str]], item: str, reason: str) -> None:
    rejected.append({"item": item, "reason": reason})


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else []


def validate_interpretation(
    payload: Any,
    bands: Mapping[str, Band] | Iterable[str],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, str]]]:
    """Validate a model interpretation response.

    ``bands`` maps each finding id to the band its own measured evidence
    implies. A plain iterable of ids is also accepted, in which case only the
    global severity allowlist applies — callers that have the evidence should
    pass bands so the severity is constrained by what was measured.

    Returns ``(accepted, rejected)``. Accepted is keyed by finding id and each
    value has exactly the four allowed keys — no more, whatever the model sent.
    Nothing in here raises: a hostile or malformed payload yields an empty
    accepted map and a list of reasons, and the caller degrades to the
    deterministic values.
    """
    accepted: dict[str, dict[str, Any]] = {}
    rejected: list[dict[str, str]] = []
    if not isinstance(payload, Mapping):
        _reject(rejected, "<root>", "not_an_object")
        return accepted, rejected

    allowed = dict(bands) if isinstance(bands, Mapping) else {key: None for key in bands}
    items = _as_list(payload.get("interpretations"))
    if len(items) > MAX_ITEMS:
        _reject(rejected, "<root>", "too_many_items")
        items = items[:MAX_ITEMS]

    for index, raw in enumerate(items):
        label = f"<item {index}>"
        if not isinstance(raw, Mapping):
            _reject(rejected, label, "not_an_object")
            continue
        finding_id = raw.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id:
            _reject(rejected, label, "missing_finding_id")
            continue
        label = finding_id
        if finding_id not in allowed:
            _reject(rejected, label, "unknown_finding_id")
            continue
        if finding_id in accepted:
            _reject(rejected, label, "duplicate_id")
            continue

        severity = raw.get("severity")
        if not isinstance(severity, str) or severity not in SEVERITY_ALLOWLIST:
            _reject(rejected, label, "invalid_severity")
            continue
        # Severity and confidence are accepted or dropped as a unit. Mixing a
        # model severity with a deterministic confidence (or the reverse) would
        # produce a rating no single source actually stands behind.
        band = allowed[finding_id]
        if band is not None and not band.allows(severity):
            _reject(rejected, label, "severity_outside_evidence_band")
            continue

        # An unusable confidence is not fatal: the narrative and severity are
        # still usable and the deterministic value fills the gap downstream.
        confidence = safe_confidence(raw.get("confidence"))
        if confidence is None:
            _reject(rejected, f"{label}.confidence", "non_numeric")

        accepted[finding_id] = {
            "finding_id": finding_id,
            "severity": severity,
            "confidence": confidence,
            "narrative": safe_text(raw.get("narrative"), MAX_NARRATIVE_CHARS),
        }
    return accepted, rejected


def validate_risk_brief(payload: Any) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Validate the report-stage risk brief.

    Same contract as `validate_interpretation`: known keys only, fixed shapes,
    every violation recorded rather than raised.
    """
    rejected: list[dict[str, str]] = []
    if not isinstance(payload, Mapping):
        return {}, [{"item": "<root>", "reason": "not_an_object"}]

    brief: dict[str, Any] = {}

    severity = payload.get("overall_risk")
    if isinstance(severity, str) and severity in SEVERITY_ALLOWLIST:
        brief["overall_risk"] = severity
    else:
        _reject(rejected, "overall_risk", "invalid_severity")

    summary = safe_text(payload.get("executive_summary"), MAX_SUMMARY_CHARS)
    if summary:
        brief["executive_summary"] = summary
    else:
        _reject(rejected, "executive_summary", "empty")

    for field_name, cap in (("prioritized_actions", MAX_ACTION_CHARS), ("limitations", MAX_ACTION_CHARS)):
        entries: list[str] = []
        for index, entry in enumerate(_as_list(payload.get(field_name))[:MAX_ACTIONS]):
            text = safe_text(entry, cap)
            if text:
                entries.append(text)
            else:
                _reject(rejected, f"{field_name}[{index}]", "empty")
        if entries:
            brief[field_name] = entries

    return brief, rejected


__all__ = [
    "Band",
    "MEASURED_FAILED",
    "MEASURED_VERIFIED",
    "PROMPT_VERSION",
    "BRIEF_VERSION",
    "INTERPRETATION_KEYS",
    "SEVERITY_ALLOWLIST",
    "SEVERITY_RANK",
    "UNMEASURED",
    "apply_band",
    "band_for",
    "evidence_digest",
    "finding_band",
    "finding_brief",
    "safe_confidence",
    "safe_text",
    "severity_rank",
    "validate_interpretation",
    "validate_risk_brief",
]
