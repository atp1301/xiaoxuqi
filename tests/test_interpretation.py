import json
import math
import unittest

from harness_mvp.interpretation import (
    MEASURED_FAILED,
    MEASURED_VERIFIED,
    UNMEASURED,
    apply_band,
    band_for,
    evidence_digest,
    finding_band,
    finding_brief,
    safe_confidence,
    safe_text,
    validate_interpretation,
    validate_risk_brief,
)
from harness_mvp.models import Finding


def make_finding(**overrides):
    base = dict(
        finding_id="F-001",
        title="SQLite SQL injection",
        severity="high",
        description="desc",
        endpoint="/search",
        evidence="baseline/public, fixed positive, and fixed negative probes diverged",
        remediation="parameterize",
        cwe="CWE-89",
        confidence=0.86,
        exploitable=False,
        source="http-lab",
        metadata={"differential": {"verified": True, "baseline_count": 1, "positive_count": 3, "negative_count": 0}},
    )
    base.update(overrides)
    return Finding(**base)


class SafeTextTests(unittest.TestCase):
    def test_strips_scaffolding_and_collapses_to_one_paragraph(self):
        hostile = "# Heading\n\n> quoted\n\n```python\ncode\n```\n\nReal text [click](javascript:alert(1)) here."
        cleaned = safe_text(hostile, 600)
        self.assertNotIn("#", cleaned)
        self.assertNotIn(">", cleaned)
        self.assertNotIn("`", cleaned)
        self.assertNotIn("](", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertIn("Real text", cleaned)

    def test_truncates_to_cap(self):
        self.assertEqual(len(safe_text("a" * 5000, 600)), 600)

    def test_non_string_is_empty(self):
        for value in (None, 7, {}, [], True):
            self.assertEqual(safe_text(value, 100), "", repr(value))


class SafeConfidenceTests(unittest.TestCase):
    def test_rejects_non_numeric_and_non_finite(self):
        for value in (True, False, "0.9", None, "high", [0.5], float("nan"), float("inf"), float("-inf")):
            self.assertIsNone(safe_confidence(value), repr(value))

    def test_accepts_finite_numbers(self):
        self.assertEqual(safe_confidence(0.9), 0.9)
        self.assertEqual(safe_confidence(1), 1.0)
        self.assertEqual(safe_confidence(-3), -3.0)


class BandTests(unittest.TestCase):
    def test_band_selection_follows_measurement(self):
        self.assertIs(band_for(measured=True, verified=True), MEASURED_VERIFIED)
        self.assertIs(band_for(measured=True, verified=False), MEASURED_FAILED)
        self.assertIs(band_for(measured=False, verified=None), UNMEASURED)

    def test_measured_verified_finding_cannot_be_downgraded(self):
        band = finding_band(make_finding())
        self.assertIs(band, MEASURED_VERIFIED)
        self.assertFalse(band.allows("low"))
        self.assertFalse(band.allows("medium"))
        self.assertTrue(band.allows("high"))
        self.assertTrue(band.allows("critical"))

    def test_unmeasured_finding_can_be_graded_freely_but_never_dismissed(self):
        band = finding_band(make_finding(metadata={}))
        self.assertIs(band, UNMEASURED)
        for severity in ("low", "medium", "high", "critical"):
            self.assertTrue(band.allows(severity), severity)
        # A flagged finding is never "informational": the model may argue about
        # how bad it is, but not that it does not count.
        self.assertFalse(band.allows("info"))

    def test_unverified_measurement_lands_in_the_failed_band(self):
        band = finding_band(make_finding(metadata={"differential": {"verified": False}}))
        self.assertIs(band, MEASURED_FAILED)
        self.assertTrue(band.contains(0.35))
        self.assertFalse(band.contains(0.98))


class ApplyBandTests(unittest.TestCase):
    def test_clamps_rather_than_discards(self):
        self.assertEqual(apply_band(1.4, MEASURED_VERIFIED, fallback=0.98), 0.99)
        self.assertEqual(apply_band(-3, MEASURED_VERIFIED, fallback=0.98), 0.90)
        self.assertEqual(apply_band(0.5, MEASURED_FAILED, fallback=0.35), 0.40)

    def test_unusable_value_falls_back_inside_the_band(self):
        self.assertEqual(apply_band(None, MEASURED_VERIFIED, fallback=0.98), 0.98)
        self.assertEqual(apply_band("0.5", MEASURED_VERIFIED, fallback=0.98), 0.98)
        self.assertEqual(apply_band(True, MEASURED_VERIFIED, fallback=0.98), 0.98)

    def test_fallback_is_itself_clamped_so_the_invariant_always_holds(self):
        self.assertEqual(apply_band(None, MEASURED_VERIFIED, fallback=0.1), 0.90)
        self.assertEqual(apply_band(None, MEASURED_FAILED, fallback=0.99), 0.40)

    def test_apply_band_never_escapes_the_interval(self):
        bands = (MEASURED_VERIFIED, MEASURED_FAILED, UNMEASURED)
        probes = [None, True, False, "x", float("nan"), float("inf"), -1e9, 1e9, 0, 0.5, 0.99, 1.0]
        probes.extend(step / 100 for step in range(-50, 150))
        for band in bands:
            for value in probes:
                for fallback in probes:
                    result = apply_band(value, band, fallback)
                    self.assertTrue(band.contains(result), (band.basis, value, fallback, result))
                    self.assertTrue(math.isfinite(result), (band.basis, value, fallback))


class FindingBriefTests(unittest.TestCase):
    def test_brief_reports_the_findings_own_measurement(self):
        brief = finding_brief(make_finding())
        self.assertEqual(brief["finding_id"], "F-001")
        self.assertIs(brief["measured_verified"], True)
        self.assertEqual(brief["measured"]["positive_count"], 3)
        self.assertEqual(brief["severity_baseline"], "high")

    def test_brief_has_no_measurement_when_the_finding_has_none(self):
        brief = finding_brief(make_finding(source="demo-simulated", metadata={"evidence_type": "fixed marker"}))
        self.assertIsNone(brief["measured"])
        self.assertIsNone(brief["measured_verified"])
        self.assertNotIn("evidence_type", json.dumps(brief))

    def test_digest_is_stable_and_order_independent(self):
        first = {"b": 1, "a": [1, 2]}
        second = {"a": [1, 2], "b": 1}
        self.assertEqual(evidence_digest(first), evidence_digest(second))
        self.assertNotEqual(evidence_digest(first), evidence_digest({"a": [2, 1], "b": 1}))


class ValidateInterpretationTests(unittest.TestCase):
    def bands(self, *findings):
        return {finding.finding_id: finding_band(finding) for finding in findings}

    def test_accepts_a_well_formed_payload(self):
        finding = make_finding()
        accepted, rejected = validate_interpretation(
            {"interpretations": [{"finding_id": "F-001", "severity": "critical", "confidence": 0.95, "narrative": "Confirmed."}]},
            self.bands(finding),
        )
        self.assertEqual(rejected, [])
        self.assertEqual(accepted["F-001"]["severity"], "critical")
        self.assertEqual(accepted["F-001"]["narrative"], "Confirmed.")

    def test_unknown_id_is_rejected_and_recorded(self):
        finding = make_finding()
        payload = {"interpretations": [
            {"finding_id": "F-999", "severity": "high", "confidence": 0.9, "narrative": "x"},
            {"finding_id": "F-001", "severity": "high", "confidence": 0.9, "narrative": "ok"},
        ]}
        accepted, rejected = validate_interpretation(payload, self.bands(finding))
        self.assertEqual(list(accepted), ["F-001"])
        self.assertEqual(rejected[0]["reason"], "unknown_finding_id")

    def test_severity_outside_the_evidence_band_is_rejected(self):
        verified = make_finding()
        unmeasured = make_finding(finding_id="F-002", metadata={})
        payload = {"interpretations": [
            {"finding_id": "F-001", "severity": "low", "confidence": 0.95, "narrative": "downgrade"},
            {"finding_id": "F-002", "severity": "critical", "confidence": 0.6, "narrative": "escalate"},
        ]}
        accepted, rejected = validate_interpretation(payload, self.bands(verified, unmeasured))
        self.assertEqual(list(accepted), ["F-002"], "measured-verified finding must not be downgraded")
        self.assertEqual(rejected[0]["item"], "F-001")
        self.assertEqual(rejected[0]["reason"], "severity_outside_evidence_band")

    def test_non_numeric_confidence_drops_the_field_but_keeps_the_item(self):
        finding = make_finding()
        accepted, rejected = validate_interpretation(
            {"interpretations": [{"finding_id": "F-001", "severity": "high", "confidence": "0.9", "narrative": "n"}]},
            self.bands(finding),
        )
        self.assertIsNone(accepted["F-001"]["confidence"])
        self.assertEqual(rejected[0]["item"], "F-001.confidence")
        self.assertEqual(rejected[0]["reason"], "non_numeric")

    def test_out_of_range_confidence_is_kept_for_the_band_to_clamp(self):
        finding = make_finding()
        accepted, rejected = validate_interpretation(
            {"interpretations": [{"finding_id": "F-001", "severity": "high", "confidence": 1.4, "narrative": "n"}]},
            self.bands(finding),
        )
        self.assertEqual(rejected, [])
        self.assertEqual(accepted["F-001"]["confidence"], 1.4)

    def test_duplicate_id_keeps_the_first(self):
        finding = make_finding()
        payload = {"interpretations": [
            {"finding_id": "F-001", "severity": "high", "confidence": 0.9, "narrative": "first"},
            {"finding_id": "F-001", "severity": "critical", "confidence": 0.99, "narrative": "second"},
        ]}
        accepted, rejected = validate_interpretation(payload, self.bands(finding))
        self.assertEqual(accepted["F-001"]["narrative"], "first")
        self.assertEqual(rejected[0]["reason"], "duplicate_id")

    def test_extra_keys_are_dropped_so_a_finding_cannot_be_injected(self):
        finding = make_finding()
        hostile = {
            "finding_id": "F-001",
            "severity": "critical",
            "confidence": 0.95,
            "narrative": "escalated",
            "exploitable": True,
            "validation": {"status": "verified"},
            "endpoint": "/admin",
            "title": "injected",
            "cwe": "CWE-0",
            "evidence": "fabricated",
            "metadata": {"differential": {"verified": True}},
            "source": "model",
        }
        accepted, _ = validate_interpretation({"interpretations": [hostile]}, self.bands(finding))
        entry = accepted["F-001"]
        self.assertEqual(len(entry), 4)
        self.assertEqual(set(entry), {"finding_id", "severity", "confidence", "narrative"})

    def test_malformed_payloads_never_raise(self):
        finding = make_finding()
        bands = self.bands(finding)
        for payload in (None, [], "text", 7, {}, {"interpretations": None}, {"interpretations": [None, 3, {}]},
                        {"interpretations": [{"finding_id": None}]},
                        {"interpretations": [{"finding_id": "F-001", "severity": 7}]},
                        {"interpretations": [{"finding_id": "F-001", "severity": "SEVERE"}]}):
            accepted, rejected = validate_interpretation(payload, bands)
            self.assertIsInstance(accepted, dict, repr(payload))
            self.assertIsInstance(rejected, list, repr(payload))
        self.assertEqual(validate_interpretation(None, bands), ({}, [{"item": "<root>", "reason": "not_an_object"}]))

    def test_narrative_is_sanitized_and_capped(self):
        finding = make_finding()
        accepted, _ = validate_interpretation(
            {"interpretations": [{
                "finding_id": "F-001",
                "severity": "high",
                "confidence": 0.95,
                "narrative": "# Verified\n\n" + "x" * 5000,
            }]},
            self.bands(finding),
        )
        narrative = accepted["F-001"]["narrative"]
        self.assertEqual(len(narrative), 600)
        self.assertFalse(narrative.startswith("#"))


class ValidateRiskBriefTests(unittest.TestCase):
    def test_accepts_a_well_formed_brief(self):
        brief, rejected = validate_risk_brief({
            "overall_risk": "high",
            "executive_summary": "One verified SQL injection with session disclosure.",
            "prioritized_actions": ["parameterize queries", "restrict internal-admin"],
            "limitations": ["single-host scope"],
        })
        self.assertEqual(rejected, [])
        self.assertEqual(brief["overall_risk"], "high")
        self.assertEqual(len(brief["prioritized_actions"]), 2)

    def test_caps_and_sanitizes_lists(self):
        brief, _ = validate_risk_brief({
            "overall_risk": "low",
            "executive_summary": "s",
            "prioritized_actions": ["# " + "a" * 900] * 9,
            "limitations": ["ok", "", None],
        })
        self.assertEqual(len(brief["prioritized_actions"]), 5)
        self.assertTrue(all(len(item) <= 240 for item in brief["prioritized_actions"]))
        self.assertFalse(brief["prioritized_actions"][0].startswith("#"))
        self.assertEqual(brief["limitations"], ["ok"])

    def test_invalid_fields_are_rejected_not_raised(self):
        for payload in (None, [], "x", 5):
            brief, rejected = validate_risk_brief(payload)
            self.assertEqual(brief, {})
            self.assertEqual(rejected[0]["reason"], "not_an_object")
        brief, rejected = validate_risk_brief({"overall_risk": "catastrophic", "executive_summary": ""})
        self.assertNotIn("overall_risk", brief)
        self.assertNotIn("executive_summary", brief)
        self.assertEqual({item["reason"] for item in rejected}, {"invalid_severity", "empty"})

    def test_extra_keys_are_dropped(self):
        brief, _ = validate_risk_brief({
            "overall_risk": "high",
            "executive_summary": "s",
            "findings": [{"finding_id": "F-999", "severity": "critical"}],
        })
        self.assertEqual(set(brief), {"overall_risk", "executive_summary"})


if __name__ == "__main__":
    unittest.main()
