import json
import tempfile
import unittest
from pathlib import Path

from harness_mvp.complex_lab import ComplexWebAdapter
from harness_mvp.labs import check_labs
from harness_mvp.models import AgentStatus, RunStatus
from harness_mvp.orchestrator import Orchestrator
from lab.complex_web.constants import DEFAULT_FLAG, SESSION_TOKEN
from lab.complex_web.server import running_lab


class ComplexWebLabTests(unittest.TestCase):
    def test_full_chain_discovers_verifies_identity_and_flag(self):
        with running_lab() as lab, tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(adapter=ComplexWebAdapter()).run(lab.gateway_url, "complex-web", directory)
            self.assertEqual(state.status, RunStatus.COMPLETED)
            self.assertEqual(len(state.findings), 1)
            self.assertEqual(state.findings[0].source, "complex-web")
            self.assertEqual(state.findings[0].cwe, "CWE-89")
            self.assertTrue(state.findings[0].exploitable)
            self.assertEqual(state.exploit_results[0]["status"], "verified")
            self.assertTrue(state.exploit_results[0]["shell_obtained"])
            self.assertTrue(state.exploit_results[0]["flag_match"])
            self.assertTrue(state.facts["complex_sqli_differential"]["verified"])
            evidence = state.facts["test_evidence"]
            self.assertEqual(evidence["flag"], DEFAULT_FLAG)
            self.assertEqual(evidence["shell_identity"], "uid=65532(labuser)")
            self.assertEqual(evidence["chain"], ["discover", "verify", "constrained-shell-identity", "read-flag"])
            recon_bodies = " ".join(item["body_excerpt"] for item in state.facts["endpoints"]).lower()
            self.assertNotIn(DEFAULT_FLAG.lower(), recon_bodies)
            self.assertTrue(any(item["path"] == "/internal/whoami" and item["status_code"] == 401 for item in state.facts["endpoints"]))
            raw = state.facts["raw_http_evidence"]
            self.assertGreaterEqual(len(raw), 6)
            self.assertTrue(any(item["step"] == "read-flag" and DEFAULT_FLAG in (item["response"]["body"] or "") for item in raw))
            report = json.loads(Path(state.report_paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(report["test_evidence"]["flag"], DEFAULT_FLAG)
            markdown = Path(state.report_paths["markdown"]).read_text(encoding="utf-8")
            self.assertIn("Attack Chain Evidence", markdown)
            self.assertIn(DEFAULT_FLAG, markdown)

    def test_parameterized_repair_blocks_token_and_flag(self):
        with running_lab(fixed=True) as lab, tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(adapter=ComplexWebAdapter()).run(lab.gateway_url, "complex-web", directory)
            self.assertEqual(state.status, RunStatus.COMPLETED)
            self.assertEqual(state.findings, [])
            self.assertEqual(next(item.status for item in state.agent_results if item.agent == "exploit"), AgentStatus.SKIPPED)
            self.assertFalse(state.facts["complex_sqli_differential"]["verified"])
            self.assertNotIn(SESSION_TOKEN, json.dumps(state.facts.get("complex_sqli_validation", {})))

    def test_public_search_does_not_include_session_or_flag(self):
        with running_lab() as lab:
            adapter = ComplexWebAdapter()
            baseline = adapter.probe(lab.gateway_url, "/search")
            whoami = adapter.probe(lab.gateway_url, "/internal/whoami")
            flag = adapter.probe(lab.gateway_url, "/internal/flag")
            body = (baseline.metadata.get("body") or "").lower()
            self.assertIn("public-training-record", body)
            self.assertNotIn(SESSION_TOKEN, body)
            self.assertNotIn("flag{", body)
            self.assertEqual(whoami.status_code, 401)
            self.assertEqual(flag.status_code, 401)

    def test_readiness_includes_complex_web(self):
        checks = {item.lab_id: item for item in check_labs()}
        self.assertIn(checks["complex-web"].status, {"ready", "not_ready"})
        self.assertEqual(checks["complex-web"].requirement, "complex Web/network lab")


if __name__ == "__main__":
    unittest.main()
