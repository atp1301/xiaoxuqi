import json
import tempfile
import time
import unittest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock

from harness_mvp.models import AgentStatus, Finding, RunStatus
from harness_mvp.orchestrator import Orchestrator
from harness_mvp.policy import PolicyEngine, PolicyViolation, parse_target
from harness_mvp.tools import SafeCommandRunner
from harness_mvp.tools import HttpLabAdapter
from harness_mvp.labs import check_labs
from harness_mvp.llm import LLMClient, ModelConfig
from harness_mvp.agents import ExploitAgent
from lab.app import Handler


class FlakyAdapter:
    def __init__(self, delegate):
        self.delegate = delegate
        self.failed = False

    def probe(self, target, path="/"):
        if not self.failed:
            self.failed = True
            raise RuntimeError("transient lab timeout")
        return self.delegate.probe(target, path)


class HarnessMvpTests(unittest.TestCase):
    def test_demo_run_produces_findings_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(mode="deterministic").run(output_dir=directory)
            self.assertEqual(state.status, RunStatus.COMPLETED)
            self.assertEqual(len(state.findings), 3)
            self.assertEqual(state.agent_results[-1].status, AgentStatus.SUCCESS)
            self.assertTrue(Path(state.report_paths["markdown"]).exists())
            payload = json.loads(Path(state.report_paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["finding_count"], 3)

    def test_policy_blocks_out_of_scope_and_shell(self):
        with self.assertRaises(PolicyViolation):
            PolicyEngine().require_target("https://example.com")
        with self.assertRaises(PolicyViolation):
            SafeCommandRunner().run(["python", "-c", "print('unsafe')"])

    def test_target_parser_accepts_allowed_forms(self):
        target = parse_target("http://127.0.0.1:8080")
        self.assertEqual(target.host, "127.0.0.1")
        self.assertEqual(target.port, 8080)

    def test_local_http_adapter_runs_full_chain_against_local_lab(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = f"http://127.0.0.1:{server.server_port}"
                state = Orchestrator(mode="deterministic", adapter=HttpLabAdapter()).run(target, "local-web", directory)
                self.assertEqual(state.status, RunStatus.COMPLETED)
                self.assertEqual(len(state.findings), 1)
                self.assertEqual(state.findings[0].source, "http-lab")
                self.assertTrue(state.findings[0].metadata["validation"]["status"] == "verified")
                self.assertEqual(state.findings[0].metadata["validation"]["baseline_count"], 1)
                self.assertGreater(state.findings[0].metadata["validation"]["positive_count"], 1)
                self.assertEqual(state.findings[0].metadata["validation"]["negative_count"], 0)
                self.assertEqual(state.exploit_results[0]["status"], "verified")
                self.assertEqual(state.facts["endpoints"][1]["source"], "http-lab")
                self.assertTrue(state.facts["sqlite_sqli_differential"]["verified"])
        finally:
            server.shutdown()
            server.server_close()

    def test_local_lab_parameterized_repair_does_not_expose_proof(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        Handler.fixed = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                target = f"http://127.0.0.1:{server.server_port}"
                state = Orchestrator(mode="deterministic", adapter=HttpLabAdapter()).run(target, "local-web", directory)
                self.assertEqual(state.status, RunStatus.COMPLETED)
                self.assertEqual(state.findings, [])
                self.assertEqual(next(item.status for item in state.agent_results if item.agent == "exploit"), AgentStatus.SKIPPED)
                self.assertFalse(state.facts["sqlite_sqli_differential"]["verified"])
        finally:
            Handler.fixed = False
            server.shutdown()
            server.server_close()

    def test_exploit_validation_exception_marks_agent_failed(self):
        agent = ExploitAgent(PolicyEngine())
        adapter = MagicMock(spec=HttpLabAdapter)
        adapter.validate_sqlite_sqli.side_effect = RuntimeError("probe boom")
        agent.adapter = adapter
        state = MagicMock()
        state.findings = [
            Finding(
                "F-001",
                "SQLite SQL injection",
                "high",
                "desc",
                "/search",
                "evidence",
                "fix",
                "CWE-89",
                0.8,
                False,
                "http-lab",
                {},
            )
        ]
        state.scenario = "local-web"
        state.target = parse_target("http://127.0.0.1:8088")
        state.exploit_results = []
        result = agent.run(state)
        self.assertEqual(result.status, AgentStatus.FAILED)
        self.assertEqual(state.exploit_results[0]["status"], "failed")
        self.assertIn("probe boom", result.errors[0])

    def test_lab_readiness_check_is_read_only_and_explicit(self):
        checks = {item.lab_id: item for item in check_labs()}
        self.assertIn(checks["docker"].status, {"ready", "blocked"})
        self.assertIn(checks["goad"].status, {"not_configured", "not_ready", "ready"})
        self.assertIn(checks["exploitgym"].status, {"not_configured", "not_ready", "ready"})
        self.assertIn(checks["vulhub"].status, {"not_configured", "not_ready", "ready"})
        self.assertIn(checks["complex-web"].status, {"ready", "not_ready"})

    def test_llm_config_is_optional_and_key_is_not_serialized(self):
        config = ModelConfig(api_key="secret", base_url="http://127.0.0.1:9/v1", model="test")
        self.assertTrue(config.configured)
        self.assertNotIn("secret", repr(config))

    def test_openai_compatible_client_parses_json_advisory(self):
        class MockModelHandler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers["Content-Length"])
                self.rfile.read(length)
                body = json.dumps({"choices": [{"message": {"content": json.dumps({"risk_summary": "evidence", "recommended_next_step": "review", "confidence": 0.8})}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), MockModelHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = LLMClient(ModelConfig(api_key="secret", base_url=f"http://127.0.0.1:{server.server_port}/v1", model="mock"))
            advisory = client.advisory("http://127.0.0.1", [{"path": "/health", "status_code": 200}])
            self.assertEqual(advisory["recommended_next_step"], "review")
        finally:
            server.shutdown()
            server.server_close()

    def test_llm_timeout_is_bounded(self):
        self.assertEqual(LLMClient(ModelConfig(api_key="x", base_url="http://127.0.0.1", model="m"), timeout=999).timeout, 300.0)


class FakeModelTests(unittest.TestCase):
    """End-to-end runs against a scripted OpenAI-compatible endpoint.

    The fake dispatches on `prompt_version`, so one server answers both call
    sites and the run exercises the real code path rather than a stub.
    """

    def serve_model(self, reply=None, raw_content=None, delay=0.0, timeout=30.0):
        """Start a fake model; `reply(prompt) -> dict` decides each response."""
        def content_for(request_body):
            if raw_content is not None:
                return raw_content
            prompt = json.loads(request_body["messages"][1]["content"])
            return json.dumps(reply(prompt))

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers["Content-Length"])
                request_body = json.loads(self.rfile.read(length).decode("utf-8"))
                if delay:
                    time.sleep(delay)
                body = json.dumps(
                    {"choices": [{"message": {"content": content_for(request_body)}}]}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    # The timeout test hangs up mid-response on purpose; the
                    # resulting socket error is expected, not a test failure.
                    pass

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return LLMClient(
            ModelConfig(api_key="secret", base_url=f"http://127.0.0.1:{server.server_port}/v1", model="fake-model"),
            timeout=timeout,
        )

    @staticmethod
    def cooperative(prompt):
        if prompt.get("prompt_version") == "interpretation-v1":
            return {"interpretations": [
                {
                    "finding_id": brief["finding_id"],
                    "severity": "critical",
                    "confidence": 0.95,
                    "narrative": f"model reading for {brief['finding_id']}",
                }
                for brief in prompt.get("findings", [])
            ]}
        return {
            "overall_risk": "high",
            "executive_summary": "One confirmed injection reachable from the public edge.",
            "prioritized_actions": ["parameterize the search query"],
            "limitations": ["single-host scope"],
        }

    def run_local_web(self, client, directory):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            target = f"http://127.0.0.1:{server.server_port}"
            return Orchestrator(mode="llm", llm=client, adapter=HttpLabAdapter()).run(
                target, "local-web", directory
            )
        finally:
            server.shutdown()
            server.server_close()

    def test_model_grading_is_applied_at_both_call_sites(self):
        client = self.serve_model(self.cooperative)
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
            # Read the reports while the temp directory is still alive.
            report = json.loads(Path(state.report_paths["json"]).read_text(encoding="utf-8"))
            markdown = Path(state.report_paths["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(state.status, RunStatus.COMPLETED)
        fact = state.facts["llm_findings_interpretation"]
        self.assertTrue(fact["available"])
        self.assertEqual(fact["applied"], ["F-001"])
        self.assertEqual(fact["model"], "fake-model")
        self.assertEqual(len(fact["raw_sha256"]), 64)

        finding = state.findings[0]
        self.assertEqual(finding.metadata["severity_source"], "model")
        self.assertNotEqual(finding.severity, finding.metadata["severity_baseline"])
        self.assertEqual(finding.metadata["severity_baseline"], "high")
        self.assertEqual(finding.metadata["confidence_source"], "measured_differential_band")
        self.assertEqual(finding.confidence, 0.95)
        self.assertIn("model reading", finding.metadata["interpretation"]["narrative"])

        brief = state.facts["llm_risk_brief"]
        self.assertTrue(brief["available"])
        self.assertEqual(brief["content"]["overall_risk"], "high")

        self.assertEqual(report["interpretation"]["risk_brief"]["content"]["overall_risk"], "high")
        self.assertIn("not evidence", markdown)
        self.assertIn("model interpretation", markdown)
        self.assertIn("model reading for F-001", markdown)
        self.assertIn("- Agent mode: `llm`", markdown)

    def test_a_verified_exploit_survives_a_model_that_understates_it(self):
        """The measurement is authoritative: the model cannot clear `exploitable`."""
        def hostile(prompt):
            if prompt.get("prompt_version") == "interpretation-v1":
                return {"interpretations": [
                    {
                        "finding_id": brief["finding_id"],
                        "severity": "low",
                        "confidence": 0.0,
                        "narrative": "not really exploitable",
                    }
                    for brief in prompt.get("findings", [])
                ]}
            return {"overall_risk": "info", "executive_summary": "nothing to see"}

        client = self.serve_model(hostile)
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)

        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertTrue(state.facts["sqlite_sqli_differential"]["verified"])
        finding = state.findings[0]
        self.assertTrue(finding.exploitable, "verification came from the probe, not the model")
        self.assertEqual(finding.metadata["validation"]["status"], "verified")
        # `low` is outside the verified band, so the item is dropped outright.
        self.assertEqual(state.facts["llm_findings_interpretation"]["applied"], [])
        self.assertEqual(state.facts["llm_findings_interpretation"]["rejected"][0]["reason"],
                         "severity_outside_evidence_band")
        self.assertEqual(finding.metadata["severity_source"], "deterministic")
        self.assertGreaterEqual(finding.confidence, 0.90)
        self.assertLessEqual(finding.confidence, 0.99)

    def test_an_injected_finding_is_impossible_to_add(self):
        def injector(prompt):
            if prompt.get("prompt_version") == "interpretation-v1":
                return {"interpretations": [
                    {
                        "finding_id": brief["finding_id"],
                        "severity": "critical",
                        "confidence": 0.99,
                        "narrative": "keep the real one",
                        "exploitable": False,
                        "validation": {"status": "failed"},
                    }
                    for brief in prompt.get("findings", [])
                ] + [{
                    "finding_id": "F-999",
                    "severity": "critical",
                    "confidence": 0.99,
                    "narrative": "invented",
                    "exploitable": True,
                    "endpoint": "/invented",
                }]}
            return {"overall_risk": "critical", "executive_summary": "escalated by injection",
                    "findings": [{"finding_id": "F-999", "severity": "critical"}]}

        client = self.serve_model(injector)
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
            report = json.loads(Path(state.report_paths["json"]).read_text(encoding="utf-8"))

        self.assertEqual([f.finding_id for f in state.findings], ["F-001"])
        self.assertEqual(len(state.findings), 1)
        self.assertEqual(state.findings[0].endpoint, "/search")
        self.assertEqual(len(state.exploit_results), 1)
        self.assertNotIn("F-999", json.dumps(report["findings"]))
        self.assertNotIn("F-999", json.dumps(report["exploit_results"]))

    def test_the_key_never_reaches_a_report(self):
        client = self.serve_model(self.cooperative)
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
            report_text = Path(state.report_paths["json"]).read_text(encoding="utf-8")
            markdown = Path(state.report_paths["markdown"]).read_text(encoding="utf-8")
        self.assertNotIn("secret", report_text)
        self.assertNotIn("secret", markdown)
        self.assertNotIn("Bearer", report_text)

    def test_a_malformed_model_response_degrades_instead_of_failing_the_run(self):
        client = self.serve_model(raw_content="I am not JSON at all.")
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
            markdown = Path(state.report_paths["markdown"]).read_text(encoding="utf-8")

        self.assertEqual(state.status, RunStatus.COMPLETED, "a broken model must not fail the assessment")
        fact = state.facts["llm_findings_interpretation"]
        self.assertFalse(fact["available"])
        self.assertIn("error", fact)
        self.assertIsNotNone(fact["error"])
        self.assertEqual(state.working_memory["llm_status"]["available"], False)
        finding = state.findings[0]
        self.assertEqual(finding.metadata["severity_source"], "deterministic")
        self.assertTrue(finding.exploitable)
        self.assertIn("deterministic grading retained", markdown)
        self.assertIn("Model risk brief unavailable", markdown)

    def test_a_timed_out_model_call_degrades(self):
        client = self.serve_model(self.cooperative, delay=3.0, timeout=5.0)
        client.timeout = 1.0
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertFalse(state.facts["llm_findings_interpretation"]["available"])

    def test_render_markdown_tolerates_a_non_numeric_confidence(self):
        from harness_mvp.report import build_report, render_markdown

        with tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(mode="deterministic").run(output_dir=directory)
        report = build_report(state)
        report["findings"][0]["confidence"] = "high"
        rendered = render_markdown(report)
        self.assertIn("Harness MVP Security Assessment", rendered)
        self.assertIn("0%", rendered)

    def test_the_report_says_so_when_a_requested_model_never_answered(self):
        """Mode `llm` with every call failing must not read as participation."""
        client = self.serve_model(raw_content="not json")
        with tempfile.TemporaryDirectory() as directory:
            state = self.run_local_web(client, directory)
            markdown = Path(state.report_paths["markdown"]).read_text(encoding="utf-8")
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertIn("model was called but every call failed", markdown)
        self.assertNotIn("model participated; interpretation is labelled", markdown)

    def test_deterministic_mode_makes_no_model_call(self):
        """Hermeticity: with no client attached, nothing may reach the network."""
        client = self.serve_model(self.cooperative)
        with tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(mode="deterministic", llm=client).run(output_dir=directory)
        self.assertIsNone(state.facts.get("llm_findings_interpretation"))
        self.assertIsNone(state.facts.get("llm_risk_brief"))
        self.assertEqual(state.working_memory["agent_mode"]["effective"], "deterministic")
        self.assertEqual(state.status, RunStatus.COMPLETED)

    def test_react_retries_a_transient_agent_failure(self):
        from harness_mvp.tools import DemoLabAdapter

        policy = PolicyEngine()
        state = Orchestrator(mode="deterministic", policy=policy, adapter=FlakyAdapter(DemoLabAdapter(policy))).run(output_dir=tempfile.mkdtemp())
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertTrue(any(event.message == "agent failed; retrying" for event in state.events))

    def test_checkpoint_resume_reuses_run_and_skips_completed_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Orchestrator(mode="deterministic").run(output_dir=directory)
            checkpoint = Path(first.checkpoint_path)
            self.assertTrue(checkpoint.exists())
            resumed = Orchestrator(mode="deterministic").run(resume_from=checkpoint, output_dir=directory)
            self.assertEqual(resumed.run_id, first.run_id)
            self.assertEqual(resumed.status, RunStatus.COMPLETED)
            self.assertTrue(any("restored from checkpoint" in event.message for event in resumed.events))
            report = json.loads(Path(resumed.report_paths["json"]).read_text(encoding="utf-8"))
            self.assertIn("agent_results", report)
            self.assertEqual(report["checkpoint"]["schema_version"], 2)


if __name__ == "__main__":
    unittest.main()

