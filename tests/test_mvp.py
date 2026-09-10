import json
import tempfile
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
            state = Orchestrator().run(output_dir=directory)
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
                state = Orchestrator(adapter=HttpLabAdapter()).run(target, "local-web", directory)
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
                state = Orchestrator(adapter=HttpLabAdapter()).run(target, "local-web", directory)
                self.assertEqual(state.status, RunStatus.COMPLETED)
                self.assertEqual(state.findings, [])
                self.assertEqual(state.agent_results[2].status, AgentStatus.SKIPPED)
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
        self.assertEqual(LLMClient(ModelConfig(api_key="x", base_url="http://127.0.0.1", model="m"), timeout=999).timeout, 120.0)

    def test_react_retries_a_transient_agent_failure(self):
        from harness_mvp.tools import DemoLabAdapter

        policy = PolicyEngine()
        state = Orchestrator(policy=policy, adapter=FlakyAdapter(DemoLabAdapter(policy))).run(output_dir=tempfile.mkdtemp())
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertTrue(any(event.message == "agent failed; retrying" for event in state.events))

    def test_checkpoint_resume_reuses_run_and_skips_completed_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Orchestrator().run(output_dir=directory)
            checkpoint = Path(first.checkpoint_path)
            self.assertTrue(checkpoint.exists())
            resumed = Orchestrator().run(resume_from=checkpoint, output_dir=directory)
            self.assertEqual(resumed.run_id, first.run_id)
            self.assertEqual(resumed.status, RunStatus.COMPLETED)
            self.assertTrue(any("restored from checkpoint" in event.message for event in resumed.events))
            report = json.loads(Path(resumed.report_paths["json"]).read_text(encoding="utf-8"))
            self.assertIn("agent_results", report)
            self.assertEqual(report["checkpoint"]["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()

