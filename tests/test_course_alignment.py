import tempfile
import unittest
from harness_mvp.agents import CodeAuditAgent, EnvReproAgent, PostExploitAgent
from harness_mvp.knowledge import KNOWLEDGE_CATEGORIES, KnowledgeBase
from harness_mvp.models import AgentStatus, OPERATOR_GOAL, RunState, RunStatus
from harness_mvp.orchestrator import OPERATOR_ROLE, Orchestrator
from harness_mvp.policy import PolicyEngine, PolicyViolation, parse_target
from harness_mvp.tools import TOOL_REGISTRY, get_tool


class CourseAlignmentTests(unittest.TestCase):
    def test_seven_specialist_agents_and_operator_tree(self):
        orch = Orchestrator(mode="deterministic")
        plan = orch.plan()
        self.assertEqual([step.agent for step in plan], [
            "recon", "code_audit", "env_repro", "vuln", "exploit", "post_exploit", "report",
        ])
        self.assertTrue(all(step.parent_id == "goal" for step in plan))
        tree = orch.task_tree()
        self.assertEqual(tree[0].agent, "operator")
        self.assertEqual(tree[0].step_id, OPERATOR_GOAL.step_id)
        self.assertEqual(len(tree), 8)
        self.assertIn("code_audit", orch.agents)
        self.assertIn("env_repro", orch.agents)
        self.assertIn("post_exploit", orch.agents)
        self.assertNotIn("operator", orch.agents)
        self.assertIn("Operator", OPERATOR_ROLE)

    def test_demo_run_records_react_memory_and_simulated_post_exploit(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Orchestrator(mode="deterministic").run(output_dir=directory)
        self.assertEqual(state.status, RunStatus.COMPLETED)
        self.assertEqual(len(state.findings), 3)
        phases = [event.phase for event in state.events]
        self.assertIn("thought", phases)
        self.assertIn("action", phases)
        self.assertIn("observation", phases)
        self.assertIn("operator", phases)
        self.assertGreaterEqual(len(state.episodic_memory), 7)
        self.assertEqual(state.working_memory["current_goal"], "complete attack-chain assessment")
        self.assertIs(state.facts, state.working_memory)
        self.assertIn("execute", str(state.facts["code_audit"]))
        self.assertEqual(state.facts["env_repro"]["environment_id"], "demo-in-process")
        self.assertTrue(state.facts["post_exploit"]["simulated"])
        self.assertFalse(state.facts["post_exploit"]["executed"])
        agents = [item.agent for item in state.agent_results if item.status != AgentStatus.FAILED]
        self.assertEqual(agents[-1], "report")
        self.assertTrue(any(item.agent == "code_audit" for item in state.agent_results))

    def test_code_audit_marks_concatenated_execute_as_tainted(self):
        agent = CodeAuditAgent(PolicyEngine())
        state = RunState(target=parse_target("demo.local"), scenario="demo")
        result = agent.run(state)
        self.assertEqual(result.status, AgentStatus.SUCCESS)
        sinks = state.facts["code_audit"]["sinks"]
        self.assertTrue(any(item["sink"] == "execute" and item["tainted"] for item in sinks))

    def test_env_repro_reads_local_web_manifest(self):
        agent = EnvReproAgent(PolicyEngine())
        state = RunState(target=parse_target("http://127.0.0.1:18088"), scenario="local-web")
        result = agent.run(state)
        self.assertEqual(result.status, AgentStatus.SUCCESS)
        self.assertEqual(state.facts["env_repro"]["environment_id"], "local-training-web-v1")
        self.assertIn("docker compose", state.facts["env_repro"]["start_command"])

    def test_post_exploit_skips_without_foothold(self):
        agent = PostExploitAgent(PolicyEngine())
        state = RunState(target=parse_target("demo.local"), scenario="demo")
        result = agent.run(state)
        self.assertEqual(result.status, AgentStatus.SKIPPED)
        self.assertTrue(state.facts["post_exploit"]["simulated"])

    def test_tool_registry_blocks_stubs_and_lists_implemented_tools(self):
        self.assertEqual(get_tool("nmap_scan").status, "stub")
        with self.assertRaises(PolicyViolation):
            PolicyEngine().require_action("nmap_scan", "demo.local")
        PolicyEngine().require_action("code_audit_scan", "demo.local")
        categories = {item.category for item in TOOL_REGISTRY.values()}
        self.assertEqual(categories, {"recon", "exploit", "post-exploit"})

    def test_knowledge_has_four_rag_categories(self):
        kb = KnowledgeBase(include_report_cases=False)
        found = {entry.category for entry in kb.entries}
        self.assertEqual(KNOWLEDGE_CATEGORIES, ("cve", "ttp", "payload", "case"))
        self.assertTrue(set(KNOWLEDGE_CATEGORIES).issubset(found))
        self.assertEqual(kb.search("ATT&CK T1021 lateral movement", category="ttp")[0].entry_id, "T1021")
        self.assertEqual(kb.search("SQLite differential probe template", category="payload")[0].category, "payload")
        self.assertEqual(kb.search("complex-web success case flag", category="case")[0].category, "case")
        self.assertTrue(any(entry.entry_id.startswith("CVE-") for entry in kb.entries))
