import unittest
from harness_mvp.services import (
    check_port,
    check_http,
    check_system_health,
    start_local_services,
    run_goad_requirement_test,
    run_exploitgym_requirement_test,
    run_complex_web_requirement_test,
)


class ServicesTests(unittest.TestCase):
    def test_check_system_health_structure(self):
        health = check_system_health()
        self.assertIn("timestamp", health)
        self.assertIn("verdict", health)
        self.assertIn(health["verdict"], {"HEALTHY", "DEGRADED", "UNHEALTHY"})
        self.assertIn("local_node", health)
        self.assertIn("distributed_nodes", health)
        self.assertEqual(len(health["distributed_nodes"]), 2)

    def test_requirement_evaluators(self):
        goad = run_goad_requirement_test()
        self.assertEqual(goad["requirement_id"], "req-1-goad")
        self.assertIn("domain_topology", goad)
        self.assertIn("attack_path", goad)

        eg = run_exploitgym_requirement_test()
        self.assertEqual(eg["requirement_id"], "req-2-exploitgym")
        self.assertIn("task_1_specified", eg)
        self.assertIn("task_2_custom", eg)
        self.assertEqual(eg["task_1_specified"]["task_id"], "v8:sbxbrk/398773898")

        cw = run_complex_web_requirement_test()
        self.assertEqual(cw["requirement_id"], "req-3-complex-web")
        self.assertEqual(cw["target"], "http://127.0.0.1:18089")
        self.assertIn("FLAG{", cw["ground_truth_flag"])

    def test_start_local_services_idempotent(self):
        res = start_local_services("complex-web")
        self.assertIn("success", res)
        self.assertTrue(res["success"])


if __name__ == "__main__":
    unittest.main()
