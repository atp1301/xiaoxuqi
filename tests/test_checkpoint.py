import json
import tempfile
import unittest
from pathlib import Path

from harness_mvp.models import RunStatus
from harness_mvp.orchestrator import Orchestrator
from harness_mvp.policy import PolicyEngine
from harness_mvp.tools import DemoLabAdapter


class AlwaysFailAdapter:
    def probe(self, target, path="/"):
        raise RuntimeError("injected interruption")


class CheckpointRecoveryTests(unittest.TestCase):
    def test_failed_step_can_resume_with_a_repaired_adapter(self):
        policy = PolicyEngine()
        with tempfile.TemporaryDirectory() as directory:
            interrupted = Orchestrator(policy=policy, adapter=AlwaysFailAdapter()).run(output_dir=directory)
            self.assertEqual(interrupted.status, RunStatus.FAILED)
            checkpoint = Path(interrupted.checkpoint_path)
            self.assertTrue(checkpoint.is_file())

            resumed = Orchestrator(policy=policy, adapter=DemoLabAdapter(policy)).run(resume_from=checkpoint, output_dir=directory)
            self.assertEqual(resumed.run_id, interrupted.run_id)
            self.assertEqual(resumed.status, RunStatus.COMPLETED)
            self.assertEqual(len(resumed.findings), 3)
            self.assertTrue(any(event.message == "agent started" and event.phase == "recon" for event in resumed.events))
            self.assertTrue(any("injected interruption" in error for error in resumed.errors))

    def test_unsupported_checkpoint_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Orchestrator().run(output_dir=directory)
            checkpoint = Path(state.checkpoint_path)
            payload = json.loads(checkpoint.read_text(encoding="utf-8"))
            payload["schema_version"] = 999
            checkpoint.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checkpoint schema"):
                Orchestrator().run(resume_from=checkpoint, output_dir=directory)


if __name__ == "__main__":
    unittest.main()
