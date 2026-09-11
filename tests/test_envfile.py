import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness_mvp.envfile import load_env_file


class EnvFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def write(self, text: str, name: str = ".env") -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_real_environment_wins_over_file(self):
        path = self.write("HARNESS_LLM_TIMEOUT=1\nHARNESS_FRESH_KEY=from-file\n")
        with patch.dict(os.environ, {"HARNESS_LLM_TIMEOUT": "999"}, clear=False):
            os.environ.pop("HARNESS_FRESH_KEY", None)
            applied = load_env_file(path)
            self.assertEqual(os.environ["HARNESS_LLM_TIMEOUT"], "999")
            self.assertNotIn("HARNESS_LLM_TIMEOUT", applied)
            self.assertEqual(os.environ["HARNESS_FRESH_KEY"], "from-file")
            self.assertIn("HARNESS_FRESH_KEY", applied)
        os.environ.pop("HARNESS_FRESH_KEY", None)

    def test_returned_names_never_contain_values(self):
        secret = "sk-live-should-never-surface"
        path = self.write(f"HARNESS_LLM_API_KEY={secret}\n")
        os.environ.pop("HARNESS_LLM_API_KEY", None)
        try:
            applied = load_env_file(path)
        finally:
            os.environ.pop("HARNESS_LLM_API_KEY", None)
        self.assertEqual(applied, ["HARNESS_LLM_API_KEY"])
        self.assertNotIn(secret, " ".join(applied))

    def test_quotes_comments_and_malformed_lines_are_tolerated(self):
        path = self.write(
            "\n".join([
                "# a comment",
                "",
                "export HARNESS_QUOTED=\"double value\"",
                "HARNESS_SINGLE='single value'",
                "HARNESS_INLINE=plain value  ",
                "=no-key",
                "NOT A PAIR",
                "1INVALID=x",
            ])
        )
        for name in ("HARNESS_QUOTED", "HARNESS_SINGLE", "HARNESS_INLINE"):
            os.environ.pop(name, None)
        try:
            applied = load_env_file(path)
            self.assertEqual(os.environ["HARNESS_QUOTED"], "double value")
            self.assertEqual(os.environ["HARNESS_SINGLE"], "single value")
            self.assertEqual(os.environ["HARNESS_INLINE"], "plain value")
            self.assertEqual(sorted(applied), ["HARNESS_INLINE", "HARNESS_QUOTED", "HARNESS_SINGLE"])
        finally:
            for name in ("HARNESS_QUOTED", "HARNESS_SINGLE", "HARNESS_INLINE"):
                os.environ.pop(name, None)

    def test_value_may_contain_equals_signs(self):
        path = self.write("HARNESS_URL=https://example.test/v1?a=b\n")
        os.environ.pop("HARNESS_URL", None)
        try:
            load_env_file(path)
            self.assertEqual(os.environ["HARNESS_URL"], "https://example.test/v1?a=b")
        finally:
            os.environ.pop("HARNESS_URL", None)

    def test_missing_file_is_a_noop(self):
        self.assertEqual(load_env_file(self.root / "absent"), [])

    def test_directory_is_a_noop(self):
        self.assertEqual(load_env_file(self.root), [])


if __name__ == "__main__":
    unittest.main()
