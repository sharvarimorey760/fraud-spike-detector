"""
Tests for env_loader — the dependency-free .env loader shared by the
agent CLI and the dashboard.

Run from the project root:
    pytest
    # or: python -m unittest discover -s tests -t . -v
"""

import os
import tempfile
import unittest

from env_loader import load_dotenv


class LoadDotenvTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.saved = {
            k: os.environ.get(k) for k in ("TEST_DOTENV_ONE", "TEST_DOTENV_TWO")
        }

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _write_env(self, content, name=".env", directory=None):
        directory = directory or self.tmp.name
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def test_loads_key_from_env_file(self):
        self._write_env("TEST_DOTENV_ONE=hello\n")
        loaded = load_dotenv(os.path.join(self.tmp.name, ".env"))
        self.assertEqual(loaded, os.path.join(self.tmp.name, ".env"))
        self.assertEqual(os.environ["TEST_DOTENV_ONE"], "hello")

    def test_never_overrides_existing_environment(self):
        os.environ["TEST_DOTENV_ONE"] = "from-shell"
        self._write_env("TEST_DOTENV_ONE=from-file\n")
        load_dotenv(os.path.join(self.tmp.name, ".env"))
        self.assertEqual(os.environ["TEST_DOTENV_ONE"], "from-shell")

    def test_ignores_comments_blank_lines_and_quotes(self):
        self._write_env(
            "# comment line\n"
            "\n"
            'TEST_DOTENV_ONE="quoted value"\n'
            "TEST_DOTENV_TWO='also quoted'\n"
        )
        load_dotenv(os.path.join(self.tmp.name, ".env"))
        self.assertEqual(os.environ["TEST_DOTENV_ONE"], "quoted value")
        self.assertEqual(os.environ["TEST_DOTENV_TWO"], "also quoted")

    def test_strips_inline_comments_on_unquoted_values(self):
        self._write_env("TEST_DOTENV_ONE=abc123 # keep me\n")
        load_dotenv(os.path.join(self.tmp.name, ".env"))
        self.assertEqual(os.environ["TEST_DOTENV_ONE"], "abc123")

    def test_returns_none_when_no_env_file(self):
        self.assertIsNone(load_dotenv(os.path.join(self.tmp.name, "missing.env")))

    def test_walks_up_parent_directories(self):
        # .env lives in tmp, but we load from a nested subdirectory below it.
        self._write_env("TEST_DOTENV_ONE=found-upstream\n")
        nested = os.path.join(self.tmp.name, "agent")
        os.makedirs(nested, exist_ok=True)
        old_cwd = os.getcwd()
        try:
            os.chdir(nested)
            loaded = load_dotenv()
        finally:
            os.chdir(old_cwd)
        self.assertEqual(loaded, os.path.join(self.tmp.name, ".env"))
        self.assertEqual(os.environ["TEST_DOTENV_ONE"], "found-upstream")

    def test_explicit_path_to_nonexistent_file_is_none(self):
        self.assertIsNone(load_dotenv("/definitely/not/here/.env"))


if __name__ == "__main__":
    unittest.main()