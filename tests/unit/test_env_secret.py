"""Tests for env_secret() — secret lookup with the Docker *_FILE convention."""
import os
import tempfile
import unittest
from unittest.mock import patch

from ttydproxy.security import env_secret


class TestEnvSecret(unittest.TestCase):
    def test_reads_secret_from_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".secret", delete=False) as f:
            f.write("file-secret\n")
            path = f.name
        try:
            with patch.dict(os.environ, {"MY_SECRET_FILE": path}, clear=True):
                self.assertEqual(env_secret("MY_SECRET", "default"), "file-secret")
        finally:
            os.unlink(path)

    def test_file_takes_precedence_over_env(self):
        with tempfile.NamedTemporaryFile("w", suffix=".secret", delete=False) as f:
            f.write("from-file")
            path = f.name
        try:
            env = {"MY_SECRET_FILE": path, "MY_SECRET": "from-env"}
            with patch.dict(os.environ, env, clear=True):
                self.assertEqual(env_secret("MY_SECRET", "default"), "from-file")
        finally:
            os.unlink(path)

    def test_falls_back_to_env_var(self):
        with patch.dict(os.environ, {"MY_SECRET": "env-secret"}, clear=True):
            self.assertEqual(env_secret("MY_SECRET", "default"), "env-secret")

    def test_falls_back_to_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(env_secret("MY_SECRET", "default"), "default")

    def test_unreadable_file_falls_back_to_env(self):
        env = {"MY_SECRET_FILE": "/nonexistent/path", "MY_SECRET": "env-secret"}
        with patch.dict(os.environ, env, clear=True):
            self.assertEqual(env_secret("MY_SECRET", "default"), "env-secret")

    def test_empty_file_falls_back(self):
        with tempfile.NamedTemporaryFile("w", suffix=".secret", delete=False) as f:
            f.write("\n")
            path = f.name
        try:
            with patch.dict(os.environ, {"MY_SECRET_FILE": path}, clear=True):
                self.assertEqual(env_secret("MY_SECRET", "default"), "default")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
