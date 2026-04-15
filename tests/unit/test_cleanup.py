"""Tests for cleanup target discovery and deletion helpers."""
import os
import tempfile
import unittest
from pathlib import Path

from ttydproxy.cleanup import delete_cleanup_targets, list_cleanup_targets, summarize_cleanup_targets


def write_file(path, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)


class TestCleanupTargets(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.hapi_home = self.root / ".hapi"

        write_file(self.hapi_home / "server.log", 10)
        write_file(self.hapi_home / "settings.json", 10)
        write_file(self.hapi_home / "trash" / "artifact.bin", 64)
        write_file(self.root / "runtime" / "runtime.sock", 32)
        write_file(self.root / ".cache" / "pip" / "cache.bin", 128)
        write_file(self.root / ".npm" / "cache.db", 96)
        write_file(self.root / ".local" / "share" / "uv" / "index.db", 48)
        write_file(self.root / "project-a" / "node_modules" / "pkg.bin", 256)
        write_file(self.root / "project-b" / "venv" / "pkg.bin", 512)
        write_file(self.root / ".config" / "ignored.txt", 12)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_lists_static_and_project_targets(self):
        targets = list_cleanup_targets(self.root, self.hapi_home)
        target_ids = [target["id"] for target in targets]

        self.assertIn("hapi-home", target_ids)
        self.assertIn("runtime", target_ids)
        self.assertIn("cache-home", target_ids)
        self.assertIn("npm-cache", target_ids)
        self.assertIn("local-share", target_ids)
        self.assertIn("project:project-a", target_ids)
        self.assertIn("project:project-b", target_ids)
        self.assertNotIn("project:.config", target_ids)

        project_b = next(target for target in targets if target["id"] == "project:project-b")
        self.assertEqual(project_b["category"], "project")
        self.assertEqual(project_b["risk"], "high")
        self.assertTrue(project_b["size_bytes"] >= 512)

    def test_skips_targets_resolving_outside_root(self):
        outside = Path(self.tempdir.name).parent / "outside-cleanup-target"
        outside.mkdir(exist_ok=True)
        write_file(outside / "large.bin", 1024)
        os.symlink(outside, self.root / "linked-project")

        targets = list_cleanup_targets(self.root, self.hapi_home)
        target_ids = [target["id"] for target in targets]

        self.assertNotIn("project:linked-project", target_ids)

    def test_summarize_cleanup_targets(self):
        summary = summarize_cleanup_targets(list_cleanup_targets(self.root, self.hapi_home))
        self.assertGreater(summary["count"], 0)
        self.assertGreater(summary["total_size_bytes"], 0)
        self.assertTrue(summary["total_size_human"])


class TestCleanupDeletion(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.hapi_home = self.root / ".hapi"

        write_file(self.hapi_home / "server.log", 10)
        write_file(self.hapi_home / "settings.json", 10)
        write_file(self.hapi_home / "runner.state.json", 10)
        write_file(self.hapi_home / "trash" / "artifact.bin", 64)
        write_file(self.root / ".cache" / "pip" / "cache.bin", 128)
        write_file(self.root / "project-a" / "node_modules" / "pkg.bin", 256)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_delete_cleanup_targets_prunes_hapi_and_removes_projects(self):
        result = delete_cleanup_targets(
            ["hapi-home", "cache-home", "project:project-a"],
            self.root,
            self.hapi_home,
        )

        self.assertEqual(result["errors"], [])
        self.assertEqual(
            [item["id"] for item in result["deleted"]],
            ["hapi-home", "cache-home", "project:project-a"],
        )
        self.assertTrue((self.hapi_home / "server.log").exists())
        self.assertTrue((self.hapi_home / "settings.json").exists())
        self.assertTrue((self.hapi_home / "runner.state.json").exists())
        self.assertFalse((self.hapi_home / "trash").exists())
        self.assertFalse((self.root / ".cache").exists())
        self.assertFalse((self.root / "project-a").exists())

    def test_unknown_target_is_skipped(self):
        result = delete_cleanup_targets(["unknown-target"], self.root, self.hapi_home)
        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["skipped"], [{"id": "unknown-target", "reason": "unknown target"}])


if __name__ == "__main__":
    unittest.main()
