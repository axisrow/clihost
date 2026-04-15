"""Tests for cleanup target discovery and deletion helpers."""
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ttydproxy.cleanup import _format_size, delete_cleanup_targets, list_cleanup_targets, summarize_cleanup_targets


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

    def test_size_scan_marks_large_targets_as_approximate(self):
        write_file(self.root / "project-c" / "file.bin", 16)

        with patch("ttydproxy.cleanup._measure_directory_size", return_value=(16, True)):
            target = next(
                item for item in list_cleanup_targets(self.root, self.hapi_home)
                if item["id"] == "project:project-c"
            )

        self.assertTrue(target["size_approximate"])
        self.assertEqual(target["size_human"], "~16 B")

    def test_symlink_target_keeps_original_relative_path(self):
        real_cache = self.root / "cache_data"
        write_file(real_cache / "pip" / "cache.bin", 64)
        symlink_path = self.root / "linked-cache"
        symlink_path.symlink_to(real_cache, target_is_directory=True)

        target = next(
            item for item in list_cleanup_targets(self.root, self.hapi_home)
            if item["id"] == "project:linked-cache"
        )

        self.assertEqual(target["path"], "linked-cache")

    def test_warns_when_hapi_home_is_outside_root(self):
        outside_hapi_home = Path(self.tempdir.name).parent / "external-hapi-home"
        outside_hapi_home.mkdir(exist_ok=True)

        with patch("builtins.print") as mock_print:
            targets = list_cleanup_targets(self.root, outside_hapi_home)

        self.assertNotIn("hapi-home", [target["id"] for target in targets])
        mock_print.assert_called()


class TestFormatSize(unittest.TestCase):
    def test_zero_bytes(self):
        self.assertEqual(_format_size(0), "0 B")

    def test_1023_bytes(self):
        self.assertEqual(_format_size(1023), "1023 B")

    def test_exactly_1024_bytes(self):
        self.assertEqual(_format_size(1024), "1.0 KB")

    def test_one_terabyte(self):
        self.assertEqual(_format_size(1024 ** 4), "1.0 TB")


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

    def test_missing_target_returns_already_removed(self):
        shutil.rmtree(self.root / "project-a")

        result = delete_cleanup_targets(["project:project-a"], self.root, self.hapi_home)

        self.assertEqual(result["deleted"], [])
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            result["skipped"],
            [{"id": "project:project-a", "label": "project-a/", "reason": "already removed"}],
        )

    def test_delete_symlink_target_unlinks_symlink_only(self):
        real_cache = self.root / "cache_data"
        write_file(real_cache / "pip" / "cache.bin", 64)
        symlink_path = self.root / "linked-cache"
        symlink_path.symlink_to(real_cache, target_is_directory=True)

        result = delete_cleanup_targets(["project:linked-cache"], self.root, self.hapi_home)

        self.assertEqual(result["errors"], [])
        self.assertFalse(symlink_path.exists())
        self.assertTrue(real_cache.exists())

    def test_duplicate_ids_are_deleted_once(self):
        result = delete_cleanup_targets(
            ["cache-home", "cache-home", "project:project-a", "project:project-a"],
            self.root,
            self.hapi_home,
        )

        self.assertEqual(
            [item["id"] for item in result["deleted"]],
            ["cache-home", "project:project-a"],
        )

    def test_prune_hapi_home_unlinks_symlink_child(self):
        external_dir = self.root / "external-cache"
        write_file(external_dir / "cache.bin", 32)
        symlink_path = self.hapi_home / "linked-cache"
        symlink_path.symlink_to(external_dir, target_is_directory=True)

        result = delete_cleanup_targets(["hapi-home"], self.root, self.hapi_home)

        self.assertEqual(result["errors"], [])
        self.assertFalse(symlink_path.exists())
        self.assertTrue(external_dir.exists())

    def test_prune_hapi_home_continues_after_child_error(self):
        good_dir = self.hapi_home / "good-dir"
        bad_dir = self.hapi_home / "bad-dir"
        write_file(good_dir / "artifact.bin", 16)
        write_file(bad_dir / "artifact.bin", 16)

        real_rmtree = shutil.rmtree

        def fake_rmtree(path, *args, **kwargs):
            if Path(path).name == "bad-dir":
                raise OSError("permission denied")
            return real_rmtree(path, *args, **kwargs)

        with patch("ttydproxy.cleanup.shutil.rmtree", side_effect=fake_rmtree):
            result = delete_cleanup_targets(["hapi-home"], self.root, self.hapi_home)

        self.assertEqual(result["deleted"], [])
        self.assertEqual(len(result["errors"]), 1)
        self.assertFalse(good_dir.exists())
        self.assertTrue(bad_dir.exists())


if __name__ == "__main__":
    unittest.main()
