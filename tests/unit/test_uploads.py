"""Tests for uploads.py — image sniffing and saving pasted images."""
import os
import pathlib
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch

from ttydproxy.uploads import detect_image_extension, save_upload

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 16
GIF87_BYTES = b"GIF87a" + b"\x00" * 16
GIF89_BYTES = b"GIF89a" + b"\x00" * 16
WEBP_BYTES = b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"\x00" * 16


class TestDetectImageExtension(unittest.TestCase):
    def test_known_formats(self):
        cases = (
            (PNG_BYTES, "png"),
            (JPEG_BYTES, "jpg"),
            (GIF87_BYTES, "gif"),
            (GIF89_BYTES, "gif"),
            (WEBP_BYTES, "webp"),
        )
        for data, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(detect_image_extension(data), expected)

    def test_riff_but_not_webp(self):
        self.assertIsNone(detect_image_extension(b"RIFF\x10\x00\x00\x00WAVEfmt "))

    def test_truncated_webp(self):
        self.assertIsNone(detect_image_extension(b"RIFF\x10\x00"))

    def test_non_images(self):
        for data in (b"", b"#!/bin/sh\necho hi\n", b"<svg xmlns='...'></svg>"):
            with self.subTest(data=data[:10]):
                self.assertIsNone(detect_image_extension(data))


class TestSaveUpload(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        # Hermetic default regardless of who runs the tests: owner lookup
        # fails, so chown is skipped. Owner-specific tests re-patch inside.
        patcher = patch("ttydproxy.uploads.pwd.getpwnam", side_effect=KeyError)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_saves_png_and_returns_absolute_path(self):
        path = save_upload(PNG_BYTES, self.dir, "hapi")
        self.assertTrue(os.path.isabs(path))
        self.assertEqual(pathlib.Path(path).parent, pathlib.Path(self.dir))
        self.assertEqual(pathlib.Path(path).read_bytes(), PNG_BYTES)

    def test_filename_is_generated_not_client_derived(self):
        path = save_upload(PNG_BYTES, self.dir, "hapi")
        name = pathlib.Path(path).name
        self.assertRegex(name, r"^img-\d{8}-\d{6}-[0-9a-f]{8}\.png$")

    def test_extension_follows_magic_bytes(self):
        path = save_upload(WEBP_BYTES, self.dir, "hapi")
        self.assertTrue(path.endswith(".webp"))

    def test_creates_missing_directory(self):
        target = os.path.join(self.dir, "uploads")
        path = save_upload(PNG_BYTES, target, "hapi")
        self.assertTrue(os.path.isdir(target))
        self.assertTrue(os.path.isfile(path))

    def test_chowns_dir_and_file_to_owner(self):
        record = MagicMock()
        record.pw_uid, record.pw_gid = 1234, 5678
        # chown only happens in root mode, and pre-existing directories are
        # deliberately left untouched — save into a missing subdir to exercise
        # both chowns. They go through fchown on the directory and file fds;
        # capture the (uid, gid) of each call (fd values are non-deterministic).
        target = os.path.join(self.dir, "uploads")
        with patch("ttydproxy.uploads.os.geteuid", return_value=0), patch(
            "ttydproxy.uploads.pwd.getpwnam", return_value=record
        ), patch("ttydproxy.uploads.os.fchown") as mock_fchown:
            save_upload(PNG_BYTES, target, "hapi")
        owners = {call.args[1:] for call in mock_fchown.call_args_list}
        self.assertEqual(owners, {(1234, 5678)})
        # Two chowns: one for the created directory fd, one for the file fd.
        self.assertEqual(mock_fchown.call_count, 2)

    def test_unknown_owner_still_saves(self):
        with patch("ttydproxy.uploads.os.geteuid", return_value=0), patch(
            "ttydproxy.uploads.os.fchown"
        ) as mock_fchown:
            path = save_upload(PNG_BYTES, self.dir, "nosuchuser")
        self.assertTrue(os.path.isfile(path))
        mock_fchown.assert_not_called()

    def test_chown_permission_error_still_saves(self):
        record = MagicMock()
        record.pw_uid, record.pw_gid = 1234, 5678
        with patch("ttydproxy.uploads.os.geteuid", return_value=0), patch(
            "ttydproxy.uploads.pwd.getpwnam", return_value=record
        ), patch("ttydproxy.uploads.os.fchown", side_effect=PermissionError):
            path = save_upload(PNG_BYTES, self.dir, "hapi")
        self.assertTrue(os.path.isfile(path))

    def test_nonroot_skips_owner_lookup_and_chown(self):
        # An unprivileged proxy creates entries with the right owner already;
        # the passwd lookup and fchown calls must not happen at all.
        with patch("ttydproxy.uploads.os.geteuid", return_value=1000), patch(
            "ttydproxy.uploads.pwd.getpwnam"
        ) as mock_getpwnam, patch("ttydproxy.uploads.os.fchown") as mock_fchown:
            path = save_upload(PNG_BYTES, self.dir, "hapi")
        self.assertTrue(os.path.isfile(path))
        mock_getpwnam.assert_not_called()
        mock_fchown.assert_not_called()

    def test_rejects_symlinked_upload_dir(self):
        # An attacker replaces the upload dir with a symlink to another dir;
        # save_upload must refuse to follow it (no write, no chown escape).
        victim = os.path.join(self.dir, "victim")
        os.mkdir(victim)
        link = os.path.join(self.dir, "uploads")
        os.symlink(victim, link)
        with self.assertRaises(OSError):
            save_upload(PNG_BYTES, link, "hapi")
        self.assertEqual(os.listdir(victim), [])

    def test_rejects_symlink_planted_as_target_file(self):
        # Even if the directory itself is real, a symlink planted under the
        # generated filename must not be followed (O_NOFOLLOW on the file).
        outside = os.path.join(self.dir, "outside")
        with open(outside, "wb"):
            pass
        fixed_name = "img-20260101-000000-deadbeef.png"
        os.symlink(outside, os.path.join(self.dir, fixed_name))
        with patch(
            "ttydproxy.uploads.secrets.token_hex", return_value="deadbeef"
        ), patch("ttydproxy.uploads.time.strftime", return_value="20260101-000000"):
            with self.assertRaises(OSError):
                save_upload(PNG_BYTES, self.dir, "hapi")
        # The symlink target outside the intended file must stay empty.
        self.assertEqual(os.path.getsize(outside), 0)

    def test_rejects_symlinked_existing_ancestor_swapped_in(self):
        # TOCTOU: the deepest existing ancestor is a real dir when the walk
        # computes it, but an attacker swaps it for a symlink before the anchor
        # is opened. The anchor open must use O_NOFOLLOW so the swap is rejected
        # instead of letting the privileged write/chown escape the tree.
        victim = os.path.join(self.dir, "victim")
        os.mkdir(victim)
        anchor = os.path.join(self.dir, "anchor")
        os.mkdir(anchor)
        target = os.path.join(anchor, "uploads")  # missing leaf -> anchor is `anchor`

        real_open = os.open
        swapped = {"done": False}

        def swapping_open(path, flags, *args, **kwargs):
            # On the first directory open (the anchor, addressed by path string,
            # not a dir_fd), perform the swap to simulate the race, then open.
            if not swapped["done"] and "dir_fd" not in kwargs and path == anchor:
                swapped["done"] = True
                os.rmdir(anchor)
                os.symlink(victim, anchor)
            return real_open(path, flags, *args, **kwargs)

        with patch("ttydproxy.uploads.os.open", side_effect=swapping_open):
            with self.assertRaises(OSError):
                save_upload(PNG_BYTES, target, "hapi")
        # Nothing must have been written through the symlink into the victim.
        self.assertEqual(os.listdir(victim), [])

    def test_non_image_raises_value_error(self):
        with self.assertRaises(ValueError):
            save_upload(b"plain text", self.dir, "hapi")
        self.assertEqual(os.listdir(self.dir), [])

    def test_same_second_saves_get_distinct_paths(self):
        first = save_upload(PNG_BYTES, self.dir, "hapi")
        second = save_upload(PNG_BYTES, self.dir, "hapi")
        self.assertNotEqual(first, second)

    def test_collision_retries_and_succeeds(self):
        # A generated-name collision (O_EXCL FileExistsError) must regenerate a
        # fresh name and retry, not surface as a failed upload (B5). The first
        # token collides with an existing file; the second succeeds.
        with patch("ttydproxy.uploads.time.strftime", return_value="20260101-000000"):
            with patch("ttydproxy.uploads.secrets.token_hex", return_value="deadbeef"):
                first = save_upload(PNG_BYTES, self.dir, "hapi")
            with patch(
                "ttydproxy.uploads.secrets.token_hex",
                side_effect=["deadbeef", "cafe1234"],
            ):
                second = save_upload(PNG_BYTES, self.dir, "hapi")
        self.assertNotEqual(first, second)
        self.assertTrue(second.endswith("img-20260101-000000-cafe1234.png"))
        self.assertEqual(len(os.listdir(self.dir)), 2)

    def test_exhausted_retries_raises(self):
        # If every generated name collides, the bounded retry eventually gives
        # up and raises FileExistsError (rather than looping forever).
        with patch("ttydproxy.uploads.time.strftime", return_value="20260101-000000"):
            with patch("ttydproxy.uploads.secrets.token_hex", return_value="deadbeef"):
                save_upload(PNG_BYTES, self.dir, "hapi")
                with self.assertRaises(FileExistsError):
                    save_upload(PNG_BYTES, self.dir, "hapi")

    def test_concurrent_uploads_into_missing_dir_all_succeed(self):
        # ThreadingHTTPServer runs one thread per request and the client sends
        # up to 5 images per gesture; when uploads/ does not exist yet (fresh
        # container or just cleaned), every thread races to create it. None of
        # them may fail — the directory creation must tolerate the race. The
        # race window is tiny, so repeat across fresh dirs to surface it.
        worker_count = 8
        errors = []
        lock = threading.Lock()

        for attempt in range(40):
            target = os.path.join(self.dir, f"uploads-{attempt}")
            barrier = threading.Barrier(worker_count)

            def worker():
                barrier.wait()
                try:
                    save_upload(PNG_BYTES, target, "hapi")
                except OSError as exc:
                    with lock:
                        errors.append(f"{type(exc).__name__}: {exc}")

            threads = [threading.Thread(target=worker) for _ in range(worker_count)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(
                len(os.listdir(target)), worker_count, f"attempt {attempt}: lost files"
            )

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
