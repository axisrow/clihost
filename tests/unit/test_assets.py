"""A single missing static asset must not take down the whole proxy (B18).

assets.py eagerly loads the injected scripts and the favicons at import time.
load_template (views.py) degrades gracefully on a missing file; the asset
loaders must follow a consistent contract:
  - a missing *decorative* favicon degrades (the route/link is dropped), the
    proxy still imports and serves login/terminal/health;
  - a missing *required* asset (tab_fix_script, vkbd) fails fast with a clear
    error naming the file, not a bare deep traceback.

The import is exercised in a fresh subprocess against a COPY of app/ so we never
touch the repo tree and never collide with already-imported modules.
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_APP = REPO_ROOT / "app"


class AssetDegradationTest(unittest.TestCase):
    def _run_import(self, app_dir, probe):
        """Import ttydproxy.app from app_dir in a subprocess, then run probe.

        probe is python source that may print markers / sys.exit(nonzero).
        Returns the CompletedProcess.
        """
        lines = [
            "import sys",
            f"sys.path.insert(0, {str(app_dir)!r})",
            "try:",
            "    from ttydproxy import app",
            "except Exception as exc:",
            '    print("IMPORT_FAILED:" + type(exc).__name__ + ":" + str(exc))',
            "    sys.exit(3)",
        ]
        lines.extend(probe.splitlines())
        script = "\n".join(lines)
        return subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True
        )

    def _fresh_copy(self):
        tmp = tempfile.mkdtemp(prefix="b18_")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        dst = os.path.join(tmp, "app")
        shutil.copytree(SRC_APP, dst)
        return dst

    def test_all_assets_present_imports_cleanly(self):
        app_dir = self._fresh_copy()
        probe = (
            "print('ROUTES:' + ','.join(sorted(app.FAVICON_ROUTES.keys())))"
        )
        result = self._run_import(app_dir, probe)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("/favicon.ico", result.stdout)
        self.assertIn("/favicon-16x16.png", result.stdout)

    def test_missing_favicon_degrades_not_crash(self):
        app_dir = self._fresh_copy()
        os.remove(os.path.join(app_dir, "assets", "favicon-16x16.png"))
        probe = (
            "print('ROUTES:' + ','.join(sorted(app.FAVICON_ROUTES.keys())))\n"
            "from ttydproxy import views\n"
            "print('LINKS:' + views.FAVICON_LINKS)"
        )
        result = self._run_import(app_dir, probe)
        # Import must SUCCEED despite the missing decorative file.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # The missing favicon's route must be dropped, others kept.
        self.assertNotIn("/favicon-16x16.png", result.stdout)
        self.assertIn("/favicon.ico", result.stdout)
        # And its <link> must not be advertised.
        self.assertNotIn("favicon-16x16.png", result.stdout.split("LINKS:")[1])

    def test_missing_required_asset_raises_clear_error(self):
        app_dir = self._fresh_copy()
        os.remove(os.path.join(app_dir, "assets", "tab_fix_script.html"))
        result = self._run_import(app_dir, "pass")
        # A required asset is fatal, but with a clear message naming the file.
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("IMPORT_FAILED:", result.stdout)
        self.assertIn("tab_fix_script.html", result.stdout)
        # Not a bare FileNotFoundError traceback — a deliberate RuntimeError.
        self.assertIn("RuntimeError", result.stdout)


if __name__ == "__main__":
    unittest.main()
