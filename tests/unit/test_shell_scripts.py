"""Static checks for shell scripts (syntax + known-bug regressions)."""
import pathlib
import re
import subprocess
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "entrypoint.sh"
BUILD_SH = REPO_ROOT / "build.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"
CLI_PACKAGES = REPO_ROOT / "cli-packages.txt"


class TestShellSyntax(unittest.TestCase):
    def test_scripts_parse(self):
        for script in (ENTRYPOINT, BUILD_SH):
            with self.subTest(script=script.name):
                result = subprocess.run(
                    ["bash", "-n", str(script)], capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 0, result.stderr)


class TestEntrypointRegressions(unittest.TestCase):
    def setUp(self):
        self.text = ENTRYPOINT.read_text()

    def test_root_password_not_piped_through_echo(self):
        # echo "root:$PW" | chpasswd exposes the password to process listing;
        # the password must reach chpasswd via heredoc/stdin redirection.
        self.assertNotRegex(self.text, r'echo\s+"root:.*\|\s*chpasswd')
        self.assertIn("chpasswd", self.text)

    def test_password_secret_passed_via_file(self):
        # The proxy child process must receive PASSWORD_SECRET_FILE, not the
        # secret value itself in its environment (/proc/<pid>/environ).
        self.assertIn("PASSWORD_SECRET_FILE=", self.text)
        self.assertNotRegex(
            self.text,
            re.compile(r'^PASSWORD_SECRET="\$\{PASSWORD_SECRET\}"', re.MULTILINE),
        )

    def test_proxy_started_as_ttyd_user(self):
        # The proxy must drop root (issue #52): launched via runuser, with the
        # secret file owned by TTYD_USER so the unprivileged proxy can read it.
        self.assertIn(
            'runuser -u "${TTYD_USER}" -- python3 /app/ttyd_proxy.py &', self.text
        )
        self.assertIn('install -m 400 -o "${TTYD_USER}"', self.text)

    def test_port_validated_numeric_before_range_check(self):
        # A non-numeric PORT must fail loudly: `[ "$PORT" -lt 1024 ]` returns
        # exit 2 (error, not "false"), so the range guard silently passes and
        # the proxy starts on the default 8080. A numeric pre-check prevents it.
        case_pos = self.text.find("*[!0-9]*")
        range_pos = self.text.find('[ "${PORT}" -lt 1024 ]')
        self.assertGreater(case_pos, -1, "PORT is not validated as numeric")
        self.assertLess(case_pos, range_pos)

    def test_upload_dir_prepared_before_proxy(self):
        # The unprivileged proxy creates upload files itself; a bind-mounted
        # /home/hapi may not be writable by the hapi UID, so the entrypoint
        # must create+chown UPLOAD_DIR before starting the proxy.
        prep_pos = self.text.find('ensure_dir_owned "${UPLOAD_DIR}"')
        proxy_pos = self.text.find('runuser -u "${TTYD_USER}" -- python3')
        self.assertGreater(prep_pos, -1, "UPLOAD_DIR is not pre-created")
        self.assertLess(prep_pos, proxy_pos)

    def test_hapi_server_log_precreated(self):
        # The log file must exist before the URL-extraction loop starts so the
        # [ -f "$HAPI_SERVER_LOG" ] guard passes on the first iteration.
        touch_pos = self.text.find('touch "${HAPI_SERVER_LOG}"')
        server_start_pos = self.text.find("hapi server --relay 2>&1")
        self.assertGreater(touch_pos, -1, "HAPI_SERVER_LOG is not pre-created")
        self.assertLess(touch_pos, server_start_pos)

    def test_droid_daemon_started_as_hapi_with_log(self):
        self.assertIn('DROID_DAEMON_LOG="${HAPI_HOME}/droid-daemon.log"', self.text)
        self.assertIn('PATH="${HAPI_RUN_PATH}" command -v droid', self.text)
        self.assertIn(
            'run_as_hapi "stdbuf -oL droid daemon --remote-access 2>&1 | tee \\"${DROID_DAEMON_LOG}\\"" &',
            self.text,
        )


class TestDockerPackageRegressions(unittest.TestCase):
    def test_droid_package_is_installed_and_cache_busted(self):
        packages = CLI_PACKAGES.read_text()
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("droid@latest", packages)
        self.assertIn(
            "https://registry.npmjs.org/droid/latest /tmp/npm-manifests/droid.json",
            dockerfile,
        )


class TestBuildShRegressions(unittest.TestCase):
    def test_build_runs_from_script_dir(self):
        # docker build uses "." as context, so the script must cd to its own
        # directory first to work when invoked from elsewhere.
        text = BUILD_SH.read_text()
        cd_match = re.search(r'^cd "\$\(dirname "\$\{BASH_SOURCE\[0\]\}"\)"', text, re.MULTILINE)
        build_match = re.search(r"^docker build", text, re.MULTILINE)
        self.assertIsNotNone(cd_match, "build.sh does not cd to its own directory")
        self.assertIsNotNone(build_match)
        self.assertLess(cd_match.start(), build_match.start())


if __name__ == "__main__":
    unittest.main()
