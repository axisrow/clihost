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
TMUX_WRAPPER = REPO_ROOT / "bin/tmux-wrapper.sh"


class TestShellSyntax(unittest.TestCase):
    def test_scripts_parse(self):
        for script in (ENTRYPOINT, BUILD_SH, TMUX_WRAPPER):
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

    def test_local_bin_env_created_before_interactive_shells(self):
        # Persisted home volumes may have shell startup files that source
        # ~/.local/bin/env. Create a compatibility file instead of rewriting
        # user dotfiles, and do it before ttyd or ssh can start a shell.
        local_env_pos = self.text.find('LOCAL_BIN_ENV="${LOCAL_BIN_DIR}/env"')
        proxy_pos = self.text.find('runuser -u "${TTYD_USER}" -- python3')
        sshd_pos = self.text.find("exec /usr/sbin/sshd -D -e")
        self.assertGreater(local_env_pos, -1, "LOCAL_BIN_ENV bootstrap is missing")
        self.assertLess(local_env_pos, proxy_pos)
        self.assertLess(local_env_pos, sshd_pos)
        self.assertIn('mkdir -p "${LOCAL_BIN_DIR}"', self.text)
        self.assertIn('[ ! -e "${LOCAL_BIN_ENV}" ]', self.text)
        self.assertIn("cat > \"${LOCAL_BIN_ENV}\" <<'EOF'", self.text)
        self.assertIn('case ":${PATH}:" in', self.text)
        self.assertIn('*":${HOME}/.local/bin:"*) ;;', self.text)
        self.assertIn('export PATH="${HOME}/.local/bin:${PATH}"', self.text)
        self.assertIn('chmod 0644 "${LOCAL_BIN_ENV}"', self.text)
        self.assertIn('chown "${HAPI_USER}:${HAPI_USER}" "${LOCAL_BIN_ENV}"', self.text)

    def test_hapi_server_log_precreated(self):
        # The log file must exist before the URL-extraction loop starts so the
        # [ -f "$HAPI_SERVER_LOG" ] guard passes on the first iteration.
        touch_pos = self.text.find('touch "${HAPI_SERVER_LOG}"')
        server_start_pos = self.text.find("hapi server --relay 2>&1")
        self.assertGreater(touch_pos, -1, "HAPI_SERVER_LOG is not pre-created")
        self.assertLess(touch_pos, server_start_pos)

    def test_droid_daemon_started_as_hapi_with_log(self):
        self.assertIn(': "${DROID_DAEMON_ENABLED:=false}"', self.text)
        self.assertIn(': "${DROID_COMPUTER_NAME:=}"', self.text)
        self.assertIn('[ "${DROID_DAEMON_ENABLED}" = "true" ]', self.text)
        self.assertIn("DROID_DAEMON_ENABLED=true requires DROID_COMPUTER_NAME", self.text)
        self.assertIn('droid computer register \\"${DROID_COMPUTER_NAME}\\" -y', self.text)
        self.assertIn('DROID_DAEMON_LOG="${HAPI_HOME}/droid-daemon.log"', self.text)
        self.assertIn('PATH="${HAPI_RUN_PATH}" command -v droid', self.text)
        self.assertIn(
            'run_as_hapi "stdbuf -oL droid daemon --remote-access 2>&1 | tee \\"${DROID_DAEMON_LOG}\\"" &',
            self.text,
        )

    def test_sandbox_flag_passed_to_proxy(self):
        # tmux-wrapper.sh only sees TTYD_SANDBOX if the entrypoint defaults it
        # and adds it to the proxy's runuser env block (a closed allow-list);
        # the proxy then inherits it down to the ttyd -> tmux-wrapper child.
        self.assertIn(': "${TTYD_SANDBOX:=false}"', self.text)
        self.assertIn('TTYD_SANDBOX="${TTYD_SANDBOX}"', self.text)


class TestClaudeConfigPersistence(unittest.TestCase):
    """The 'Claude Code login keeps resetting' report (issue #59 tail) blamed
    lost ~/.claude credentials. Root cause was a missing /home/hapi volume
    mount, NOT the entrypoint deleting the config. These regressions pin the
    entrypoint's contract so a future edit can't start wiping ~/.claude and
    silently reintroduce the symptom on top of a correctly mounted volume.
    """

    def setUp(self):
        self.text = ENTRYPOINT.read_text()

    def test_claude_dir_is_ensured_owned_not_recreated(self):
        # ~/.claude must be created+chowned (so a fresh volume is usable) but
        # never deleted/recreated, or persisted credentials would vanish.
        self.assertIn('ensure_dir_owned "${HAPI_USER_HOME}/.claude"', self.text)

    def test_entrypoint_never_removes_claude_config(self):
        # No destructive op may target ~/.claude (directly or via HAPI_USER_HOME).
        # Covers rm AND the non-rm deletion/truncation mechanisms a future edit
        # could reach for — find -delete, rmdir, and `:`/`>` truncation — so the
        # contract is pinned against more than a literal `rm`.
        for pattern in (
            r'rm\s+[^\n]*\.claude\b',
            r'rm\s+[^\n]*\$\{HAPI_USER_HOME\}/\.claude',
            r'rm\s+[^\n]*HOME[^\n]*/\.claude',
            r'find\s+[^\n]*\.claude[^\n]*-delete',
            r'rmdir\s+[^\n]*\.claude\b',
            r'(?:^|[;&|]|\btrue\b)\s*>\s*[^\n]*\.claude',
        ):
            with self.subTest(pattern=pattern):
                self.assertNotRegex(self.text, re.compile(pattern))

    def test_cleanup_runner_state_does_not_touch_claude(self):
        # cleanup_runner_state wipes stale runner state on restart; it must stay
        # scoped to ~/.hapi / ~/*.json and never list anything under ~/.claude.
        match = re.search(
            r"cleanup_runner_state\(\)\s*\{(.*?)\n\}", self.text, re.DOTALL
        )
        if match is None:
            self.fail("cleanup_runner_state() not found")
        body = match.group(1)
        self.assertNotIn(".claude", body)
        # sanity: it does target the runner state files it is meant to clear.
        self.assertIn("runner.state.json", body)


class TestTmuxWrapperSandboxRegressions(unittest.TestCase):
    def setUp(self):
        self.text = TMUX_WRAPPER.read_text()

    def test_sandbox_default_off(self):
        # Single-user clihost stays unchanged unless explicitly opted in.
        self.assertIn(': "${TTYD_SANDBOX:=false}"', self.text)

    def test_sandbox_is_flag_gated(self):
        self.assertIn('if [ "${TTYD_SANDBOX}" = "true" ]', self.text)

    def test_default_path_is_byte_for_byte_original(self):
        # The flag-off exec must be the original jail-free tmux launch AND the
        # last line of the file (so the gated branch never shadows it).
        last_exec = self.text.rstrip().splitlines()[-1]
        self.assertEqual(
            last_exec.strip(),
            'exec tmux new-session -A -s "$SESSION_NAME" -c "$HOME"',
        )

    def test_sandbox_uses_bwrap(self):
        self.assertIn("exec bwrap", self.text)

    def test_required_unshare_flags_present(self):
        for flag in ("--unshare-user", "--unshare-pid", "--unshare-ipc",
                     "--die-with-parent"):
            with self.subTest(flag=flag):
                self.assertIn(flag, self.text)

    def test_network_namespace_not_unshared(self):
        # AI CLIs (claude-code/codex/gemini) need network — net stays shared.
        self.assertNotIn("--unshare-net", self.text)

    def test_proc_inherited_readonly(self):
        # A fresh --proc can't be mounted in some target envs; /proc is ro-bound.
        self.assertIn("--ro-bind /proc /proc", self.text)

    def test_binds_are_guarded(self):
        # Each --ro-bind SOURCE is added only if it exists, else bwrap aborts.
        self.assertRegex(self.text, r'\[ -e "\$p" \] && binds\+=\(--ro-bind')
        for p in ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"):
            with self.subTest(path=p):
                self.assertIn(p, self.text)

    def test_home_is_writable_bind(self):
        self.assertIn('--bind "$HOME" "$HOME"', self.text)

    def test_tmux_socket_pinned_under_home(self):
        # Per-jail tmpfs /tmp would break `new-session -A` reattach, so the tmux
        # socket lives under the bound $HOME and survives reconnects.
        self.assertIn("tmux -S", self.text)
        self.assertIn('${HOME}/.cache/tmux', self.text)
        self.assertIn("new-session -A -s", self.text)


class TestDockerPackageRegressions(unittest.TestCase):
    def test_bubblewrap_is_installed_for_ttyd_sandbox(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("bubblewrap", dockerfile)

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
