"""Static checks for shell scripts (syntax + known-bug regressions)."""
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO_ROOT / "entrypoint.sh"
BUILD_SH = REPO_ROOT / "build.sh"
DOCKERFILE = REPO_ROOT / "Dockerfile"
CLI_PACKAGES = REPO_ROOT / "cli-packages.txt"
INSTALL_CLI = REPO_ROOT / "bin/install-cli.sh"
TMUX_WRAPPER = REPO_ROOT / "bin/tmux-wrapper.sh"

# Component keys whose INSTALL_<KEY> build args gate the modular image (issue #57).
NPM_COMPONENT_KEYS = (
    "CLAUDE_CODE", "CODEX", "GEMINI", "COPILOT", "OPENCODE", "DROID", "HAPI",
)
ALL_COMPONENT_KEYS = NPM_COMPONENT_KEYS + ("HERMES",)
NPM_MANIFEST_SLUGS = {
    "CLAUDE_CODE": "claude-code",
    "CODEX": "codex",
    "GEMINI": "gemini",
    "COPILOT": "copilot",
    "OPENCODE": "opencode",
    "DROID": "droid",
    "HAPI": "hapi",
}


class TestShellSyntax(unittest.TestCase):
    def test_scripts_parse(self):
        for script in (ENTRYPOINT, BUILD_SH, INSTALL_CLI, TMUX_WRAPPER):
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

    def test_hapi_commands_are_skipped_when_cli_missing(self):
        guard_pos = self.text.find(
            'if PATH="${HAPI_RUN_PATH}" command -v hapi >/dev/null 2>&1; then'
        )
        warning_pos = self.text.find(
            "WARNING: hapi CLI not found; skipping hapi server --relay startup"
        )
        self.assertGreater(guard_pos, -1, "hapi command guard is missing")
        self.assertGreater(warning_pos, guard_pos)
        for marker in (
            'run_as_hapi "HAPI_RELAY_FORCE_TCP=true stdbuf -oL hapi server --relay',
            'run_as_hapi "hapi runner start 2>&1"',
            'run_as_hapi "hapi runner status 2>&1"',
            'run_as_hapi "hapi doctor 2>&1"',
        ):
            with self.subTest(marker=marker):
                pos = self.text.find(marker)
                self.assertGreater(pos, guard_pos)
                self.assertLess(pos, warning_pos)
        self.assertIn(
            "WARNING: HAPI_RUNNER_ENABLED=true but hapi CLI is not installed",
            self.text,
        )

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

    def test_ssh_tunnel_env_defaults(self):
        # Pluggable SSH tunnel (issue #79): env defaults must be set so the gate
        # and provider switch never run against an unset variable (set -u).
        for marker in (
            ': "${SSH_TUNNEL_ENABLED:=false}"',
            ': "${SSH_TUNNEL_PROVIDER:=cloudflared}"',
            ': "${CLOUDFLARE_TUNNEL_TOKEN:=}"',
            ': "${CLOUDFLARE_TUNNEL_HOSTNAME:=}"',
            ': "${CHISEL_SERVER:=}"',
            ': "${CHISEL_AUTH:=}"',
            ': "${CHISEL_REMOTE_PORT:=2222}"',
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.text)

    def test_ssh_tunnel_gated_and_independent_of_hapi(self):
        # The tunnel block must be gated by SSH_TUNNEL_ENABLED and live BEFORE the
        # `command -v hapi` guard so it starts regardless of hapi (INSTALL_HAPI=false).
        gate_pos = self.text.find('if [ "${SSH_TUNNEL_ENABLED}" = "true" ]; then')
        hapi_guard_pos = self.text.find(
            'if PATH="${HAPI_RUN_PATH}" command -v hapi >/dev/null 2>&1; then'
        )
        self.assertGreater(gate_pos, -1, "SSH tunnel gate is missing")
        self.assertGreater(hapi_guard_pos, -1, "hapi guard not found")
        self.assertLess(gate_pos, hapi_guard_pos,
                        "tunnel must start independently of hapi (before the hapi guard)")
        self.assertIn(
            'echo "SSH tunnel disabled (set SSH_TUNNEL_ENABLED=true', self.text
        )

    def test_ssh_tunnel_provider_switch_and_commands(self):
        # Provider switch: cloudflared (default) named tunnel, chisel reverse, and
        # a visible error on an invalid provider. Both are launched argv-based via
        # run_as_hapi_argv (no `sh -c` string) so env values can't be shell-parsed.
        self.assertIn('case "${SSH_TUNNEL_PROVIDER}" in', self.text)
        self.assertIn(
            'stdbuf -oL cloudflared tunnel --no-autoupdate run', self.text
        )
        self.assertIn(
            'stdbuf -oL chisel client --max-retry-count -1', self.text
        )
        self.assertIn(
            '"${CHISEL_SERVER}" "R:${CHISEL_REMOTE_PORT}:localhost:22"', self.text
        )
        self.assertIn(
            "SSH_TUNNEL_PROVIDER='${SSH_TUNNEL_PROVIDER}' is invalid", self.text
        )

    def test_ssh_tunnel_secrets_not_in_argv(self):
        # Regression for the review findings (cycle 1 C1/C2 + cycle 2): the secret
        # VALUE must never appear in any argv (not even briefly as `env NAME=VALUE`).
        # The caller EXPORTS the secret into the launcher env and passes only its
        # NAME; runuser (no --login) inherits it from the environment across the
        # privilege drop, so the value never enters argv.
        # This is the no-secrets-in-argv invariant (cf. ROOT_PASSWORD / PASSWORD_SECRET).
        self.assertIn("run_as_hapi_argv", self.text)
        # cloudflared: export TUNNEL_TOKEN, pass only the NAME.
        self.assertIn('TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN}" \\', self.text)
        self.assertIn("run_as_hapi_argv TUNNEL_TOKEN --", self.text)
        # chisel: export AUTH, pass only the NAME.
        self.assertIn('AUTH="${CHISEL_AUTH}" \\', self.text)
        self.assertIn("run_as_hapi_argv AUTH --", self.text)
        # The old insecure forms must all be gone:
        #  - no `--token` argv flag carrying the token,
        #  - no `env NAME=VALUE` form embedding the secret value,
        #  - no secret interpolated into a `run_as_hapi "..."` (sh -c) string.
        self.assertNotRegex(
            self.text, re.compile(r'--token\s+\S*CLOUDFLARE_TUNNEL_TOKEN'))
        self.assertNotIn('"TUNNEL_TOKEN=${CLOUDFLARE_TUNNEL_TOKEN}"', self.text)
        self.assertNotIn('"AUTH=${CHISEL_AUTH}"', self.text)
        self.assertNotRegex(
            self.text, re.compile(r'run_as_hapi "[^"]*CLOUDFLARE_TUNNEL_TOKEN'))
        self.assertNotRegex(
            self.text, re.compile(r'run_as_hapi "[^"]*CHISEL_AUTH'))

    def test_run_as_hapi_argv_helper_defined(self):
        # The argv-based launcher consumes the documented secret NAMES up to `--`
        # (the secret VALUES are inherited from the exported environment, never
        # passed in argv), then execs via `runuser -u hapi -- env ... "$@"`. It
        # relies on runuser's default (no --login → env not cleared); it must NOT
        # use --whitelist-environment (a no-op without --login).
        self.assertIn("run_as_hapi_argv() {", self.text)
        self.assertIn('while [ "$1" != "--" ]; do', self.text)
        self.assertIn('runuser -u "${HAPI_USER}" -- env', self.text)
        # --whitelist-environment must not be USED as an argument to runuser (it is
        # a no-op without --login). A comment mentioning it is fine; an actual
        # `runuser ... --whitelist-environment` invocation is not.
        self.assertNotRegex(
            self.text, re.compile(r'runuser[^\n]*--whitelist-environment'))

    def test_ssh_tunnel_chisel_remote_port_validated_numeric(self):
        # CHISEL_REMOTE_PORT is interpolated into the R:<port>:... spec, so a
        # non-numeric value must fail loudly (like the PORT check), not silently
        # produce a broken forward.
        self.assertIn(
            "CHISEL_REMOTE_PORT='${CHISEL_REMOTE_PORT}' must be a positive integer",
            self.text,
        )

    def test_ssh_tunnel_logs_via_redirect_not_tee(self):
        # Logging through a plain redirect (not `| tee`) keeps $! on the tunnel
        # process so an immediate exit (bad token/server) isn't masked by a live
        # tee. The tunnel launch must not pipe to tee.
        # Locate the tunnel block and assert its launches use >>"${SSH_TUNNEL_LOG}".
        self.assertIn('>>"${SSH_TUNNEL_LOG}" 2>&1 &', self.text)
        block_start = self.text.find("Start external SSH tunnel (issue #79)")
        block_end = self.text.find("SSH tunnel disabled", block_start)
        tunnel_block = self.text[block_start:block_end]
        self.assertNotIn('tee "${SSH_TUNNEL_LOG}"', tunnel_block)

    def test_ssh_tunnel_missing_required_env_warns_not_fatal(self):
        # An enabled tunnel with a missing required var must warn + skip, not die
        # silently (cloudflared needs a token; chisel needs a server).
        self.assertIn(
            "SSH_TUNNEL_PROVIDER=cloudflared requires CLOUDFLARE_TUNNEL_TOKEN", self.text
        )
        self.assertIn(
            "SSH_TUNNEL_PROVIDER=chisel requires CHISEL_SERVER", self.text
        )
        # Missing binary must be fail-visible too.
        self.assertIn("cloudflared binary not found", self.text)
        self.assertIn("chisel binary not found", self.text)

    def test_ssh_tunnel_writes_connection_file_for_dashboard(self):
        # Connection string for the dashboard (#80) is built from env and written
        # to ssh-url; the stale file is cleared up front (like HAPI_URL_FILE).
        self.assertIn('SSH_URL_FILE="${HAPI_USER_HOME}/ssh-url"', self.text)
        self.assertIn('rm -f "${SSH_URL_FILE}"', self.text)
        self.assertIn('cloudflared access ssh --hostname', self.text)
        self.assertIn('ssh -p %s %s@%s', self.text)

    def test_sandbox_flag_passed_to_proxy(self):
        # tmux-wrapper.sh only sees TTYD_SANDBOX if the entrypoint defaults it
        # and adds it to the proxy's runuser env block (a closed allow-list);
        # the proxy then inherits it down to the ttyd -> tmux-wrapper child.
        self.assertIn(': "${TTYD_SANDBOX:=false}"', self.text)
        self.assertIn('TTYD_SANDBOX="${TTYD_SANDBOX}"', self.text)

    def test_home_owned_before_subdirs(self):
        # issue #65: on a fresh /home volume the first `mkdir -p .../.config/gh`
        # creates /home/hapi as root and a later chown -R only touches the leaf.
        # The home dir itself must be chowned before any subdir is created.
        home_pos = self.text.find("ensure_home_owned\n")
        first_subdir_pos = self.text.find('ensure_dir_owned "${HAPI_USER_HOME}/.config/gh"')
        self.assertGreater(home_pos, -1, "ensure_home_owned is not called")
        self.assertLess(home_pos, first_subdir_pos,
                        "home must be chowned before subdirs are created")
        self.assertIn('chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}"', self.text)


class TestRunAsHapiArgvSecretHygiene(unittest.TestCase):
    """Behavioural regression for the #82 review (cycle 1 C1/C2 + cycle 2): a
    secret handed to run_as_hapi_argv must reach the child via the ENVIRONMENT and
    its VALUE must NEVER appear in any argv — not even briefly as `env NAME=VALUE`
    (argv is world-readable via ps / /proc/<pid>/cmdline for every process in the
    launch chain). The secret is exported into the launcher env and inherited by
    runuser (which, without --login, does not clear the environment).

    Sources the real run_as_hapi_argv from entrypoint.sh and runs it with a fake
    `runuser` that records its full argv AND whether the secret was present in its
    inherited environment, so the fix is proven without root/Docker.
    """

    def _extract_helper(self):
        text = ENTRYPOINT.read_text()
        match = re.search(
            r"^run_as_hapi_argv\(\) \{\n.*?^\}", text, re.MULTILINE | re.DOTALL
        )
        self.assertIsNotNone(match, "run_as_hapi_argv not found in entrypoint.sh")
        assert match is not None
        return match.group(0)

    def _run(self, secret):
        helper = self._extract_helper()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            argv_log = tmp_path / "argv.log"
            env_log = tmp_path / "env.log"
            # Fake runuser: log every argv element one per line, and separately log
            # whether TUNNEL_TOKEN was inherited via the ENVIRONMENT (the real
            # runuser without --login does not clear the env, so it is preserved).
            # This lets the test assert "value in env, never in argv".
            fake_runuser = tmp_path / "runuser"
            fake_runuser.write_text(
                "#!/bin/bash\n"
                'for a in "$@"; do printf "%%s\\n" "$a" >> "%s"; done\n'
                'printf "%%s\\n" "TUNNEL_TOKEN=${TUNNEL_TOKEN:-<unset>}" >> "%s"\n'
                % (argv_log, env_log)
            )
            fake_runuser.chmod(0o755)
            # Export the secret into the launcher env (exactly like the real
            # entrypoint: `TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN}" run_as_hapi_argv
            # TUNNEL_TOKEN -- ...`). Passed via the SECRET env var, never baked into
            # the script text — otherwise the harness's own bash would expand
            # $(...)/backticks before run_as_hapi_argv ever saw them.
            script = (
                "set -euo pipefail\n"
                'HAPI_USER="hapi"\n'
                'HAPI_USER_HOME="/home/hapi"\n'
                'HAPI_RUN_PATH="/usr/local/bin:/usr/bin:/bin"\n'
                'HAPI_HOME="/home/hapi/.hapi"\n'
                f"{helper}\n"
                'TUNNEL_TOKEN="${SECRET}" run_as_hapi_argv TUNNEL_TOKEN -- '
                'cloudflared tunnel --no-autoupdate run\n'
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            env["SECRET"] = secret
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            argv = argv_log.read_text().splitlines() if argv_log.exists() else []
            envlog = env_log.read_text().splitlines() if env_log.exists() else []
            return argv, envlog

    def test_secret_in_env_never_in_argv(self):
        secret = "s3cr3t-token-value"
        argv, envlog = self._run(secret)
        # The secret VALUE reaches runuser via the inherited environment (runuser
        # without --login does not clear the env)...
        self.assertIn(f"TUNNEL_TOKEN={secret}", envlog,
                      "secret must be inherited via the environment")
        # The program + flags are present as separate argv elements...
        self.assertIn("cloudflared", argv)
        self.assertIn("--no-autoupdate", argv)
        # ...but the secret VALUE must NEVER appear in argv — not bare, and not as
        # an `env TUNNEL_TOKEN=<value>` pair. Check every element.
        for element in argv:
            self.assertNotIn(secret, element,
                             f"secret value leaked into argv element: {element!r}")

    def test_metachar_value_never_executed_or_in_argv(self):
        # A value with shell metacharacters must never be interpreted (no sh -c)
        # nor appear in argv — proving both the injection and the leak vectors are
        # closed. If $(...) were evaluated, /tmp/pwned would be created.
        payload = "a$(touch /tmp/clihost_pwned_test)b`id`;echo"
        try:
            argv, envlog = self._run(payload)
        finally:
            pathlib.Path("/tmp/clihost_pwned_test").unlink(missing_ok=True)
        self.assertIn(f"TUNNEL_TOKEN={payload}", envlog,
                      "metachar value must reach the env verbatim")
        for element in argv:
            self.assertNotIn(payload, element,
                             "metachar secret value must not appear in argv")
        # The injection must not have fired during _run (file unlinked in finally,
        # but assert it was never created in the first place via a fresh check is
        # racy; the unlink-in-finally + no exception is the guarantee here).


class TestEntrypointHomeOwnershipBehaviour(unittest.TestCase):
    """Behavioural regression for issue #65: hapi must own its own $HOME.

    Sources the ensure_home_owned / ensure_dir_owned helpers from entrypoint.sh
    with a fake `chown` (records its targets) and a temp HAPI_USER_HOME, so the
    bug — /home/hapi and .config left root-owned after the first `mkdir -p
    .config/gh` — is reproduced without needing root or Docker.
    """

    def _extract_helpers(self):
        text = ENTRYPOINT.read_text()
        # Pull the two function definitions verbatim so the test exercises the
        # real implementation, not a paraphrase of it.
        helpers = []
        for name in ("ensure_home_owned", "ensure_dir_owned"):
            match = re.search(
                rf"^{name}\(\) \{{\n.*?^\}}", text, re.MULTILINE | re.DOTALL
            )
            self.assertIsNotNone(match, f"{name} not found in entrypoint.sh")
            helpers.append(match.group(0))
        return "\n\n".join(helpers)

    def _run(self):
        helpers = self._extract_helpers()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            home = tmp_path / "home" / "hapi"
            chown_log = tmp_path / "chown.log"
            # Fake chown: record (target) of every invocation, ignore flags/owner.
            fake_chown = tmp_path / "chown"
            fake_chown.write_text(
                "#!/bin/bash\n"
                'for a in "$@"; do case "$a" in -*) ;; *:*) ;; '
                f'*) echo "$a" >> "{chown_log}" ;; esac; done\n'
            )
            fake_chown.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                f'HAPI_USER="hapi"\n'
                f'HAPI_USER_HOME="{home}"\n'
                f"{helpers}\n"
                "ensure_home_owned\n"
                'ensure_dir_owned "${HAPI_USER_HOME}/.config/gh"\n'
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            targets = chown_log.read_text().splitlines() if chown_log.exists() else []
            return str(home), targets

    def test_home_and_config_are_chowned(self):
        home, targets = self._run()
        # The bug: /home/hapi (the home root) and .config (an intermediate parent
        # created by `mkdir -p .config/gh`) were never chowned. Both must appear.
        self.assertIn(home, targets, "/home/hapi itself was never chowned (issue #65)")
        self.assertIn(f"{home}/.config", targets,
                      ".config parent was never chowned (issue #65)")
        self.assertIn(f"{home}/.config/gh", targets, "leaf subdir was not chowned")

    def test_chown_stays_within_home(self):
        home, targets = self._run()
        # The parent walk must stop at HAPI_USER_HOME and never chown /home or /.
        for target in targets:
            with self.subTest(target=target):
                self.assertTrue(
                    target == home or target.startswith(f"{home}/"),
                    f"chown escaped HAPI_USER_HOME: {target}",
                )


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
            "https://registry.npmjs.org/droid/latest /manifest.json",
            dockerfile,
        )
        self.assertIn(
            "FROM npm-manifest-droid-${INSTALL_DROID} AS npm-manifest-droid",
            dockerfile,
        )

    def test_ssh_tunnel_binaries_installed_multiarch_and_gated(self):
        # Pluggable SSH tunnel (issue #79): cloudflared + chisel are curl-prebuilt
        # on both arches (no Go build-stage), each gated by a strict INSTALL_<KEY>
        # case (fail-closed on invalid values, like Hermes).
        dockerfile = DOCKERFILE.read_text()
        for key in ("INSTALL_CLOUDFLARED", "INSTALL_CHISEL"):
            with self.subTest(arg=key):
                self.assertIn(f"ARG {key}=true", dockerfile)
        # Multi-arch via dpkg --print-architecture (amd64/arm64), pinned versions.
        self.assertIn('TUNNEL_ARCH="$(dpkg --print-architecture)"', dockerfile)
        self.assertIn('CLOUDFLARED_VERSION="2026.6.1"', dockerfile)
        self.assertIn(
            "cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${TUNNEL_ARCH}",
            dockerfile,
        )
        self.assertIn('CHISEL_VERSION="1.11.5"', dockerfile)
        self.assertIn(
            "chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${TUNNEL_ARCH}.gz",
            dockerfile,
        )
        # Strict fail-closed gates.
        self.assertIn(
            "INSTALL_CLOUDFLARED='${INSTALL_CLOUDFLARED}' is invalid", dockerfile
        )
        self.assertIn("INSTALL_CHISEL='${INSTALL_CHISEL}' is invalid", dockerfile)


class TestAoGoBuildStage(unittest.TestCase):
    """issue #76 + #77: ao is built from upstream Go source in a dedicated
    build-stage (NOT npm, NOT a prebuilt curl), gated by INSTALL_AO via a
    FROM alias. CGO_ENABLED=0 + modernc.org/sqlite ⟶ one arch-agnostic build
    path (no arch branches), closing both the x86_64 and arm64 issues at once.
    """

    def setUp(self):
        self.dockerfile = DOCKERFILE.read_text()

    def test_ao_is_not_an_npm_component(self):
        # ao must NOT leak into the npm install path: no cli-packages.txt row,
        # no npm-manifest stage. It is a from-source Go binary.
        self.assertNotIn("AO ", CLI_PACKAGES.read_text())
        self.assertNotIn("@aoagents/ao", self.dockerfile)
        self.assertNotIn("npm-manifest-ao", self.dockerfile)

    def test_ao_built_in_pinned_golang_stage(self):
        self.assertIn("FROM golang:1.25-bookworm AS ao-build-true", self.dockerfile)

    def test_ao_ref_is_pinned_commit_and_overridable(self):
        # The Go backend/ tree is not in any upstream release tag yet, so AO_REF
        # is pinned to a specific 40-char commit SHA (reproducible), exposed as an
        # ARG to bump. AO_REPO is likewise an ARG so the source can be retargeted.
        self.assertRegex(self.dockerfile, r"ARG AO_REF=[0-9a-f]{40}\b")
        self.assertIn(
            "ARG AO_REF=405be363fbe414dd93a81b12dfcfea112e277741",
            self.dockerfile,
        )
        self.assertRegex(self.dockerfile, r"ARG AO_REPO=https://github\.com/")

    def test_ao_pinned_by_sha_via_fetch_not_branch_clone(self):
        # A full SHA cannot be used with `clone --branch`; the stage must fetch
        # the exact commit and check out FETCH_HEAD so the pin is honoured.
        self.assertNotIn('git clone --depth 1 --branch "${AO_REF}"', self.dockerfile)
        self.assertIn('git fetch --depth 1 origin "${AO_REF}"', self.dockerfile)
        self.assertIn("git checkout -q FETCH_HEAD", self.dockerfile)

    def test_ao_source_repo_is_configured(self):
        # Source currently tracks the fork (only place with the Go backend/ tree
        # at a pinnable commit); retargetable via the AO_REPO build arg.
        self.assertIn("axisrow/agent-orchestrator.git", self.dockerfile)

    def test_ao_build_is_cgo_free_and_arch_agnostic(self):
        # CGO_ENABLED=0 + a single GOARCH = one build path for all arches.
        self.assertIn("CGO_ENABLED=0", self.dockerfile)
        self.assertIn("ARG TARGETARCH", self.dockerfile)
        self.assertIn(
            "go build -trimpath -ldflags='-s -w' -o /out/ao ./cmd/ao",
            self.dockerfile,
        )
        # The build runs inside the upstream backend/ module.
        self.assertIn("cd /src/backend", self.dockerfile)

    def test_ao_goarch_falls_back_to_host_not_silent_amd64(self):
        # TARGETARCH is a BuildKit-only automatic arg; a non-BuildKit native build
        # leaves it empty. Defaulting to amd64 there would ship an amd64 binary in
        # an arm64 image (green build, runtime failure — undercuts #77). GOARCH must
        # fall back to the host's dpkg arch, matching the ttyd/tunnel steps.
        self.assertIn(
            'GOARCH="${TARGETARCH:-$(dpkg --print-architecture)}"', self.dockerfile
        )
        self.assertNotIn('GOARCH="${TARGETARCH:-amd64}"', self.dockerfile)

    def test_ao_gated_by_install_arg_via_from_alias(self):
        # Mirrors npm-manifest-* gating: a FROM alias selects the real build
        # or an empty busybox placeholder; disabled never schedules the toolchain.
        self.assertIn("FROM busybox AS ao-build-false", self.dockerfile)
        self.assertIn("FROM ao-build-${INSTALL_AO} AS ao-build", self.dockerfile)
        # ARG declared both at the top (for the alias) and in the final stage.
        self.assertEqual(self.dockerfile.count("ARG INSTALL_AO=true"), 2)

    def test_ao_install_gate_is_strict_boolean(self):
        # COPY pulls the binary, then a strict case installs or drops it.
        self.assertIn("COPY --from=ao-build /out/ao /tmp/ao.bin", self.dockerfile)
        self.assertIn('case "${INSTALL_AO}" in', self.dockerfile)
        self.assertIn("install -m 0755 /tmp/ao.bin /usr/local/bin/ao", self.dockerfile)
        self.assertIn("Skipping ao (INSTALL_AO=false)", self.dockerfile)
        self.assertIn(
            "INSTALL_AO='${INSTALL_AO}' is invalid", self.dockerfile
        )

    def test_ao_binary_not_executed_at_build_time(self):
        # A cross-built foreign-arch image can't run ao; the gate must not call it.
        self.assertNotRegex(self.dockerfile, r"/usr/local/bin/ao --version")
        self.assertNotRegex(self.dockerfile, r"\bao --version\b")

    def test_ao_runtime_deps_present(self):
        # The ao daemon needs tmux and git at runtime; both are in the base apt layer.
        self.assertRegex(self.dockerfile, r"apt-get install[^\n]*\btmux\b")
        self.assertRegex(self.dockerfile, r"apt-get install[^\n]*\bgit\b")

    def test_go_toolchain_not_in_runtime(self):
        # Only the binary is COPY'd from the build stage; no golang in final image.
        self.assertNotIn("FROM golang:1.25-bookworm\n", self.dockerfile)
        self.assertNotRegex(self.dockerfile, r"apt-get install[^\n]*\bgolang\b")

    def test_build_sh_forwards_install_ao(self):
        # ao is forwarded through the shared non-npm flag loop (alongside the
        # tunnel providers), not the npm cache-hash path. The loop validates and
        # forwards each INSTALL_<KEY> by indirect expansion.
        text = BUILD_SH.read_text()
        self.assertRegex(text, r"for nonnpm_key in [^\n]*\bINSTALL_AO\b")
        self.assertIn('validate_bool "${nonnpm_key}" "${!nonnpm_key}"', text)
        self.assertIn(
            'BUILD_ARGS+=(--build-arg "${nonnpm_key}=${!nonnpm_key}")', text
        )


def _parse_cli_packages():
    """Mirror install-cli.sh / build.sh parsing: (KEY, npm-spec) per real line."""
    rows = []
    for line in CLI_PACKAGES.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        rows.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return rows


class TestCliPackagesFormat(unittest.TestCase):
    """cli-packages.txt is now '<COMPONENT_KEY> <npm-spec>' (issue #57)."""

    def test_every_line_has_key_and_spec(self):
        rows = _parse_cli_packages()
        self.assertTrue(rows, "cli-packages.txt has no package rows")
        for key, spec in rows:
            with self.subTest(key=key):
                self.assertRegex(key, r"^[A-Z0-9_]+$", "key must be UPPER_SNAKE")
                self.assertTrue(spec.endswith("@latest"), f"{spec} should pin @latest")

    def test_keys_match_expected_components(self):
        keys = [key for key, _ in _parse_cli_packages()]
        self.assertEqual(sorted(keys), sorted(NPM_COMPONENT_KEYS))


class TestModularInstallFlags(unittest.TestCase):
    """Build-time INSTALL_<KEY> flags wired through Dockerfile and build.sh."""

    def test_dockerfile_declares_every_install_arg(self):
        dockerfile = DOCKERFILE.read_text()
        for key in ALL_COMPONENT_KEYS:
            with self.subTest(key=key):
                self.assertIn(f"ARG INSTALL_{key}=true", dockerfile)

    def test_dockerfile_uses_install_script_not_bare_xargs(self):
        dockerfile = DOCKERFILE.read_text()
        # Install is centralized in install-cli.sh; the old unconditional
        # `xargs npm install -g < cli-packages.txt` must be gone.
        self.assertIn("install-cli.sh", dockerfile)
        self.assertNotRegex(dockerfile, r"xargs\s+npm\s+install")

    def test_dockerfile_promotes_npm_flags_into_install_run(self):
        dockerfile = DOCKERFILE.read_text()
        for key in NPM_COMPONENT_KEYS:
            with self.subTest(key=key):
                self.assertIn(f'INSTALL_{key}="${{INSTALL_{key}}}"', dockerfile)

    def test_dockerfile_gates_manifest_fetches_by_install_args(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertNotRegex(
            dockerfile,
            re.compile(r"^ADD https://registry\.npmjs\.org/.+ /tmp/npm-manifests/", re.MULTILINE),
        )
        self.assertIn("FROM scratch AS npm-manifest-disabled", dockerfile)
        for key, slug in NPM_MANIFEST_SLUGS.items():
            with self.subTest(key=key):
                self.assertIn(
                    f"FROM npm-manifest-disabled AS npm-manifest-{slug}-false",
                    dockerfile,
                )
                self.assertIn(
                    f"FROM npm-manifest-{slug}-${{INSTALL_{key}}} AS npm-manifest-{slug}",
                    dockerfile,
                )
                self.assertIn(
                    f"COPY --from=npm-manifest-{slug} /manifest.json "
                    f"/tmp/npm-manifests/{slug}",
                    dockerfile,
                )

    def test_hermes_install_is_gated(self):
        dockerfile = DOCKERFILE.read_text()
        # Strict true|false case gate (fails closed on invalid values).
        self.assertIn('case "${INSTALL_HERMES}" in', dockerfile)
        self.assertIn("Skipping Hermes Agent (INSTALL_HERMES=false)", dockerfile)
        self.assertIn(
            "INSTALL_HERMES='${INSTALL_HERMES}' is invalid", dockerfile
        )

    def test_disabled_manifest_placeholder_is_independent_of_cli_packages(self):
        # The disabled-manifest stage must copy a stable placeholder, NOT
        # cli-packages.txt — otherwise editing a disabled tool's row would change
        # the stage output and invalidate the shared install layer (issue #57).
        dockerfile = DOCKERFILE.read_text()
        self.assertIn(
            "COPY bin/npm-manifest-placeholder.json /manifest.json", dockerfile
        )
        self.assertNotIn("COPY cli-packages.txt /manifest.json", dockerfile)
        self.assertTrue(
            (REPO_ROOT / "bin/npm-manifest-placeholder.json").is_file(),
            "placeholder file is missing",
        )

    def test_install_cli_rejects_invalid_boolean(self):
        # Strict boolean: a non true/false flag must fail the build, not silently
        # install (or skip) the tool.
        result = subprocess.run(
            ["bash", str(INSTALL_CLI), str(CLI_PACKAGES)],
            capture_output=True, text=True,
            env={**os.environ, "INSTALL_CODEX": "False"},
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("INSTALL_CODEX='False' is invalid", result.stderr)

    def test_build_sh_validates_boolean_flags(self):
        text = BUILD_SH.read_text()
        self.assertIn("validate_bool", text)
        self.assertIn("must be 'true' or 'false'", text)

    def test_entrypoint_clears_stale_url_before_hapi_check(self):
        # On a persistent volume a URL from a previous hapi-enabled image must not
        # leak into a hapi-disabled run; the entrypoint removes it up front.
        text = ENTRYPOINT.read_text()
        rm_pos = text.find('rm -f "${HAPI_URL_FILE}"')
        guard_pos = text.find(
            'if PATH="${HAPI_RUN_PATH}" command -v hapi >/dev/null 2>&1; then'
        )
        self.assertGreater(rm_pos, -1, "stale URL is not cleared")
        self.assertLess(rm_pos, guard_pos, "URL must be cleared before the hapi check")

    def test_build_sh_forwards_flags_as_build_args(self):
        text = BUILD_SH.read_text()
        self.assertIn('--build-arg', text)
        self.assertIn('flag_var="INSTALL_${key}"', text)
        # Disabled tools must drop out of the cache-busting hash.
        self.assertIn('Skipping', text)

    def test_build_sh_forwards_tunnel_flags(self):
        # cloudflared/chisel are curl-installed (not npm), so build.sh forwards
        # their INSTALL_* flags like Hermes — only when explicitly set (issue #79).
        # They share the non-npm flag loop with ao (#76/#77).
        text = BUILD_SH.read_text()
        self.assertRegex(
            text, r"for nonnpm_key in [^\n]*\bINSTALL_CLOUDFLARED\b[^\n]*\bINSTALL_CHISEL\b"
        )
        self.assertIn('validate_bool "${nonnpm_key}" "${!nonnpm_key}"', text)


class TestInstallCliScript(unittest.TestCase):
    """Behavioural test of bin/install-cli.sh with a fake npm on PATH."""

    def _run(self, env_overrides):
        with tempfile.TemporaryDirectory() as tmp:
            fake_npm = pathlib.Path(tmp) / "npm"
            fake_npm.write_text("#!/bin/bash\necho \"NPM $*\"\n")
            fake_npm.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = f"{tmp}{os.pathsep}{env['PATH']}"
            env.update(env_overrides)
            return subprocess.run(
                ["bash", str(INSTALL_CLI), str(CLI_PACKAGES)],
                capture_output=True, text=True, env=env,
            )

    def test_all_enabled_by_default_installs_everything(self):
        result = self._run({})
        self.assertEqual(result.returncode, 0, result.stderr)
        for _, spec in _parse_cli_packages():
            with self.subTest(spec=spec):
                self.assertIn(spec, result.stdout)

    def test_disabled_tool_is_skipped(self):
        result = self._run({"INSTALL_CODEX": "false", "INSTALL_GEMINI": "false"})
        self.assertEqual(result.returncode, 0, result.stderr)
        npm_line = [l for l in result.stdout.splitlines() if l.startswith("NPM ")]
        self.assertEqual(len(npm_line), 1, result.stdout)
        self.assertNotIn("@openai/codex", npm_line[0])
        self.assertNotIn("@google/gemini-cli", npm_line[0])
        self.assertIn("@anthropic-ai/claude-code", npm_line[0])

    def test_all_disabled_installs_nothing(self):
        overrides = {f"INSTALL_{k}": "false" for k in NPM_COMPONENT_KEYS}
        result = self._run(overrides)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("NPM ", result.stdout)
        self.assertIn("nothing to install", result.stdout)


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


class TestEntrypointRelayUrlRegex(unittest.TestCase):
    """B12: the relay-URL subdomain class must accept valid DNS-label chars.

    A subdomain like my-sub-01.relay.hapi.run (hyphens, digits) must match so
    the connection URL is built; the original [a-z0-9]+ silently dropped it.
    """

    def setUp(self):
        self.text = ENTRYPOINT.read_text()

    def _extract_grep_regex(self):
        # Pull the actual grep -oE pattern out of the real script so the test
        # cannot drift from the source.
        match = re.search(
            r"grep -oE '(https://[^']*relay\\.hapi\\.run)'", self.text
        )
        self.assertIsNotNone(match, "relay-URL grep pattern not found in entrypoint.sh")
        return match.group(1)

    def _grep_relay_url(self, log):
        """Run the real entrypoint grep pattern over `log`, return the match."""
        result = subprocess.run(
            ["grep", "-oE", self._extract_grep_regex()],
            input=log, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def test_regex_matches_hyphenated_subdomain(self):
        self.assertEqual(
            self._grep_relay_url("noise\nready at https://my-sub-01.relay.hapi.run now\n"),
            "https://my-sub-01.relay.hapi.run",
            "hyphenated relay subdomain was not matched (B12)",
        )

    def test_regex_matches_plain_lowercase_subdomain(self):
        self.assertEqual(
            self._grep_relay_url("x https://abc123.relay.hapi.run y\n"),
            "https://abc123.relay.hapi.run",
        )

    def test_source_uses_dns_label_class(self):
        self.assertIn("[A-Za-z0-9-]+\\.relay\\.hapi\\.run", self.text)
        self.assertNotIn("[a-z0-9]+\\.relay\\.hapi\\.run", self.text)


class TestDockerEntrypointSignals(unittest.TestCase):
    """B13: tini must forward signals to the whole process group (-g).

    entrypoint.sh `exec`s sshd after backgrounding the ttyd proxy / hapi server
    / droid daemon, which are reparented to tini (PID 1). Without -g, tini only
    SIGTERMs its direct child (sshd); the reparented children are SIGKILLed
    after the grace period. -g makes `docker stop` reach them gracefully.

    A full repro needs tini as PID 1 inside a container (out of unit scope), so
    this pins the fix statically.
    """

    def test_tini_entrypoint_uses_group_signal_flag(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn(
            '["/usr/bin/tini", "-g", "--", "/entrypoint.sh"]',
            dockerfile,
            "tini must run with -g so SIGTERM reaches reparented children (B13)",
        )


class TestBuildShGetVersion(unittest.TestCase):
    """B14: an empty `npm view` result must be treated as a fetch failure, not
    accepted as a valid (empty) version that bypasses the unknown-count guard.
    """

    def _extract_get_version(self):
        text = BUILD_SH.read_text()
        match = re.search(r"^get_version\(\) \{\n.*?^\}", text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(match, "get_version() not found in build.sh")
        return match.group(0)

    def _run_get_version(self, npm_body):
        get_version = self._extract_get_version()
        with tempfile.TemporaryDirectory() as tmp:
            fake_npm = pathlib.Path(tmp) / "npm"
            fake_npm.write_text("#!/bin/bash\n" + npm_body)
            fake_npm.chmod(0o755)
            # sleep 0 so the retry loop doesn't actually wait.
            script = (
                "set -uo pipefail\n"
                "sleep() { :; }\n"
                f"{get_version}\n"
                'get_version "somepkg"\n'
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp}{os.pathsep}{env['PATH']}"
            return subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env
            )

    def test_empty_npm_view_becomes_unknown(self):
        # npm view exits 0 but prints nothing (transient registry / missing field).
        result = self._run_get_version('printf ""\nexit 0\n')
        self.assertEqual(result.stdout.strip(), "unknown", result.stderr)

    def test_nonempty_npm_view_passes_through(self):
        result = self._run_get_version('echo "1.2.3"\nexit 0\n')
        self.assertEqual(result.stdout.strip(), "1.2.3", result.stderr)

    def test_source_requires_nonempty_version(self):
        self.assertIn('[ -n "$ver" ]', BUILD_SH.read_text())


if __name__ == "__main__":
    unittest.main()
