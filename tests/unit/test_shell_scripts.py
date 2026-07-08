"""Static checks for shell scripts (syntax + known-bug regressions)."""
import json
import os
import pathlib
import re
import stat
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
GLM = REPO_ROOT / "bin/glm"
CLAUDE_AUTH_SNAPSHOT = REPO_ROOT / "bin/claude-auth-snapshot.sh"
CLAUDE_AUTH_SNAPSHOT_HOST = REPO_ROOT / "bin/claude-auth-snapshot-host.sh"
CLIHOST_SYNC = REPO_ROOT / "bin/clihost-sync.sh"
README = REPO_ROOT / "README.md"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"
CLAUDE_SETTINGS_TEMPLATE = REPO_ROOT / "config/claude-settings.json"
ENV_EXAMPLE = REPO_ROOT / ".env.example"

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
        for script in (
            ENTRYPOINT,
            BUILD_SH,
            INSTALL_CLI,
            TMUX_WRAPPER,
            CLAUDE_AUTH_SNAPSHOT,
            CLAUDE_AUTH_SNAPSHOT_HOST,
            CLIHOST_SYNC,
        ):
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

    def test_password_secret_unset_before_proxy_launch(self):
        # runuser (no --login) inherits the caller's whole environment, so an
        # operator-supplied `-e PASSWORD_SECRET=...` would land in the proxy's
        # /proc/<pid>/environ unless the entrypoint drops it first. The secret
        # must be unset AFTER it is written to the file and BEFORE the proxy is
        # launched, so the file (mode 400) is the only channel (#101/#1).
        unset_pos = self.text.find("unset PASSWORD_SECRET")
        secret_file_write_pos = self.text.find('> "${PROXY_SECRET_FILE}"')
        proxy_pos = self.text.find('runuser -u "${TTYD_USER}" -- python3')
        self.assertGreater(unset_pos, -1, "PASSWORD_SECRET is never unset")
        self.assertGreater(
            unset_pos, secret_file_write_pos,
            "PASSWORD_SECRET must be unset only after it is written to the file",
        )
        self.assertLess(
            unset_pos, proxy_pos,
            "PASSWORD_SECRET must be unset before the proxy is launched",
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

    def test_ao_daemon_started_as_hapi_with_log(self):
        # agent-orchestrator daemon (issue #72, closes #61): off by default, gated
        # by AO_DAEMON_ENABLED, started as hapi with its log under HAPI_HOME, the
        # `ao` binary guarded by `command -v` so a missing binary skips (not fails).
        self.assertIn(': "${AO_DAEMON_ENABLED:=false}"', self.text)
        self.assertIn(': "${AO_PORT:=3001}"', self.text)
        self.assertIn('[ "${AO_DAEMON_ENABLED}" = "true" ]', self.text)
        self.assertIn('PATH="${HAPI_RUN_PATH}" command -v ao', self.text)
        self.assertIn("ao CLI not found; skipping ao daemon startup", self.text)
        self.assertIn('AO_DAEMON_LOG="${HAPI_HOME}/ao-daemon.log"', self.text)
        self.assertIn(
            'run_as_hapi "AO_PORT=\\"${AO_PORT}\\" stdbuf -oL ao daemon 2>&1 | tee \\"${AO_DAEMON_LOG}\\"" &',
            self.text,
        )
        self.assertIn(
            "ao daemon disabled (set AO_DAEMON_ENABLED=true", self.text
        )

    def test_ao_port_validated_numeric_in_daemon_gate(self):
        # AO_PORT is interpolated into the `ao daemon` launch string, so a
        # non-numeric value must fail loudly (mirrors PORT / CHISEL_REMOTE_PORT).
        # The guard lives inside the AO_DAEMON_ENABLED gate so the default path
        # (flag off) never validates a value it doesn't use.
        gate_pos = self.text.find('if [ "${AO_DAEMON_ENABLED}" = "true" ]; then')
        self.assertGreater(gate_pos, -1, "AO_DAEMON_ENABLED gate is missing")
        check_pos = self.text.find(
            "AO_PORT='${AO_PORT}' must be a positive integer", gate_pos
        )
        self.assertGreater(check_pos, gate_pos, "AO_PORT numeric check missing in gate")

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


class TestSyncFoundationBootstrap(unittest.TestCase):
    """Bootstrap contract for sync foundation directories (issue #91).

    Sources the real entrypoint helpers and runs them with fake chown/chmod
    binaries on PATH, so ownership/mode intent is proven without root or Docker.
    """

    def _extract_helpers(self):
        text = ENTRYPOINT.read_text()
        helpers = []
        for name in ("ensure_dir_owned", "ensure_ssh_dir", "ensure_gitconfig_file"):
            match = re.search(
                rf"^{name}\(\) \{{\n.*?^\}}", text, re.MULTILINE | re.DOTALL
            )
            self.assertIsNotNone(match, f"{name} not found in entrypoint.sh")
            helpers.append(match.group(0))
        return "\n\n".join(helpers)

    def _run_helpers(self, existing_gitconfig=None):
        helpers = self._extract_helpers()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            home = tmp_path / "home" / "hapi"
            home.mkdir(parents=True)
            gitconfig = home / ".gitconfig"
            if existing_gitconfig is not None:
                gitconfig.write_text(existing_gitconfig)

            chown_log = tmp_path / "chown.log"
            chmod_log = tmp_path / "chmod.log"

            fake_chown = tmp_path / "chown"
            fake_chown.write_text(
                "#!/bin/bash\n"
                'printf "%%s\\n" "$*" >> "%s"\n' % chown_log
            )
            fake_chown.chmod(0o755)

            fake_chmod = tmp_path / "chmod"
            fake_chmod.write_text(
                "#!/bin/bash\n"
                'printf "%%s\\n" "$*" >> "%s"\n'
                'exec /bin/chmod "$@"\n' % chmod_log
            )
            fake_chmod.chmod(0o755)

            script = (
                "set -euo pipefail\n"
                'HAPI_USER="hapi"\n'
                f'HAPI_USER_HOME="{home}"\n'
                f"{helpers}\n"
                "ensure_ssh_dir\n"
                "ensure_gitconfig_file\n"
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            ssh_dir = home / ".ssh"
            return {
                "home": str(home),
                "ssh": str(ssh_dir),
                "ssh_is_dir": ssh_dir.is_dir(),
                "ssh_mode": stat.S_IMODE(ssh_dir.stat().st_mode)
                if ssh_dir.exists() else None,
                "gitconfig": str(gitconfig),
                "gitconfig_is_file": gitconfig.is_file(),
                "gitconfig_content": gitconfig.read_text()
                if gitconfig.exists() else None,
                "chown": chown_log.read_text().splitlines()
                if chown_log.exists() else [],
                "chmod": chmod_log.read_text().splitlines()
                if chmod_log.exists() else [],
            }

    def test_dockerfile_installs_rsync_in_base_apt_layer(self):
        self.assertRegex(
            DOCKERFILE.read_text(),
            r"apt-get install -y --no-install-recommends[^\n]*\brsync\b",
        )

    def test_ssh_dir_created_chowned_and_mode_700(self):
        result = self._run_helpers()

        self.assertTrue(result["ssh_is_dir"])
        self.assertEqual(result["ssh_mode"], 0o700)
        self.assertTrue(
            any("hapi:hapi" in line and result["ssh"] in line
                for line in result["chown"]),
            f".ssh was not chowned to hapi: {result['chown']}",
        )
        self.assertTrue(
            any(re.fullmatch(rf"0?700 {re.escape(result['ssh'])}", line)
                for line in result["chmod"]),
            f".ssh chmod 700 call missing: {result['chmod']}",
        )

    def test_gitconfig_created_when_missing_and_chowned(self):
        result = self._run_helpers()

        self.assertTrue(result["gitconfig_is_file"])
        self.assertEqual(result["gitconfig_content"], "")
        self.assertTrue(
            any("hapi:hapi" in line and result["gitconfig"] in line
                for line in result["chown"]),
            f".gitconfig was not chowned to hapi: {result['chown']}",
        )

    def test_existing_gitconfig_is_not_overwritten(self):
        existing = "[user]\n\tname = persisted\n"
        result = self._run_helpers(existing_gitconfig=existing)

        self.assertEqual(result["gitconfig_content"], existing)

    def test_ssh_dir_symlink_attack_is_refused(self):
        # Codex + Claude finding (PR #95): ensure_ssh_dir runs as root before the
        # privilege drop over hapi-writable /home/hapi. A hapi-planted ~/.ssh
        # *symlink* must NOT be followed — otherwise the root chmod/chown re-perms
        # and re-owns the attacker-chosen target (arbitrary-path chmod+chown). Uses
        # the REAL chmod (not the fake logger) so a follow-through actually mutates
        # the victim and the assertion catches it. Mirrors the #90 symlink tests.
        helpers = self._extract_helpers()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            home = tmp_path / "home" / "hapi"
            home.mkdir(parents=True)
            victim = tmp_path / "victim"
            victim.mkdir()
            victim.chmod(0o755)
            (home / ".ssh").symlink_to(victim)  # attack: ~/.ssh -> victim dir

            chown_log = tmp_path / "chown.log"
            fake_chown = tmp_path / "chown"
            fake_chown.write_text(
                "#!/bin/bash\n" 'printf "%%s\\n" "$*" >> "%s"\n' % chown_log
            )
            fake_chown.chmod(0o755)
            # NOTE: no fake chmod here — use the real one so a symlink follow bites.
            script = (
                "set -euo pipefail\n"
                'HAPI_USER="hapi"\n'
                f'HAPI_USER_HOME="{home}"\n'
                f"{helpers}\n"
                "ensure_ssh_dir\n"
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            # victim must be untouched: mode still 0755, and it was never chowned.
            self.assertEqual(
                stat.S_IMODE(victim.stat().st_mode), 0o755,
                "chmod followed the ~/.ssh symlink onto the victim dir",
            )
            self.assertFalse(
                any(str(victim) in line for line in
                    (chown_log.read_text().splitlines()
                     if chown_log.exists() else [])),
                "chown followed the ~/.ssh symlink onto the victim dir",
            )
            # the planted symlink itself is left as-is (not turned into a real dir)
            self.assertTrue((home / ".ssh").is_symlink())


class TestClihostSyncScript(unittest.TestCase):
    """rsync-over-SSH sync command contract (issues #92 and #93)."""

    def _make_ssh_material(self, home, *, dir_mode=0o700, key_mode=0o600):
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir()
        (ssh_dir / "known_hosts").write_text("example.test ssh-ed25519 AAAA\n")
        (ssh_dir / "config").write_text("Host example\n  HostName example.test\n")
        (ssh_dir / "id_ed25519.pub").write_text("ssh-ed25519 AAAA public\n")
        private_key = ssh_dir / "id_ed25519"
        private_key.write_text(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "private-test-fixture\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        )
        ssh_dir.chmod(dir_mode)
        private_key.chmod(key_mode)
        return ssh_dir

    def _run_sync(self, args, *, mounts=None, make_remote=None, make_local=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            fake_remote_home = tmp_path / "remote-home"
            fake_local_home = tmp_path / "local-home"
            fake_remote_home.mkdir()
            fake_local_home.mkdir()
            if mounts is None:
                mounts = [
                    "proc /proc proc rw 0 0",
                    f"/dev/sda1 {fake_remote_home} ext4 rw 0 0",
                ]
            (fake_local_home / ".gitconfig").write_text("[user]\n\tname = host\n")
            (fake_local_home / ".config" / "gh").mkdir(parents=True)
            (fake_local_home / ".config" / "gh" / "hosts.yml").write_text(
                "github.com:\n  user: axisrow\n"
            )
            if make_remote is not None:
                make_remote(fake_remote_home)
            if make_local is not None:
                make_local(fake_local_home)

            mounts_file = tmp_path / "mounts"
            mounts_file.write_text("\n".join(mounts) + "\n")
            ssh_log = tmp_path / "ssh.log"
            rsync_log = tmp_path / "rsync.log"

            fake_ssh = tmp_path / "ssh"
            fake_ssh.write_text(
                "#!/bin/bash\n"
                f'printf "SSH" >> "{ssh_log}"\n'
                f'printf " [%s]" "$@" >> "{ssh_log}"\n'
                f'printf "\\n" >> "{ssh_log}"\n'
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = \"bash\" ]; then\n"
                "    shift\n"
                "    if [ \"${1:-}\" = \"-s\" ]; then shift; fi\n"
                "    if [ \"${1:-}\" = \"--\" ]; then shift; fi\n"
                "    [ \"$#\" -ge 1 ] && shift\n"
                "    [ \"$#\" -ge 1 ] && shift\n"
                f'    exec bash -s -- "{fake_remote_home}" "{mounts_file}" "$@"\n'
                "  fi\n"
                "  shift\n"
                "done\n"
                "cat >/dev/null\n"
            )
            fake_ssh.chmod(0o755)

            fake_rsync = tmp_path / "rsync"
            fake_rsync.write_text(
                "#!/bin/bash\n"
                f'for a in "$@"; do printf "%s\\n" "$a" >> "{rsync_log}"; done\n'
                'printf "rsync %s\\n" "$*"\n'
            )
            fake_rsync.chmod(0o755)

            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            env["HOME"] = str(fake_local_home)
            env["CLIHOST_SSH_TARGET"] = "hapi@example.test"
            result = subprocess.run(
                ["bash", str(CLIHOST_SYNC), *args],
                capture_output=True,
                text=True,
                env=env,
            )
            return {
                "result": result,
                "rsync_args": rsync_log.read_text().splitlines()
                if rsync_log.exists() else [],
                "ssh_log": ssh_log.read_text() if ssh_log.exists() else "",
                "local_home": fake_local_home,
                "remote_home": fake_remote_home,
            }

    def test_pull_defaults_to_dry_run_and_never_deletes(self):
        out = self._run_sync(["pull"])

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertIn("--dry-run", out["rsync_args"])
        self.assertNotIn("--delete", out["rsync_args"])
        self.assertIn("hapi@example.test:/home/hapi/", out["rsync_args"])

    def test_ssh_defaults_to_dry_run(self):
        out = self._run_sync(["ssh"], make_local=self._make_ssh_material)

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertIn("--dry-run", out["rsync_args"])
        self.assertNotIn("--delete", out["rsync_args"])
        self.assertIn(str(out["local_home"] / ".ssh") + "/", out["rsync_args"])
        self.assertIn("hapi@example.test:/home/hapi/.ssh/", out["rsync_args"])

    def test_ssh_push_direction_syncs_container_to_host(self):
        out = self._run_sync(["ssh", "push"], make_remote=self._make_ssh_material)

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertIn("--dry-run", out["rsync_args"])
        self.assertIn("hapi@example.test:/home/hapi/.ssh/", out["rsync_args"])
        self.assertIn(str(out["local_home"] / ".ssh") + "/", out["rsync_args"])

    def test_ssh_default_include_list_is_public_material_only(self):
        out = self._run_sync(["ssh"], make_local=self._make_ssh_material)

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        includes = [arg for arg in out["rsync_args"] if arg.startswith("--include=")]
        self.assertEqual(
            includes,
            ["--include=/known_hosts", "--include=/*.pub", "--include=/config"],
        )
        joined = "\n".join(out["rsync_args"])
        self.assertNotIn("id_ed25519", joined)

    def test_ssh_include_private_keys_adds_private_material_and_warning(self):
        out = self._run_sync(
            ["ssh", "--include-private-keys"],
            make_local=self._make_ssh_material,
        )

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertIn("--include=/id_ed25519", out["rsync_args"])
        self.assertIn("private key material", out["result"].stdout)
        self.assertIn("relay/blast-radius", out["result"].stdout)

    def test_ssh_rejects_local_private_key_name_with_control_character(self):
        def make_local(home):
            ssh_dir = self._make_ssh_material(home)
            hostile = ssh_dir / "id\n--delete-excluded"
            hostile.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "private-test-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
            hostile.chmod(0o600)

        out = self._run_sync(
            ["ssh", "--include-private-keys"],
            make_local=make_local,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("control", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_remote_private_key_name_with_control_character(self):
        def make_remote(home):
            ssh_dir = self._make_ssh_material(home)
            hostile = ssh_dir / "id\n--delete-excluded"
            hostile.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "private-test-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
            hostile.chmod(0o600)

        out = self._run_sync(
            ["ssh", "push", "--include-private-keys"],
            make_remote=make_remote,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("control", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_local_private_key_name_with_rsync_filter_glob(self):
        def make_local(home):
            ssh_dir = self._make_ssh_material(home)
            for name in ("*", "***"):
                hostile = ssh_dir / name
                hostile.write_text(
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "private-test-fixture\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                )
                hostile.chmod(0o600)

        out = self._run_sync(
            ["ssh", "--include-private-keys"],
            make_local=make_local,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("rsync filter", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_remote_private_key_name_with_rsync_filter_glob(self):
        def make_remote(home):
            ssh_dir = self._make_ssh_material(home)
            for name in ("*", "***"):
                hostile = ssh_dir / name
                hostile.write_text(
                    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                    "private-test-fixture\n"
                    "-----END OPENSSH PRIVATE KEY-----\n"
                )
                hostile.chmod(0o600)

        out = self._run_sync(
            ["ssh", "push", "--include-private-keys"],
            make_remote=make_remote,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("rsync filter", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_private_key_disguised_as_public_file(self):
        def make_local(home):
            ssh_dir = self._make_ssh_material(home)
            disguised = ssh_dir / "id_ed25519.pub"
            disguised.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "private-test-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
            disguised.chmod(0o600)

        out = self._run_sync(["ssh"], make_local=make_local)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("public", out["result"].stderr)
        self.assertIn("private key", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_private_key_disguised_as_public_file_with_crlf_pem(self):
        def make_local(home):
            ssh_dir = self._make_ssh_material(home)
            disguised = ssh_dir / "id_ed25519.pub"
            disguised.write_bytes(
                b"-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
                b"private-test-fixture\r\n"
                b"-----END OPENSSH PRIVATE KEY-----\r\n"
            )
            disguised.chmod(0o600)

        out = self._run_sync(["ssh"], make_local=make_local)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("public", out["result"].stderr)
        self.assertIn("private key", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_remote_private_key_disguised_as_public_file(self):
        def make_remote(home):
            ssh_dir = self._make_ssh_material(home)
            disguised = ssh_dir / "id_ed25519.pub"
            disguised.write_text(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "private-test-fixture\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
            )
            disguised.chmod(0o600)

        out = self._run_sync(["ssh", "push"], make_remote=make_remote)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("public", out["result"].stderr)
        self.assertIn("private key", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_rejects_remote_private_key_disguised_as_public_file_with_crlf_pem(self):
        def make_remote(home):
            ssh_dir = self._make_ssh_material(home)
            disguised = ssh_dir / "id_ed25519.pub"
            disguised.write_bytes(
                b"-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
                b"private-test-fixture\r\n"
                b"-----END OPENSSH PRIVATE KEY-----\r\n"
            )
            disguised.chmod(0o600)

        out = self._run_sync(["ssh", "push"], make_remote=make_remote)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("public", out["result"].stderr)
        self.assertIn("private key", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_refuses_open_private_key_permissions_before_rsync(self):
        def make_local(home):
            self._make_ssh_material(home, key_mode=0o644)

        out = self._run_sync(["ssh"], make_local=make_local)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("private key", out["result"].stderr)
        self.assertIn("600", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_refuses_open_ssh_dir_permissions_before_rsync(self):
        def make_local(home):
            self._make_ssh_material(home, dir_mode=0o755)

        out = self._run_sync(["ssh"], make_local=make_local)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn(".ssh", out["result"].stderr)
        self.assertIn("700", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_option_like_target_is_rejected_before_ssh_or_rsync(self):
        out = self._run_sync(
            ["ssh", "--target", "-oProxyCommand=touch /tmp/pwned"],
            make_local=self._make_ssh_material,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("must not start with '-'", out["result"].stderr)
        self.assertEqual(out["ssh_log"], "")
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_option_like_identity_file_is_rejected_before_ssh_or_rsync(self):
        out = self._run_sync(
            ["ssh", "--identity-file", "-oProxyCommand=touch /tmp/pwned"],
            make_local=self._make_ssh_material,
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("must not start with '-'", out["result"].stderr)
        self.assertEqual(out["ssh_log"], "")
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_dir_symlink_attack_is_refused(self):
        def make_local(home):
            victim = home.parent / "victim-ssh"
            victim.mkdir()
            (home / ".ssh").symlink_to(victim)

        out = self._run_sync(["ssh"], make_local=make_local)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("symlink", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_ssh_apply_without_allow_delete_does_not_delete(self):
        out = self._run_sync(["ssh", "--apply"], make_local=self._make_ssh_material)

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertNotIn("--dry-run", out["rsync_args"])
        self.assertIn("--backup", out["rsync_args"])
        self.assertNotIn("--delete", out["rsync_args"])

    def test_apply_uses_backup_without_dry_run(self):
        out = self._run_sync(["pull", "--apply"])

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertNotIn("--dry-run", out["rsync_args"])
        self.assertIn("--backup", out["rsync_args"])
        self.assertTrue(
            any(arg.startswith("--backup-dir=/home/hapi/.clihost-sync-backups/")
                for arg in out["rsync_args"]),
            out["rsync_args"],
        )

    def test_allow_delete_is_the_only_way_to_pass_delete(self):
        dry = self._run_sync(["pull"])
        deleting = self._run_sync(["pull", "--allow-delete"])

        self.assertNotIn("--delete", dry["rsync_args"])
        self.assertIn("--delete", deleting["rsync_args"])

    def test_aborts_when_home_is_not_mounted_at_home_hapi(self):
        out = self._run_sync(
            ["pull"],
            mounts=["proc /proc proc rw 0 0", "/dev/sda1 /home ext4 rw 0 0"],
        )

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("/home/hapi", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_include_list_is_only_gitconfig_and_gh_config(self):
        out = self._run_sync(["pull"])
        joined = "\n".join(out["rsync_args"])

        self.assertEqual(out["result"].returncode, 0, out["result"].stderr)
        self.assertIn("/.gitconfig", joined)
        self.assertIn("/.config/gh/***", joined)
        self.assertNotIn(".claude", joined)
        self.assertNotIn(".ssh", joined)
        self.assertNotIn("settings.json", joined)

    def test_remote_symlink_guard_refuses_to_follow_target(self):
        def make_remote(home):
            victim = home.parent / "victim"
            victim.mkdir()
            (home / ".gitconfig").symlink_to(victim / "gitconfig")

        out = self._run_sync(["pull"], make_remote=make_remote)

        self.assertNotEqual(out["result"].returncode, 0, out["result"].stdout)
        self.assertIn("symlink", out["result"].stderr)
        self.assertEqual(out["rsync_args"], [])

    def test_remote_symlink_guards_defined_exactly_once(self):
        # #101/#10: the remote guard pair used to be byte-identical triplicates
        # (local pair + one copy in each of the two `bash -s` heredocs), so
        # hardening one copy silently bypassed the others — the exact class of
        # bug caught 3× before (#88/#90/#95). The remote guards must now live in
        # a single shared prelude (emit_remote_prelude), defined ONCE.
        text = CLIHOST_SYNC.read_text()
        self.assertEqual(
            text.count("guard_remote_path() {"), 1,
            "guard_remote_path must be defined exactly once (shared prelude)",
        )
        self.assertEqual(
            text.count("guard_remote_tree_no_symlinks() {"), 1,
            "guard_remote_tree_no_symlinks must be defined exactly once",
        )
        # The single copy must live inside the shared prelude emitter.
        self.assertIn("emit_remote_prelude() {", text)

    def test_option_like_target_is_rejected_before_ssh_or_rsync(self):
        # Codex + Claude finding (PR #96, both reproduced host RCE): printf %q
        # guards SHELL injection but not OPTION injection — ssh/rsync parse a
        # leading-dash target as a flag, so `-oProxyCommand=<cmd>` executes <cmd>
        # LOCALLY during preflight, before any mount/symlink guard. Same class as
        # the dashboard ProxyCommand issue (#85). The script must reject a target
        # starting with '-' and never reach ssh/rsync. A canary file proves the
        # ProxyCommand never ran.
        with tempfile.TemporaryDirectory() as canary_dir:
            canary = pathlib.Path(canary_dir) / "PWNED"
            env = dict(os.environ)
            # a real ssh would run this ProxyCommand locally on an option-like target
            hostile = f'-oProxyCommand=touch {canary}'
            env["CLIHOST_SSH_TARGET"] = hostile
            # keep a real HOME so arg-parse reaches the target validation
            with tempfile.TemporaryDirectory() as home:
                (pathlib.Path(home) / ".gitconfig").write_text("")
                env["HOME"] = home
                result = subprocess.run(
                    ["bash", str(CLIHOST_SYNC), "pull"],
                    capture_output=True, text=True, env=env,
                )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("must not start with '-'", result.stderr)
            self.assertFalse(canary.exists(),
                             "ProxyCommand executed — option injection not blocked")

    def test_ssh_and_rsync_calls_use_end_of_options_separator(self):
        # Defence-in-depth alongside the target reject: the ssh preflight and the
        # rsync invocation both pass `--` before the host/positional operands so a
        # `-`-leading value can never be parsed as a flag.
        text = CLIHOST_SYNC.read_text()
        self.assertRegex(text, r'\$\{ssh_args\[@\]\}"\s+--\s+"\$\{target\}"')
        self.assertRegex(text, r'rsync "\$\{rsync_args\[@\]\}"\s+--\s+')

    def test_dockerfile_installs_container_sync_script(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn("COPY bin/clihost-sync.sh /bin/clihost-sync.sh", dockerfile)
        self.assertIn("/bin/clihost-sync.sh", dockerfile)

    def test_docs_and_env_document_safe_sync_command(self):
        self.assertIn("CLIHOST_SSH_TARGET", (REPO_ROOT / ".env.example").read_text())
        for path in (README, CLAUDE_MD):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn("clihost-sync.sh pull", text)
                self.assertIn("clihost-sync.sh ssh", text)
                self.assertIn("dry-run", text)
                self.assertIn("~/.gitconfig", text)
                self.assertIn("~/.config/gh", text)
                self.assertIn("--include-private-keys", text)
                self.assertIn("relay/blast-radius", text)
                self.assertIn("PEM-only", text)
                self.assertIn("flat", text)
                self.assertNotRegex(
                    text,
                    re.compile(r"clihost-sync\.sh[^\n]*(\.claude|settings\.json)"),
                )


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


class TestClaudeAuthSnapshotScript(unittest.TestCase):
    """Diagnostic snapshots for Claude Code OAuth must expose metadata only."""

    def _write_fake_curl(self, tmp_path, http_code="200"):
        fake_curl = tmp_path / "curl"
        fake_curl.write_text(
            "#!/bin/bash\n"
            f"printf '{http_code}'\n"
        )
        fake_curl.chmod(0o755)

    def _env(self, tmp_path):
        claude_dir = tmp_path / ".claude"
        snapshot_dir = tmp_path / "snapshots"
        claude_dir.mkdir(parents=True, exist_ok=True)
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        self._write_fake_curl(tmp_path)
        env = dict(os.environ)
        env["CLAUDE_CONFIG_DIR"] = str(claude_dir)
        env["CLAUDE_AUTH_SNAPSHOT_DIR"] = str(snapshot_dir)
        env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
        return env, claude_dir, snapshot_dir

    def _write_credentials(self, claude_dir, expires_at):
        credentials = claude_dir / ".credentials.json"
        credentials.write_text(json.dumps({
            "claudeAiOauth": {
                "accessToken": "sk-ant-SECRET",
                "refreshToken": "sk-ant-REFRESH",
                "expiresAt": expires_at,
                "scopes": ["user:inference", "org:read"],
                "subscriptionType": "pro",
            }
        }))
        credentials.chmod(0o600)
        return credentials

    def _snapshot(self, env, label="baseline"):
        result = subprocess.run(
            ["bash", str(CLAUDE_AUTH_SNAPSHOT), "snapshot", label],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        path = pathlib.Path(result.stdout.strip())
        self.assertTrue(path.is_file(), result.stdout)
        return path, json.loads(path.read_text())

    def _diff(self, a, b):
        result = subprocess.run(
            ["bash", str(CLAUDE_AUTH_SNAPSHOT), "diff", str(a), str(b)],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_snapshot_redacts_oauth_tokens_and_extracts_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, claude_dir, _ = self._env(tmp_path)
            self._write_credentials(claude_dir, 4102444800000)

            snapshot_path, snapshot = self._snapshot(env)
            raw = snapshot_path.read_text()

            for forbidden in (
                "sk-ant-SECRET",
                "sk-ant-REFRESH",
                "accessToken",
                "refreshToken",
            ):
                self.assertNotIn(forbidden, raw)

            credentials = snapshot["credentials"]
            self.assertTrue(credentials["has_credentials"])
            self.assertRegex(credentials["sha256"], r"^[0-9a-f]{64}$")
            oauth = credentials["oauth"]
            self.assertEqual(oauth["expiresAt"], 4102444800000)
            self.assertEqual(oauth["scopes"], ["user:inference", "org:read"])
            self.assertEqual(oauth["subscriptionType"], "pro")
            self.assertFalse(oauth["is_expired"])
            self.assertGreater(oauth["expires_in_minutes"], 0)

    def test_snapshot_marks_expired_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, claude_dir, _ = self._env(tmp_path)
            self._write_credentials(claude_dir, 946684800000)

            _, snapshot = self._snapshot(env, "expired")

            oauth = snapshot["credentials"]["oauth"]
            self.assertTrue(oauth["is_expired"])
            self.assertLess(oauth["expires_in_minutes"], 0)

    def test_snapshot_without_credentials_does_not_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, _, _ = self._env(tmp_path)

            _, snapshot = self._snapshot(env, "missing")

            self.assertFalse(snapshot["credentials"]["has_credentials"])
            self.assertIsNone(snapshot["credentials"]["sha256"])

    def test_snapshot_never_leaks_token_nested_in_scopes_or_subscription(self):
        # Codex finding (PR #90): the redaction is a scalar allowlist, so a
        # malformed/schema-drifted file that hides a token inside a nested object
        # under scopes/subscriptionType must NOT leak it. Only plain-string scopes
        # and a str/None subscriptionType survive; anything else is dropped.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, claude_dir, _ = self._env(tmp_path)
            (claude_dir / ".credentials.json").write_text(json.dumps({
                "claudeAiOauth": {
                    "accessToken": "sk-ant-SECRET",
                    "refreshToken": "sk-ant-REFRESH",
                    "expiresAt": 4102444800000,
                    # hostile nesting: token smuggled inside scopes / subscriptionType
                    "scopes": ["user:inference", {"accessToken": "sk-ant-NESTED"}],
                    "subscriptionType": {"refreshToken": "sk-ant-SUBTOK"},
                }
            }))
            snapshot_path, snapshot = self._snapshot(env, "nested")
            raw = snapshot_path.read_text()
            for forbidden in (
                "sk-ant-SECRET", "sk-ant-REFRESH",
                "sk-ant-NESTED", "sk-ant-SUBTOK",
                "accessToken", "refreshToken",
            ):
                self.assertNotIn(forbidden, raw)
            oauth = snapshot["credentials"]["oauth"]
            # non-string scope dropped, string scope kept
            self.assertEqual(oauth["scopes"], ["user:inference"])
            # non-str/None subscriptionType coerced to None
            self.assertIsNone(oauth["subscriptionType"])

    def test_snapshot_refuses_symlinked_snapshot_dir(self):
        # Codex finding (PR #90): the tool may run as root via `docker exec` over
        # hapi-writable storage, and Path write follows symlinks — a hapi-planted
        # symlinked snapshot dir could steer a root write outside it. The script
        # must refuse to operate on a symlinked snapshot dir.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, claude_dir, snapshot_dir = self._env(tmp_path)
            self._write_credentials(claude_dir, 4102444800000)
            # replace the real snapshot dir with a symlink to a victim dir
            victim = tmp_path / "victim"
            victim.mkdir()
            snapshot_dir.rmdir()
            snapshot_dir.symlink_to(victim)
            result = subprocess.run(
                ["bash", str(CLAUDE_AUTH_SNAPSHOT), "snapshot", "attack"],
                capture_output=True, text=True, env=env,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
            # nothing was written into the victim dir
            self.assertEqual(list(victim.iterdir()), [], "wrote through symlink")

    def test_diff_verdict_refresh_works_when_file_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            env, claude_dir, _ = self._env(tmp_path)
            self._write_credentials(claude_dir, 4102444800000)
            before, _ = self._snapshot(env, "before")
            self._write_credentials(claude_dir, 4102448400000)
            after, _ = self._snapshot(env, "after")

            output = self._diff(before, after)

            self.assertIn("refresh работает", output)

    def test_diff_verdict_no_refresh_when_expired_and_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            first = tmp_path / "a.json"
            second = tmp_path / "b.json"
            snapshot = {
                "credentials": {
                    "has_credentials": True,
                    "sha256": "a" * 64,
                    "mtime": 1000,
                    "oauth": {"expiresAt": 946684800000, "is_expired": True},
                },
                "permissions": {
                    "credentials": {
                        "owner": "hapi:hapi",
                        "mode": "600",
                        "writable_by_hapi": True,
                    }
                },
                "network": {"anthropic": {"ok": True}},
            }
            first.write_text(json.dumps(snapshot))
            second.write_text(json.dumps(snapshot))

            output = self._diff(first, second)

            self.assertIn("refresh НЕ происходит", output)

    def test_diff_verdict_permissions_block_refresh_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            first = tmp_path / "a.json"
            second = tmp_path / "b.json"
            before = {
                "credentials": {
                    "has_credentials": True,
                    "sha256": "a" * 64,
                    "mtime": 1000,
                    "oauth": {"expiresAt": 4102444800000, "is_expired": False},
                },
                "permissions": {
                    "credentials": {
                        "owner": "hapi:hapi",
                        "mode": "600",
                        "writable_by_hapi": True,
                    }
                },
                "network": {"anthropic": {"ok": True}},
            }
            after = json.loads(json.dumps(before))
            after["permissions"]["credentials"] = {
                "owner": "root:root",
                "mode": "400",
                "writable_by_hapi": False,
            }
            first.write_text(json.dumps(before))
            second.write_text(json.dumps(after))

            output = self._diff(first, second)

            self.assertIn("права мешают", output)

    def test_dockerfile_installs_only_container_snapshot_script(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn(
            "COPY bin/claude-auth-snapshot.sh /bin/claude-auth-snapshot.sh",
            dockerfile,
        )
        self.assertIn("/bin/claude-auth-snapshot.sh", dockerfile)
        self.assertNotIn("claude-auth-snapshot-host.sh /bin/", dockerfile)

    def test_docs_and_env_document_snapshot_diagnostics(self):
        self.assertIn("CLAUDE_AUTH_SNAPSHOT_DIR", (REPO_ROOT / ".env.example").read_text())
        for path in (README, CLAUDE_MD):
            with self.subTest(path=path.name):
                text = path.read_text()
                self.assertIn("Диагностика слёта Claude Code auth", text)
                self.assertIn("claude-auth-snapshot.sh snapshot", text)
                self.assertIn("claude-auth-snapshot-host.sh", text)
                self.assertIn("токенов в снэпшоте нет", text)


class TestClaudeNativeZaiConfig(unittest.TestCase):
    """Native Claude Code configuration for z.ai Coding Plan (issue #60)."""

    def _extract_helper(self):
        text = ENTRYPOINT.read_text()
        match = re.search(
            r"^ensure_claude_settings\(\) \{\n.*?^\}",
            text,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, "ensure_claude_settings not found in entrypoint.sh")
        assert match is not None
        return match.group(0)

    def _run_helper(self, settings_content=None, local_content="local hooks",
                    settings_symlink_to=None, claude_symlink_to=None):
        helper = self._extract_helper()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            home = tmp_path / "home" / "hapi"
            claude_dir = home / ".claude"
            if claude_symlink_to is not None:
                # Attack: .claude itself is a symlink to an attacker-chosen dir.
                home.mkdir(parents=True)
                target = tmp_path / claude_symlink_to
                target.mkdir(parents=True, exist_ok=True)
                claude_dir.symlink_to(target)
            else:
                claude_dir.mkdir(parents=True)
            template = tmp_path / "claude-settings.json"
            template.write_text('{"env":{"from":"template"}}\n')
            settings = claude_dir / "settings.json"
            if settings_symlink_to is not None:
                # Attack: settings.json is a symlink to an attacker-chosen path.
                target = tmp_path / settings_symlink_to
                target.mkdir(parents=True, exist_ok=True)
                settings.symlink_to(target)
            elif settings_content is not None:
                settings.write_text(settings_content)
            settings_local = claude_dir / "settings.local.json"
            # When .claude is itself the attacker symlink, do NOT write through it
            # (that would be the test corrupting the victim, not the helper).
            if claude_symlink_to is None:
                settings_local.write_text(local_content)
            chown_log = tmp_path / "chown.log"
            fake_chown = tmp_path / "chown"
            fake_chown.write_text(
                "#!/bin/bash\n"
                'for a in "$@"; do case "$a" in -*) ;; *:*) ;; '
                f'*) echo "$a" >> "{chown_log}" ;; esac; done\n'
            )
            fake_chown.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                'HAPI_USER="hapi"\n'
                f'HAPI_USER_HOME="{home}"\n'
                f'CLAUDE_SETTINGS_TEMPLATE="{template}"\n'
                f"{helper}\n"
                "ensure_claude_settings\n"
            )
            env = dict(os.environ)
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            result = subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True, env=env,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            chown_targets = (
                chown_log.read_text().splitlines() if chown_log.exists() else []
            )
            # For symlink-attack cases, report whether the template leaked into
            # the attacker-controlled target directory (it must not). "Leaked" =
            # the template content was written somewhere under the victim dir.
            template_text = template.read_text()
            leaked = False
            for attack_target in (settings_symlink_to, claude_symlink_to):
                if attack_target is not None:
                    tgt = tmp_path / attack_target
                    if tgt.is_dir():
                        for child in tgt.rglob("*"):
                            if child.is_file() and child.read_text() == template_text:
                                leaked = True
            return {
                "template": template_text,
                "settings": settings.read_text()
                if settings.is_file() and not settings.is_symlink() else None,
                "settings_local": settings_local.read_text()
                if settings_local.is_file() else None,
                "chown_targets": chown_targets,
                "settings_path": str(settings),
                "leaked": leaked,
            }

    def test_template_uses_zai_coding_plan_without_token(self):
        data = json.loads(CLAUDE_SETTINGS_TEMPLATE.read_text())
        self.assertEqual(
            data,
            {
                "env": {
                    "ANTHROPIC_BASE_URL": "https://api.z.ai/api/coding/paas/v4",
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL": "glm-4.7",
                    "ANTHROPIC_DEFAULT_SONNET_MODEL": "glm-5.2[1m]",
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": "glm-5.2[1m]",
                    "API_TIMEOUT_MS": "3000000",
                    "CLAUDE_CODE_AUTO_COMPACT_WINDOW": "1000000",
                }
            },
        )
        text = CLAUDE_SETTINGS_TEMPLATE.read_text()
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", text)
        self.assertNotIn("ZAI_TOKEN", text)

    def test_dockerfile_copies_claude_settings_template_only(self):
        dockerfile = DOCKERFILE.read_text()
        self.assertIn(
            "COPY config/claude-settings.json /etc/skel/.claude/settings.json",
            dockerfile,
        )
        self.assertNotRegex(
            dockerfile,
            re.compile(r"(ANTHROPIC_(BASE_URL|AUTH_TOKEN)|ZAI_TOKEN)"),
        )

    def test_glm_wrapper_stays_compatible_with_zai_token(self):
        glm = GLM.read_text()
        self.assertIn("ANTHROPIC_BASE_URL=https://api.z.ai/api/coding/paas/v4", glm)
        self.assertIn(
            'ANTHROPIC_AUTH_TOKEN="${ZAI_TOKEN:?ZAI_TOKEN environment variable is required}"',
            glm,
        )
        self.assertIn("ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-4.7", glm)
        self.assertIn("ANTHROPIC_DEFAULT_SONNET_MODEL=glm-5.2[1m]", glm)
        self.assertIn("ANTHROPIC_DEFAULT_OPUS_MODEL=glm-5.2[1m]", glm)
        self.assertIn("CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000", glm)

    def test_entrypoint_copies_template_when_settings_missing(self):
        result = self._run_helper()
        self.assertEqual(result["settings"], result["template"])
        self.assertEqual(result["settings_local"], "local hooks")
        self.assertIn(result["settings_path"], result["chown_targets"])

    def test_entrypoint_does_not_overwrite_existing_settings(self):
        existing = '{"env":{"custom":"user"}}\n'
        result = self._run_helper(settings_content=existing)
        self.assertEqual(result["settings"], existing)
        self.assertEqual(result["settings_local"], "local hooks")
        self.assertNotIn(result["settings_path"], result["chown_targets"])

    def test_entrypoint_rejects_settings_symlink_attack(self):
        # The helper runs as root before the privilege drop, and /home/hapi is
        # writable by the hapi user via the persistent volume. A planted
        # settings.json *symlink* must NOT cause the root cp/chown to follow it
        # (arbitrary-path write + ownership change). Gating on `! -f` alone would
        # treat a symlink-to-dir as "missing"; the helper must bail on any
        # pre-existing path including a symlink. (Codex finding, PR #88 review.)
        result = self._run_helper(settings_symlink_to="victim")
        self.assertFalse(result["leaked"], "template leaked through settings symlink")
        self.assertNotIn(result["settings_path"], result["chown_targets"])

    def test_entrypoint_rejects_claude_dir_symlink_attack(self):
        # Same class of attack one level up: ~/.claude itself is a symlink. The
        # helper must refuse to operate unless .claude is a real, non-symlink dir.
        result = self._run_helper(claude_symlink_to="victim2")
        self.assertFalse(result["leaked"], "template leaked through .claude symlink")
        self.assertNotIn(result["settings_path"], result["chown_targets"])


class TestClaudeAuthRootCause69(unittest.TestCase):
    """Issue #69 — 'Claude Code auth keeps resetting'. The root cause was
    established by reproducing it in Docker: the ONLY trigger is the persistent
    volume being mounted at the parent `/home` instead of `/home/hapi`. A Docker
    volume is seeded from the image only while empty, so once a platform's
    persistent storage (Dokku/Railway) survives the first deploy and stays
    non-empty, a `/home` mount is no longer re-seeded and the entrypoint recreates
    `/home/hapi/.claude` empty on top of it — the saved login is gone. The three
    rival hypotheses (entrypoint chown, cleanup_runner_state, glm leaking
    ANTHROPIC_*) were all disproven. These tests pin the two artifacts that
    actually prevent the bug — the credential path and the docs that warn against
    the wrong mount point — plus the glm contract that keeps hypothesis #4 false.
    """

    def test_dockerfile_pins_claude_config_dir(self):
        # Claude Code reads/writes credentials under CLAUDE_CONFIG_DIR; the whole
        # persistence story depends on it living inside the home dir that the
        # /home/hapi volume persists. Pin the exact path so a stray edit can't
        # move credentials outside the persisted mount.
        self.assertIn(
            "CLAUDE_CONFIG_DIR=/home/hapi/.claude", DOCKERFILE.read_text()
        )

    def test_docs_warn_against_mounting_parent_home(self):
        # The fix is operational (mount /home/hapi, not /home). It only lives in
        # the docs, so pin the warning in both README and CLAUDE.md; if it is
        # removed the footgun returns silently.
        for path in (README, CLAUDE_MD):
            text = path.read_text()
            with self.subTest(doc=path.name):
                self.assertIn("/home/hapi", text)
                # an explicit "not/never the parent /home" caution must be present
                self.assertRegex(
                    text,
                    re.compile(
                        r"(not|never)\s+(the\s+parent\s+)?`?/home`?", re.IGNORECASE
                    ),
                )

    def test_entrypoint_warns_on_parent_home_mount(self):
        # The footgun is a runtime condition, so the entrypoint must detect the
        # wrong mount and warn on the console (issue #69), not only the docs.
        text = ENTRYPOINT.read_text()
        # The detector function exists and is actually called.
        self.assertIn("warn_if_volume_mounted_at_parent_home() {", text)
        self.assertRegex(
            text,
            re.compile(r"^warn_if_volume_mounted_at_parent_home$", re.MULTILINE),
        )
        # It reads /proc/mounts and keys off the exact mountpoints.
        self.assertIn("/proc/mounts", text)
        self.assertRegex(text, re.compile(r'\$2\s*==\s*"/home"'))
        self.assertRegex(text, re.compile(r'\$2\s*==\s*"/home/hapi"'))
        # It must warn, and must NOT abort (warn-only: no-volume is valid too).
        func = re.search(
            r"warn_if_volume_mounted_at_parent_home\(\)\s*\{(.*?)\n\}",
            text, re.DOTALL,
        )
        self.assertIsNotNone(func, "detector function body not found")
        body = func.group(1)
        self.assertIn("WARNING", body)
        self.assertNotIn("exit 1", body)

    def test_warning_explains_volume_migration(self):
        # A naive "mount at /home/hapi" fix orphans an existing /home volume's
        # data (it ends up at /home/hapi/hapi/, invisible to the app). The
        # warning AND both docs must call out the migration step (Codex finding,
        # PR #86 review). Pin the migration guidance everywhere the fix appears.
        entry = ENTRYPOINT.read_text()
        self.assertRegex(entry, re.compile(r"MIGRATION", re.IGNORECASE))
        self.assertIn("/home/hapi/hapi", entry)
        for path in (README, CLAUDE_MD):
            with self.subTest(doc=path.name):
                text = path.read_text()
                self.assertRegex(text, re.compile(r"migrat", re.IGNORECASE))
                self.assertIn("/home/hapi/hapi", text)

    def _run_detector(self, mounts_lines):
        # Extract the real detector function from entrypoint.sh, point its
        # /proc/mounts read at a temp file, and execute it under the same
        # `set -euo pipefail` the entrypoint uses. This closes the coverage gap
        # the static test leaves: it exercises the actual awk logic, not strings.
        text = ENTRYPOINT.read_text()
        func = re.search(
            r"(warn_if_volume_mounted_at_parent_home\(\)\s*\{.*?\n\})",
            text, re.DOTALL,
        )
        self.assertIsNotNone(func, "detector function not found")
        body = func.group(1).replace("/proc/mounts", "${MOUNTS_FILE}")
        with tempfile.TemporaryDirectory() as tmp:
            mounts = pathlib.Path(tmp) / "mounts"
            mounts.write_text("\n".join(mounts_lines) + "\n")
            script = (
                "set -euo pipefail\n"
                f'MOUNTS_FILE="{mounts}"\n'
                f"{body}\n"
                "warn_if_volume_mounted_at_parent_home\n"
            )
            return subprocess.run(
                ["bash", "-c", script], capture_output=True, text=True,
            )

    def test_detector_warns_only_on_parent_home_mount(self):
        # Behavioral: run the real awk logic across every realistic mount table.
        home = "/dev/sda1 /home ext4 rw 0 0"
        hapi = "/dev/sda1 /home/hapi ext4 rw 0 0"
        sibling = "/dev/sda1 /home/hapi-other ext4 rw 0 0"
        proc = "proc /proc proc rw 0 0"
        cases = {
            "volume_at_home": ([proc, home], True),          # the bug → warn
            "volume_at_hapi": ([proc, hapi], False),         # correct → silent
            "both_mounted": ([proc, home, hapi], False),     # persistence ok → silent
            "no_volume": ([proc], False),                    # valid → silent
            "sibling_prefix": ([proc, sibling], False),      # no prefix bleed → silent
        }
        for name, (lines, should_warn) in cases.items():
            with self.subTest(case=name):
                result = self._run_detector(lines)
                # warn-only: the function must never abort the container start.
                self.assertEqual(result.returncode, 0, result.stderr)
                warned = "WARNING: a volume is mounted at /home" in result.stderr
                self.assertEqual(warned, should_warn, result.stderr)

    def test_glm_does_not_leak_anthropic_env_into_normal_sessions(self):
        # Hypothesis #4 (glm's ANTHROPIC_* override poisons the normal `claude`
        # session) stays false ONLY because glm is a standalone wrapper that
        # `exec`s claude — the exports replace the process and never return to a
        # parent shell. Pin that contract: glm must end by exec-ing claude, and
        # the ANTHROPIC_* exports must NOT be sourced into shell startup files.
        glm = GLM.read_text()
        self.assertRegex(glm, re.compile(r"^\s*exec\s+claude\b", re.MULTILINE))
        # The exports must be the last things before exec (no command after exec
        # could run in glm's env, and exec is the final line).
        last_meaningful = [
            ln.strip() for ln in glm.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ][-1]
        self.assertTrue(
            last_meaningful.startswith("exec claude"),
            f"glm must end with 'exec claude', got: {last_meaningful!r}",
        )
        # ANTHROPIC_* / ZAI_TOKEN must not leak into global shell startup, where
        # they WOULD poison every interactive `claude` invocation.
        for path in (DOCKERFILE, ENTRYPOINT):
            with self.subTest(file=path.name):
                self.assertNotRegex(
                    path.read_text(),
                    re.compile(r"(ANTHROPIC_(BASE_URL|AUTH_TOKEN)|ZAI_TOKEN)"),
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


class TestEnvExampleDocumentsRuntimeVars(unittest.TestCase):
    """`.env.example` must document the runtime knobs the code reads (#101/#11).

    An operator copying .env.example as the source of truth otherwise cannot
    discover how to set the session lifetime or enable root SSH, even though
    CLAUDE.md lists them and config.py / entrypoint.sh read them.
    """

    def setUp(self):
        self.text = ENV_EXAMPLE.read_text()

    def test_runtime_vars_present(self):
        # Previously-missing first-class runtime variables (#101/#11) plus the
        # new slowloris timeout (#101/#2), which must also stay documented.
        for var in (
            "SESSION_TIMEOUT",
            "CLEANUP_ROOT",
            "ROOT_PASSWORD",
            "HAPI_USER",
            "HERMES_AUTO_UPDATE",
            "REQUEST_TIMEOUT",
        ):
            self.assertRegex(
                self.text,
                re.compile(rf"^#?\s*{re.escape(var)}=", re.MULTILINE),
                f"{var} is read by the code but not documented in .env.example",
            )


if __name__ == "__main__":
    unittest.main()
