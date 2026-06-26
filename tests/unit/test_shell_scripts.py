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
