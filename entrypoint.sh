#!/usr/bin/env bash
set -euo pipefail

# TTYD Configuration
: "${PORT:=8080}"
: "${TTYD_USER:=hapi}"
: "${TTYD_PASSWORD:=}"

# Generate secure random secret if not provided
if [ -z "${PASSWORD_SECRET:-}" ]; then
  PASSWORD_SECRET=$(openssl rand -hex 32)
  echo "Generated random PASSWORD_SECRET (set PASSWORD_SECRET environment variable to persist across restarts)"
fi

: "${HAPI_HOST:=0.0.0.0}"
: "${HAPI_PORT:=80}"
: "${CLI_API_TOKEN:=}"
: "${HAPI_API_URL:=}"
: "${HAPI_RUNNER_ENABLED:=false}"
: "${DROID_DAEMON_ENABLED:=false}"
: "${DROID_COMPUTER_NAME:=}"
: "${AO_DAEMON_ENABLED:=false}"
: "${AO_PORT:=3001}"
: "${ROOT_PASSWORD:=}"
: "${TTYD_SANDBOX:=false}"

# External SSH tunnel (issue #79): pluggable provider exposing sshd (22) where
# port forwarding is unavailable (Railway/PaaS). Independent of hapi — works with
# INSTALL_HAPI=false. cloudflared is the default; chisel is the alternative.
: "${SSH_TUNNEL_ENABLED:=false}"
: "${SSH_TUNNEL_PROVIDER:=cloudflared}"
: "${CLOUDFLARE_TUNNEL_TOKEN:=}"
: "${CLOUDFLARE_TUNNEL_HOSTNAME:=}"
: "${CHISEL_SERVER:=}"
: "${CHISEL_AUTH:=}"
: "${CHISEL_REMOTE_PORT:=2222}"

HAPI_USER="${HAPI_USER:-hapi}"
HAPI_USER_HOME="/home/${HAPI_USER}"
: "${CLEANUP_ROOT:=${HAPI_USER_HOME}}"
: "${HAPI_HOME:=${HAPI_USER_HOME}/.hapi}"
: "${UPLOAD_DIR:=${CLEANUP_ROOT}/.uploads}"
HAPI_RUN_PATH="/usr/local/bin:/usr/bin:/bin"
CLAUDE_SETTINGS_TEMPLATE="${CLAUDE_SETTINGS_TEMPLATE:-/etc/skel/.claude/settings.json}"

echo "Starting clihost container..."

# Warn loudly if the persistent volume is mounted at the parent /home instead of
# /home/hapi (issue #69). A Docker volume is seeded from the image only while
# empty, so a /home volume that survives one deploy stops being re-seeded — the
# entrypoint then recreates /home/hapi/.claude empty on top of it and the saved
# Claude Code login is lost on every redeploy ("auth keeps resetting"). We detect
# it from /proc/mounts: a separate mount AT /home with no separate mount at
# /home/hapi means the volume is one level too high. Warn only (never abort) —
# the container is still usable, the user just won't get credential persistence.
warn_if_volume_mounted_at_parent_home() {
  [ -r /proc/mounts ] || return 0
  # A mount line's 2nd field is the mountpoint; match it exactly.
  if awk '$2 == "/home" {found=1} END {exit !found}' /proc/mounts \
     && ! awk '$2 == "/home/hapi" {found=1} END {exit !found}' /proc/mounts; then
    echo "================================================================" >&2
    echo "WARNING: a volume is mounted at /home, NOT at /home/hapi." >&2
    echo "  Claude Code credentials (and other home-dir state) will NOT" >&2
    echo "  persist across redeploys: a non-empty /home volume is no longer" >&2
    echo "  seeded from the image, so ~/.claude is recreated empty each time" >&2
    echo "  and the login keeps resetting (issue #69)." >&2
    echo "  Fix: mount the persistent volume at exactly /home/hapi." >&2
    echo "  MIGRATION: this /home volume already holds your data under its" >&2
    echo "  'hapi/' subdir. If you simply retarget the SAME volume to" >&2
    echo "  /home/hapi, that data ends up at /home/hapi/hapi/ and stays" >&2
    echo "  invisible to the app. First move the volume's 'hapi/' contents" >&2
    echo "  up to its root (or copy them into a fresh /home/hapi volume)." >&2
    echo "================================================================" >&2
  fi
}
warn_if_volume_mounted_at_parent_home

# Guarantee HAPI_USER owns its own $HOME (issue #65). On a fresh/empty /home
# volume the very first `mkdir -p` of a subdir (e.g. .config/gh) creates the
# parent /home/hapi as root, and a later `chown -R` on the subdir never touches
# the parent — leaving /home/hapi root:root (755) so hapi cannot write into its
# own home. Fix the home dir itself before creating anything underneath it.
# Non-recursive on purpose: subdirs may legitimately be owned by other UIDs.
ensure_home_owned() {
  mkdir -p "${HAPI_USER_HOME}"
  chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}"
}

ensure_dir_owned() {
  local path="$1"
  mkdir -p "${path}"
  chown -R "${HAPI_USER}:${HAPI_USER}" "${path}"
  # `mkdir -p path/to/leaf` creates intermediate parents as root; chown -R above
  # only reaches the leaf. Walk back up to HAPI_USER_HOME so parents created by
  # this call (e.g. .config when making .config/gh) end up hapi-owned too.
  local parent="${path}"
  while parent="$(dirname "${parent}")"; do
    case "${parent}" in
      "${HAPI_USER_HOME}"/*) chown "${HAPI_USER}:${HAPI_USER}" "${parent}" ;;
      *) break ;;
    esac
  done
}

ensure_ssh_dir() {
  local ssh_dir="${HAPI_USER_HOME}/.ssh"
  # Runs as root before the privilege drop, and /home/hapi is hapi-writable via
  # the persistent volume. A hapi-planted ~/.ssh *symlink* (e.g. -> /etc or another
  # tenant's home) would be dereferenced by chown -R / chmod, letting root re-perm /
  # re-own an attacker-chosen target (arbitrary-path chmod+chown). Bail on any
  # pre-existing symlink, and only touch a real, non-symlink directory. Mirrors the
  # symlink hardening in ensure_claude_settings / uploads.py.
  if [ -L "${ssh_dir}" ]; then
    echo "WARNING: ${ssh_dir} is a symlink; refusing to chmod/chown it" >&2
    return 0
  fi
  if [ -e "${ssh_dir}" ] && [ ! -d "${ssh_dir}" ]; then
    echo "WARNING: ${ssh_dir} exists but is not a directory; leaving it alone" >&2
    return 0
  fi
  ensure_dir_owned "${ssh_dir}"
  # Re-check after mkdir -p (defence in depth) before the root chmod follows the path.
  if [ -d "${ssh_dir}" ] && [ ! -L "${ssh_dir}" ]; then
    chmod 700 "${ssh_dir}"
  fi
}

ensure_gitconfig_file() {
  local gitconfig_file="${HAPI_USER_HOME}/.gitconfig"
  if [ ! -e "${gitconfig_file}" ] && [ ! -L "${gitconfig_file}" ]; then
    : > "${gitconfig_file}"
    chown "${HAPI_USER}:${HAPI_USER}" "${gitconfig_file}"
  fi
}

ensure_local_bin_env() {
  LOCAL_BIN_DIR="${HAPI_USER_HOME}/.local/bin"
  LOCAL_BIN_ENV="${LOCAL_BIN_DIR}/env"
  mkdir -p "${LOCAL_BIN_DIR}"
  chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}/.local" "${LOCAL_BIN_DIR}"
  if [ ! -e "${LOCAL_BIN_ENV}" ]; then
    cat > "${LOCAL_BIN_ENV}" <<'EOF'
# Compatibility shim for shell startup files that source ~/.local/bin/env.
case ":${PATH}:" in
  *":${HOME}/.local/bin:"*) ;;
  *) export PATH="${HOME}/.local/bin:${PATH}" ;;
esac
EOF
    chmod 0644 "${LOCAL_BIN_ENV}"
    chown "${HAPI_USER}:${HAPI_USER}" "${LOCAL_BIN_ENV}"
  fi
}

ensure_claude_settings() {
  local claude_dir="${HAPI_USER_HOME}/.claude"
  local settings_file="${claude_dir}/settings.json"
  # This runs as root before the privilege drop, and /home/hapi is writable by
  # the (untrusted in multi-tenant forks) hapi user via the persistent volume.
  # So treat ANY pre-existing destination as hands-off and never follow symlinks:
  # gating only on `! -f` would let a hapi-planted settings.json *symlink* (e.g.
  # -> a directory or /etc) pass the check, and the root `cp`/`chown` would then
  # follow it — writing the template through the link and chowning its target
  # (arbitrary-path write + ownership change). Mirrors the symlink hardening in
  # uploads.py. Bail unless .claude is a real (non-symlink) dir and settings.json
  # is genuinely absent (also rejecting a dangling/symlink settings.json via -L).
  if [ ! -d "${claude_dir}" ] || [ -L "${claude_dir}" ]; then return 0; fi
  if [ -e "${settings_file}" ] || [ -L "${settings_file}" ]; then return 0; fi
  if [ ! -f "${CLAUDE_SETTINGS_TEMPLATE}" ]; then return 0; fi
  # cp over a guaranteed-absent, non-symlink path; restrictive mode up front so a
  # future credential-bearing template never lands world-readable (default umask).
  cp "${CLAUDE_SETTINGS_TEMPLATE}" "${settings_file}"
  chmod 600 "${settings_file}"
  chown "${HAPI_USER}:${HAPI_USER}" "${settings_file}"
}

# Run a program as the hapi user, dropping root privileges. The program and its
# arguments are passed as separate argv elements (NOT interpolated into an
# `sh -c` string), so values containing shell metacharacters (quotes, $(),
# backticks, ;) can never be executed as code. The former string-based
# `run_as_hapi` (which interpolated its argument into `sh -c`) was removed in
# favor of this argv form for droid/ao/hapi startup — a latent root-context
# command-injection surface even though callers guarded their inputs (#101/#9).
#
# Secrets (tunnel token/auth) must NEVER appear in argv — not even briefly as an
# `env NAME=VALUE` argument — because argv is world-readable via `ps` /
# `/proc/<pid>/cmdline` for the lifetime of every process in the launch chain.
# Instead, the caller EXPORTS each secret into this launcher's own environment and
# passes only its NAME (before the `--` separator) to document the contract. We
# rely on util-linux runuser's documented default (WITHOUT --login it does NOT
# clear the environment — it only sets HOME/SHELL), so an exported secret is
# inherited across the privilege drop with its VALUE never entering any argv. This
# matches the repo's no-secrets-in-argv invariant (cf. ROOT_PASSWORD heredoc,
# PASSWORD_SECRET file). (--whitelist-environment is intentionally NOT used: it is
# a no-op without --login.) Non-secret vars (HOME/PATH/HAPI_HOME) are set via
# `env` since they are not sensitive; PATH in particular must be forced because
# runuser would otherwise leave the caller's root PATH in place.
run_as_hapi_argv() {
  # Consume (and ignore) the documented secret NAMES up to the `--` separator;
  # they are inherited from the exported environment, not passed here.
  while [ "$1" != "--" ]; do
    shift
  done
  shift  # drop the "--" separator
  runuser -u "${HAPI_USER}" -- env \
    HOME="${HAPI_USER_HOME}" PATH="${HAPI_RUN_PATH}" HAPI_HOME="${HAPI_HOME}" \
    "$@"
}

cleanup_runner_state() {
  local paths=(
    "${HAPI_USER_HOME}/.hapi/runner.state.json"
    "${HAPI_USER_HOME}/runner.state.json"
    "${HAPI_USER_HOME}/.hapi/runner.state.json.lock"
    "${HAPI_USER_HOME}/runner.state.json.lock"
    "${HAPI_USER_HOME}/.hapi/settings.json"
    "${HAPI_USER_HOME}/settings.json"
  )
  local path
  for path in "${paths[@]}"; do
    rm -f "${path}" 2>/dev/null || true
  done
}

ensure_home_owned
ensure_dir_owned "${HAPI_USER_HOME}/.config/gh"
ensure_dir_owned "${HAPI_USER_HOME}/.claude"
ensure_ssh_dir
ensure_gitconfig_file
ensure_local_bin_env
ensure_claude_settings

# Ensure tmux config exists (volume mount may overwrite it)
if [ ! -f "${HAPI_USER_HOME}/.tmux.conf" ]; then
  cp /etc/skel/.tmux.conf "${HAPI_USER_HOME}/.tmux.conf" 2>/dev/null || \
    echo "set -g mouse on" > "${HAPI_USER_HOME}/.tmux.conf"
  chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}/.tmux.conf"
fi

# Setup sshd (started as main process via CMD in Dockerfile)
mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true

# Configure root SSH access if ROOT_PASSWORD is set
if [ -n "${ROOT_PASSWORD}" ]; then
  # Heredoc keeps the password out of every process cmdline (/proc/<pid>/cmdline)
  chpasswd <<EOF
root:${ROOT_PASSWORD}
EOF
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  echo "Root SSH access enabled"
fi

cleanup_runner_state

# Update Hermes Agent to latest version
if [ "${HERMES_AUTO_UPDATE:-true}" != "false" ] && command -v hermes &>/dev/null; then
  echo "Updating Hermes Agent..."
  HERMES_UPDATE_DIR=""
  # The subshell keeps the parent cwd intact when any step fails.
  if HERMES_UPDATE_DIR=$(mktemp -d) && (
       git clone --depth 1 https://github.com/NousResearch/hermes-agent.git "$HERMES_UPDATE_DIR" &&
       cd "$HERMES_UPDATE_DIR" &&
       pip install --break-system-packages '.[all,messaging]'
     ); then
    echo "Hermes Agent updated"
  else
    echo "Hermes Agent update failed, using installed version"
  fi
  if [ -n "${HERMES_UPDATE_DIR}" ]; then
    rm -rf "${HERMES_UPDATE_DIR}"
  fi
fi

ensure_dir_owned "${HAPI_HOME}"

# Start Droid daemon with remote access in background
if [ "${DROID_DAEMON_ENABLED}" = "true" ]; then
  if PATH="${HAPI_RUN_PATH}" command -v droid >/dev/null 2>&1; then
    if [ -z "${DROID_COMPUTER_NAME}" ]; then
      echo "ERROR: DROID_DAEMON_ENABLED=true requires DROID_COMPUTER_NAME for non-interactive registration" >&2
      exit 1
    fi
    case "${DROID_COMPUTER_NAME}" in
      *[!A-Za-z0-9_.-]*)
        echo "ERROR: DROID_COMPUTER_NAME may only contain letters, numbers, dot, underscore, and dash" >&2
        exit 1
        ;;
    esac

    echo "Registering Droid computer '${DROID_COMPUTER_NAME}'..."
    if ! run_as_hapi_argv -- droid computer register "${DROID_COMPUTER_NAME}" -y 2>&1; then
      echo "ERROR: Droid computer registration failed; daemon not started" >&2
      exit 1
    fi

    DROID_DAEMON_LOG="${HAPI_HOME}/droid-daemon.log"
    touch "${DROID_DAEMON_LOG}"
    chown "${HAPI_USER}:${HAPI_USER}" "${DROID_DAEMON_LOG}"
    echo "Starting droid daemon --remote-access in background (logs: ${DROID_DAEMON_LOG})..."
    # argv form (no `sh -c` interpolation): the log is written via a redirect
    # instead of `| tee` (argv cannot express a pipe), matching the tunnel
    # helpers. The dashboard reads the log file, not container stdout (#101/#9).
    run_as_hapi_argv -- stdbuf -oL droid daemon --remote-access >>"${DROID_DAEMON_LOG}" 2>&1 &
    DROID_DAEMON_PID=$!
    echo "Droid daemon started with PID: ${DROID_DAEMON_PID}"
  else
    echo "droid CLI not found; skipping droid daemon startup" >&2
  fi
else
  echo "Droid daemon disabled (set DROID_DAEMON_ENABLED=true to enable remote access)"
fi

# Start agent-orchestrator daemon (issue #72, closes #61). Loopback-only
# 127.0.0.1:${AO_PORT} by design (no AO_HOST / auth / TLS) — external access is via
# the existing SSH tunnel (#79) + `ssh -L 127.0.0.1:3001:127.0.0.1:3001`.
# Independent of hapi (binary built into the image in #83), like the droid daemon.
#
# The loopback bind is enforced by the `ao` binary itself, NOT by this script:
# verified against the binary, the listen address is hardcoded to 127.0.0.1
# (`ao daemon` exposes no --host/--listen flag and honors no AO_HOST env), and it
# range-validates AO_PORT on its own. So there is nothing here to pass to keep it
# on loopback. If a future `ao` upgrade ever adds a bind-host knob or changes the
# default, this no-auth/no-TLS daemon could be exposed on a published port — re-check
# that the hardcoded-loopback invariant still holds before bumping the pinned ao ref.
if [ "${AO_DAEMON_ENABLED}" = "true" ]; then
  # Validate AO_PORT numeric: it is interpolated into the `ao daemon` launch
  # string, so a non-numeric value must fail loudly (mirrors PORT / CHISEL_REMOTE_PORT).
  case "${AO_PORT}" in
    ''|*[!0-9]*)
      echo "ERROR: AO_PORT='${AO_PORT}' must be a positive integer" >&2
      exit 1
      ;;
  esac
  if PATH="${HAPI_RUN_PATH}" command -v ao >/dev/null 2>&1; then
    AO_DAEMON_LOG="${HAPI_HOME}/ao-daemon.log"
    touch "${AO_DAEMON_LOG}"
    chown "${HAPI_USER}:${HAPI_USER}" "${AO_DAEMON_LOG}"
    echo "Starting ao daemon on 127.0.0.1:${AO_PORT} in background (logs: ${AO_DAEMON_LOG})..."
    # argv form: AO_PORT is passed as an env assignment consumed by run_as_hapi_argv's
    # `env` (not interpolated into `sh -c`), and the log via redirect not `| tee`.
    run_as_hapi_argv -- env "AO_PORT=${AO_PORT}" stdbuf -oL ao daemon >>"${AO_DAEMON_LOG}" 2>&1 &
    AO_DAEMON_PID=$!
    echo "ao daemon started with PID: ${AO_DAEMON_PID}"
  else
    echo "ao CLI not found; skipping ao daemon startup" >&2
  fi
else
  echo "ao daemon disabled (set AO_DAEMON_ENABLED=true to enable agent-orchestrator remote access)"
fi

# Start external SSH tunnel (issue #79). Pluggable provider, gated by
# SSH_TUNNEL_ENABLED, started here (next to — not inside — the hapi block) so it
# runs independently of hapi (works with INSTALL_HAPI=false), like the droid
# daemon. Connection string for the dashboard (#80) is built from env (neither
# provider prints the public hostname to its log) and written to SSH_URL_FILE.
SSH_URL_FILE="${HAPI_USER_HOME}/ssh-url"
# Drop any stale connection string up front (persistent /home volume may carry one
# from a previous run / provider); recreated below only when a tunnel starts.
rm -f "${SSH_URL_FILE}" 2>/dev/null || true
if [ "${SSH_TUNNEL_ENABLED}" = "true" ]; then
  # Validate CHISEL_REMOTE_PORT is numeric up front: it is interpolated into the
  # chisel R:<port>:localhost:22 spec, so a non-numeric value must fail loudly
  # rather than silently produce a broken forward (mirrors the PORT check below).
  case "${CHISEL_REMOTE_PORT}" in
    ''|*[!0-9]*)
      echo "ERROR: CHISEL_REMOTE_PORT='${CHISEL_REMOTE_PORT}' must be a positive integer" >&2
      exit 1
      ;;
  esac
  SSH_TUNNEL_LOG="${HAPI_HOME}/ssh-tunnel.log"
  touch "${SSH_TUNNEL_LOG}"
  chown "${HAPI_USER}:${HAPI_USER}" "${SSH_TUNNEL_LOG}"
  case "${SSH_TUNNEL_PROVIDER}" in
    cloudflared)
      if PATH="${HAPI_RUN_PATH}" command -v cloudflared >/dev/null 2>&1; then
        if [ -z "${CLOUDFLARE_TUNNEL_TOKEN}" ]; then
          echo "WARNING: SSH_TUNNEL_PROVIDER=cloudflared requires CLOUDFLARE_TUNNEL_TOKEN; skipping tunnel startup" >&2
        else
          echo "Starting cloudflared tunnel in background (logs: ${SSH_TUNNEL_LOG})..."
          # Secret hygiene: cloudflared reads the token natively from TUNNEL_TOKEN.
          # We EXPORT it into this launcher's env and pass only its NAME to
          # run_as_hapi_argv; runuser (no --login) inherits it across the privilege
          # drop, so the token VALUE never appears in any argv (`ps`/`/proc/<pid>/
          # cmdline`), not even briefly as an `env NAME=VALUE` arg. argv-based launch
          # (no `sh -c` string) also means no env value can be interpreted as shell code.
          # Logging via a plain redirect (not `| tee`) keeps $! pointing at the
          # tunnel process itself, so an immediate exit isn't masked by a live tee.
          TUNNEL_TOKEN="${CLOUDFLARE_TUNNEL_TOKEN}" \
          run_as_hapi_argv TUNNEL_TOKEN -- \
            stdbuf -oL cloudflared tunnel --no-autoupdate run \
            >>"${SSH_TUNNEL_LOG}" 2>&1 &
          SSH_TUNNEL_PID=$!
          echo "cloudflared tunnel started with PID: ${SSH_TUNNEL_PID}"
          # Public hostname is configured in the Cloudflare dashboard, not logged,
          # so the dashboard connection string comes from env.
          if [ -n "${CLOUDFLARE_TUNNEL_HOSTNAME}" ]; then
            printf 'ssh -o ProxyCommand="cloudflared access ssh --hostname %%h" %s@%s\n' \
              "${HAPI_USER}" "${CLOUDFLARE_TUNNEL_HOSTNAME}" > "${SSH_URL_FILE}"
            chown "${HAPI_USER}:${HAPI_USER}" "${SSH_URL_FILE}"
            echo "SSH connection: $(cat "${SSH_URL_FILE}")"
          else
            echo "WARNING: CLOUDFLARE_TUNNEL_HOSTNAME not set; dashboard SSH connection string unavailable" >&2
          fi
        fi
      else
        echo "WARNING: cloudflared binary not found; skipping SSH tunnel startup" >&2
      fi
      ;;
    chisel)
      if PATH="${HAPI_RUN_PATH}" command -v chisel >/dev/null 2>&1; then
        if [ -z "${CHISEL_SERVER}" ]; then
          echo "WARNING: SSH_TUNNEL_PROVIDER=chisel requires CHISEL_SERVER; skipping tunnel startup" >&2
        else
          echo "Starting chisel client in background (logs: ${SSH_TUNNEL_LOG})..."
          # AUTH (user:pass) is read natively by chisel from the env. We EXPORT it
          # and pass only its NAME to run_as_hapi_argv; runuser (no --login)
          # inherits it, so the value never lands in argv. argv-based launch
          # prevents shell interpretation of CHISEL_SERVER/CHISEL_REMOTE_PORT.
          # Logging via redirect (not tee) keeps $! on the chisel process.
          # CHISEL_REMOTE_PORT is validated numeric above so the R:<port>:... spec
          # can't be corrupted.
          AUTH="${CHISEL_AUTH}" \
          run_as_hapi_argv AUTH -- \
            stdbuf -oL chisel client --max-retry-count -1 \
            "${CHISEL_SERVER}" "R:${CHISEL_REMOTE_PORT}:localhost:22" \
            >>"${SSH_TUNNEL_LOG}" 2>&1 &
          SSH_TUNNEL_PID=$!
          echo "chisel client started with PID: ${SSH_TUNNEL_PID}"
          # Public endpoint is deterministic: the chisel server's host + the
          # reverse-forwarded port (CHISEL_REMOTE_PORT).
          CHISEL_HOST="$(printf '%s' "${CHISEL_SERVER}" | sed -E 's#^[A-Za-z]+://##; s#[:/].*$##')"
          printf 'ssh -p %s %s@%s\n' "${CHISEL_REMOTE_PORT}" "${HAPI_USER}" "${CHISEL_HOST}" > "${SSH_URL_FILE}"
          chown "${HAPI_USER}:${HAPI_USER}" "${SSH_URL_FILE}"
          echo "SSH connection: $(cat "${SSH_URL_FILE}")"
        fi
      else
        echo "WARNING: chisel binary not found; skipping SSH tunnel startup" >&2
      fi
      ;;
    *)
      echo "ERROR: SSH_TUNNEL_PROVIDER='${SSH_TUNNEL_PROVIDER}' is invalid; must be 'cloudflared' or 'chisel'" >&2
      exit 1
      ;;
  esac
else
  echo "SSH tunnel disabled (set SSH_TUNNEL_ENABLED=true to expose sshd externally)"
fi

# Start TTYD HTTP proxy (manages TTYD processes dynamically; drops root and
# runs as TTYD_USER). The secret goes through a TTYD_USER-only file (Docker
# *_FILE convention) so it never appears in the proxy's /proc/<pid>/environ.
# Validate PORT is numeric first: `[ "$PORT" -lt 1024 ]` on a non-numeric value
# exits 2 (error, not false), which would let the range guard silently pass.
case "${PORT}" in
  ''|*[!0-9]*)
    echo "ERROR: PORT=${PORT} must be a positive integer" >&2
    exit 1
    ;;
esac
if [ "${PORT}" -lt 1024 ]; then
  echo "ERROR: PORT=${PORT} is a privileged port; the proxy runs as ${TTYD_USER} and needs PORT >= 1024" >&2
  exit 1
fi
# The proxy runs as TTYD_USER and creates upload files itself; pre-create and
# chown UPLOAD_DIR so a bind-mounted /home/hapi (often not writable by the hapi
# UID) doesn't make pasted-image uploads fail with 500.
ensure_dir_owned "${UPLOAD_DIR}"
PROXY_SECRET_FILE="/run/ttyd-proxy.secret"
install -m 400 -o "${TTYD_USER}" /dev/null "${PROXY_SECRET_FILE}"
printf '%s' "${PASSWORD_SECRET}" > "${PROXY_SECRET_FILE}"
# Drop PASSWORD_SECRET from this shell's environment before launching the proxy.
# runuser (without --login) inherits the caller's whole environment, so an
# operator-supplied `-e PASSWORD_SECRET=...` would otherwise land in the proxy's
# /proc/<pid>/environ — readable by any TTYD_USER process (including terminal
# shells) and enough to forge session/CSRF tokens. The file above (mode 400,
# owner TTYD_USER) is the only channel; CLAUDE.md guarantees the secret "never
# appears in the proxy's environment". PASSWORD_SECRET is unused past this point.
unset PASSWORD_SECRET
echo "Starting TTYD HTTP proxy on port ${PORT} as ${TTYD_USER}"
PORT="${PORT}" \
TTYD_USER="${TTYD_USER}" \
TTYD_PASSWORD="${TTYD_PASSWORD}" \
PASSWORD_SECRET_FILE="${PROXY_SECRET_FILE}" \
CLEANUP_ROOT="${CLEANUP_ROOT}" \
HAPI_HOME="${HAPI_HOME}" \
TTYD_SANDBOX="${TTYD_SANDBOX}" \
runuser -u "${TTYD_USER}" -- python3 /app/ttyd_proxy.py &

# Drop any stale dashboard URL up front. On a persistent /home/hapi volume a URL
# from a previous hapi-enabled image would otherwise make the dashboard render an
# old relay link/token even when hapi is now absent (INSTALL_HAPI=false). It is
# recreated below only after a fresh relay URL + token are observed.
HAPI_URL_FILE="${HAPI_USER_HOME}/url"
rm -f "${HAPI_URL_FILE}" 2>/dev/null || true

if PATH="${HAPI_RUN_PATH}" command -v hapi >/dev/null 2>&1; then
  # Start hapi server with relay in background (logs to file, force TCP relay)
  HAPI_SERVER_LOG="${HAPI_HOME}/server.log"
  # Pre-create the log so the URL-extraction loop's -f check passes immediately
  touch "${HAPI_SERVER_LOG}"
  chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_SERVER_LOG}"
  echo "Starting hapi server --relay in background (logs: ${HAPI_SERVER_LOG})..."
  # argv form: HAPI_RELAY_FORCE_TCP via env, log via redirect not `| tee` (#101/#9).
  run_as_hapi_argv -- env HAPI_RELAY_FORCE_TCP=true stdbuf -oL hapi server --relay >>"${HAPI_SERVER_LOG}" 2>&1 &
  HAPI_SERVER_PID=$!
  echo "Hapi server started with PID: ${HAPI_SERVER_PID}"

  # Build the legacy connection URL file by delegating to the SAME builder the
  # dashboard uses (ttydproxy.views.build_hapi_url_from_runtime), instead of a
  # second bash reimplementation. The two copies had already drifted — bash took
  # the FIRST relay URL (head -1) while views took the LAST, and bash left the
  # token un-encoded while views quote()s it — so a token with &/+/% produced a
  # broken /home/hapi/url that disagreed with the working on-demand dashboard
  # link (#101/#12). One builder = no drift.
  HAPI_SETTINGS_FILE="${HAPI_HOME}/settings.json"
  (
    for i in $(seq 1 60); do
      if [ -f "${HAPI_SERVER_LOG}" ] && [ -f "${HAPI_SETTINGS_FILE}" ]; then
        # PYTHONPATH=/app makes the ttydproxy package importable (same layout as
        # `python3 /app/ttyd_proxy.py`). The helper returns the URL or nothing.
        FULL_URL=$(PYTHONPATH=/app python3 -c '
import sys
from ttydproxy.views import build_hapi_url_from_runtime
log = open(sys.argv[1], encoding="utf-8", errors="replace").read()
settings = open(sys.argv[2], encoding="utf-8", errors="replace").read()
url = build_hapi_url_from_runtime(log, settings)
if url:
    print(url)
' "${HAPI_SERVER_LOG}" "${HAPI_SETTINGS_FILE}" 2>/dev/null || true)
        if [ -n "$FULL_URL" ]; then
          echo "$FULL_URL" > "${HAPI_URL_FILE}"
          chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_URL_FILE}"
          echo "Hapi connection URL: ${FULL_URL}"
          break
        fi
      fi
      sleep 1
    done
    # Visible failure path: if the loop ran out without writing the URL file,
    # the relay log never produced a matching URL (B12) — don't fail silently.
    if [ ! -f "${HAPI_URL_FILE}" ]; then
      echo "WARNING: could not build hapi connection URL after 60s; relay log did not contain a matching URL" >&2
    fi
  ) &

  # Start hapi runner if enabled (reads config from volume)
  if [ "${HAPI_RUNNER_ENABLED}" = "true" ]; then
    echo "Starting hapi runner..."
    if ! run_as_hapi_argv -- hapi runner start 2>&1; then
      echo '=== RUNNER START FAILED ===' >&2
    fi

    # Verify runner is running
    echo "Checking hapi runner status..."
    if ! run_as_hapi_argv -- hapi runner status 2>&1; then
      echo '=== RUNNER NOT RUNNING ===' >&2
      echo 'Running hapi doctor for diagnostics:' >&2
      run_as_hapi_argv -- hapi doctor 2>&1 || true
    fi
    echo "Hapi runner startup complete"
  else
    echo "Hapi runner disabled (set HAPI_RUNNER_ENABLED=true to enable)"
    echo "Config created by 'hapi server --relay' - run 'hapi runner start' manually if needed"
  fi
else
  echo "WARNING: hapi CLI not found; skipping hapi server --relay startup" >&2
  if [ "${HAPI_RUNNER_ENABLED}" = "true" ]; then
    echo "WARNING: HAPI_RUNNER_ENABLED=true but hapi CLI is not installed; skipping hapi runner startup" >&2
  else
    echo "Hapi runner disabled (set HAPI_RUNNER_ENABLED=true to enable)"
  fi
fi

# sshd is now the main process (via CMD in Dockerfile)
# Container stays alive as long as sshd runs
exec /usr/sbin/sshd -D -e
