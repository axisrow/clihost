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
: "${ROOT_PASSWORD:=}"
: "${TTYD_SANDBOX:=false}"

HAPI_USER="${HAPI_USER:-hapi}"
HAPI_USER_HOME="/home/${HAPI_USER}"
: "${CLEANUP_ROOT:=${HAPI_USER_HOME}}"
: "${HAPI_HOME:=${HAPI_USER_HOME}/.hapi}"
: "${UPLOAD_DIR:=${CLEANUP_ROOT}/.uploads}"
HAPI_RUN_PATH="/usr/local/bin:/usr/bin:/bin"

echo "Starting clihost container..."

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

run_as_hapi() {
  local command="$1"
  runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"${HAPI_RUN_PATH}\" HAPI_HOME=\"${HAPI_HOME}\" ${command}"
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
ensure_local_bin_env

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
    if ! run_as_hapi "droid computer register \"${DROID_COMPUTER_NAME}\" -y 2>&1"; then
      echo "ERROR: Droid computer registration failed; daemon not started" >&2
      exit 1
    fi

    DROID_DAEMON_LOG="${HAPI_HOME}/droid-daemon.log"
    touch "${DROID_DAEMON_LOG}"
    chown "${HAPI_USER}:${HAPI_USER}" "${DROID_DAEMON_LOG}"
    echo "Starting droid daemon --remote-access in background (logs: ${DROID_DAEMON_LOG})..."
    run_as_hapi "stdbuf -oL droid daemon --remote-access 2>&1 | tee \"${DROID_DAEMON_LOG}\"" &
    DROID_DAEMON_PID=$!
    echo "Droid daemon started with PID: ${DROID_DAEMON_PID}"
  else
    echo "droid CLI not found; skipping droid daemon startup" >&2
  fi
else
  echo "Droid daemon disabled (set DROID_DAEMON_ENABLED=true to enable remote access)"
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
  run_as_hapi "HAPI_RELAY_FORCE_TCP=true stdbuf -oL hapi server --relay 2>&1 | tee \"${HAPI_SERVER_LOG}\"" &
  HAPI_SERVER_PID=$!
  echo "Hapi server started with PID: ${HAPI_SERVER_PID}"

  # Extract tunnel URL and token, build full connection URL
  # (HAPI_URL_FILE was set + cleared above; recreated here only on a fresh URL.)
  HAPI_SETTINGS_FILE="${HAPI_HOME}/settings.json"
  (
    for i in $(seq 1 60); do
      if [ -f "${HAPI_SERVER_LOG}" ] && [ -f "${HAPI_SETTINGS_FILE}" ]; then
        # Extract relay URL from log: https://xxx.relay.hapi.run
        RELAY_URL=$(grep -oE 'https://[a-z0-9]+\.relay\.hapi\.run' "${HAPI_SERVER_LOG}" 2>/dev/null | head -1 || true)
        # Extract token from settings.json
        TOKEN=$(grep -oE '"cliApiToken":\s*"[^"]+"' "${HAPI_SETTINGS_FILE}" 2>/dev/null | sed 's/.*"cliApiToken":\s*"\([^"]*\)".*/\1/' || true)
        if [ -n "$RELAY_URL" ] && [ -n "$TOKEN" ]; then
          # URL-encode the relay URL (replace : with %3A, / with %2F)
          ENCODED_URL=$(echo "$RELAY_URL" | sed 's/:/%3A/g; s/\//%2F/g')
          # Build full connection URL
          FULL_URL="https://app.hapi.run/?hub=${ENCODED_URL}&token=${TOKEN}"
          echo "$FULL_URL" > "${HAPI_URL_FILE}"
          chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_URL_FILE}"
          echo "Hapi connection URL: ${FULL_URL}"
          break
        fi
      fi
      sleep 1
    done
  ) &

  # Start hapi runner if enabled (reads config from volume)
  if [ "${HAPI_RUNNER_ENABLED}" = "true" ]; then
    echo "Starting hapi runner..."
    if ! run_as_hapi "hapi runner start 2>&1"; then
      echo '=== RUNNER START FAILED ===' >&2
    fi

    # Verify runner is running
    echo "Checking hapi runner status..."
    if ! run_as_hapi "hapi runner status 2>&1"; then
      echo '=== RUNNER NOT RUNNING ===' >&2
      echo 'Running hapi doctor for diagnostics:' >&2
      run_as_hapi "hapi doctor 2>&1" || true
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
