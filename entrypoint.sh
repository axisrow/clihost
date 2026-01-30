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
: "${ROOT_PASSWORD:=}"

HAPI_USER="${HAPI_USER:-hapi}"
HAPI_USER_HOME="/home/${HAPI_USER}"
: "${HAPI_HOME:=${HAPI_USER_HOME}/.hapi}"

echo "Starting clihost container..."

# Ensure gh CLI config directory exists for persistence on volume
mkdir -p "${HAPI_USER_HOME}/.config/gh"
chown -R "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}/.config"

# Ensure Claude CLI config directory exists for persistence on volume
mkdir -p "${HAPI_USER_HOME}/.claude"
chown -R "${HAPI_USER}:${HAPI_USER}" "${HAPI_USER_HOME}/.claude"

# Setup sshd (started as main process via CMD in Dockerfile)
mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true

# Configure root SSH access if ROOT_PASSWORD is set
if [ -n "${ROOT_PASSWORD}" ]; then
  echo "root:${ROOT_PASSWORD}" | chpasswd
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
  sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  echo "Root SSH access enabled"
fi

# Clean old runner state before starting (force re-registration on each deploy)
rm -f "${HAPI_USER_HOME}/.hapi/runner.state.json" 2>/dev/null || true
rm -f "${HAPI_USER_HOME}/runner.state.json" 2>/dev/null || true
# Clean stale lock files (prevents "another runner is running" error after container restart)
rm -f "${HAPI_USER_HOME}/.hapi/runner.state.json.lock" 2>/dev/null || true
rm -f "${HAPI_USER_HOME}/runner.state.json.lock" 2>/dev/null || true
# Clean machineId settings to force re-registration on each deploy
rm -f "${HAPI_USER_HOME}/.hapi/settings.json" 2>/dev/null || true
rm -f "${HAPI_USER_HOME}/settings.json" 2>/dev/null || true

# Start TTYD process (bind to localhost only, hardcoded port 7681)
echo "Starting TTYD for user: ${TTYD_USER}"
runuser -u "${TTYD_USER}" -- /usr/local/bin/ttyd \
    -p 7681 \
    -i 127.0.0.1 \
    -W \
    /bin/tmux-wrapper.sh &

TTYD_PID=$!
echo "TTYD started with PID: ${TTYD_PID}"

# Wait for TTYD to be ready with health check
echo "Waiting for TTYD to be ready..."
for i in $(seq 1 30); do
  if curl -sS http://127.0.0.1:7681 >/dev/null 2>&1; then
    echo "TTYD is ready (after ${i}s)"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "ERROR: TTYD failed to start within 30 seconds" >&2
    exit 1
  fi
  sleep 1
done

# Start TTYD HTTP proxy
echo "Starting TTYD HTTP proxy on port ${PORT}"
PORT="${PORT}" \
TTYD_USER="${TTYD_USER}" \
TTYD_PASSWORD="${TTYD_PASSWORD}" \
PASSWORD_SECRET="${PASSWORD_SECRET}" \
python3 /app/ttyd_proxy.py &

# Start hapi server with relay in background (logs to file, force TCP relay)
HAPI_SERVER_LOG="${HAPI_HOME}/server.log"
mkdir -p "${HAPI_HOME}"
chown "${HAPI_USER}:${HAPI_USER}" "${HAPI_HOME}"
echo "Starting hapi server --relay in background (logs: ${HAPI_SERVER_LOG})..."
runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOME=\"${HAPI_HOME}\" HAPI_RELAY_FORCE_TCP=true stdbuf -oL hapi server --relay 2>&1 | tee \"${HAPI_SERVER_LOG}\"" &
HAPI_SERVER_PID=$!
echo "Hapi server started with PID: ${HAPI_SERVER_PID}"

# Extract tunnel URL and token, build full connection URL
HAPI_URL_FILE="${HAPI_USER_HOME}/url"
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
  if ! runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOME=\"${HAPI_HOME}\" hapi runner start 2>&1"; then
    echo '=== RUNNER START FAILED ===' >&2
  fi

  # Verify runner is running
  echo "Checking hapi runner status..."
  if ! runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOME=\"${HAPI_HOME}\" hapi runner status 2>&1"; then
    echo '=== RUNNER NOT RUNNING ===' >&2
    echo 'Running hapi doctor for diagnostics:' >&2
    runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOME=\"${HAPI_HOME}\" hapi doctor 2>&1" || true
  fi
  echo "Hapi runner startup complete"
else
  echo "Hapi runner disabled (set HAPI_RUNNER_ENABLED=true to enable)"
  echo "Config created by 'hapi server --relay' - run 'hapi runner start' manually if needed"
fi

# sshd is now the main process (via CMD in Dockerfile)
# Container stays alive as long as sshd runs
exec /usr/sbin/sshd -D -e
