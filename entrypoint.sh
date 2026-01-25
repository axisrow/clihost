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
: "${CLI_API_TOKEN}"
: "${HAPI_API_URL}"
: "${ROOT_PASSWORD:=}"

HAPI_USER="${HAPI_USER:-hapi}"
HAPI_USER_HOME="/home/${HAPI_USER}"
: "${HAPI_HOME:=${HAPI_USER_HOME}}"

echo "Starting hapi codex against ${HAPI_API_URL}..."

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

# Clean old daemon state before starting (force re-registration on each deploy)
rm -f "${HAPI_USER_HOME}/.hapi/daemon.state.json" 2>/dev/null || true
rm -f "${HAPI_USER_HOME}/daemon.state.json" 2>/dev/null || true
# Clean stale lock files (prevents "another daemon is running" error after container restart)
rm -f "${HAPI_USER_HOME}/.hapi/daemon.state.json.lock" 2>/dev/null || true
rm -f "${HAPI_USER_HOME}/daemon.state.json.lock" 2>/dev/null || true
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

# Start hapi daemon in background as hapi user
echo "Starting hapi daemon: HAPI_HOST=${HAPI_HOST} HAPI_PORT=${HAPI_PORT} HAPI_API_URL=${HAPI_API_URL}"
if ! runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOST=\"${HAPI_HOST}\" HAPI_PORT=\"${HAPI_PORT}\" HAPI_API_URL=\"${HAPI_API_URL}\" CLI_API_TOKEN=\"${CLI_API_TOKEN}\" HAPI_HOME=\"${HAPI_HOME}\" hapi daemon start 2>&1"; then
  echo '=== DAEMON START FAILED ===' >&2
fi

# Verify daemon is running, run diagnostics if not
echo "Checking hapi daemon status..."
if ! runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOST=\"${HAPI_HOST}\" HAPI_PORT=\"${HAPI_PORT}\" CLI_API_TOKEN=\"${CLI_API_TOKEN}\" HAPI_API_URL=\"${HAPI_API_URL}\" HAPI_HOME=\"${HAPI_HOME}\" hapi daemon status 2>&1"; then
  echo '=== DAEMON NOT RUNNING ===' >&2
  echo 'Running hapi doctor for diagnostics:' >&2
  runuser -u "${HAPI_USER}" -- sh -c "cd \"${HAPI_USER_HOME}\" && env HOME=\"${HAPI_USER_HOME}\" PATH=\"/usr/local/bin:/usr/bin:/bin\" HAPI_HOST=\"${HAPI_HOST}\" HAPI_PORT=\"${HAPI_PORT}\" CLI_API_TOKEN=\"${CLI_API_TOKEN}\" HAPI_API_URL=\"${HAPI_API_URL}\" HAPI_HOME=\"${HAPI_HOME}\" hapi doctor 2>&1"
fi
echo "Hapi daemon startup complete"

# sshd is now the main process (via CMD in Dockerfile)
# Container stays alive as long as sshd runs
exec /usr/sbin/sshd -D -e
