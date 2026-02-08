# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Build with auto-detection of new npm package versions (recommended)
./build.sh

# Build without checking for updates (uses Docker cache)
docker build -t clihost .

# Run container (basic - web terminal + SSH only)
docker run -p 22:22 -p 8080:8080 clihost

# Run with hapi runner enabled
docker run -p 22:22 -p 8080:8080 \
  -e HAPI_RUNNER_ENABLED=true \
  -e CLI_API_TOKEN=your_token \
  -e HAPI_API_URL=your_server_url \
  -v "$(pwd)/volume/hapi:/home/hapi" \
  clihost

# Health check
curl http://localhost:8080/health
# Expected: {"status": "ok", "ttyd": "running"}
```

## Architecture

Docker container running hapi CLI runner alongside OpenSSH server, bundling AI CLI tools (Claude Code, Codex, Gemini CLI), with an integrated web terminal (TTYD).

### Container Structure

**Entry point flow** (entrypoint.sh):
1. Configures SSH server (optionally enables root access if ROOT_PASSWORD set)
2. Cleans old hapi runner state files
3. Starts TTYD process on 127.0.0.1:7681 (as hapi user via tmux-wrapper)
4. Starts TTYD HTTP proxy server (Python, port 8080 by default)
5. Starts hapi runner in background if HAPI_RUNNER_ENABLED=true
6. Runs sshd as main process (keeps container alive)

**Multi-process architecture:**
- `sshd` (port 22) - SSH access, main process
- `hapi runner` (HAPI_PORT, default 80) - CLI tool runner (optional, requires HAPI_RUNNER_ENABLED=true)
- `ttyd` (127.0.0.1:7681) - Web terminal process
- `ttyd_proxy.py` (PORT, default 8080) - HTTP/WebSocket reverse proxy

**Data flow:**
```
Browser → WebSocket → HTTP Proxy (8080) → TTYD (127.0.0.1:7681) → tmux-wrapper → Shell
SSH Client → SSHD (22) → Shell Access
hapi Client → HTTP API (HAPI_PORT) → hapi Runner
```

**Volume mount:**
- `/home/hapi`: Persistent runner state, logs, runtime files

### Key Components

**app/server.py** - Base HTTP server with common utilities (JSON/HTML responses, silent logging)

**app/ttyd_proxy.py** - TTYD reverse proxy with:
- Cookie-based HMAC-signed session authentication
- PAM/shadow password verification (or global password via TTYD_PASSWORD)
- WebSocket tunneling to TTYD process
- Login form at `/`, terminal at `/ttyd`

**bin/tmux-wrapper.sh** - tmux session persistence wrapper (auto-attach or create new session)

### Environment Variables

**TTYD web terminal:**
- `PORT` - HTTP proxy port (default: 8080)
- `TTYD_USER` - terminal user (default: hapi)
- `TTYD_PASSWORD` - optional global password (if not set, uses system passwords)
- `PASSWORD_SECRET` - secret for HMAC session signatures (CHANGE IN PRODUCTION)
- `ROOT_PASSWORD` - optional root SSH password
- `VIRTUAL_KEYBOARD` - enable virtual keyboard for mobile devices (default: true)

**Hapi runner (optional):**
- `HAPI_RUNNER_ENABLED` - enable hapi runner (default: false)
- `CLI_API_TOKEN` - authentication token (required if runner enabled)
- `HAPI_API_URL` - hapi server endpoint (required if runner enabled)
- `HAPI_HOST` - bind address (default: 0.0.0.0)
- `HAPI_PORT` - port where hapi client connects (default: 80)
- `HAPI_USER` - user to run hapi runner as (default: hapi)

## Coding Conventions

- Shell scripts use Bash with `set -euo pipefail`
- Environment variables are UPPERCASE with defaults via `${VAR:=default}`
- Dockerfile changes grouped by purpose (base OS, tools, user setup)
- Python uses standard library only (http.server, hmac, crypt, etc.)
- Commits: short imperative subjects (e.g., "Add feature", "Fix bug")
- Retry logic for network operations: use `for i in 1 2 3 4 5; do ... && break || sleep 10; done` pattern

## TTYD Module Details

The TTYD module provides secure web terminal access. Key implementation details:

- **Session tokens**: HMAC-SHA256 signed, base64url-encoded (username:port:signature)
- **WebSocket proxying**: Bidirectional socket tunneling using non-blocking I/O + select
- **Authentication flow**: POST /login → Set ttyd_session cookie → Redirect to /ttyd
- **Security**: TTYD bound to localhost only, proxy enforces authentication

### Tab Key Fix

The proxy injects a JavaScript fix into TTYD HTML to enable Tab key for shell completion. Technical notes:

- **Gzip handling**: TTYD returns gzip-compressed HTML. The `inject_tab_fix_script()` function decompresses before injection and re-compresses after.
- **WebSocket capture**: The injected script intercepts `window.WebSocket` constructor to capture the TTYD socket. The socket reference must be stored in `window._ttydSocket` (global), not as a local variable inside IIFE.
- **Tab sending**: Uses TTYD protocol prefix `'0'` (INPUT command) + tab character (`\t`) via WebSocket.
- **Shell requirement**: Tab completion only works in shells that support it (bash). Default `/bin/sh` (dash) does not have completion.

Reference: `TTYD_MODULE.md` in repository root (in Russian) for comprehensive documentation.

## Testing

Manual smoke test: build image, run container, verify logs show "Hapi runner startup complete" (or fallback message) and sshd stays running.

Web terminal test: Open http://localhost:8080 in browser, login with system credentials.

## Debugging Commands

```bash
# View container logs
docker logs <container_id>

# Enter running container for debugging
docker exec -it <container_id> bash

# Check hapi runner status
docker exec <container_id> hapi runner status

# Run hapi diagnostics
docker exec <container_id> hapi doctor
```
