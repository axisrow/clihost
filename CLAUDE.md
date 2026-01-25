# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Build the container image
docker build -t clihost .

# Setup environment (fill in CLI_API_TOKEN and HAPI_API_URL)
cp .env.example .env

# Run container with persistent volume
docker run --env-file .env -p 22:22 -p 8080:8080 -v "$(pwd)/volume/hapi:/home/hapi" clihost

# Health check
curl http://localhost:8080/health
# Expected: {"status": "ok", "ttyd": "running"}
```

## Architecture

Docker container running hapi CLI daemon alongside OpenSSH server, bundling AI CLI tools (Claude Code, Codex, Gemini CLI), with an integrated web terminal (TTYD).

### Container Structure

**Entry point flow** (entrypoint.sh):
1. Configures SSH server (optionally enables root access if ROOT_PASSWORD set)
2. Cleans old hapi daemon state files
3. Starts TTYD process on 127.0.0.1:7681 (as hapi user via tmux-wrapper)
4. Starts TTYD HTTP proxy server (Python, port 8080 by default)
5. Starts hapi daemon in background (as hapi user)
6. Runs sshd as main process (keeps container alive)

**Multi-process architecture:**
- `sshd` (port 22) - SSH access, main process
- `hapi daemon` (HAPI_PORT, default 80) - CLI tool daemon
- `ttyd` (127.0.0.1:7681) - Web terminal process
- `ttyd_proxy.py` (PORT, default 8080) - HTTP/WebSocket reverse proxy

**Data flow:**
```
Browser → WebSocket → HTTP Proxy (8080) → TTYD (127.0.0.1:7681) → tmux-wrapper → Shell
SSH Client → SSHD (22) → Shell Access
hapi Client → HTTP API (HAPI_PORT) → hapi Daemon
```

**Volume mount:**
- `/home/hapi`: Persistent daemon state, logs, runtime files

### Key Components

**app/server.py** - Base HTTP server with common utilities (JSON/HTML responses, silent logging)

**app/ttyd_proxy.py** - TTYD reverse proxy with:
- Cookie-based HMAC-signed session authentication
- PAM/shadow password verification (or global password via TTYD_PASSWORD)
- WebSocket tunneling to TTYD process
- Login form at `/`, terminal at `/ttyd`

**bin/tmux-wrapper.sh** - tmux session persistence wrapper (auto-attach or create new session)

### Required Environment Variables

**Hapi daemon:**
- `CLI_API_TOKEN` - authentication token for hapi server
- `HAPI_API_URL` - hapi server endpoint
- `HAPI_HOST` - bind address (default: 0.0.0.0)
- `HAPI_PORT` - port where hapi client connects (default: 80)
- `HAPI_USER` - user to run hapi daemon as (default: hapi)

**TTYD web terminal:**
- `PORT` - HTTP proxy port (default: 8080)
- `TTYD_USER` - terminal user (default: hapi)
- `TTYD_PASSWORD` - optional global password (if not set, uses system passwords)
- `PASSWORD_SECRET` - secret for HMAC session signatures (CHANGE IN PRODUCTION)
- `ROOT_PASSWORD` - optional root SSH password

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

Reference: `TTYD_MODULE.md` in repository root (in Russian) for comprehensive documentation.

## Testing

Manual smoke test: build image, run container, verify logs show "Hapi daemon started successfully" (or fallback message) and sshd stays running.

Web terminal test: Open http://localhost:8080 in browser, login with system credentials.

## Debugging Commands

```bash
# View container logs
docker logs <container_id>

# Enter running container for debugging
docker exec -it <container_id> bash

# Check hapi daemon status
docker exec <container_id> hapi daemon status

# Run hapi diagnostics
docker exec <container_id> hapi doctor
```
