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
# Expected: {"status": "ok", "uptime": N, "ttyd": "running", "terminal_count": N, "terminals": [...], "memory_mb": N}
```

## Architecture

Docker container running hapi CLI runner alongside OpenSSH server, bundling AI CLI tools (Claude Code, Codex, Gemini CLI), with an integrated web terminal (TTYD).

### Container Structure

**Entry point flow** (entrypoint.sh):
1. Fixes permissions for hapi home directory (Railway volume mount overwrites permissions)
2. Creates config directories (.config/gh, .claude) for persistence on volume
3. Configures SSH server (optionally enables root access if ROOT_PASSWORD set)
4. Cleans old hapi runner state files and lock files
5. Starts TTYD process on 127.0.0.1:7681 (as hapi user via tmux-wrapper)
6. Starts TTYD HTTP proxy server (Python, port 8080 by default)
7. Starts hapi server with relay in background (extracts tunnel URL and token)
8. Starts hapi runner in background if HAPI_RUNNER_ENABLED=true
9. Runs sshd as main process (keeps container alive)

**Multi-process architecture:**
- `sshd` (port 22) - SSH access, main process
- `hapi server --relay` - relay server (always starts, provides tunnel URL)
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

**app/server.py** - Base HTTP server with common utilities (JSON/HTML responses, silent logging, security headers)

**app/ttyd_proxy.py** - TTYD reverse proxy (`ThreadingHTTPServer`) with:
- Cookie-based HMAC-signed session authentication
- PAM/shadow password verification (or global password via TTYD_PASSWORD)
- WebSocket tunneling to TTYD process
- Rate limiting (5 attempts per 60s per IP, 5 per 300s per account)
- CSRF double-submit token protection
- Username validation (alphanumeric, max 32 chars) and command injection prevention
- `env_bool()` utility for parsing boolean environment variables (used for feature toggles like VIRTUAL_KEYBOARD, SECURE_COOKIES)
- Routes: `/` (dashboard/menu), `/login` (login form), `/health` (health check), `/ttyd` (terminal), `/ttyd/*` (WebSocket proxy)

**app/index.html, app/login.html** - HTML templates with variable substitution (`{{USERNAME}}`, `{{CSRF_TOKEN}}`, `{{HAPI_LINK}}`). Values are escaped via `html.escape()` to prevent XSS.

**Dashboard UI (app/index.html)** - Terminal list and controls are built dynamically in JavaScript (not static HTML), so searching for button text in HTML will not find them. Key UI elements:
- **Terminal row** (`terminal-row` class): each active ttyd instance gets a row with an open link + close button
- **Close terminal button** (`delete-btn` class, red ×): closes a terminal session — calls `deleteTerminal(id)` → `DELETE /terminals/{id}`. This is what users refer to as "кнопка закрытия сессии" (session close button). It is **not** a logout button.
- **New terminal button** (`new-terminal` class): calls `createTerminal()` → `POST /terminals`
- **No logout button exists** — there is no route or UI element to invalidate the login session cookie

**bin/tmux-wrapper.sh** - tmux session persistence wrapper (auto-attach or create new session)

**bin/glm** - Anthropic API wrapper that routes through z.ai proxy, requires `ZAI_TOKEN` env var

### Environment Variables

**TTYD web terminal:**
- `PORT` - HTTP proxy port (default: 8080)
- `TTYD_USER` - terminal user (default: hapi)
- `TTYD_PASSWORD` - optional global password (if not set, uses system passwords)
- `PASSWORD_SECRET` - secret for HMAC session signatures (CHANGE IN PRODUCTION)
- `ROOT_PASSWORD` - optional root SSH password
- `VIRTUAL_KEYBOARD` - enable virtual keyboard for mobile devices (default: true)
- `SESSION_TIMEOUT` - session token lifetime in seconds (default: 604800 = 1 week)
- `CSRF_TOKEN_TTL` - CSRF token time-to-live in seconds (default: 604800 = 7 days)
- `SECURE_COOKIES` - set Secure flag on cookies for HTTPS (default: false)
- `MAX_TERMINALS` - maximum number of concurrent terminal instances (default: 100)

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
- HTTP server uses `ThreadingHTTPServer` (not `HTTPServer`) — one thread per request so slow/long-lived connections don't block others
- Commits: short imperative subjects (e.g., "Add feature", "Fix bug")
- Retry logic for network operations: use `for i in 1 2 3 4 5; do ... && break || sleep 10; done` pattern

## TTYD Module Details

The TTYD module provides secure web terminal access. Key implementation details:

- **Session tokens**: HMAC-SHA256 signed, base64url-encoded (username:port:signature)
- **WebSocket proxying**: Bidirectional socket tunneling using non-blocking I/O + select
- **Authentication flow**: POST /login → Set ttyd_session cookie → Redirect to /ttyd
- **Security**: TTYD bound to localhost only, proxy enforces authentication, rate limiting, CSRF protection

### Tab Key Fix

The proxy injects a JavaScript fix into TTYD HTML to enable Tab key for shell completion. Technical notes:

- **Gzip handling**: TTYD returns gzip-compressed HTML. The `inject_tab_fix_script()` function decompresses before injection and re-compresses after.
- **WebSocket capture**: The injected script intercepts `window.WebSocket` constructor to capture the TTYD socket. The socket reference must be stored in `window._ttydSocket` (global), not as a local variable inside IIFE.
- **Tab sending**: Uses TTYD protocol prefix `'0'` (INPUT command) + tab character (`\t`) via WebSocket.
- **Shell requirement**: Tab completion only works in shells that support it (bash). Default `/bin/sh` (dash) does not have completion.

### Mouse Wheel Scroll Fix

The same injected script also fixes mouse wheel scroll (added alongside the Tab fix in `TAB_FIX_SCRIPT`):

- **Normal screen** (bash/zsh): intercepts `wheel` events with `capture: true, passive: false`, calls `term.scrollLines(n)` and prevents xterm.js default (which sends ArrowUp/ArrowDown).
- **Alternate screen** (vim/less/htop): detected via `term.buffer.active.type === 'alternate'`; event passes through untouched.
- **deltaMode handling**: `1` = lines (use as-is), `2` = page (use `term.rows`), `0` = pixels (divide by 40).

Reference: `TTYD_MODULE.md` in repository root for comprehensive documentation.

## Testing

```bash
# Run all tests
python -m pytest tests/

# Run unit tests only
python -m pytest tests/unit/

# Run a single test file
python -m pytest tests/unit/test_env_bool.py

# Run a single test by name
python -m pytest tests/ -k "test_truthy_1"
```

Note: `conftest.py` adds `app/` to `sys.path` for imports.

**Test structure:**
- `tests/unit/` - Pure function tests (`env_bool`, virtual keyboard HTML generation, threading). Run without Linux-specific dependencies.
  - `test_threading.py` — verifies `ThreadingHTTPServer` handles concurrent requests in parallel (3 × 0.3s requests must finish in ~0.3s total, not 0.9s)
- `tests/integration/` - TTYD handler tests. Simulate handler behavior without importing full ttyd_proxy.py (avoids Linux-only deps like `crypt`, PAM).

**Manual smoke test:** build image, run container, verify logs show "Hapi runner startup complete" (or fallback message) and sshd stays running.

**Web terminal test:** Open http://localhost:8080 in browser, login with system credentials.

## Pull Request Guidelines

PRs should include:
- Summary of changes
- New/changed environment variables (update `.env.example`)
- Port or volume mapping changes and their rationale

## CI/CD

- `.github/workflows/claude.yml` - Claude Code action, triggers on @claude mentions in issues/PR comments
- `.github/workflows/claude-code-review.yml` - Automatic code review on PR open/synchronize

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
