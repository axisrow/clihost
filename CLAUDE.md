# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Build with auto-detection of new npm package versions (recommended)
# Hashes versions of packages from cli-packages.txt to bust Docker cache when a CLI tool updates
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
# {"status": "ok", "uptime": N, "ttyd": "running", "terminal_count": N, "terminals": [...], "memory_mb": N}
```

To add a new bundled npm CLI tool: add a line to `cli-packages.txt` and the corresponding install step in `Dockerfile`. `build.sh` reads `cli-packages.txt` to compute the cache-busting hash. Hermes Agent is installed via pip from GitHub (not npm) and auto-updates at container start unless `HERMES_AUTO_UPDATE=false`.

## Testing

```bash
python -m pytest tests/                          # all tests
python -m pytest tests/unit/                     # unit tests only
python -m pytest tests/unit/test_csrf.py         # single file
python -m pytest tests/ -k "test_truthy_1"       # single test by name
```

`tests/conftest.py` adds `app/` to `sys.path`, so tests import modules directly (`from ttydproxy.security import ...`).

- `tests/unit/` — pure-function and module tests (security/CSRF, TTYDManager, cleanup, terminals API, asset injection, threading). Run on any OS without Linux-only deps.
  - `test_threading.py` verifies `ThreadingHTTPServer` handles concurrent requests in parallel (3 × 0.3s requests must finish in ~0.3s, not 0.9s)
- `tests/integration/` — TTYD handler tests that simulate handler behavior without importing the full app wiring (avoids Linux-only deps like `crypt`/PAM).
- `tests/preview/vkbd_preview.html` — manual visual preview of the virtual keyboard.

**Manual smoke test:** build image, run container, verify logs show "Hapi runner startup complete" (or fallback message) and sshd stays running. Web terminal: open http://localhost:8080, login with system credentials.

## Architecture

Docker container running hapi CLI runner alongside OpenSSH server, bundling AI CLI tools (Claude Code, Codex, Gemini CLI, Copilot, OpenCode, Hermes Agent), with an integrated multi-terminal web UI (TTYD).

**Multi-process layout:**
- `sshd` (port 22) — SSH access, the container's main process (`exec` at end of entrypoint.sh)
- `ttyd_proxy.py` (PORT, default 8080) — HTTP/WebSocket reverse proxy with auth; **spawns and manages ttyd processes itself**; runs unprivileged as `TTYD_USER` (entrypoint drops root via `runuser`)
- `ttyd` (127.0.0.1:7681, 7682, …) — one process per terminal, localhost-only, each attached to its own tmux session `ttyd-{id}` via `bin/tmux-wrapper.sh`
- `hapi server --relay` — always starts; tunnel URL + token are extracted from its log into `/home/hapi/url` (shown on the dashboard)
- `hapi runner` (HAPI_PORT, default 80) — optional, requires HAPI_RUNNER_ENABLED=true

**Data flow:**
```
Browser → HTTP/WS → ttyd_proxy (8080) → ttyd (127.0.0.1:768x) → tmux-wrapper → shell
SSH Client → sshd (22) → shell
hapi Client → HTTP API (HAPI_PORT) → hapi runner
```

**Entry point flow** (entrypoint.sh): fix volume permissions → ensure `.tmux.conf` / config dirs → configure sshd (root access if ROOT_PASSWORD) → clean stale hapi runner state → update Hermes Agent → start ttyd proxy (as `TTYD_USER` via runuser; it auto-creates the first terminal) → start `hapi server --relay` and extract connection URL → optionally start hapi runner → `exec sshd`.

**Volume mount:** `/home/hapi` — persistent runner state, logs, configs. The mount overwrites permissions, hence the permission fixes in entrypoint.sh.

### ttyd proxy package (app/)

`app/ttyd_proxy.py` is only a **thin process entry point** (imports `main` from `ttydproxy.app`; referenced by entrypoint.sh as `python3 /app/ttyd_proxy.py`); all logic lives in the `app/ttydproxy/` package:

- `config.py` — env-based configuration constants and `TTYD_ROUTE_PATTERN`
- `security.py` — HMAC session/CSRF tokens, PAM/shadow password check, `env_bool`, username validation
- `manager.py` — `TTYDManager`: spawn/kill ttyd processes, port allocation from TTYD_BASE_PORT (7681), dead-process reaping, tmux session cleanup
- `proxy.py` — HTTP/WebSocket proxying to ttyd, gzip-aware HTML injection (`inject_tab_fix_script`)
- `ratelimit.py` — in-memory `RateLimiter`
- `views.py` — render login/menu/terminal pages from templates (`render_template`; shared favicon `<link>` block injected via the `{{FAVICON}}` placeholder from `FAVICON_LINKS`)
- `cleanup.py` — disk cleanup targets listing/deletion for the dashboard
- `assets.py` — loads static assets from `app/assets/` **at import time** into module constants (editing an asset requires proxy restart)
- `app.py` — `TTYDProxyHandler` routing + `main()` (creates the first terminal, installs SIGTERM/SIGINT handlers that kill all terminals). `_read_request_body` returns 400/413 on invalid or oversized Content-Length; CSRF double-submit comparison is timing-safe (`hmac.compare_digest`)

`app/server.py` — shared `BaseHTTPHandler` (JSON/HTML/binary responses, silent logging, security headers). Server is `ThreadingHTTPServer` (one thread per request) — never switch to plain `HTTPServer`, slow WebSocket connections would block everything.

**Templates & assets:** `app/index.html` (dashboard), `app/login.html`, `app/terminal.html` — variable substitution like `{{USERNAME}}`, `{{CSRF_TOKEN}}`, values escaped via `html.escape()`. Front-end JS/CSS injected into pages lives in `app/assets/` (tab_fix_script.html, virtual_keyboard.html/.css, terminal_parent_tab_handler.html, favicons).

### HTTP routes

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/` | GET | cookie (redirect) | Dashboard with terminal list |
| `/login` | GET/POST | CSRF | Login form / authentication |
| `/health` | GET | none | Health JSON |
| `/favicon*`, `/apple-touch-icon.png` | GET | none | Favicons |
| `/terminals` | GET/POST | cookie (+CSRF on POST) | List / create terminal |
| `/terminals/{id}` | DELETE | cookie + CSRF | Kill terminal |
| `/cleanup` | GET | cookie | List disk cleanup targets |
| `/cleanup/delete` | POST | cookie + CSRF | Delete cleanup targets |
| `/upload` | POST | cookie + CSRF | Save a pasted/dropped image (raw body), returns `{"path"}` |
| `/ttyd{N}` | GET | cookie (redirect) | Terminal iframe page |
| `/ttyd{N}/*` | GET/WS | cookie | HTTP/WebSocket proxy to that ttyd |

State-changing requests use a CSRF double-submit token (`X-CSRF-Token` header must match the `csrf_token` cookie and verify against PASSWORD_SECRET). Login is rate-limited: 5 attempts per 60s per IP and 5 per 300s per IP+account.

### Dashboard UI (app/index.html)

Terminal list and controls are built **dynamically in JavaScript**, not static HTML — searching for button text in the HTML will not find them:
- **Close terminal button** (`delete-btn` class, red ×): calls `deleteTerminal(id)` → `DELETE /terminals/{id}`. This is what users mean by "кнопка закрытия сессии". It is **not** a logout button.
- **New terminal button** (`new-terminal` class): `createTerminal()` → `POST /terminals`
- **No logout button exists** — there is no route or UI to invalidate the session cookie.

### Environment Variables

**TTYD web terminal:**
- `PORT` — HTTP proxy port (default: 8080; must be >= 1024 — the proxy runs without root)
- `TTYD_USER` — terminal user (default: hapi); the proxy process itself also runs as this user
- `TTYD_PASSWORD` — optional global password (if not set, system passwords — but only for `TTYD_USER`: the unprivileged proxy verifies passwords via `su`/unix_chkpwd, which can only check its own user's password)
- `PASSWORD_SECRET` — secret for HMAC signatures (entrypoint generates a random one if unset; set explicitly to persist sessions across restarts)
- `PASSWORD_SECRET_FILE` — path to a file containing the secret (Docker secrets convention, takes precedence over `PASSWORD_SECRET`; entrypoint hands the secret to the proxy via `/run/ttyd-proxy.secret` — mode 400, owned by `TTYD_USER` — so it never appears in the proxy's environment; an unreadable or empty secret file aborts proxy startup instead of silently falling back)
- `ROOT_PASSWORD` — optional root SSH password
- `VIRTUAL_KEYBOARD` — mobile virtual keyboard (default: true)
- `SESSION_TIMEOUT` — session token lifetime, seconds (default: 604800 = 1 week)
- `CSRF_TOKEN_TTL` — CSRF token TTL, seconds (default: 604800)
- `SECURE_COOKIES` — Secure flag on cookies for HTTPS (default: false)
- `MAX_TERMINALS` — max concurrent terminals (default: 100)
- `CLEANUP_ROOT` — root for cleanup dashboard targets (default: /home/hapi)
- `MAX_UPLOAD_SIZE` — image upload size limit, bytes (default: 10485760 = 10 MB)
- `UPLOAD_DIR` — where pasted/dropped terminal images are saved (default: `CLEANUP_ROOT/.uploads`; the cleanup dashboard's `uploads` target always points at `CLEANUP_ROOT/.uploads`, so overriding `UPLOAD_DIR` elsewhere decouples it from cleanup)

**Hapi runner (optional):**
- `HAPI_RUNNER_ENABLED` — enable runner (default: false)
- `CLI_API_TOKEN`, `HAPI_API_URL` — required if runner enabled
- `HAPI_HOST` (default: 0.0.0.0), `HAPI_PORT` (default: 80), `HAPI_USER` (default: hapi)

**Other:** `HERMES_AUTO_UPDATE` — set `false` to skip Hermes Agent update at container start.

Update `.env.example` when adding/changing variables.

## Coding Conventions

- Shell scripts use Bash with `set -euo pipefail`
- Environment variables are UPPERCASE with defaults via `${VAR:=default}`
- Dockerfile changes grouped by purpose (base OS, tools, user setup)
- Python uses standard library only (http.server, hmac, crypt, …) — no pip dependencies in app code
- Commits: short imperative subjects (e.g., "Add feature", "Fix bug")
- Retry logic for network operations: `for i in 1 2 3 4 5; do ... && break || sleep 10; done`

## Injected Terminal Fixes (app/assets/tab_fix_script.html)

The proxy injects a script into ttyd's HTML (`inject_tab_fix_script` in `proxy.py`). Implementation notes:

- **Gzip handling**: ttyd serves gzip-compressed HTML; injection decompresses, inserts, re-compresses.
- **WebSocket capture**: the script intercepts the `window.WebSocket` constructor; the socket reference must live in `window._ttydSocket` (global), not a local inside the IIFE.
- **Tab key**: sends ttyd protocol prefix `'0'` (INPUT) + `\t` over the WebSocket. Completion only works in shells that support it (bash); `/bin/sh` (dash) does not.
- **Mouse wheel**: normal screen — intercepts `wheel` with `capture: true, passive: false`, calls `term.scrollLines(n)`; alternate screen (vim/less/htop, `term.buffer.active.type === 'alternate'`) — passes through. deltaMode: `1` = lines, `2` = pages (`term.rows`), `0` = pixels (÷40).
- **Paste/drop triage**: capture-phase `paste`/`drop` listeners triage the payload — images upload to `POST /upload` (CSRF token read from the non-HttpOnly `csrf_token` cookie; up to 5 in parallel, returned paths typed in order + space), text types into the prompt (`term.paste`, bracketed-paste-safe; on iframe paste text stays on xterm's default path), anything else (non-image files) is silently skipped. Server validates by magic bytes only (png/jpg/gif/webp; SVG rejected) — the client Content-Type is never trusted. `terminal_parent_tab_handler.html` forwards paste/drop from the parent page into the iframe via `contentWindow.__handleDataTransfer(dataTransfer)`. `handle_ttyd` refreshes the `csrf_token` cookie so long-lived terminal tabs keep uploading.

**tmux mouse mode** (`config/.tmux.conf`, copied to `/home/hapi/.tmux.conf` in Dockerfile): mouse is **off by default** so xterm.js keeps native browser text selection and Cmd+C (#40). `Ctrl+B m` toggles tmux mouse mode when tmux scroll/copy is needed. A direct Ctrl+M binding is impossible — C-m and Enter are the same byte (0x0D).

## Pull Request Guidelines

PRs should include:
- Summary of changes
- New/changed environment variables (update `.env.example`)
- Port or volume mapping changes and their rationale

## CI/CD

- `.github/workflows/claude.yml` — Claude Code action, triggers on @claude mentions in issues/PR comments
- `.github/workflows/claude-code-review.yml` — automatic code review on PR open/synchronize

## Debugging Commands

```bash
docker logs <container_id>                       # container logs
docker exec -it <container_id> bash              # shell inside container
docker exec <container_id> hapi runner status    # runner status
docker exec <container_id> hapi doctor           # hapi diagnostics
```
