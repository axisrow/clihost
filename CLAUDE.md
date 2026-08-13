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

To add a new bundled npm CLI tool: add a line `COMPONENT_KEY pkg@latest` to `cli-packages.txt`, a matching `ADD https://registry.npmjs.org/<pkg>/latest ...` cache-bust manifest, and an `ARG INSTALL_<COMPONENT_KEY>=true` to `Dockerfile`. The actual `npm install -g` is centralized in `bin/install-cli.sh` (no per-tool install step needed). `build.sh` parses `cli-packages.txt` (first token = key, second = npm spec) to compute the cache-busting hash. Hermes Agent is installed via pip from GitHub (not npm) and auto-updates at container start unless `HERMES_AUTO_UPDATE=false`.

### Modular image composition (build-time, issue #57)

Each bundled CLI tool can be dropped from the image to build a lighter, deploy-specific image. This is a **build-time** mechanism (the tools install during `docker build`), driven by `INSTALL_<KEY>` build args that default to `true`:

- `bin/install-cli.sh` reads `cli-packages.txt` and installs only the npm tools whose `INSTALL_<KEY>` env var is not `false`. The `Dockerfile` declares one `ARG INSTALL_<KEY>=true` per component and promotes them into the env for that `RUN`. Hermes has its own `INSTALL_HERMES`-gated `RUN`. `ao` is built from source in its own Go build-stage (see below).
- `build.sh` forwards every `INSTALL_<KEY>` (read from the shell environment, default `true`) to `docker build` as `--build-arg`, and excludes disabled tools from the cache-busting hash (so bumping a disabled tool's version no longer invalidates the cache). The non-npm flags (`INSTALL_HERMES`, `INSTALL_CLOUDFLARED`, `INSTALL_CHISEL`, `INSTALL_AO`) are forwarded only when set in the environment and never enter the npm cache hash.
- Keys: `INSTALL_CLAUDE_CODE`, `INSTALL_CODEX`, `INSTALL_GEMINI`, `INSTALL_COPILOT`, `INSTALL_OPENCODE`, `INSTALL_DROID`, `INSTALL_HAPI`, `INSTALL_HERMES`, `INSTALL_CLOUDFLARED`, `INSTALL_CHISEL`, `INSTALL_AO`. Disabling `INSTALL_HAPI` removes the runtime core (tunnel/runner/dashboard URL); the entrypoint skips hapi startup when the binary is absent and warns if `HAPI_RUNNER_ENABLED=true`. `INSTALL_CLOUDFLARED`/`INSTALL_CHISEL` gate the two SSH-tunnel providers (issue #79): both are non-npm curl-prebuilt binaries (so they are forwarded by `build.sh` like `INSTALL_HERMES`, not via `cli-packages.txt`), installed in a dedicated `Dockerfile` `RUN` after the ttyd step with a strict `true|false` case (fail-closed on anything else).

##### ao — built from upstream Go source, not npm/curl (issues #76 + #77)

`ao` (agent-orchestrator) is a **Go binary compiled from source** inside a dedicated `golang:1.25-bookworm` build-stage — it is **not** a prebuilt download and **not** an npm package (the public npm `@aoagents/ao` is stuck on the old 0.9.5 Node scheme; no Go prebuilts are published). Both the x86_64 issue (#76) and the arm64 issue (#77) are closed by **this single go-build path**: `ao`'s only native dependency is the pure-Go `modernc.org/sqlite` driver, so `CGO_ENABLED=0 GOOS=linux GOARCH=<arch> go build -trimpath -ldflags='-s -w' -o /out/ao ./cmd/ao` (run in the `backend/` module) produces a static binary identically for every architecture — no arch branches, no gcc/musl. `GOARCH` is resolved as `${TARGETARCH:-$(dpkg --print-architecture)}`: buildx's `TARGETARCH` wins for cross-builds, but it is a **BuildKit-only** automatic arg, so a non-BuildKit native build falls back to the host's `dpkg --print-architecture` (same arch-detect the ttyd/tunnel steps use; its `amd64`/`arm64` values are already valid `GOARCH`). Defaulting to `amd64` instead would silently cross-ship an amd64 binary inside an arm64 image (green build, runtime failure).

**Source pinning (`ARG AO_REPO` / `ARG AO_REF`):** the Go `backend/` rewrite is **not yet in any upstream release tag** — the published tags (e.g. `v0.10.1-nightly-249…`) are still the *old TypeScript monorepo* with no `backend/` dir, so a clone of that tag fails at `cd /src/backend`. The Go tree currently exists only on the moving upstream `main` and on the fork branch. To get a **reproducible** pin we therefore build from a **specific fork commit**: `AO_REPO=https://github.com/axisrow/agent-orchestrator.git`, `AO_REF=405be363fbe414dd93a81b12dfcfea112e277741`. A full SHA can't be used with `git clone --branch`, so the stage does `git init` + `git fetch --depth 1 origin <SHA>` + `git checkout FETCH_HEAD`. Once upstream publishes a Go-bearing tag, retarget by overriding `--build-arg AO_REPO=… AgentWrapper… --build-arg AO_REF=<tag>` (and update the defaults here).

`INSTALL_AO` gates the build via a `FROM ao-build-${INSTALL_AO}` alias (`ao-build-true` = real golang stage; `ao-build-false` = empty busybox placeholder), so a disabled build never schedules the toolchain; the final `COPY --from=ao-build` + strict `case` either installs `/usr/local/bin/ao` or drops the placeholder (fail-closed on a non-`true`/`false` value). Same caveat as the npm-manifest/Hermes gates: an invalid value passed straight to `docker build` (bypassing `build.sh`) errors first at the `FROM ao-build-${INSTALL_AO}` alias with an opaque "base name not found" — the friendly strict-`case` message in the final `RUN` is the readable one (and `build.sh`'s `validate_bool` catches it earliest). The binary is never executed at build time (a cross-built foreign-arch image can't run it). `go build -o /out/ao` creates `/out` itself, so the real stage needs no `mkdir` (the busybox placeholder's `mkdir -p /out` is only because shell `: > /out/ao` redirection won't create the parent). The ao daemon needs `tmux`+`git` at runtime — both are already in the base apt layer. NOTE: this Go stage is **only** for the `ao` binary; the tunnel work (#79) does not need it — `cloudflared`/`chisel` install via `curl` (per investigation #78).

#### Headless mode — running without hapi (issue #63)

Building with `INSTALL_HAPI=false` yields a "terminal-only" image: the relay tunnel, hapi runner, and the dashboard relay-URL are all gone, but the **ttyd web terminal + SSH** keep working as the container's reason to exist. With no relay URL, `render_menu_page` (`views.py`) drops the **"HAPI Server" menu item entirely** (no disabled "(not available)" stub), and the dashboard renders the neutral title `clihost` (via the `{{TITLE}}` placeholder) instead of "HAPI Dashboard". This is purely build-time — there is no `HAPI_ENABLED` runtime flag; the same neutral-title path also runs whenever hapi is installed but the live relay URL + token are not available yet.
- Every `INSTALL_<KEY>` must be exactly `true` or `false` — `install-cli.sh`, `build.sh`, and the Hermes `RUN` all fail closed on anything else (`False`, `0`, typos) so a misconfigured build never silently ships a tool. Caveat: an invalid value passed straight to `docker build` (bypassing `build.sh`) still fails the build, but for an npm tool the manifest stage `FROM npm-manifest-<tool>-${INSTALL_<KEY>}` errors first with an opaque "base name not found" instead of the friendly message — the strict check in `install-cli.sh` is the readable one.

Examples — drop Codex and Gemini:
```bash
docker build --build-arg INSTALL_CODEX=false --build-arg INSTALL_GEMINI=false -t clihost .
# or, with npm version auto-detection for the cache hash:
INSTALL_CODEX=false INSTALL_GEMINI=false ./build.sh
```
On Railway, set these names as **Build-time variables** on the service (not regular runtime env vars) — Railway passes them into `docker build` as build args. They have no effect at `docker run` time.

Keep the `INSTALL_<KEY>` keys in sync across `cli-packages.txt`, `Dockerfile`, `build.sh`, and `.env.example`.

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

### Executable JS asset tests (`tests/js/`, issue #66)

The Python tests for the terminal assets only *grep* the HTML strings — they never execute the JavaScript, which is how the paste-pipeline regression in #53/#54 slipped through (the strings were present, the behavior was broken). `tests/js/` closes that gap by **running the real `<script>` body** of each asset inside a jsdom window and synthesizing paste/drop events / vkbd clicks against it.

```bash
npm install        # one-time: installs jsdom (the ONLY npm dependency; test-only)
npm test           # node --test over tests/js/**/*.test.mjs
```

- **Stack: Node's built-in `node --test` + jsdom.** Chosen because it actually reproduces the regression — the four #66 scenarios (parent text-paste suppressing native xterm, unconditional drop `preventDefault`, ^V bypassing `term.paste`) each fail on the broken code and pass once fixed. jsdom was enough; Playwright/mobile-emulation was the fallback if jsdom couldn't model the clipboard/focus quirks, and proved unnecessary.
- **Runtime app stays stdlib/npm-free.** jsdom lives only in `devDependencies`; `node_modules/` is gitignored; nothing in `app/` imports it. `package-lock.json` is committed for reproducibility.
- `tests/js/harness.mjs` extracts the `<script>` from an asset, runs it in jsdom, and provides fakes (`makeFakeTerm` records `term.paste`, `makeFakeSocket` records ttyd frames, `makeDataTransfer`/`makeImageItems` model clipboard payloads incl. the iOS empty-`getData` quirk). Parent-page tests boot the **real** `tab_fix_script.html` inside the iframe's `contentWindow` (`bootIframeScript`) so the parent forwards into genuine triage logic, not a stub.
- These tests do not run under pytest; run `npm test` separately. Both suites must be green before pushing.

**Manual smoke test:** build image, run container, verify logs show "Hapi runner startup complete" (or fallback message) and sshd stays running. Web terminal: open http://localhost:8080, login with system credentials.

## Architecture

Docker container running hapi CLI runner alongside OpenSSH server, bundling AI CLI tools (Claude Code, Codex, Gemini CLI, Copilot, OpenCode, Droid, ao, Hermes Agent), with an integrated multi-terminal web UI (TTYD). The base image also includes `rsync` as the transport foundation for the sync epic (#17); actual sync orchestration is intentionally outside this image bootstrap.

**Multi-process layout:**
- `sshd` (port 22) — SSH access, the container's main process (`exec` at end of entrypoint.sh)
- `ttyd_proxy.py` (PORT, default 8080) — HTTP/WebSocket reverse proxy with auth; **spawns and manages ttyd processes itself**; runs unprivileged as `TTYD_USER` (entrypoint drops root via `runuser`)
- `ttyd` (127.0.0.1:7681, 7682, …) — one process per terminal, localhost-only, each attached to its own tmux session `ttyd-{id}` via `bin/tmux-wrapper.sh`
- `droid daemon --remote-access` — optional remote-access gateway; starts as `hapi` only when `DROID_DAEMON_ENABLED=true`; requires `DROID_COMPUTER_NAME` for non-interactive `droid computer register <name> -y`; logs to `/home/hapi/.hapi/droid-daemon.log`
- `ao daemon` — optional agent-orchestrator gateway (issues #72/#61); starts as `hapi` only when `AO_DAEMON_ENABLED=true`; binds **loopback-only** `127.0.0.1:AO_PORT` (default 3001) by design — no `AO_HOST`/auth/TLS, so external access is via the SSH tunnel (#79) + `ssh -L 127.0.0.1:3001:127.0.0.1:3001`. Independent of hapi (the `ao` binary is built into the image in #83); logs to `/home/hapi/.hapi/ao-daemon.log`. **No `EXPOSE 3001`** (loopback by design).
- `hapi server --relay` — always starts when the `hapi` binary is installed; the dashboard builds the "HAPI Server" link on demand from `/home/hapi/.hapi/server.log` (latest `https://*.relay.hapi.run`) plus `/home/hapi/.hapi/settings.json` (`cliApiToken`). `entrypoint.sh` still writes `/home/hapi/url` best-effort for compatibility, and the dashboard uses that file only as a fallback while hapi is available.
- SSH tunnel (`cloudflared` or `chisel`) — optional external SSH access (issue #79); starts as `hapi` only when `SSH_TUNNEL_ENABLED=true`, next to (not inside) the hapi block so it is **independent of hapi** (works with `INSTALL_HAPI=false`); provider chosen by `SSH_TUNNEL_PROVIDER` (default `cloudflared`); logs to `/home/hapi/.hapi/ssh-tunnel.log`; the dashboard connection string is built from env (the public hostname is not logged) into `/home/hapi/ssh-url` (consumed by #80)
- `hapi runner` (HAPI_PORT, default 80) — optional, requires HAPI_RUNNER_ENABLED=true

**Data flow:**
```
Browser → HTTP/WS → ttyd_proxy (8080) → ttyd (127.0.0.1:768x) → tmux-wrapper → [bwrap jail if TTYD_SANDBOX=true] → shell
SSH Client → sshd (22) → shell
hapi Client → HTTP API (HAPI_PORT) → hapi runner
```

**Entry point flow** (entrypoint.sh): fix volume permissions → ensure `.tmux.conf` / config dirs → copy the default Claude Code settings from `/etc/skel/.claude/settings.json` to `/home/hapi/.claude/settings.json` only if missing → configure sshd (root access if ROOT_PASSWORD) → clean stale hapi runner state → update Hermes Agent → optionally start Droid daemon → optionally start ao daemon → start ttyd proxy (as `TTYD_USER` via runuser; it auto-creates the first terminal) → drop any stale dashboard URL → if `hapi` is installed, start `hapi server --relay`, write a best-effort legacy connection URL file, and optionally start hapi runner (otherwise warn and skip) → `exec "$@"` (the Docker CMD defaults to sshd; `docker run IMAGE <command>` overrides it). Background launches share `start_background_service` for a one-time PID liveness check; the exact required/optional and post-start failure contract is in `docs/service-lifecycle.md`. The entrypoint deliberately does not supervise or restart children.

**Volume mount:** `/home/hapi` — persistent runner state, logs, configs. The mount overwrites permissions, hence the permission fixes in entrypoint.sh. **Mount at exactly `/home/hapi`, never the parent `/home`** (issue #69): a Docker volume is seeded from the image only while empty, so a persistent `/home` that survives one deploy stops being re-seeded — the entrypoint then recreates `/home/hapi/.claude` empty on top of it and the saved Claude Code login (`CLAUDE_CONFIG_DIR=/home/hapi/.claude`, set in the Dockerfile) is lost on every redeploy ("auth keeps resetting"). Mounting `/home/hapi` keeps the home dir itself as the persisted unit. Verified in Docker: a non-empty `/home` volume drops the creds on container recreate, a non-empty `/home/hapi` volume keeps them. **Migration caveat:** an existing `/home` volume holds its data under a `hapi/` subdir, so naively retargeting the *same* volume to `/home/hapi` buries it at `/home/hapi/hapi/` (invisible to the app) — move the volume's `hapi/` contents to its root first, or copy them into a fresh `/home/hapi` volume. The entrypoint warning spells this out at startup.

**`bin/` helper scripts:**
- `tmux-wrapper.sh` — wraps each ttyd's shell in a tmux session `ttyd-{id}` (and, when `TTYD_SANDBOX=true`, inside the bwrap jail). ttyd is launched against this script by `manager.py`.
- `glm` — compatibility wrapper that runs `claude` against the z.ai GLM Coding Plan endpoint (`https://api.z.ai/api/coding/paas/v4`) with Sonnet/Opus mapped to `glm-5.2[1m]` and Haiku mapped to `glm-4.7`. Requires `ZAI_TOKEN`. Native `claude` no longer needs this wrapper when `ANTHROPIC_AUTH_TOKEN` is present.

### Native Claude Code z.ai GLM configuration (issue #60)

Claude Code is preconfigured for z.ai GLM Coding Plan through a template at `config/claude-settings.json`, copied into the image at `/etc/skel/.claude/settings.json`. At container startup, `entrypoint.sh` copies that file to `/home/hapi/.claude/settings.json` only when the user's file is missing. Existing `settings.json` is not overwritten, and `settings.local.json` is a separate Claude Code file and must not be touched by this bootstrap.

The settings template contains only non-secret values:
- `ANTHROPIC_BASE_URL=https://api.z.ai/api/coding/paas/v4`
- `ANTHROPIC_DEFAULT_SONNET_MODEL=glm-5.2[1m]`
- `ANTHROPIC_DEFAULT_OPUS_MODEL=glm-5.2[1m]`
- `ANTHROPIC_DEFAULT_HAIKU_MODEL=glm-4.7`
- `API_TIMEOUT_MS=3000000`
- `CLAUDE_CODE_AUTO_COMPACT_WINDOW=1000000`

Tokens are runtime-only. Use `ANTHROPIC_AUTH_TOKEN` for ordinary `claude`; keep `ZAI_TOKEN` only for the compatibility `bin/glm` wrapper. Do not put `ANTHROPIC_*` or `ZAI_TOKEN` literals in `Dockerfile` or `entrypoint.sh`: `TestClaudeAuthRootCause69` deliberately guards against shell-level GLM env leakage that could affect normal Claude Code auth.

### Диагностика слёта Claude Code auth

`bin/claude-auth-snapshot.sh` is copied into the image as
`/bin/claude-auth-snapshot.sh` for diagnosing ordinary Claude Code OAuth
logout/refresh failures. It reads
`$CLAUDE_CONFIG_DIR/.credentials.json` (default
`/home/hapi/.claude/.credentials.json`) and writes JSON snapshots under
`${CLAUDE_AUTH_SNAPSHOT_DIR:-/home/hapi/.hapi/auth-snapshots}`. Secret hygiene is
the main contract: токенов в снэпшоте нет. The snapshot must never contain
`accessToken` or `refreshToken`; it stores only metadata such as `expiresAt`,
`scopes`, `subscriptionType`, sha256/mtime, permissions, process uid, UTC time,
uptime, and a no-token reachability check for `api.anthropic.com`.

Operational flow:

```bash
# immediately after a successful claude login
docker exec <container> bash /bin/claude-auth-snapshot.sh snapshot baseline

# after Claude Code logs out
docker exec <container> bash /bin/claude-auth-snapshot.sh snapshot failed
docker exec <container> bash /bin/claude-auth-snapshot.sh diff
docker exec <container> bash /bin/claude-auth-snapshot.sh list
```

The built-in `diff` compares two explicit files or, without args, the two latest
container snapshots. Verdicts separate the expected root-cause buckets:
refresh works when sha256/mtime/`expiresAt` changed; refresh is not happening
when the file is unchanged and `expiresAt` is expired; permissions block refresh
when `.credentials.json` becomes non-`hapi` or loses write access; Anthropic
network loss is called out separately; missing credentials points back to
mount/persistence.

`bin/claude-auth-snapshot-host.sh` is a host-only wrapper and must not be copied
into the image. It runs `docker inspect` for only `RestartCount`,
`State.StartedAt`, `State.Status`, and `Mounts`, then executes the inner
`claude-auth-snapshot.sh snapshot` and writes a host JSON snapshot under
`./claude-auth-host-snapshots` (override with `CLAUDE_AUTH_HOST_SNAPSHOT_DIR`).
Use it when you need to prove whether the container restarted or the `/home/hapi`
mount changed:

```bash
bin/claude-auth-snapshot-host.sh <container> baseline
bin/claude-auth-snapshot-host.sh <container> failed
bin/claude-auth-snapshot-host.sh diff ./claude-auth-host-snapshots/<A>.json ./claude-auth-host-snapshots/<B>.json
```

This is diagnostic only. It distinguishes (a) mount/persistence, (b)
permissions/refresh write failure, and (c) network/token refresh failure; it does
not change OAuth state.

### Синхронизация окружения хост↔контейнер

This is the authoritative sync contract for epic #17. `bin/clihost-sync.sh` is
the host-side rsync-over-SSH command for the config-level subset. It is not
strictly non-secret: `~/.config/gh` may contain a GitHub OAuth token in plaintext
in `hosts.yml` (`oauth_token:`) when `gh` is not using the OS keyring, which is
common on headless servers and inside containers. Syncing `~/.config/gh` is a
deliberate tradeoff, and that token crosses the SSH relay with the rest of the
config-level data. The script is copied into the image as `/bin/clihost-sync.sh`
for parity, but the documented workflow runs the repo script from the host
against the container's SSH endpoint.

Directions are intentionally named from the operator's host perspective:

- `pull` copies host → container.
- `push` copies container → host.
- `ssh` copies `~/.ssh` separately; its default direction is `pull`, and it also
  accepts `ssh push` or `--direction push`.

The regular config-level include-list is intentionally narrow:

- `~/.gitconfig`
- `~/.config/gh`

Examples:

```bash
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh pull
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh pull --apply
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh push
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh ssh
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh ssh push --apply
```

Target selection:

- Direct SSH: set `CLIHOST_SSH_TARGET`, `CLIHOST_SSH_PORT`, and optionally
  `CLIHOST_SSH_IDENTITY_FILE`, or pass `--target`, `--ssh-port`, and
  `--identity-file`.
- chisel tunnel (#79): use the public chisel host as target and
  `CHISEL_REMOTE_PORT` as `CLIHOST_SSH_PORT`.
- cloudflared tunnel (#79): create a local `~/.ssh/config` Host with the
  required `ProxyCommand`, then use that Host alias as `CLIHOST_SSH_TARGET`.
  The helper intentionally exposes only target, port, and identity-file flags;
  complex transport policy belongs in SSH config.

Safety defaults:

- Every run is dry-run by default and prints rsync itemized changes.
- `--apply` is required for a real transfer and enables rsync `--backup` plus
  `--backup-dir=...`.
- `--delete` is never used unless `--allow-delete` is passed explicitly.
- rsync always uses `--no-links`, and local/remote guards reject controlled
  symlink paths before transfer.

The `ssh` subcommand is default-off and public-by-default. It includes only
`~/.ssh/known_hosts`, `~/.ssh/*.pub`, and `~/.ssh/config` unless
`--include-private-keys` is passed. That flag prints a warning because private
key material crosses the SSH relay; this is the #17 risk B relay/blast-radius
case that keeps `~/.ssh` out of regular `pull`/`push`. Before transfer, the
source `~/.ssh` directory must not be more open than `700`, and private keys
must not be more open than `600`; apply mode also fixes those permissions on the
receiver. The private-key detector is PEM-only, so PuTTY `.ppk` or DER keys are
not selected by `--include-private-keys`. The `~/.ssh` contract is flat: it
targets top-level files; keys in subdirectories are permission-checked but not
copied.

Non-goals:

- `~/.claude` is not part of sync. Credential persistence belongs to the
  `/home/hapi` volume. Copying this tree from the host or an old container can
  overwrite fresh Claude Code OAuth credentials during the refresh-token race
  diagnosed in #69/#89. Treat the correctly mounted volume as the source of
  truth.
- Private `~/.ssh` material is not part of regular `pull`/`push` because it
  expands blast radius and crosses the relay path. Keep it behind the explicit
  `ssh` subcommand and the extra `--include-private-keys` opt-in.
- Claude Code `settings.json` is not part of sync. It is managed by
  `config/claude-settings.json` and the template/bootstrap contract from #60;
  syncing arbitrary copies would make stale config drift harder to reason about.

Fail-closed mount preflight:

`run_remote_preflight` SSHes into the container before any rsync call. It refuses
to continue unless the remote home is a separate mount exactly at `/home/hapi`.
A parent `/home` mount triggers that abort only when the distinct `/home/hapi`
mount is absent; if both `/home` and `/home/hapi` are mounted, the `/home/hapi`
mount satisfies preflight and sync continues. It also aborts on an unreadable
`/proc/mounts` or a symlink in a controlled path. Recovery is to fix the
deployment mount first: mount the persistent volume at `/home/hapi`; if an old
deployment mounted `/home`, move the volume's `hapi/` contents to the volume root
or copy them into a fresh `/home/hapi` volume before retrying sync.

Recovery after a bad apply:

- Dry-run makes no changes, so there is nothing to restore.
- Apply mode writes backups on the destination side. For host → container,
  overwritten files go under `/home/hapi/.clihost-sync-backups/<UTC timestamp>`.
  For container → host, overwritten files go under
  `~/.clihost-sync-backups/<UTC timestamp>`.
- Restore by inspecting the latest backup-dir and copying the needed files back
  to the destination path. Do this manually instead of running a broad reverse
  sync when the broken state is not yet understood.
- `~/.claude` recovery is volume recovery, not sync recovery: fix the mount,
  then use the known-good `/home/hapi` volume contents. The sync command should
  not be expanded to repair Claude OAuth state.

Syncthing / real-time sync is explicitly deferred. The accepted design is
rsync-first for this release; a long-running bidirectional file watcher is
over-engineering until the manual contract proves insufficient.

### Host-side billing (Dokku usage accounting, issue #37)

`bin/clihost-billing.sh` + `bin/clihost_billing_lib.py` are a **host-only** pair
(like `claude-auth-snapshot-host.sh`): they are **never** copied into the image
(`Dockerfile` is not touched) — inside the container billing is meaningless and
unsafe (no `docker.sock`). They live on the Dokku host (e.g. `/home/dokku/bin/`)
and run as the `dokku` user, who is in the `docker` group and can therefore call
`docker stats/ps -s/inspect` **without sudo** (`sudo` needs a password and is
unavailable). This is the accounting and operational foundation for issue #37;
stage 2 (tariffs/invoices) remains follow-up work.

The bash file is a thin dispatcher (`set -euo pipefail`, `die`/`usage`/`main`
+`case`, one docker/I-O owner); all pure logic (parsers + aggregation +
formatting) lives in the stdlib-only `clihost_billing_lib.py` so it is unit
tested without root or Docker (`tests/unit/test_clihost_billing_agg.py`, plus
static+end-to-end checks in `tests/unit/test_shell_scripts.py`). No `jq`/`sqlite3`
(not guaranteed on the host); the dispatcher shells out to `python3` inline.

**Subcommands:**

| Subcommand | Purpose |
|---|---|
| `collect` | Sample every `clihost-*` container once (cron-driven). Idempotent, `flock`-serialized, appends JSONL. |
| `cron-line` | Print ready-to-paste collector and daily orphan-GC lines — the operator installs them manually (`crontab -e` as `dokku`; we never auto-install into a crontab, no sudo). |
| `report [--json]` | Aggregated usage table per app (avg CPU cores / avg mem / disk / container-hours / uptime% / COST). |
| `raw` | Alias for `report --json` (machine-readable). |
| `diagnose [--app] APP` | Read-only container health evidence and a compact verdict. |
| `restart APP [--apply] [--yes]` | Safe app restart; dry-run by default and non-TTY apply requires `--yes`. |
| `gc-mounts [--apply] [--yes]` | Track legacy `clihost-*` storage directories and delete only after 30 days continuously orphaned; dry-run by default. |
| `idle-sleep [--apply] [--yes]` | Stop explicitly allowlisted apps after continuous CPU and network inactivity; dry-run by default. |
| `help` | Usage. |

**Storage** — append-only JSONL under `${CLIHOST_BILLING_DIR:=/home/dokku/.clihost-billing}`
(gitignored: `.clihost-billing/`):
- `samples/YYYY-MM.jsonl` — one JSON sample object per container per collect (monthly rotation).
- `state/collect.lock` — `flock` guard so overlapping cron runs don't interleave.
- `state/last-collect.json` — last-collect metadata (feeds the "collector likely
  not running" warning `report` prints when the newest sample is older than
  `2 × interval`).
- `state/orphan-mounts.json` — first-seen times for directories continuously
  absent from both the Dokku app inventory and every Docker container mount.
- `state/idle-sleep.json` — per-app network counter, last observation, and start
  of the current continuous idle window.
- `rates.json` (stage 2) — not present yet; `report` calls `apply_rates(rows, None)`
  so COST renders as an em dash (`—`) until rates exist.

**Data sources** (docker only, no sudo, **no `du`** — the `dokku` user can't read
the root storage mount):
- CPU%/Mem: `docker stats --no-stream --format '{{json .}}'` (one call, running
  containers only).
- Disk: `docker ps -a -s` writable-layer `Size` field (`"2.54GB (virtual 5.73GB)"`);
  `rootfs` = first number, `image` = `virtual − rootfs`.
- Diagnostics carried per sample: `docker inspect` `RestartCount`/`Status`/
  `ExitCode`/`OOMKilled` (used by the follow-up `diagnose` PR).

**Container-hours** are **left-Riemann** integrated over the *actual* `dt`
between consecutive samples *of the same container* (an app with several
`.web.N` instances sums each container's contribution — grouping only by app
would fabricate bogus intervals). Two guards: `dt <= 0` (clock skew / duplicate)
is skipped, and `dt > 2.5 × CLIHOST_BILLING_INTERVAL` is treated as a **gap**
(collector down / server asleep) and excluded from billed time. A stopped
container writes a `running:false` sample: its seconds count toward the billed
denominator (uptime%) but not toward billable *running* hours; disk is still
tracked. Disk is a point-in-time size (latest per container summed), not integrated.

**Environment:** `CLIHOST_BILLING_DIR` (storage root), `CLIHOST_BILLING_INTERVAL`
(collector cadence in seconds, default 300 — also the gap-detection base),
`CLIHOST_APP_PREFIX` (container/app prefix to account, default `clihost-`),
`CLIHOST_STORAGE_ROOT` (legacy app-named Dokku storage directory root, default
`/var/lib/dokku/data/storage`), `CLIHOST_GC_RETENTION_DAYS` (continuous
orphan retention, default 30), `CLIHOST_IDLE_APPS` (comma-separated idle-sleep
allowlist, default empty/disabled), `CLIHOST_IDLE_MINUTES` (continuous idle
window, default 60), `CLIHOST_IDLE_CPU_PCT` (max aggregate CPU percentage
considered idle, default 1), and `CLIHOST_IDLE_NET_BYTES` (max network bytes
per observation considered idle, default 65536).

`gc-mounts` is deliberately fail-closed. It considers only direct directories
whose names match `clihost-[a-z0-9_-]+`; existing Dokku apps and paths mounted
by running or stopped Docker containers are always preserved. A new orphan is
tracked, not deleted. It becomes eligible only after it remains absent from both
inventories for the full retention window. Inventory/state errors abort, the
storage root must be an absolute non-symlink directory, and deletion requires
both `--apply` and (outside a TTY) `--yes`. The default invocation records the
observation and prints what would be deleted without deleting it.
`cron-line` includes a daily `gc-mounts --apply --yes` entry; installing that
line is the explicit operator opt-in to automatic cleanup.

Eligibility is sampled once per scan (daily, per the generated cron-line), not
observed continuously: only a scan that catches a directory active resets its
tracked first-seen time, so a reuse-and-reorphan cycle squeezed entirely inside
one scan interval is invisible. Worst case, a deletion's true continuous-orphan
age can be short of `CLIHOST_GC_RETENTION_DAYS` by up to one scan interval
(~24h with the shipped daily cron) — closing that gap fully would need
event-based hooks into Dokku app create/destroy rather than periodic sampling.

**Idle sleep is opt-in and fail-closed.** `CLIHOST_IDLE_APPS` is an empty
comma-separated allowlist by default, so the command does nothing until an
operator names apps explicitly. `CLIHOST_IDLE_MINUTES` defaults to 60 and
`CLIHOST_IDLE_CPU_PCT` defaults to 1 aggregate CPU percent.
`CLIHOST_IDLE_NET_BYTES` defaults to 65536 bytes per observation, allowing
small tunnel/runner keepalives without keeping an otherwise idle app awake.
Every invocation reads live `docker stats`: CPU above the threshold, cumulative
`NetIO` growth above that byte threshold, a container counter reset, or an observation gap greater than `2.5 ×
CLIHOST_BILLING_INTERVAL` resets the idle window. Missing/malformed stats or
state abort instead of being interpreted as idle. The first observation only
starts tracking. An eligible app is printed in dry-run mode; stopping requires
`--apply` and, outside a TTY, `--yes`, and uses `dokku ps:stop APP`.

This implements **automatic sleeping**, not automatic request-triggered waking.
Dokku's default nginx proxy has no built-in scale-from-zero request hook, and
once the web container is stopped it cannot receive the request that would wake
it. Wake manually with `dokku ps:start APP`. True wake-on-HTTP requires a
separate always-on, wake-aware proxy/control-plane integration and is outside
this repository's container/host-helper scope. `cron-line` prints a commented
opt-in template; replace the example allowlist and uncomment it to schedule the
sleep evaluator.

**Verification:** `python -m pytest tests/unit/test_clihost_billing_agg.py
tests/unit/test_shell_scripts.py`; on the server, copy both files to
`/home/dokku/bin/`, run `clihost-billing.sh collect` a few times with a pause,
then `clihost-billing.sh report` — the table should list `clihost-axisrow` /
`clihost-work1nw`. `clihost-billing.sh cron-line` prints the collector line.

### ttyd proxy package (app/)

`app/ttyd_proxy.py` is only a **thin process entry point** (imports `main` from `ttydproxy.app`; referenced by entrypoint.sh as `python3 /app/ttyd_proxy.py`); all logic lives in the `app/ttydproxy/` package:

- `config.py` — env-based configuration constants and `TTYD_ROUTE_PATTERN`
- `security.py` — HMAC session/CSRF tokens, PAM/shadow password check, `env_bool`, username validation
- `manager.py` — `TTYDManager`: spawn/kill ttyd processes, port allocation from TTYD_BASE_PORT (7681), dead-process reaping, tmux session cleanup
- `proxy.py` — HTTP/WebSocket proxying to ttyd, gzip-aware HTML injection (`inject_tab_fix_script`)
- `ratelimit.py` — in-memory `RateLimiter`
- `uploads.py` — `save_upload` for pasted/dropped images: validates by **magic bytes** (`detect_image_extension`: png/jpg/gif/webp; SVG rejected), then writes the file. Hardened against symlink/TOCTOU attacks because the proxy may run as root while `UPLOAD_DIR` lives under a user-controlled home: it descends the directory tree component-by-component with `O_NOFOLLOW`/`O_DIRECTORY` (`_open_upload_dir_nofollow`), binds every privileged op to an open fd (never re-resolves the string path), and writes via `O_CREAT|O_EXCL|O_NOFOLLOW`. All this hardening only matters in root mode; if root mode is dropped it collapses to `os.makedirs` + an `O_EXCL` open.
- `views.py` — render login/menu/terminal pages from templates (`render_template`; shared favicon `<link>` block injected via the `{{FAVICON}}` placeholder from `FAVICON_LINKS`)
- `cleanup.py` — disk cleanup targets listing/deletion for the dashboard
- `assets.py` — loads static assets from `app/assets/` **at import time** into module constants (editing an asset requires proxy restart)
- `app.py` — `TTYDProxyHandler` routing + `main()` (creates the first terminal, installs SIGTERM/SIGINT handlers that kill all terminals). `_read_request_body` returns 400/413 on invalid or oversized Content-Length; CSRF double-submit comparison is timing-safe (`hmac.compare_digest`)

`app/server.py` — shared `BaseHTTPHandler` (JSON/HTML/binary responses, silent logging, security headers). Server is `ThreadingHTTPServer` (one thread per request) — never switch to plain `HTTPServer`, slow WebSocket connections would block everything.

**Templates & assets:** `app/index.html` (dashboard), `app/login.html`, `app/terminal.html` — variable substitution like `{{TITLE}}`, `{{USERNAME}}`, `{{CSRF_TOKEN}}`, values escaped via `html.escape()`. `{{TITLE}}` defaults to the neutral `DEFAULT_TITLE` (`clihost`) via `BASE_REPLACEMENTS` (applied to every page); `render_terminal_page` overrides it per terminal. On the dashboard, `{{HAPI_LINK}}` is the "HAPI Server" link only when hapi is available and a relay URL is available from live runtime files or the legacy `/home/hapi/url` fallback, otherwise an empty string (no menu item at all). Front-end JS/CSS injected into pages lives in `app/assets/` (tab_fix_script.html, virtual_keyboard.html/.css, terminal_parent_tab_handler.html, favicons).

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

The page title/heading is the templated `{{TITLE}}` (rendered as `clihost`), and the "HAPI Server" link (`{{HAPI_LINK}}`) only appears when a relay URL is available — without hapi the menu shows just the terminal list and "+ New terminal".

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

**Other:**
- `DROID_DAEMON_ENABLED` — set `true` to start `droid daemon --remote-access` at container start (default: false)
- `DROID_COMPUTER_NAME` — required when `DROID_DAEMON_ENABLED=true`; limited to letters, numbers, dots, underscores, and dashes; used for non-interactive registration before daemon startup
- `AO_DAEMON_ENABLED` — set `true` to start `ao daemon` (agent-orchestrator) at container start (default: false). Loopback-only; reach it from the host through the SSH tunnel (#79) + `ssh -L 127.0.0.1:3001:127.0.0.1:3001`. Independent of hapi.
- `AO_PORT` — `ao daemon` bind port (default: 3001; loopback-only by design, read by the daemon itself; validated numeric in the entrypoint since it is interpolated into the launch string)
- `HERMES_AUTO_UPDATE` — set `false` to skip Hermes Agent update at container start.

**External SSH tunnel (optional, issue #79):**
- `SSH_TUNNEL_ENABLED` — set `true` to expose the container's sshd (port 22) externally where port forwarding is unavailable (Railway/PaaS) (default: false). Independent of hapi (works with `INSTALL_HAPI=false`).
- `SSH_TUNNEL_PROVIDER` — `cloudflared` (default) or `chisel`. An invalid value fails the startup loudly.
- `CLOUDFLARE_TUNNEL_TOKEN` — required for the `cloudflared` provider; the token of a remotely-managed named tunnel (`cloudflared tunnel --no-autoupdate run --token …`). Quick tunnels (trycloudflare) are HTTP-only and cannot carry SSH, so a named tunnel + Cloudflare account/domain is mandatory. Empty token → visible warning + skip.
- `CLOUDFLARE_TUNNEL_HOSTNAME` — the public hostname (e.g. `ssh.example.com`) used to build the dashboard connection string; cloudflared does not print it to the log, so it comes from env.
- `CHISEL_SERVER` — required for the `chisel` provider; URL of a self-hosted `chisel server --reverse` (e.g. `https://chisel.example.com:9312`). Empty → visible warning + skip.
- `CHISEL_AUTH` — `user:pass` credential passed to chisel via the `AUTH` env var (same on server and client).
- `CHISEL_REMOTE_PORT` — server port that the reverse-forwarded `:22` listens on (default: 2222).
- Client connection: cloudflared → `ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@$CLOUDFLARE_TUNNEL_HOSTNAME` (needs cloudflared installed locally); chisel → `ssh -p $CHISEL_REMOTE_PORT hapi@<host of CHISEL_SERVER>`; add `-L 127.0.0.1:3001:127.0.0.1:3001` to reach `ao daemon`.

**Sandbox (optional):**
- `TTYD_SANDBOX` — set `true` to launch each tmux session inside a bubblewrap (bwrap)
  jail (default: false). Isolates per-user `/home` (other users' homes are invisible),
  makes system dirs read-only. Intended for multi-tenant forks (e.g. clihost_cloud) where
  each terminal runs as a different Linux user via `runuser`. **REQUIRES** the container to
  start with `--security-opt seccomp=unconfined` — Docker's default seccomp blocks the
  `clone(CLONE_NEW*)` syscalls bwrap needs, so without it the jail fails at namespace
  creation. On Dokku: `dokku docker-options:add <app> deploy,run "--security-opt seccomp=unconfined"`.
  Behavior is **fail-closed**: if `TTYD_SANDBOX=true` but the jail can't start, the terminal
  does not open (it never falls back to an unsandboxed shell). The jail does NOT unshare the
  network (AI CLIs need it) and inherits `/proc` read-only, so filesystem isolation is complete
  but process hiding is not (host PIDs stay visible via `/proc/{pid}`; a later `hidepid` concern).
  Cleanup note: when sandboxed, `manager.py`'s `tmux kill-session` becomes a no-op (the jailed
  tmux uses a socket under `$HOME/.cache/tmux/`, not the default one); the real lifecycle
  guarantee is `--die-with-parent`, and the orphaned tmux server is harmlessly reattached on
  reconnect. Known limitation: a future nested bwrap (e.g. codex's own sandbox) breaks under the
  outer `--unshare-user`; codex does not invoke bwrap today.

Update `.env.example` when adding/changing variables.

## Coding Conventions

> A shorter `AGENTS.md` exists at the repo root for non-Claude agents. It overlaps with this file but is less detailed. When the two disagree, **CLAUDE.md is authoritative**; keep `AGENTS.md` in sync when you change conventions here.

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
- **Paste/drop triage**: capture-phase `paste`/`drop` listeners triage the payload — **images** upload to `POST /upload` (CSRF token read from the non-HttpOnly `csrf_token` cookie; up to 5 in parallel, returned paths typed in order + space); a **non-image file** is `preventDefault`'d (so a dropped file can't navigate the iframe away) but otherwise skipped; **plain text is left entirely to xterm's native paste/drop** — the listeners only `preventDefault` when they actually consume a file, never for text. This is the #66 fix: the earlier pipeline routed text through a fragile `term.paste`/socket path and `preventDefault`'d it, which lost the text on mobile (iOS paste gesture exposes an empty `getData('text/plain')`, focus is not in the iframe). `terminal_parent_tab_handler.html` forwards **only images** from the parent page into the iframe via `contentWindow.__handleImageTransfer(dataTransfer)`; text paste/drop on the parent falls through untouched. (The earlier full-triage `__handleDataTransfer`/`pasteTextToTerminal` path was removed with the #66 fix — nothing typed pasted text any more, so it was dead code.) Server validates uploads by magic bytes only (png/jpg/gif/webp; SVG rejected) — the client Content-Type is never trusted. The `^V` vkbd button delivers clipboard text via `term.paste` (bracketed-paste-safe) with a raw-socket fallback, and warns on a `readText()` rejection instead of swallowing it. `handle_ttyd` refreshes the `csrf_token` cookie so long-lived terminal tabs keep uploading. Executable coverage lives in `tests/js/` (run `npm test`).

**tmux mouse mode** (`config/.tmux.conf`, copied to `/home/hapi/.tmux.conf` in Dockerfile): mouse is **off by default** so xterm.js keeps native browser text selection and Cmd+C (#40). `Ctrl+B m` toggles tmux mouse mode when tmux scroll/copy is needed. A direct Ctrl+M binding is impossible — C-m and Enter are the same byte (0x0D).

## Pull Request Guidelines

PRs should include:
- Summary of changes
- New/changed environment variables (update `.env.example`)
- Port or volume mapping changes and their rationale

## CI/CD

- `.github/workflows/ci.yml` — pytest, `npm test`, and lightweight Docker build+smoke on every PR and push to `main` (`/health`, `sshd`, and root-context `~/.ssh` symlink hardening)
- `.github/workflows/claude.yml` — Claude Code action, triggers on @claude mentions in issues/PR comments
- `.github/workflows/claude-code-review.yml` — automatic code review on PR open/synchronize

## Debugging Commands

```bash
docker logs <container_id>                       # container logs
docker exec -it <container_id> bash              # shell inside container
docker exec <container_id> hapi runner status    # runner status
docker exec <container_id> hapi doctor           # hapi diagnostics
```
