# clihost

Docker container with web terminal (TTYD) and AI CLI tools (Claude Code, Codex, Gemini CLI, Copilot, OpenCode, Droid, Hermes). Each tool can be excluded at build time for a lighter image — see [Модульный состав образа](#модульный-состав-образа). The web terminal proxy uses a multithreaded HTTP server — concurrent connections do not block each other.

## Quick Start

```bash
# Build
docker build -t clihost .

# Run
docker run -p 22:22 -p 8080:8080 clihost
```

Open http://localhost:8080 for web terminal access.

## Модульный состав образа

Каждый CLI-инструмент можно исключить из образа на этапе сборки, чтобы получить более лёгкий, заточенный под конкретный деплой образ. Управление — через **build-time** аргументы `INSTALL_<KEY>` (по умолчанию `true`, ставится всё):

| Build arg | Компонент |
|-----------|-----------|
| `INSTALL_CLAUDE_CODE` | Claude Code (`@anthropic-ai/claude-code`) |
| `INSTALL_CODEX` | Codex (`@openai/codex`) |
| `INSTALL_GEMINI` | Gemini CLI (`@google/gemini-cli`) |
| `INSTALL_COPILOT` | GitHub Copilot (`@github/copilot`) |
| `INSTALL_OPENCODE` | OpenCode (`opencode-ai`) |
| `INSTALL_DROID` | Droid (`droid`) |
| `INSTALL_HAPI` | Hapi (`@twsxtd/hapi`) — ядро рантайма (туннель/runner/URL на дашборде) |
| `INSTALL_HERMES` | Hermes Agent (Nous Research, ставится через pip) |

```bash
# Собрать без Codex и Gemini
docker build --build-arg INSTALL_CODEX=false --build-arg INSTALL_GEMINI=false -t clihost .

# То же через build.sh (он также авто-определяет версии npm для cache-busting)
INSTALL_CODEX=false INSTALL_GEMINI=false ./build.sh
```

> Это **не** runtime-переменные: инструменты устанавливаются во время `docker build`, поэтому задавать их через `docker run -e` бесполезно. На Railway укажите их в разделе **Build-time variables** сервиса — платформа пробросит их в `docker build`.

## Deploy on Railway

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/new/template/qpCUGO)

### Environment Variables for Railway

| Variable | Required | Notes |
|----------|----------|-------|
| `TTYD_PASSWORD` | **Required** | Password for web terminal access |
| `PASSWORD_SECRET` | Recommended | Session persistence across restarts |
| `SECURE_COOKIES` | Set to `true` | Railway serves HTTPS automatically |
| `PORT` | Auto | Injected by Railway, do not set manually |

### Volume

Add persistent volume at `/home/hapi` via Railway dashboard → Service → Volumes.

> **Mount the volume at exactly `/home/hapi`, not `/home`.** Mounting a persistent
> volume at the parent `/home` breaks credential persistence on redeploy: a Docker
> volume is only seeded from the image when it is *empty*, so once the platform's
> persistent storage survives the first deploy and stays non-empty, subsequent
> deploys do **not** re-copy the image's `/home/hapi`. The entrypoint then recreates
> `/home/hapi/.claude` empty on top of the volume and the saved Claude Code login is
> gone (it looks like "auth keeps resetting", issue #69). Mounting `/home/hapi`
> directly keeps the home directory itself as the persisted unit and avoids this.
> The entrypoint also detects this wrong mount at startup and prints a loud
> `WARNING: a volume is mounted at /home, NOT at /home/hapi` to the container logs.

### Notes

- By default SSH (port 22) is not reachable externally on Railway (no arbitrary port forwarding) — web terminal only. To get external SSH, enable the **external SSH tunnel** below (`SSH_TUNNEL_ENABLED=true`).
- `PORT` is injected automatically by Railway, `ttyd_proxy.py` reads it via `os.environ`

## Архитектура

```
Browser → HTTP/WebSocket → ttyd_proxy.py (8080) → TTYD (127.0.0.1:768x) → tmux → Shell
SSH Client                → sshd (22)            → Shell
hapi Client               → hapi runner (80)     → CLI tools
```

**Процессы внутри контейнера:**

| Процесс | Порт | Описание |
|---------|------|----------|
| `sshd` | 22 | SSH-доступ, main-процесс контейнера |
| `ttyd_proxy.py` | 8080 | Multithreaded HTTP/WS прокси с аутентификацией |
| `ttyd` | 127.0.0.1:768x | Web-терминал (по одному на сессию, только localhost) |
| `droid daemon --remote-access` | — | Optional Droid gateway, logs to `/home/hapi/.hapi/droid-daemon.log` |
| `ao daemon` | 127.0.0.1:3001 | Optional agent-orchestrator gateway (loopback-only), logs to `/home/hapi/.hapi/ao-daemon.log` |
| `hapi runner` | `HAPI_PORT` (default 80) | Запуск CLI-инструментов по API (опционально) |
| `hapi server --relay` | — | Туннель для внешнего доступа |

> **Railway:** платформа проксирует внешний трафик (порт 80/443) на внутренний порт **8080** контейнера. `ttyd_proxy.py` остаётся на 8080, hapi runner — на 80. Конфликта нет: Railway форвардит только на 8080, а hapi runner доступен снаружи исключительно через relay-туннель.

**Поток аутентификации:** `POST /login` → HMAC-подписанная cookie `ttyd_session` → редирект на `/`.

**Мультитерминальность:** каждый терминал — отдельный процесс `ttyd` на своём порту (7681, 7682, …). Управление через `GET/POST/DELETE /terminals`.

### Внутренняя структура ttyd proxy

После рефакторинга точка входа `app/ttyd_proxy.py` остаётся совместимой оболочкой, а основная логика разложена по модульному пакету `app/ttydproxy/`:

- `config.py` — env-конфигурация и route-константы
- `assets.py` — загрузка статических terminal HTML/JS/CSS-ассетов
- `security.py` — cookies, signed tokens, CSRF, username validation
- `manager.py` — lifecycle ttyd/tmux процессов
- `proxy.py` — HTTP/WebSocket proxy и HTML injection
- `ratelimit.py` — in-memory rate limiting helpers
- `views.py` — рендер login/menu/terminal страниц
- `app.py` — wiring handler'а и запуск сервера

Terminal iframe page и связанные JS/CSS-ассеты лежат в `app/terminal.html` и `app/assets/`.

## Ports

- **22** - SSH access
- **8080** - Web terminal (TTYD)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | Web terminal HTTP proxy port |
| `TTYD_USER` | hapi | Terminal user |
| `TTYD_PASSWORD` | - | Global password for web terminal (uses system passwords if not set) |
| `PASSWORD_SECRET` | auto | Secret for session signatures (auto-generated if not set) |
| `ROOT_PASSWORD` | - | Enable root SSH access with this password |
| `DROID_DAEMON_ENABLED` | false | Start `droid daemon --remote-access` for Droid remote access |
| `DROID_COMPUTER_NAME` | - | Required when `DROID_DAEMON_ENABLED=true`; used for non-interactive `droid computer register <name> -y` |
| `AO_DAEMON_ENABLED` | false | Start `ao daemon` (agent-orchestrator); loopback-only, reach it through the SSH tunnel |
| `AO_PORT` | 3001 | `ao daemon` bind port (loopback-only by design; understood by the daemon itself) |
| `TTYD_SANDBOX` | false | Wrap each tmux session in a bubblewrap jail (see Multi-tenant sandbox below) |

### Multi-tenant sandbox (optional)

`TTYD_SANDBOX=true` launches every tmux session inside a [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) jail so that, in multi-tenant deployments where each terminal runs as a different Linux user, users can't read each other's `/home/*` and system directories are read-only. It is **off by default** — single-user clihost is unchanged.

The jail **requires** the container to run with `--security-opt seccomp=unconfined` (Docker's default seccomp profile blocks the namespace syscalls bwrap needs). On Dokku:

```bash
dokku docker-options:add <app> deploy,run "--security-opt seccomp=unconfined"
```

The jail keeps network access (AI CLIs need it) and is **fail-closed**: if it can't start, the terminal doesn't open rather than falling back to an unsandboxed shell.

### External SSH tunnel (optional)

Exposes the container's sshd (port 22) externally where arbitrary port forwarding is unavailable (Railway and similar PaaS). Pluggable: both providers ship in the image, selected by `SSH_TUNNEL_PROVIDER`. **Independent of hapi** — works with `INSTALL_HAPI=false`. Off by default.

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_TUNNEL_ENABLED` | false | Enable the external SSH tunnel |
| `SSH_TUNNEL_PROVIDER` | cloudflared | `cloudflared` or `chisel` |
| `CLOUDFLARE_TUNNEL_TOKEN` | - | Required for `cloudflared`; named-tunnel token (`cloudflared tunnel run --token …`) |
| `CLOUDFLARE_TUNNEL_HOSTNAME` | - | Public hostname (e.g. `ssh.example.com`) for the dashboard connection string |
| `CHISEL_SERVER` | - | Required for `chisel`; URL of a self-hosted `chisel server --reverse` |
| `CHISEL_AUTH` | - | `user:pass` credential (same on server and client) |
| `CHISEL_REMOTE_PORT` | 2222 | Server port the reverse-forwarded `:22` listens on |

> **cloudflared** uses a *named tunnel + token* (requires a Cloudflare account + domain). Quick tunnels (trycloudflare) are HTTP-only and cannot carry SSH. **chisel** requires you to run your own public `chisel server --reverse`.

Connecting from the client:

```bash
# cloudflared (needs cloudflared installed locally):
ssh -o ProxyCommand="cloudflared access ssh --hostname %h" hapi@$CLOUDFLARE_TUNNEL_HOSTNAME

# chisel (plain ssh):
ssh -p $CHISEL_REMOTE_PORT hapi@<host of CHISEL_SERVER>

# to reach `ao daemon` (loopback-only) through the tunnel, add:
#   -L 127.0.0.1:3001:127.0.0.1:3001
```

### Hapi Runner (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `HAPI_RUNNER_ENABLED` | false | Enable hapi runner |
| `CLI_API_TOKEN` | - | Auth token (required if runner enabled) |
| `HAPI_API_URL` | - | Server URL (required if runner enabled) |
| `HAPI_HOST` | 0.0.0.0 | Runner bind address |
| `HAPI_PORT` | 80 | Runner port |

## Examples

Basic usage (web terminal + SSH only):

```bash
docker run -p 22:22 -p 8080:8080 clihost
```

With persistent volume:

```bash
docker run -p 22:22 -p 8080:8080 \
  -v "$(pwd)/volume/hapi:/home/hapi" \
  clihost
```

With hapi runner:

```bash
docker run -p 22:22 -p 8080:8080 \
  -e HAPI_RUNNER_ENABLED=true \
  -e CLI_API_TOKEN=your_token \
  -e HAPI_API_URL=https://your-server.com \
  clihost
```

With Droid remote access:

```bash
docker run -p 22:22 -p 8080:8080 \
  -e DROID_DAEMON_ENABLED=true \
  -e DROID_COMPUTER_NAME=clihost \
  -v "$(pwd)/volume/hapi:/home/hapi" \
  clihost
```

## Health Check

```bash
curl http://localhost:8080/health
# {"status": "ok", "ttyd": "running"}
```
