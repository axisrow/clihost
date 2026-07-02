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
>
> **Migrating an existing `/home` volume:** if you already ran with a volume at
> `/home`, your data lives under that volume's `hapi/` subdirectory. Do **not** just
> retarget the same volume to `/home/hapi` — its contents would then land at
> `/home/hapi/hapi/` and stay invisible to the app (the very state you wanted to keep
> looks lost). First move the volume's `hapi/` contents up to its root, or copy them
> into a fresh volume mounted at `/home/hapi`.

### Notes

- By default SSH (port 22) is not reachable externally on Railway (no arbitrary port forwarding) — web terminal only. To get external SSH, enable the **external SSH tunnel** below (`SSH_TUNNEL_ENABLED=true`).
- `PORT` is injected automatically by Railway, `ttyd_proxy.py` reads it via `os.environ`
- When `hapi` is installed, the dashboard builds the **HAPI Server** link on demand from `/home/hapi/.hapi/server.log` (latest `https://*.relay.hapi.run`) and `/home/hapi/.hapi/settings.json` (`cliApiToken`). `/home/hapi/url` remains a legacy fallback, but the dashboard no longer depends on the entrypoint's one-shot URL writer. If hapi is absent or the URL/token is not available yet, the menu item is omitted.

### Claude Code with z.ai GLM Coding Plan

The image preconfigures native Claude Code for z.ai GLM Coding Plan through
`/home/hapi/.claude/settings.json`. On startup, `entrypoint.sh` copies
`config/claude-settings.json` from `/etc/skel/.claude/settings.json` only when
the user's `settings.json` is missing, so persisted volumes and custom Claude
settings are not overwritten. `settings.local.json` is a separate Claude Code
file and is never touched by this bootstrap.

The template contains only non-secret Claude Code env settings:
`ANTHROPIC_BASE_URL=https://api.z.ai/api/coding/paas/v4`,
Sonnet/Opus `glm-5.2[1m]`, Haiku `glm-4.7`, and the long timeout/context
window settings. It does **not** contain a token.

For native `claude`, pass the z.ai Coding Plan token at runtime:

```bash
docker run --env-file .env -e ANTHROPIC_AUTH_TOKEN=your_zai_token clihost
```

`bin/glm` is still shipped for compatibility and still reads `ZAI_TOKEN`, but it
is no longer required for GLM: ordinary `claude` uses the native settings file
when `ANTHROPIC_AUTH_TOKEN` is present in the environment.

### Диагностика слёта Claude Code auth

Для обычного Claude Code OAuth (`claude login`, файл
`/home/hapi/.claude/.credentials.json`) в образе есть диагностический snapshot
без секретов: токенов в снэпшоте нет, сохраняются только `expiresAt`, scopes,
тип подписки, sha256/mtime файла, права, время и быстрый сетевой чек Anthropic.

Снимите baseline сразу после успешного `claude login` внутри живого контейнера:

```bash
docker exec <container> bash /bin/claude-auth-snapshot.sh snapshot baseline
```

Когда Claude Code разлогинился, снимите второй snapshot и сравните:

```bash
docker exec <container> bash /bin/claude-auth-snapshot.sh snapshot failed
docker exec <container> bash /bin/claude-auth-snapshot.sh diff
docker exec <container> bash /bin/claude-auth-snapshot.sh list
```

По умолчанию файлы пишутся в
`/home/hapi/.hapi/auth-snapshots`; при необходимости путь меняется через
`CLAUDE_AUTH_SNAPSHOT_DIR`. `diff` выдаёт подсказку причины: refresh работает,
refresh не происходит при истёкшем `expiresAt`, права мешают записи
`.credentials.json`, пропал доступ к `api.anthropic.com`, либо credentials-файл
исчез.

С хоста используйте wrapper, чтобы добавить `docker inspect`-мету
(`RestartCount`, `State.StartedAt`, `State.Status`, mounts) и отделить
mount/persistence-рестарт от token/refresh-проблемы:

```bash
bin/claude-auth-snapshot-host.sh <container> baseline
bin/claude-auth-snapshot-host.sh <container> failed
bin/claude-auth-snapshot-host.sh diff ./claude-auth-host-snapshots/<A>.json ./claude-auth-host-snapshots/<B>.json
```

Этот инструмент диагностический: он разделяет (а) mount/persistence, (б)
права/refresh-запись, (в) сетевой или token-refresh провал, но сам OAuth не
чинит.

### Синхронизация окружения хост↔контейнер

`bin/clihost-sync.sh` запускается с хоста и синхронизирует через
rsync-over-SSH только безопасный несекретный subset:

- `~/.gitconfig`
- `~/.config/gh`

Команда подключается к `sshd` контейнера под пользователем `hapi`. В этом
контракте `pull` означает хост → контейнер, а `push` — контейнер → хост.
По умолчанию это dry-run с itemized output от rsync; реальная запись требует
`--apply`. `--delete` не используется без явного `--allow-delete`.

```bash
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh pull
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh pull --apply
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh push
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh ssh
CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 bin/clihost-sync.sh ssh --apply
```

Для прямого SSH используйте `CLIHOST_SSH_TARGET`, `CLIHOST_SSH_PORT` и при
необходимости `CLIHOST_SSH_IDENTITY_FILE` либо одноимённые флаги. Для туннеля
#79: chisel обычно выглядит как обычный `ssh -p <port>`, а cloudflared удобнее
завести в локальном `~/.ssh/config` как Host с `ProxyCommand`, после чего
передать helper-у этот Host как target.

`ssh`-подкоманда отделена от обычного `pull`/`push` и выключена по умолчанию.
Без `--include-private-keys` она переносит только `~/.ssh/known_hosts`,
`~/.ssh/*.pub` и `~/.ssh/config`. Приватные ключи требуют явного флага, потому
что ключевой материал проходит через SSH relay; это risk B relay/blast-radius
из #17. Детектор приватных ключей PEM-only, а контракт `~/.ssh` flat: копируются
только top-level файлы, ключи в поддиректориях проверяются по правам, но не
переносятся.

Non-goals:

- `~/.claude` не синкается: источник истины — volume `/home/hapi`. Синк мог бы
  затереть свежие OAuth credentials во время refresh-token гонки (#69/#89).
- Приватные `~/.ssh` не входят в основной subset из-за blast radius и relay-риска;
  для них есть отдельная явная `ssh`-подкоманда.
- Claude Code `settings.json` не синкается: он управляется
  `config/claude-settings.json` и bootstrap-контрактом (#60), иначе легко
  разнести устаревшую локальную конфигурацию.

Перед каждым запуском remote preflight работает fail-closed: если home на
удалённой стороне не является отдельным mount ровно в `/home/hapi`, есть parent
mount на `/home`, или `/proc/mounts` нельзя прочитать, rsync не стартует. В таком
случае исправьте volume mount на `/home/hapi`; если раньше использовался `/home`,
перенесите содержимое `hapi/` в корень нового volume, как описано выше.

Recovery: в режиме `--apply` helper включает rsync `--backup` и
`--backup-dir`. Для `pull` backups остаются в контейнере под
`/home/hapi/.clihost-sync-backups/<timestamp>`, для `push` — на хосте под
`~/.clihost-sync-backups/<timestamp>`. Чтобы откатиться, возьмите нужные файлы
из последнего backup-dir и скопируйте их обратно в сторону назначения.
`~/.claude` восстанавливается не через sync, а из корректно смонтированного
`/home/hapi` volume как known-good источника.

Syncthing и real-time sync отложены: текущий релиз намеренно rsync-first, без
постоянного фонового синка.

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
| `ANTHROPIC_AUTH_TOKEN` | - | z.ai Coding Plan token for native Claude Code GLM access; do not bake it into the image or settings file |
| `ZAI_TOKEN` | - | Compatibility token for the legacy `bin/glm` wrapper only |

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
