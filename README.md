# clihost

Docker container with web terminal (TTYD) and AI CLI tools (Claude Code, Codex, Gemini CLI). The web terminal proxy uses a multithreaded HTTP server — concurrent connections do not block each other.

## Quick Start

```bash
# Build
docker build -t clihost .

# Run
docker run -p 22:22 -p 8080:8080 clihost
```

Open http://localhost:8080 for web terminal access.

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

### Notes

- SSH (port 22) is not accessible externally on Railway — web terminal only
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
| `hapi runner` | `HAPI_PORT` (default 80) | Запуск CLI-инструментов по API (опционально) |
| `hapi server --relay` | — | Туннель для внешнего доступа |

> **Railway:** платформа проксирует внешний трафик (порт 80/443) на внутренний порт **8080** контейнера. `ttyd_proxy.py` остаётся на 8080, hapi runner — на 80. Конфликта нет: Railway форвардит только на 8080, а hapi runner доступен снаружи исключительно через relay-туннель.

**Поток аутентификации:** `POST /login` → HMAC-подписанная cookie `ttyd_session` → редирект на `/`.

**Мультитерминальность:** каждый терминал — отдельный процесс `ttyd` на своём порту (7681, 7682, …). Управление через `GET/POST/DELETE /terminals`.

### Внутренняя структура ttyd proxy

После рефакторинга точка входа `app/ttyd_proxy.py` остаётся совместимой оболочкой, а основная логика разложена по модульному пакету `app/ttydproxy/`:

- `config.py` — env-конфигурация и route-константы
- `security.py` — cookies, signed tokens, CSRF, username validation
- `manager.py` — lifecycle ttyd/tmux процессов
- `proxy.py` — HTTP/WebSocket proxy и HTML injection
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

## Health Check

```bash
curl http://localhost:8080/health
# {"status": "ok", "ttyd": "running"}
```
