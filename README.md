# clihost

Docker container with web terminal (TTYD) and AI CLI tools (Claude Code, Codex, Gemini CLI).

## Quick Start

```bash
# Build
docker build -t clihost .

# Run
docker run -p 22:22 -p 8080:8080 clihost
```

Open http://localhost:8080 for web terminal access.

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
