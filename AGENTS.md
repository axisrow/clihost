# Repository Guidelines

## Project Overview
This repository builds a headless Docker image with a web terminal and `sshd`, and bundles common AI CLI tools (Codex, Claude Code, Gemini). The `hapi` server starts when the CLI is installed, while the `hapi` runner is disabled by default and must be explicitly enabled. Configuration is provided via environment variables.

## Project Structure & Module Organization
- `Dockerfile`: Image build with Node.js, CLI tools, `hapi`, and OpenSSH.
- `entrypoint.sh`: Container startup; launches the web proxy and optional services, then keeps the configured container command in the foreground.
- `.env.example`: Template for required environment variables.
- `/home/hapi`: Container path for persistent runtime data (credentials, runner state, logs, and configuration). Mount a volume here, not at `/home`.

## Build, Test, and Development Commands
- `docker build -t clihost .`
  Builds the container image locally.
- `cp .env.example .env`
  Creates a local env file. `CLI_API_TOKEN` and `HAPI_API_URL` are required only when `HAPI_RUNNER_ENABLED=true`.
- `docker run --env-file .env -p 22:22 -p 8080:8080 -v clihost-home:/home/hapi clihost`
  Runs the default web terminal and SSH services with persistent home data.

## Coding Style & Naming Conventions
- Shell scripts use Bash (`#!/usr/bin/env bash`) and `set -euo pipefail`.
- Environment variables are uppercase (for example, `HAPI_PORT`, `CLI_API_TOKEN`).
- Keep Dockerfile changes grouped by purpose (base OS, tools, user setup).

## Testing Guidelines
```bash
python -m pytest tests/          # all tests
python -m pytest tests/unit/     # unit tests only
npm ci                           # install JS test dependencies
npm test                         # executable browser-asset tests
```
Tests are in `tests/unit/` (pure functions) and `tests/integration/` (handler simulation). `conftest.py` adds `app/` to `sys.path`.

Run both `python -m pytest tests/` and `npm test` before pushing. Manual smoke check: build and run the image, verify `http://localhost:8080/health`, and confirm `sshd` stays running. When testing the optional runner, set `HAPI_RUNNER_ENABLED=true` and confirm `Hapi runner startup complete` appears in logs.

## Commit & Pull Request Guidelines
Observed commit history uses short, imperative subjects (often "add ..." or Russian verbs), with no issue IDs. Follow the same style.
PRs should include:
- A brief summary of changes.
- Any new/changed environment variables (update `.env.example`).
- Port or volume mapping changes and their rationale.

## Security & Configuration Tips
- Do not commit real tokens; keep secrets in `.env` or your runtime environment.
- Treat the volume mounted at `/home/hapi` as runtime data; back it up if persistence matters.

`CLAUDE.md` contains the detailed repository contract and is authoritative if these shorter guidelines disagree with it.
