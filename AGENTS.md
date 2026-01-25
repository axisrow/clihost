# Repository Guidelines

## Project Overview
This repository builds a Docker image that runs the `hapi` CLI daemon alongside `sshd`, and bundles common AI CLI tools (Codex, Claude Code, Gemini). Configuration is provided via environment variables.

## Project Structure & Module Organization
- `Dockerfile`: Image build with Node.js, CLI tools, `hapi`, and OpenSSH.
- `entrypoint.sh`: Container startup; launches `hapi daemon` and keeps `sshd` in the foreground.
- `.env.example`: Template for required environment variables.
- `volume/hapi/`: Sample/persistent runtime data (daemon state, logs, runtime files).

## Build, Test, and Development Commands
- `docker build -t clihost .`
  Builds the container image locally.
- `cp .env.example .env`
  Creates a local env file (fill in `CLI_API_TOKEN`, `HAPI_API_URL`).
- `docker run --env-file .env -p 22:22 -p 3006:3006 -v "$(pwd)/volume/hapi:/home/hapi" clihost`
  Runs the container; set `HAPI_PORT` in `.env` to match the mapped port.

## Coding Style & Naming Conventions
- Shell scripts use Bash (`#!/usr/bin/env bash`) and `set -euo pipefail`.
- Environment variables are uppercase (for example, `HAPI_PORT`, `CLI_API_TOKEN`).
- Keep Dockerfile changes grouped by purpose (base OS, tools, user setup).

## Testing Guidelines
No automated tests are present. Use a manual smoke check:
- Build and run the image.
- Confirm `hapi daemon start` appears in logs and `sshd` stays running.

## Commit & Pull Request Guidelines
Observed commit history uses short, imperative subjects (often "add ..." or Russian verbs), with no issue IDs. Follow the same style.
PRs should include:
- A brief summary of changes.
- Any new/changed environment variables (update `.env.example`).
- Port or volume mapping changes and their rationale.

## Security & Configuration Tips
- Do not commit real tokens; keep secrets in `.env` or your runtime environment.
- Treat `volume/hapi` as runtime data; back it up if persistence matters.
