#!/bin/bash
set -euo pipefail

# Получаем актуальные версии пакетов из npm registry
VERSIONS=$(npm view @anthropic-ai/claude-code version 2>/dev/null || echo "unknown")
VERSIONS+=" $(npm view @openai/codex version 2>/dev/null || echo "unknown")"
VERSIONS+=" $(npm view @google/gemini-cli version 2>/dev/null || echo "unknown")"
VERSIONS+=" $(npm view @twsxtd/hapi version 2>/dev/null || echo "unknown")"

# Формируем хеш из версий
HASH=$(echo "$VERSIONS" | sha256sum | cut -c1-12)

echo "npm package versions: $VERSIONS"
echo "Cache hash: $HASH"

docker build --build-arg NPM_VERSIONS_HASH="$HASH" "$@" -t clihost .
