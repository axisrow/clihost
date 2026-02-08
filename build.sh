#!/bin/bash
set -euo pipefail

# Получаем версию пакета с retry (соответствует паттерну из CLAUDE.md)
get_version() {
  for i in 1 2 3 4 5; do
    ver=$(npm view "$1" version 2>/dev/null) && echo "$ver" && return || sleep 10
  done
  echo "unknown"
}

# Получаем актуальные версии пакетов из npm registry
VERSIONS=$(get_version @anthropic-ai/claude-code)
VERSIONS+=" $(get_version @openai/codex)"
VERSIONS+=" $(get_version @google/gemini-cli)"
VERSIONS+=" $(get_version @twsxtd/hapi)"

# Проверяем что хотя бы часть версий получена
if [[ "$VERSIONS" =~ ^(unknown\ ){3}unknown$ ]]; then
  echo "Error: failed to fetch all npm package versions. Check network connectivity."
  exit 1
fi
if [[ "$VERSIONS" == *"unknown"* ]]; then
  echo "Warning: failed to fetch some npm package versions"
fi

# Формируем хеш из версий
HASH=$(echo "$VERSIONS" | sha256sum | cut -c1-12)

echo "npm package versions: $VERSIONS"
echo "Cache hash: $HASH"

docker build --build-arg NPM_VERSIONS_HASH="$HASH" "$@" -t clihost .
