#!/bin/bash
set -euo pipefail

PACKAGE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/cli-packages.txt"

# Получаем версию пакета с retry (соответствует паттерну из CLAUDE.md)
get_version() {
  for i in 1 2 3 4 5; do
    ver=$(npm view "$1" version 2>/dev/null) && echo "$ver" && return || sleep 10
  done
  echo "unknown"
}

mapfile -t CLI_PACKAGES < "${PACKAGE_FILE}"

# Получаем актуальные версии пакетов из npm registry
VERSIONS=""
package_count=0
unknown_count=0
for package in "${CLI_PACKAGES[@]}"; do
  [ -n "${package}" ] || continue
  version=$(get_version "${package%@latest}")
  package_count=$((package_count + 1))
  if [[ "${version}" == "unknown" ]]; then
    unknown_count=$((unknown_count + 1))
  fi
  if [ -n "${VERSIONS}" ]; then
    VERSIONS+=" "
  fi
  VERSIONS+="${version}"
done

# Проверяем что хотя бы часть версий получена
if (( package_count == 0 )); then
  echo "Error: package list is empty"
  exit 1
fi
if (( unknown_count == package_count )); then
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
