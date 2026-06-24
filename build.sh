#!/bin/bash
set -euo pipefail

# docker build uses "." as context — always run from the repo root
cd "$(dirname "${BASH_SOURCE[0]}")"

PACKAGE_FILE="cli-packages.txt"

# Получаем версию пакета с retry (соответствует паттерну из CLAUDE.md)
get_version() {
  for i in 1 2 3 4 5; do
    ver=$(npm view "$1" version 2>/dev/null) && echo "$ver" && return || sleep 10
  done
  echo "unknown"
}

# cli-packages.txt: "<COMPONENT_KEY> <npm-spec>" (issue #57). Модульные флаги
# INSTALL_<KEY> читаются из окружения (по умолчанию true) и:
#   1) передаются в docker build как --build-arg, чтобы install-cli.sh пропустил
#      отключённые компоненты;
#   2) исключают отключённые пакеты из cache-busting хеша — иначе обновление
#      версии невыбранного инструмента зря инвалидировало бы кеш.
BUILD_ARGS=()
VERSIONS=""
package_count=0
unknown_count=0

while read -r key spec _rest; do
  case "${key}" in
    ''|\#*) continue ;;  # пустая строка или комментарий
  esac
  if [ -z "${spec}" ]; then
    echo "Error: malformed line in ${PACKAGE_FILE}: missing npm spec for '${key}'"
    exit 1
  fi

  flag_var="INSTALL_${key}"
  flag_val="${!flag_var:-true}"
  # Всегда пробрасываем флаг в сборку, чтобы образ отражал явный выбор
  BUILD_ARGS+=(--build-arg "${flag_var}=${flag_val}")

  if [ "${flag_val}" = "false" ]; then
    echo "Skipping ${spec} from cache hash (${flag_var}=false)"
    continue
  fi

  version=$(get_version "${spec%@latest}")
  package_count=$((package_count + 1))
  if [[ "${version}" == "unknown" ]]; then
    unknown_count=$((unknown_count + 1))
  fi
  if [ -n "${VERSIONS}" ]; then
    VERSIONS+=" "
  fi
  VERSIONS+="${version}"
done < "${PACKAGE_FILE}"

# Hermes ставится не из npm (pip из GitHub), но всё равно управляется флагом —
# пробрасываем его в сборку, если задан.
if [ -n "${INSTALL_HERMES:-}" ]; then
  BUILD_ARGS+=(--build-arg "INSTALL_HERMES=${INSTALL_HERMES}")
fi

# Проверяем что хотя бы часть версий получена
if (( package_count == 0 )); then
  echo "Warning: no enabled npm packages (all INSTALL_* flags are false?)"
  VERSIONS="none"
else
  if (( unknown_count == package_count )); then
    echo "Error: failed to fetch all npm package versions. Check network connectivity."
    exit 1
  fi
  if [[ "$VERSIONS" == *"unknown"* ]]; then
    echo "Warning: failed to fetch some npm package versions"
  fi
fi

# Формируем хеш из версий
HASH=$(echo "$VERSIONS" | sha256sum | cut -c1-12)

echo "npm package versions: $VERSIONS"
echo "Cache hash: $HASH"

docker build --build-arg NPM_VERSIONS_HASH="$HASH" "${BUILD_ARGS[@]}" "$@" -t clihost .
