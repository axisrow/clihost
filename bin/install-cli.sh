#!/bin/bash
set -euo pipefail
# install-cli.sh - Устанавливает npm CLI-инструменты из cli-packages.txt с учётом
# модульных флагов INSTALL_<KEY> (issue #57). Для каждой строки "<KEY> <spec>"
# инструмент ставится только если переменная окружения INSTALL_<KEY> != "false"
# (по умолчанию включено — поведение совпадает с прежней безусловной установкой).
#
# Используется в Dockerfile на этапе сборки; флаги приходят из ARG INSTALL_*,
# которые Dockerfile экспортирует в окружение перед запуском этого скрипта.
#
# Тот же парсинг (первый токен = ключ, второй = npm-spec) применяет build.sh при
# вычислении cache-busting хеша, поэтому формат файла обязан совпадать.

PACKAGE_FILE="${1:-/tmp/cli-packages.txt}"

if [ ! -f "${PACKAGE_FILE}" ]; then
  echo "ERROR: package list not found: ${PACKAGE_FILE}" >&2
  exit 1
fi

# Собираем список включённых npm-спеков, пропуская комментарии/пустые строки и
# компоненты, отключённые через INSTALL_<KEY>=false.
packages=()
skipped=()
while read -r key spec _rest; do
  case "${key}" in
    ''|\#*) continue ;;  # пустая строка или комментарий
  esac
  if [ -z "${spec}" ]; then
    echo "ERROR: malformed line in ${PACKAGE_FILE}: missing npm spec for '${key}'" >&2
    exit 1
  fi
  flag_var="INSTALL_${key}"
  flag_val="${!flag_var:-true}"
  if [ "${flag_val}" = "false" ]; then
    skipped+=("${spec} (${flag_var}=false)")
    continue
  fi
  packages+=("${spec}")
done < "${PACKAGE_FILE}"

if [ "${#skipped[@]}" -gt 0 ]; then
  echo "Skipping disabled CLI tools:"
  for s in "${skipped[@]}"; do
    echo "  - ${s}"
  done
fi

if [ "${#packages[@]}" -eq 0 ]; then
  echo "No npm CLI tools enabled; nothing to install."
  exit 0
fi

echo "Installing npm CLI tools: ${packages[*]}"
# Retry to ride out transient npm registry hiccups (matches the repo pattern).
# Track success explicitly: under `set -e` a bare `... && break || sleep 10`
# loop exits 0 even when every attempt failed (the trailing sleep succeeds), so
# a registry outage would silently produce an image missing its CLI tools.
installed=false
for i in 1 2 3 4 5; do
  if npm install -g "${packages[@]}"; then
    installed=true
    break
  fi
  sleep 10
done
if [ "${installed}" != "true" ]; then
  echo "ERROR: failed to install npm CLI tools after 5 attempts" >&2
  exit 1
fi
