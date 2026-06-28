#!/bin/bash
set -euo pipefail

# docker build uses "." as context — always run from the repo root
cd "$(dirname "${BASH_SOURCE[0]}")"

PACKAGE_FILE="cli-packages.txt"

# Получаем версию пакета с retry (соответствует паттерну из CLAUDE.md)
get_version() {
  for i in 1 2 3 4 5; do
    # Require non-empty output: an empty `npm view` (exit 0 but blank — transient
    # registry response or a missing version field) must fall through to a retry
    # and ultimately "unknown", so the unknown-count guard/warning engage (B14).
    ver=$(npm view "$1" version 2>/dev/null) && [ -n "$ver" ] && echo "$ver" && return || sleep 10
  done
  echo "unknown"
}

# Строгая валидация булевого флага: только true/false. Фейлим на любом другом
# значении, чтобы опечатка ("False"/"0") не привела к тихому включению тула.
validate_bool() {
  local name="$1" val="$2"
  case "${val}" in
    true|false) ;;
    *)
      echo "Error: ${name}='${val}' is invalid; must be 'true' or 'false'"
      exit 1
      ;;
  esac
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
  validate_bool "${flag_var}" "${flag_val}"
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
  validate_bool "INSTALL_HERMES" "${INSTALL_HERMES}"
  BUILD_ARGS+=(--build-arg "INSTALL_HERMES=${INSTALL_HERMES}")
fi

# Прочие non-npm компоненты тоже управляются INSTALL_*-флагом, но не входят в
# cli-packages.txt и cache-busting хеш: SSH-tunnel провайдеры (curl-пребилты,
# issue #79) и ao (собирается из исходников в Go build-stage по AO_REF, #76/#77).
# Пробрасываем каждый флаг в сборку, если задан.
for nonnpm_key in INSTALL_CLOUDFLARED INSTALL_CHISEL INSTALL_AO; do
  if [ -n "${!nonnpm_key:-}" ]; then
    validate_bool "${nonnpm_key}" "${!nonnpm_key}"
    BUILD_ARGS+=(--build-arg "${nonnpm_key}=${!nonnpm_key}")
  fi
done

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
