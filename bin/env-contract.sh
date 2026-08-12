#!/usr/bin/env bash

# Runtime environment parsing shared by entrypoint.sh.  A missing or empty
# value uses its documented default; an explicitly supplied malformed value is
# a configuration error.

_env_trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "${value}"
}

env_bool() {
  local name="$1" default="$2" value
  value="$(_env_trim "${!name-}")"
  [ -n "${value}" ] || value="${default}"

  case "${value}" in
    1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]) printf -v "${name}" '%s' true ;;
    0|[Ff][Aa][Ll][Ss][Ee]|[Nn][Oo]|[Oo][Ff][Ff]) printf -v "${name}" '%s' false ;;
    *)
      echo "ERROR: ${name}='${value}' is invalid; expected 1/true/yes/on or 0/false/no/off" >&2
      return 1
      ;;
  esac
  export "${name}"
}

env_positive_int() {
  local name="$1" default="$2" minimum="$3" maximum="${4-}" value digits
  value="$(_env_trim "${!name-}")"
  [ -n "${value}" ] || value="${default}"
  case "${value}" in
    +*) value="${value#+}" ;;
  esac
  case "${value}" in
    ''|*[!0-9]*)
      echo "ERROR: ${name}='${value}' is invalid; expected a decimal integer" >&2
      return 1
      ;;
  esac

  digits="${value#"${value%%[!0]*}"}"
  [ -n "${digits}" ] || digits=0

  # Strip leading zeros from the bounds too so the length+lexicographic
  # comparison below reflects numeric magnitude, not raw digit-string form
  # (a zero-padded bound like "05" must compare as 5, not sort above "9").
  local min_digits="${minimum#"${minimum%%[!0]*}"}"
  [ -n "${min_digits}" ] || min_digits=0
  if [ "${#digits}" -lt "${#min_digits}" ] \
     || { [ "${#digits}" -eq "${#min_digits}" ] && [[ "${digits}" < "${min_digits}" ]]; }; then
    echo "ERROR: ${name}=${value} is below minimum ${minimum}" >&2
    return 1
  fi
  if [ -n "${maximum}" ]; then
    local max_digits="${maximum#"${maximum%%[!0]*}"}"
    [ -n "${max_digits}" ] || max_digits=0
    if [ "${#digits}" -gt "${#max_digits}" ] \
       || { [ "${#digits}" -eq "${#max_digits}" ] && [[ "${digits}" > "${max_digits}" ]]; }; then
      echo "ERROR: ${name}=${value} is above maximum ${maximum}" >&2
      return 1
    fi
  fi

  printf -v "${name}" '%s' "${digits}"
  export "${name}"
}

env_secret() {
  local name="$1" file_name path value
  file_name="${name}_FILE"
  path="${!file_name-}"
  if [ -n "${path}" ]; then
    if [ ! -f "${path}" ] || [ ! -r "${path}" ]; then
      echo "ERROR: Cannot read ${file_name}=${path}" >&2
      return 1
    fi
    value="$(_env_trim "$(cat -- "${path}")")"
    if [ -z "${value}" ]; then
      echo "ERROR: ${file_name}=${path} is empty" >&2
      return 1
    fi
    printf -v "${name}" '%s' "${value}"
    # Keep the resolved secret in this shell only. Service children must receive
    # secrets through their dedicated file/env channels, not by broad inheritance.
    export -n "${name}" "${file_name}" 2>/dev/null || true
  elif [ -n "${!name-}" ]; then
    # No *_FILE override: a directly-supplied value still goes through the same
    # trim + empty-after-trim check as the file path, so a whitespace-only
    # PASSWORD_SECRET fails closed instead of silently becoming the effective
    # secret.
    value="$(_env_trim "${!name}")"
    if [ -z "${value}" ]; then
      echo "ERROR: ${name} is set but empty (whitespace only)" >&2
      return 1
    fi
    printf -v "${name}" '%s' "${value}"
  fi
}
