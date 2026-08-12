#!/bin/bash
set -euo pipefail

DEFAULT_SNAPSHOT_DIR="/home/hapi/.hapi/auth-snapshots"
DEFAULT_CLAUDE_CONFIG_DIR="/home/hapi/.claude"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPSHOT_LIB="${SCRIPT_DIR}/claude_auth_snapshot.py"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  claude-auth-snapshot.sh snapshot [label]
  claude-auth-snapshot.sh diff [A.json B.json]
  claude-auth-snapshot.sh list
  claude-auth-snapshot.sh latest
EOF
}

snapshot_dir() {
  printf '%s\n' "${CLAUDE_AUTH_SNAPSHOT_DIR:-${DEFAULT_SNAPSHOT_DIR}}"
}

sanitize_label() {
  local label="${1:-}"
  if [ -z "${label}" ]; then
    return 0
  fi
  printf '%s' "${label}" \
    | tr -c 'A-Za-z0-9._-' '-' \
    | sed -e 's/^-*//' -e 's/-*$//' -e 's/--*/-/g' \
    | cut -c 1-80
}

unique_snapshot_path() {
  local dir="$1"
  local label="$2"
  local stamp
  local safe_label
  local base
  local path
  local n

  stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
  safe_label="$(sanitize_label "${label}")"
  base="${dir}/${stamp}"
  if [ -n "${safe_label}" ]; then
    base="${base}-${safe_label}"
  fi
  path="${base}.json"
  n=1
  while [ -e "${path}" ]; do
    path="${base}-${n}.json"
    n=$((n + 1))
  done
  printf '%s\n' "${path}"
}

require_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found"
  [ -f "${SNAPSHOT_LIB}" ] || die "snapshot library not found: ${SNAPSHOT_LIB}"
}

create_snapshot() {
  require_python
  local label="${1:-}"
  local dir
  local out

  dir="$(snapshot_dir)"
  # The documented host flow runs this via `docker exec` as ROOT (the image sets
  # no USER), while /home/hapi is writable by the hapi user — so a hapi process
  # could pre-place the snapshot dir as a symlink and steer a root write outside
  # it (arbitrary-path write). Refuse to operate on a symlinked dir, create it
  # 0700, and let the Python writer create the file with O_NOFOLLOW|O_EXCL 0600.
  # Mirrors the symlink hardening in uploads.py / ensure_claude_settings.
  if [ -L "${dir}" ]; then
    die "snapshot dir '${dir}' is a symlink; refusing (potential arbitrary-path write)"
  fi
  mkdir -p "${dir}"
  if [ -L "${dir}" ] || [ ! -d "${dir}" ]; then
    die "snapshot dir '${dir}' is not a real directory"
  fi
  chmod 0700 "${dir}" 2>/dev/null || true
  out="$(unique_snapshot_path "${dir}" "${label}")"

  CLAUDE_AUTH_SNAPSHOT_LABEL="${label}" \
  CLAUDE_AUTH_SNAPSHOT_OUTPUT="${out}" \
  CLAUDE_CONFIG_DIR="${CLAUDE_CONFIG_DIR:-${DEFAULT_CLAUDE_CONFIG_DIR}}" \
  CLAUDE_AUTH_SNAPSHOT_COMMAND="snapshot" \
  python3 "${SNAPSHOT_LIB}"

  echo "${out}"
}

collect_latest_two() {
  local dir
  dir="$(snapshot_dir)"
  [ -d "${dir}" ] || die "snapshot dir not found: ${dir}"
  find "${dir}" -maxdepth 1 -type f -name '*.json' | sort | tail -n 2
}

run_diff() {
  require_python
  local a=""
  local b=""
  local snapshots=()

  if [ "$#" -eq 0 ]; then
    while IFS= read -r path; do
      snapshots+=("${path}")
    done < <(collect_latest_two)
    [ "${#snapshots[@]}" -eq 2 ] || die "need at least two snapshots in $(snapshot_dir)"
    a="${snapshots[0]}"
    b="${snapshots[1]}"
  elif [ "$#" -eq 2 ]; then
    a="$1"
    b="$2"
  else
    usage
    exit 2
  fi

  [ -f "${a}" ] || die "snapshot not found: ${a}"
  [ -f "${b}" ] || die "snapshot not found: ${b}"

  CLAUDE_AUTH_SNAPSHOT_COMMAND="diff" \
  CLAUDE_AUTH_SNAPSHOT_A="${a}" \
  CLAUDE_AUTH_SNAPSHOT_B="${b}" \
  python3 "${SNAPSHOT_LIB}"
}

list_snapshots() {
  local dir
  dir="$(snapshot_dir)"
  [ -d "${dir}" ] || return 0
  find "${dir}" -maxdepth 1 -type f -name '*.json' | sort
}

latest_snapshot() {
  list_snapshots | tail -n 1
}

main() {
  local command="${1:-snapshot}"
  if [ "$#" -gt 0 ]; then
    shift
  fi

  case "${command}" in
    snapshot)
      [ "$#" -le 1 ] || die "snapshot accepts at most one label"
      create_snapshot "${1:-}"
      ;;
    diff)
      run_diff "$@"
      ;;
    list)
      [ "$#" -eq 0 ] || die "list accepts no arguments"
      list_snapshots
      ;;
    latest)
      [ "$#" -eq 0 ] || die "latest accepts no arguments"
      latest_snapshot
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
