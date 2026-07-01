#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_HOST_SNAPSHOT_DIR="./claude-auth-host-snapshots"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  claude-auth-snapshot-host.sh <container-name-or-id> [label]
  claude-auth-snapshot-host.sh snapshot <container-name-or-id> [label]
  claude-auth-snapshot-host.sh diff A.json B.json
  claude-auth-snapshot-host.sh list
  claude-auth-snapshot-host.sh latest
EOF
}

host_snapshot_dir() {
  printf '%s\n' "${CLAUDE_AUTH_HOST_SNAPSHOT_DIR:-${DEFAULT_HOST_SNAPSHOT_DIR}}"
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

unique_host_snapshot_path() {
  local dir="$1"
  local label="$2"
  local stamp
  local safe_label
  local base
  local path
  local n

  stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
  safe_label="$(sanitize_label "${label}")"
  base="${dir}/${stamp}-host"
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

docker_inspect_field() {
  local container="$1"
  local template="$2"
  docker inspect --format "${template}" "${container}"
}

create_host_snapshot() {
  local container="${1:-}"
  local label="${2:-}"
  local dir
  local out
  local restart_count
  local started_at
  local status
  local mounts_json
  local container_snapshot_path
  local container_snapshot_json

  [ -n "${container}" ] || die "container name or id is required"
  command -v docker >/dev/null 2>&1 || die "docker CLI not found"

  dir="$(host_snapshot_dir)"
  mkdir -p "${dir}"
  out="$(unique_host_snapshot_path "${dir}" "${label}")"

  restart_count="$(docker_inspect_field "${container}" '{{.RestartCount}}')"
  started_at="$(docker_inspect_field "${container}" '{{.State.StartedAt}}')"
  status="$(docker_inspect_field "${container}" '{{.State.Status}}')"
  mounts_json="$(docker_inspect_field "${container}" '{{json .Mounts}}')"

  if [ -n "${label}" ]; then
    container_snapshot_path="$(docker exec "${container}" bash /bin/claude-auth-snapshot.sh snapshot "${label}")"
  else
    container_snapshot_path="$(docker exec "${container}" bash /bin/claude-auth-snapshot.sh snapshot)"
  fi
  container_snapshot_json="$(docker exec "${container}" cat "${container_snapshot_path}")"

  HOST_SNAPSHOT_OUTPUT="${out}" \
  HOST_SNAPSHOT_LABEL="${label}" \
  HOST_CONTAINER="${container}" \
  HOST_RESTART_COUNT="${restart_count}" \
  HOST_STARTED_AT="${started_at}" \
  HOST_STATUS="${status}" \
  HOST_MOUNTS_JSON="${mounts_json}" \
  CONTAINER_SNAPSHOT_PATH="${container_snapshot_path}" \
  CONTAINER_SNAPSHOT_JSON="${container_snapshot_json}" \
  python3 <<'PY'
import datetime
import json
import os
from pathlib import Path


def iso_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


mounts = json.loads(os.environ["HOST_MOUNTS_JSON"])
safe_mounts = [
    {
        "destination": mount.get("Destination"),
        "source": mount.get("Source"),
        "type": mount.get("Type"),
        "rw": mount.get("RW"),
    }
    for mount in mounts
]

snapshot = {
    "schema_version": 1,
    "kind": "claude-auth-host-snapshot",
    "label": os.environ.get("HOST_SNAPSHOT_LABEL") or None,
    "created_at": iso_now(),
    "host": {
        "container": os.environ["HOST_CONTAINER"],
        "inspect": {
            "restart_count": int(os.environ["HOST_RESTART_COUNT"]),
            "state": {
                "started_at": os.environ["HOST_STARTED_AT"],
                "status": os.environ["HOST_STATUS"],
            },
            "mounts": safe_mounts,
        },
    },
    "container_snapshot_path": os.environ["CONTAINER_SNAPSHOT_PATH"],
    "container_snapshot": json.loads(os.environ["CONTAINER_SNAPSHOT_JSON"]),
}

Path(os.environ["HOST_SNAPSHOT_OUTPUT"]).write_text(
    json.dumps(snapshot, indent=2, sort_keys=True) + "\n"
)
PY

  echo "${out}"
}

run_host_diff() {
  local a="${1:-}"
  local b="${2:-}"
  [ -n "${a}" ] && [ -n "${b}" ] || die "diff requires A.json B.json"
  [ -f "${a}" ] || die "snapshot not found: ${a}"
  [ -f "${b}" ] || die "snapshot not found: ${b}"

  python3 - "${a}" "${b}" <<'PY'
import json
import sys


def load(path):
    with open(path) as handle:
        return json.load(handle)


def mounts_fp(data):
    mounts = data.get("host", {}).get("inspect", {}).get("mounts", [])
    return sorted(
        (
            mount.get("destination"),
            mount.get("source"),
            mount.get("type"),
            mount.get("rw"),
        )
        for mount in mounts
    )


old = load(sys.argv[1])
new = load(sys.argv[2])
old_inspect = old.get("host", {}).get("inspect", {})
new_inspect = new.get("host", {}).get("inspect", {})
old_state = old_inspect.get("state", {})
new_state = new_inspect.get("state", {})

print("Host docker diff")
print(f"A: {sys.argv[1]}")
print(f"B: {sys.argv[2]}")
print("")
print("Delta:")
print(f"- RestartCount: {old_inspect.get('restart_count')} -> {new_inspect.get('restart_count')}")
print(f"- State.Status: {old_state.get('status')} -> {new_state.get('status')}")
print(f"- State.StartedAt: {old_state.get('started_at')} -> {new_state.get('started_at')}")
print(f"- Mounts changed: {mounts_fp(old) != mounts_fp(new)}")
print("")
if old_inspect.get("restart_count") != new_inspect.get("restart_count") or old_state.get("started_at") != new_state.get("started_at"):
    print("Host verdict:")
    print("- ⚠️ container restart detected; compare with inner credentials state to separate restart/mount causes from token refresh causes.")
    print("")
if mounts_fp(old) != mounts_fp(new):
    print("Mount verdict:")
    print("- ⚠️ Docker mounts changed; verify /home/hapi persistence before blaming OAuth refresh.")
    print("")
PY

  bash "${SCRIPT_DIR}/claude-auth-snapshot.sh" diff "${a}" "${b}"
}

list_host_snapshots() {
  local dir
  dir="$(host_snapshot_dir)"
  [ -d "${dir}" ] || return 0
  find "${dir}" -maxdepth 1 -type f -name '*.json' | sort
}

latest_host_snapshot() {
  list_host_snapshots | tail -n 1
}

main() {
  local command="${1:-}"
  case "${command}" in
    snapshot)
      shift
      [ "$#" -ge 1 ] && [ "$#" -le 2 ] || die "snapshot requires <container> [label]"
      create_host_snapshot "$@"
      ;;
    diff)
      shift
      [ "$#" -eq 2 ] || die "diff requires A.json B.json"
      run_host_diff "$@"
      ;;
    list)
      shift
      [ "$#" -eq 0 ] || die "list accepts no arguments"
      list_host_snapshots
      ;;
    latest)
      shift
      [ "$#" -eq 0 ] || die "latest accepts no arguments"
      latest_host_snapshot
      ;;
    -h|--help|help|"")
      usage
      [ -n "${command}" ] || exit 2
      ;;
    *)
      [ "$#" -le 2 ] || die "expected <container> [label]"
      create_host_snapshot "$@"
      ;;
  esac
}

main "$@"
