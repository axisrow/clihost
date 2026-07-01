#!/bin/bash
set -euo pipefail

REMOTE_HOME="/home/hapi"
SYNC_LABEL="~/.gitconfig and ~/.config/gh"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  clihost-sync.sh pull [--target user@host] [--ssh-port port] [--identity-file path] [--apply] [--allow-delete]
  clihost-sync.sh push [--target user@host] [--ssh-port port] [--identity-file path] [--apply] [--allow-delete]

Direction:
  pull  copies the safe host config subset into the clihost container.
  push  copies the same safe subset from the clihost container back to the host.

Safety:
  Dry-run is the default. Use --apply for a real rsync run.
  --delete is never used unless --allow-delete is passed explicitly.
  The remote home must be mounted exactly at /home/hapi.

Target:
  Set --target or CLIHOST_SSH_TARGET to the SSH destination, for example:
    CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 clihost-sync.sh pull
EOF
}

quote_join() {
  local out=""
  local quoted
  local arg
  for arg in "$@"; do
    printf -v quoted "%q" "${arg}"
    if [ -n "${out}" ]; then
      out="${out} ${quoted}"
    else
      out="${quoted}"
    fi
  done
  printf "%s\n" "${out}"
}

guard_local_path() {
  local root="$1"
  local path="$2"
  local rel
  local current
  local part
  local old_ifs
  local -a parts

  case "${path}" in
    "${root}" | "${root}"/*) ;;
    *) die "refusing to touch local path outside HOME: ${path}" ;;
  esac

  rel="${path#${root}/}"
  current="${root}"
  old_ifs="${IFS}"
  IFS="/"
  read -r -a parts <<< "${rel}"
  IFS="${old_ifs}"
  for part in "${parts[@]}"; do
    [ -n "${part}" ] || continue
    current="${current}/${part}"
    if [ -L "${current}" ]; then
      die "${current} is a symlink; refusing to sync through it"
    fi
  done
}

guard_local_tree_no_symlinks() {
  local path="$1"
  local found

  [ -d "${path}" ] || return 0
  found="$(find "${path}" -type l -print 2>/dev/null)" \
    || die "cannot inspect ${path} for symlinks"
  if [ -n "${found}" ]; then
    die "$(printf "%s\n" "${found}" | sed -n '1p') is a symlink; refusing to sync through it"
  fi
}

preflight_local() {
  local host_home="$1"
  local backup_root="$2"

  [ -n "${host_home}" ] || die "HOME is empty; refusing to sync"
  [ -d "${host_home}" ] || die "HOME '${host_home}' is not a directory"
  guard_local_path "${host_home}" "${host_home}/.gitconfig"
  guard_local_path "${host_home}" "${host_home}/.config"
  guard_local_path "${host_home}" "${host_home}/.config/gh"
  guard_local_path "${host_home}" "${backup_root}"
  guard_local_tree_no_symlinks "${host_home}/.config/gh"
  guard_local_tree_no_symlinks "${backup_root}"
}

run_remote_preflight() {
  local target="$1"
  shift
  local -a ssh_args=("$@")

  "${ssh_args[@]}" -- "${target}" bash -s -- "${REMOTE_HOME}" "/proc/mounts" <<'REMOTE'
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

remote_home="$1"
mounts_file="$2"
backup_root="${remote_home}/.clihost-sync-backups"

[ -d "${remote_home}" ] || die "${remote_home} is not a directory; refusing to sync"
[ ! -L "${remote_home}" ] || die "${remote_home} is a symlink; refusing to sync through it"
[ -r "${mounts_file}" ] || die "cannot read ${mounts_file}; refusing to sync"

if ! awk -v home="${remote_home}" '$2 == home {found=1} END {exit !found}' "${mounts_file}"; then
  if awk '$2 == "/home" {found=1} END {exit !found}' "${mounts_file}"; then
    die "volume is mounted at /home, not exactly /home/hapi; refusing to sync"
  fi
  die "no separate volume mount at /home/hapi; refusing to sync"
fi

guard_remote_path() {
  local path="$1"
  local rel
  local current
  local part
  local old_ifs
  local -a parts

  case "${path}" in
    "${remote_home}" | "${remote_home}"/*) ;;
    *) die "refusing to touch remote path outside /home/hapi: ${path}" ;;
  esac

  rel="${path#${remote_home}/}"
  current="${remote_home}"
  old_ifs="${IFS}"
  IFS="/"
  read -r -a parts <<< "${rel}"
  IFS="${old_ifs}"
  for part in "${parts[@]}"; do
    [ -n "${part}" ] || continue
    current="${current}/${part}"
    if [ -L "${current}" ]; then
      die "${current} is a symlink; refusing to sync through it"
    fi
  done
}

guard_remote_tree_no_symlinks() {
  local path="$1"
  local found

  [ -d "${path}" ] || return 0
  found="$(find "${path}" -type l -print 2>/dev/null)" \
    || die "cannot inspect ${path} for symlinks"
  if [ -n "${found}" ]; then
    die "$(printf "%s\n" "${found}" | sed -n '1p') is a symlink; refusing to sync through it"
  fi
}

guard_remote_path "${remote_home}/.gitconfig"
guard_remote_path "${remote_home}/.config"
guard_remote_path "${remote_home}/.config/gh"
guard_remote_path "${backup_root}"
guard_remote_tree_no_symlinks "${remote_home}/.config/gh"
guard_remote_tree_no_symlinks "${backup_root}"
REMOTE
}

main() {
  local command=""
  local apply="false"
  local allow_delete="false"
  local target="${CLIHOST_SSH_TARGET:-}"
  local ssh_port="${CLIHOST_SSH_PORT:-}"
  local identity_file="${CLIHOST_SSH_IDENTITY_FILE:-}"
  local host_home="${HOME:-}"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      pull|push)
        [ -z "${command}" ] || die "multiple subcommands provided"
        command="$1"
        shift
        ;;
      --apply)
        apply="true"
        shift
        ;;
      --allow-delete)
        allow_delete="true"
        shift
        ;;
      --target)
        [ "$#" -ge 2 ] || die "--target requires a value"
        target="$2"
        shift 2
        ;;
      --target=*)
        target="${1#--target=}"
        shift
        ;;
      --ssh-port|--port)
        [ "$#" -ge 2 ] || die "$1 requires a value"
        ssh_port="$2"
        shift 2
        ;;
      --ssh-port=*|--port=*)
        ssh_port="${1#*=}"
        shift
        ;;
      --identity-file|-i)
        [ "$#" -ge 2 ] || die "$1 requires a value"
        identity_file="$2"
        shift 2
        ;;
      --identity-file=*)
        identity_file="${1#--identity-file=}"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        usage
        die "unknown argument: $1"
        ;;
    esac
  done

  [ -n "${command}" ] || { usage; die "missing subcommand: pull or push"; }
  [ -n "${target}" ] || die "set --target or CLIHOST_SSH_TARGET"
  # Reject an option-like target (leading '-'). printf %q protects against SHELL
  # injection, but not OPTION injection: ssh/rsync parse a leading-dash argument
  # as a flag, so a target like `-oProxyCommand=<cmd>` runs <cmd> LOCALLY on the
  # host during preflight — before any mount/symlink guard. Same class as the
  # dashboard ProxyCommand issue (#85). Guard the target, and pass `--` before the
  # host in ssh and before the positional operands in rsync (see below).
  case "${target}" in
    -*) die "SSH target must not start with '-' (got: ${target})" ;;
  esac
  case "${ssh_port}" in
    ""|*[!0-9]*) [ -z "${ssh_port}" ] || die "SSH port must be numeric: ${ssh_port}" ;;
  esac
  [ -z "${identity_file}" ] || [ -f "${identity_file}" ] || die "identity file not found: ${identity_file}"

  local backup_stamp
  backup_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
  local local_backup_root="${host_home}/.clihost-sync-backups"
  local remote_backup_root="${REMOTE_HOME}/.clihost-sync-backups"

  preflight_local "${host_home}" "${local_backup_root}"

  local -a ssh_args=(ssh -o BatchMode=yes)
  if [ -n "${ssh_port}" ]; then
    ssh_args+=(-p "${ssh_port}")
  fi
  if [ -n "${identity_file}" ]; then
    ssh_args+=(-i "${identity_file}")
  fi

  run_remote_preflight "${target}" "${ssh_args[@]}"

  local ssh_remote_shell
  ssh_remote_shell="$(quote_join "${ssh_args[@]}")"

  local -a rsync_args=(
    -a
    --itemize-changes
    --human-readable
    --no-links
    --delay-updates
    "--include=/.gitconfig"
    "--include=/.config/"
    "--include=/.config/gh/***"
    "--exclude=*"
    -e "${ssh_remote_shell}"
  )

  if [ "${apply}" != "true" ]; then
    rsync_args+=(--dry-run)
  fi
  if [ "${apply}" = "true" ]; then
    rsync_args+=(--backup)
    if [ "${command}" = "pull" ]; then
      rsync_args+=("--backup-dir=${remote_backup_root}/${backup_stamp}")
    else
      guard_local_path "${host_home}" "${local_backup_root}/${backup_stamp}"
      rsync_args+=("--backup-dir=${local_backup_root}/${backup_stamp}")
    fi
  fi
  if [ "${allow_delete}" = "true" ]; then
    rsync_args+=(--delete)
  fi

  local source
  local destination
  local mode="dry-run"
  if [ "${apply}" = "true" ]; then
    mode="apply"
  fi
  if [ "${command}" = "pull" ]; then
    source="${host_home%/}/"
    destination="${target}:${REMOTE_HOME}/"
    echo "Pulling ${SYNC_LABEL} from host to ${target}:${REMOTE_HOME} (${mode})"
  else
    source="${target}:${REMOTE_HOME}/"
    destination="${host_home%/}/"
    echo "Pushing ${SYNC_LABEL} from ${target}:${REMOTE_HOME} to host (${mode})"
  fi

  # `--` ends rsync option parsing so a `-`-leading source/dest (option injection,
  # e.g. via a hostile target) is treated as a path operand, not a flag.
  rsync "${rsync_args[@]}" -- "${source}" "${destination}"
}

main "$@"
