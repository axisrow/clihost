#!/bin/bash
set -euo pipefail

REMOTE_HOME="/home/hapi"
SYNC_LABEL="~/.gitconfig and ~/.config/gh"
SSH_SYNC_LABEL="~/.ssh"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# Emit the shared remote prelude, then a per-action body (read from this
# function's stdin), as one script on stdout ready to pipe into `ssh ... bash
# -s`. The remote heredocs are quoted (<<'PRELUDE' / <<'REMOTE'), so this text
# is NOT expanded locally — it runs on the container.
#
# Defining the symlink guards ONCE here is the #101/#10 fix: `guard_remote_path`
# and `guard_remote_tree_no_symlinks` were byte-identical triplicates (one local
# pair plus one copy in each of the two remote heredocs), so hardening one copy
# silently bypassed the others — exactly the class of bug caught 3× before
# (#88/#90/#95). Now the two remote payloads share this single definition.
#
# Contract for callers: pass "${REMOTE_HOME}" as $1 of `bash -s` (positionally
# identical in both payloads) so `remote_home` resolves; the prelude reads only
# $1 and does not assume a fixed $# (payloads pass extra positional args). After
# the prelude, `die`, `remote_home`, and both guards are in scope for the body.
emit_remote_prelude() {
  cat <<'PRELUDE'
set -euo pipefail

die() {
  echo "ERROR: $*" >&2
  exit 1
}

remote_home="$1"

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
PRELUDE
  cat
}

usage() {
  cat >&2 <<'EOF'
Usage:
  clihost-sync.sh pull [--target user@host] [--ssh-port port] [--identity-file path] [--apply] [--allow-delete]
  clihost-sync.sh push [--target user@host] [--ssh-port port] [--identity-file path] [--apply] [--allow-delete]
  clihost-sync.sh ssh [pull|push] [--target user@host] [--ssh-port port] [--identity-file path] [--include-private-keys] [--apply] [--allow-delete]

Direction:
  pull  copies the safe host config subset into the clihost container.
  push  copies the same safe subset from the clihost container back to the host.
  ssh   copies ~/.ssh separately; default direction is pull (host to container).

Safety:
  Dry-run is the default. Use --apply for a real rsync run.
  --delete is never used unless --allow-delete is passed explicitly.
  The remote home must be mounted exactly at /home/hapi.
  ssh sync includes only known_hosts, *.pub, and config by default.
  Private keys require --include-private-keys and secure source permissions.

Target:
  Set --target or CLIHOST_SSH_TARGET to the SSH destination, for example:
    CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 clihost-sync.sh pull
    CLIHOST_SSH_TARGET=hapi@127.0.0.1 CLIHOST_SSH_PORT=2222 clihost-sync.sh ssh
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

reject_option_like() {
  local label="$1"
  local value="$2"

  case "${value}" in
    -*) die "${label} must not start with '-' (got: ${value})" ;;
  esac
}

reject_control_chars() {
  local label="$1"
  local value="$2"

  case "${value}" in
    *$'\n'*|*$'\r'*) die "${label} must not contain control characters" ;;
  esac
  if LC_ALL=C printf '%s' "${value}" | grep -q '[[:cntrl:]]'; then
    die "${label} must not contain control characters"
  fi
}

path_mode() {
  local path="$1"

  if stat -c '%a' "${path}" >/dev/null 2>&1; then
    stat -c '%a' "${path}"
  else
    stat -f '%Lp' "${path}"
  fi
}

reject_group_or_other_permissions() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local mode
  local mode_value

  mode="$(path_mode "${path}")" || die "cannot inspect permissions for ${path}"
  mode_value=$((8#${mode}))
  if (( mode_value & 077 )); then
    die "${label} permissions must be ${expected} or stricter; got ${mode} at ${path}"
  fi
}

is_private_key_file() {
  local path="$1"

  [ -f "${path}" ] || return 1
  LC_ALL=C tr -d '\r' < "${path}" 2>/dev/null \
    | grep -Eq -- '^-+BEGIN [A-Z0-9 ]*PRIVATE KEY-+$'
}

validate_default_public_ssh_material() {
  local ssh_dir="$1"
  local path

  for path in "${ssh_dir}/known_hosts" "${ssh_dir}/config" "${ssh_dir}"/*.pub; do
    [ -e "${path}" ] || continue
    [ -f "${path}" ] || continue
    if is_private_key_file "${path}"; then
      die "default SSH public material contains private key block: ${path}"
    fi
  done
}

validate_private_key_permissions() {
  local ssh_dir="$1"
  local path

  [ -d "${ssh_dir}" ] || return 0
  while IFS= read -r -d '' path; do
    if is_private_key_file "${path}"; then
      reject_group_or_other_permissions "${path}" "600" "private key"
    fi
  done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
}

private_key_include_rule() {
  local rel="$1"
  local rule

  reject_control_chars "SSH private key filename" "${rel}"
  case "${rel}" in
    *'*'*|*'?'*|*'['*|*']'*)
      die "SSH private key filename must not contain rsync filter metacharacters: ${rel}"
      ;;
  esac
  rule="--include=/${rel}"
  case "${rule}" in
    --include=/*) printf '%s\n' "${rule}" ;;
    -*) die "generated rsync include rule must not start with '-' (got: ${rule})" ;;
    *) die "invalid generated rsync include rule: ${rule}" ;;
  esac
}

collect_local_private_key_includes() {
  local ssh_dir="$1"
  local path
  local rel

  [ -d "${ssh_dir}" ] || return 0
  while IFS= read -r -d '' path; do
    if is_private_key_file "${path}"; then
      rel="${path#${ssh_dir}/}"
      private_key_include_rule "${rel}"
    fi
  done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
}

preflight_local_ssh_source() {
  local host_home="$1"
  local include_private_keys="$2"
  local ssh_dir="${host_home}/.ssh"

  [ -n "${host_home}" ] || die "HOME is empty; refusing to sync"
  [ -d "${host_home}" ] || die "HOME '${host_home}' is not a directory"
  guard_local_path "${host_home}" "${ssh_dir}"
  [ -d "${ssh_dir}" ] || die "source SSH directory not found: ${ssh_dir}"
  reject_group_or_other_permissions "${ssh_dir}" "700" ".ssh directory"
  guard_local_tree_no_symlinks "${ssh_dir}"
  validate_private_key_permissions "${ssh_dir}"
  if [ "${include_private_keys}" != "true" ]; then
    validate_default_public_ssh_material "${ssh_dir}"
  fi
}

preflight_local_ssh_destination() {
  local host_home="$1"
  local ssh_dir="${host_home}/.ssh"

  [ -n "${host_home}" ] || die "HOME is empty; refusing to sync"
  [ -d "${host_home}" ] || die "HOME '${host_home}' is not a directory"
  guard_local_path "${host_home}" "${ssh_dir}"
  if [ -e "${ssh_dir}" ]; then
    [ -d "${ssh_dir}" ] || die "${ssh_dir} exists but is not a directory"
    guard_local_tree_no_symlinks "${ssh_dir}"
  fi
}

fix_local_ssh_permissions() {
  local host_home="$1"
  local ssh_dir="${host_home}/.ssh"
  local path

  [ -e "${ssh_dir}" ] || return 0
  guard_local_path "${host_home}" "${ssh_dir}"
  [ -d "${ssh_dir}" ] || die "${ssh_dir} exists but is not a directory"
  guard_local_tree_no_symlinks "${ssh_dir}"
  chmod 700 "${ssh_dir}"
  while IFS= read -r -d '' path; do
    if is_private_key_file "${path}"; then
      chmod 600 "${path}"
    fi
  done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
}

append_generated_include_rule() {
  local rule="$1"

  reject_control_chars "generated rsync include rule" "${rule}"
  case "${rule}" in
    --include=/*)
      case "${rule#--include=/}" in
        *'*'*|*'?'*|*'['*|*']'*)
          die "generated rsync include rule must not contain rsync filter metacharacters: ${rule}"
          ;;
      esac
      rsync_args+=("${rule}")
      ;;
    -*) die "generated rsync include rule must not start with '-' (got: ${rule})" ;;
    *) die "invalid generated rsync include rule: ${rule}" ;;
  esac
}

append_generated_include_rules() {
  local include_output="$1"
  local include_rule

  [ -n "${include_output}" ] || return 0
  while IFS= read -r include_rule || [ -n "${include_rule}" ]; do
    [ -n "${include_rule}" ] || continue
    append_generated_include_rule "${include_rule}"
  done <<< "${include_output}"
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

  # The shared guard prelude (die + remote_home + guard_remote_*) is prepended
  # by emit_remote_prelude; this body only adds the mount-preflight checks and
  # the per-path guard calls. mounts_file is $2 here (matching the extra arg).
  emit_remote_prelude <<'REMOTE' | "${ssh_args[@]}" -- "${target}" bash -s -- "${REMOTE_HOME}" "/proc/mounts"
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

guard_remote_path "${remote_home}/.gitconfig"
guard_remote_path "${remote_home}/.config"
guard_remote_path "${remote_home}/.config/gh"
guard_remote_path "${backup_root}"
guard_remote_tree_no_symlinks "${remote_home}/.config/gh"
guard_remote_tree_no_symlinks "${backup_root}"
REMOTE
}

run_remote_ssh_helper() {
  local action="$1"
  local target="$2"
  local direction="$3"
  local include_private_keys="$4"
  shift 4
  local -a ssh_args=("$@")

  # Shared guard prelude (die + remote_home + guard_remote_*) is prepended by
  # emit_remote_prelude; this body only adds the ssh-helper-specific args and
  # logic. Positional args after $1 (remote_home) match the extra values passed.
  emit_remote_prelude <<'REMOTE' | "${ssh_args[@]}" -- "${target}" bash -s -- "${REMOTE_HOME}" "/proc/mounts" "${action}" "${direction}" "${include_private_keys}"
_mounts_file="$2"
action="$3"
direction="$4"
include_private_keys="$5"
ssh_dir="${remote_home}/.ssh"

path_mode() {
  local path="$1"

  if stat -c '%a' "${path}" >/dev/null 2>&1; then
    stat -c '%a' "${path}"
  else
    stat -f '%Lp' "${path}"
  fi
}

reject_control_chars() {
  local label="$1"
  local value="$2"

  case "${value}" in
    *$'\n'*|*$'\r'*) die "${label} must not contain control characters" ;;
  esac
  if LC_ALL=C printf '%s' "${value}" | grep -q '[[:cntrl:]]'; then
    die "${label} must not contain control characters"
  fi
}

reject_group_or_other_permissions() {
  local path="$1"
  local expected="$2"
  local label="$3"
  local mode
  local mode_value

  mode="$(path_mode "${path}")" || die "cannot inspect permissions for ${path}"
  mode_value=$((8#${mode}))
  if (( mode_value & 077 )); then
    die "${label} permissions must be ${expected} or stricter; got ${mode} at ${path}"
  fi
}

is_private_key_file() {
  local path="$1"

  [ -f "${path}" ] || return 1
  LC_ALL=C tr -d '\r' < "${path}" 2>/dev/null \
    | grep -Eq -- '^-+BEGIN [A-Z0-9 ]*PRIVATE KEY-+$'
}

validate_default_public_ssh_material() {
  local path

  for path in "${ssh_dir}/known_hosts" "${ssh_dir}/config" "${ssh_dir}"/*.pub; do
    [ -e "${path}" ] || continue
    [ -f "${path}" ] || continue
    if is_private_key_file "${path}"; then
      die "default SSH public material contains private key block: ${path}"
    fi
  done
}

validate_private_key_permissions() {
  local path

  [ -d "${ssh_dir}" ] || return 0
  while IFS= read -r -d '' path; do
    if is_private_key_file "${path}"; then
      reject_group_or_other_permissions "${path}" "600" "private key"
    fi
  done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
}

private_key_include_rule() {
  local rel="$1"
  local rule

  reject_control_chars "SSH private key filename" "${rel}"
  case "${rel}" in
    *'*'*|*'?'*|*'['*|*']'*)
      die "SSH private key filename must not contain rsync filter metacharacters: ${rel}"
      ;;
  esac
  rule="--include=/${rel}"
  case "${rule}" in
    --include=/*) printf '%s\n' "${rule}" ;;
    -*) die "generated rsync include rule must not start with '-' (got: ${rule})" ;;
    *) die "invalid generated rsync include rule: ${rule}" ;;
  esac
}

print_private_key_includes() {
  local path
  local rel

  [ -d "${ssh_dir}" ] || return 0
  while IFS= read -r -d '' path; do
    if is_private_key_file "${path}"; then
      rel="${path#${ssh_dir}/}"
      private_key_include_rule "${rel}"
    fi
  done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
}

guard_remote_path "${ssh_dir}"
case "${action}" in
  preflight)
    if [ "${direction}" = "push" ]; then
      [ -d "${ssh_dir}" ] || die "source SSH directory not found: ${ssh_dir}"
      reject_group_or_other_permissions "${ssh_dir}" "700" ".ssh directory"
      guard_remote_tree_no_symlinks "${ssh_dir}"
      validate_private_key_permissions
      if [ "${include_private_keys}" != "true" ]; then
        validate_default_public_ssh_material
      fi
    else
      if [ -e "${ssh_dir}" ]; then
        [ -d "${ssh_dir}" ] || die "${ssh_dir} exists but is not a directory"
        guard_remote_tree_no_symlinks "${ssh_dir}"
      fi
    fi
    ;;
  collect-private-includes)
    [ -d "${ssh_dir}" ] || exit 0
    guard_remote_tree_no_symlinks "${ssh_dir}"
    print_private_key_includes
    ;;
  fix-permissions)
    [ -e "${ssh_dir}" ] || exit 0
    [ -d "${ssh_dir}" ] || die "${ssh_dir} exists but is not a directory"
    guard_remote_tree_no_symlinks "${ssh_dir}"
    chmod 700 "${ssh_dir}"
    while IFS= read -r -d '' path; do
      if is_private_key_file "${path}"; then
        chmod 600 "${path}"
      fi
    done < <(find "${ssh_dir}" -type f -print0 2>/dev/null)
    ;;
  *)
    die "unknown remote ssh action: ${action}"
    ;;
esac
REMOTE
}

run_remote_ssh_preflight() {
  local target="$1"
  local direction="$2"
  local include_private_keys="$3"
  shift 3

  run_remote_ssh_helper "preflight" "${target}" "${direction}" "${include_private_keys}" "$@"
}

collect_remote_private_key_includes() {
  local target="$1"
  shift

  run_remote_ssh_helper "collect-private-includes" "${target}" "push" "true" "$@"
}

fix_remote_ssh_permissions() {
  local target="$1"
  shift

  run_remote_ssh_helper "fix-permissions" "${target}" "pull" "false" "$@"
}

main() {
  local command=""
  local apply="false"
  local allow_delete="false"
  local ssh_direction="pull"
  local ssh_direction_set="false"
  local include_private_keys="false"
  local target="${CLIHOST_SSH_TARGET:-}"
  local ssh_port="${CLIHOST_SSH_PORT:-}"
  local identity_file="${CLIHOST_SSH_IDENTITY_FILE:-}"
  local host_home="${HOME:-}"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      pull|push)
        if [ "${command}" = "ssh" ]; then
          [ "${ssh_direction_set}" = "false" ] || die "multiple ssh directions provided"
          ssh_direction="$1"
          ssh_direction_set="true"
        else
          [ -z "${command}" ] || die "multiple subcommands provided"
          command="$1"
        fi
        shift
        ;;
      ssh)
        [ -z "${command}" ] || die "multiple subcommands provided"
        command="ssh"
        shift
        ;;
      --direction)
        [ "$#" -ge 2 ] || die "--direction requires a value"
        case "$2" in
          pull|push) ssh_direction="$2" ;;
          *) die "--direction must be pull or push" ;;
        esac
        ssh_direction_set="true"
        shift 2
        ;;
      --direction=*)
        case "${1#--direction=}" in
          pull|push) ssh_direction="${1#--direction=}" ;;
          *) die "--direction must be pull or push" ;;
        esac
        ssh_direction_set="true"
        shift
        ;;
      --include-private-keys)
        include_private_keys="true"
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

  [ -n "${command}" ] || { usage; die "missing subcommand: pull, push, or ssh"; }
  [ -n "${target}" ] || die "set --target or CLIHOST_SSH_TARGET"
  # Reject an option-like target (leading '-'). printf %q protects against SHELL
  # injection, but not OPTION injection: ssh/rsync parse a leading-dash argument
  # as a flag, so a target like `-oProxyCommand=<cmd>` runs <cmd> LOCALLY on the
  # host during preflight — before any mount/symlink guard. Same class as the
  # dashboard ProxyCommand issue (#85). Guard the target, and pass `--` before the
  # host in ssh and before the positional operands in rsync (see below).
  reject_option_like "SSH target" "${target}"
  case "${ssh_port}" in
    ""|*[!0-9]*) [ -z "${ssh_port}" ] || die "SSH port must be numeric: ${ssh_port}" ;;
  esac
  [ -z "${identity_file}" ] || reject_option_like "identity file" "${identity_file}"
  [ -z "${identity_file}" ] || [ -f "${identity_file}" ] || die "identity file not found: ${identity_file}"

  local backup_stamp
  backup_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
  local local_backup_root="${host_home}/.clihost-sync-backups"
  local remote_backup_root="${REMOTE_HOME}/.clihost-sync-backups"

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
  )

  if [ "${command}" = "ssh" ]; then
    if [ "${ssh_direction}" = "pull" ]; then
      preflight_local_ssh_source "${host_home}" "${include_private_keys}"
    else
      preflight_local_ssh_destination "${host_home}"
    fi
    run_remote_ssh_preflight "${target}" "${ssh_direction}" "${include_private_keys}" "${ssh_args[@]}"
    rsync_args+=(
      "--include=/known_hosts"
      "--include=/*.pub"
      "--include=/config"
    )
    if [ "${include_private_keys}" = "true" ]; then
      echo "WARNING: --include-private-keys selected; private key material will be copied across the SSH relay and leave its source machine. ~/.ssh stays outside the default sync because of #17 risk B (relay/blast-radius)."
      local include_output
      if [ "${ssh_direction}" = "pull" ]; then
        if ! include_output="$(collect_local_private_key_includes "${host_home}/.ssh")"; then
          exit 1
        fi
      else
        if ! include_output="$(collect_remote_private_key_includes "${target}" "${ssh_args[@]}")"; then
          exit 1
        fi
      fi
      append_generated_include_rules "${include_output}"
    fi
    rsync_args+=("--exclude=*")
  else
    preflight_local "${host_home}" "${local_backup_root}"
    rsync_args+=(
      "--include=/.gitconfig"
      "--include=/.config/"
      "--include=/.config/gh/***"
      "--exclude=*"
    )
  fi
  rsync_args+=(-e "${ssh_remote_shell}")

  if [ "${apply}" != "true" ]; then
    rsync_args+=(--dry-run)
  fi
  if [ "${apply}" = "true" ]; then
    rsync_args+=(--backup)
    if { [ "${command}" = "pull" ]; } || { [ "${command}" = "ssh" ] && [ "${ssh_direction}" = "pull" ]; }; then
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
  local transfer_direction="${command}"
  if [ "${apply}" = "true" ]; then
    mode="apply"
  fi
  if [ "${command}" = "ssh" ]; then
    transfer_direction="${ssh_direction}"
  fi
  if [ "${command}" = "ssh" ] && [ "${transfer_direction}" = "pull" ]; then
    source="${host_home%/}/.ssh/"
    destination="${target}:${REMOTE_HOME}/.ssh/"
    echo "Syncing ${SSH_SYNC_LABEL} from host to ${target}:${REMOTE_HOME}/.ssh (${mode})"
  elif [ "${command}" = "ssh" ]; then
    source="${target}:${REMOTE_HOME}/.ssh/"
    destination="${host_home%/}/.ssh/"
    echo "Syncing ${SSH_SYNC_LABEL} from ${target}:${REMOTE_HOME}/.ssh to host (${mode})"
  elif [ "${command}" = "pull" ]; then
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

  if [ "${apply}" = "true" ] && [ "${command}" = "ssh" ]; then
    if [ "${transfer_direction}" = "pull" ]; then
      fix_remote_ssh_permissions "${target}" "${ssh_args[@]}"
    else
      fix_local_ssh_permissions "${host_home}"
    fi
  fi
}

main "$@"
