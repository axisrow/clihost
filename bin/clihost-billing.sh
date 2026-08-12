#!/bin/bash
set -euo pipefail

# Host-side usage accounting for clihost apps on a Dokku host (issue #37).
#
# This is a HOST-ONLY tool (like claude-auth-snapshot-host.sh): it is NOT copied
# into the image — inside the container it is meaningless and unsafe (no access
# to docker.sock). It lives on the Dokku host (e.g. /home/dokku/bin/) and is run
# by the `dokku` user, who is in the `docker` group and can therefore call
# `docker stats/ps -s/inspect` WITHOUT sudo.
#
# Subcommands (PR1 + PR2 — accounting + report):
#   collect     take one sample of every clihost-* container (cron-driven).
#   cron-line   print a ready-to-paste crontab line (operator installs it).
#   report      render an aggregated usage table (per app).
#   raw         emit aggregated rows as JSON (machine-readable).
#   diagnose    inspect the current container state and print a verdict.
#   restart     safely restart one clihost app (dry-run by default).
#   help        usage.
#
# Storage is append-only JSONL under ${CLIHOST_BILLING_DIR:=/home/dokku/.clihost-billing}:
#   samples/YYYY-MM.jsonl   monthly-rotated samples (one JSON object per line)
#   state/collect.lock      flock guard so overlapping cron runs don't interleave
#   state/last-collect.json last sample metadata (for the "collector down" warning)
#
# Pure parsing/aggregation lives in bin/clihost_billing_lib.py so it is unit
# tested without root or Docker; this dispatcher owns all docker calls and I/O.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BILLING_LIB="${SCRIPT_DIR}/clihost_billing_lib.py"

: "${CLIHOST_BILLING_DIR:=/home/dokku/.clihost-billing}"
: "${CLIHOST_BILLING_INTERVAL:=300}"
: "${CLIHOST_APP_PREFIX:=clihost-}"

SAMPLES_DIR="${CLIHOST_BILLING_DIR}/samples"
STATE_DIR="${CLIHOST_BILLING_DIR}/state"
LOCK_FILE="${STATE_DIR}/collect.lock"
LAST_COLLECT_FILE="${STATE_DIR}/last-collect.json"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage:
  clihost-billing.sh collect            take one sample of all clihost-* containers
  clihost-billing.sh cron-line          print a crontab line to install the collector
  clihost-billing.sh report [--json]    aggregated usage table (per app)
  clihost-billing.sh raw                aggregated rows as JSON (alias for report --json)
  clihost-billing.sh diagnose [--app] APP
                                            inspect APP.web.1 (read-only)
  clihost-billing.sh restart APP [--apply] [--yes]
                                            restart APP (dry-run by default)
  clihost-billing.sh help               this message

Environment:
  CLIHOST_BILLING_DIR       storage root (default: /home/dokku/.clihost-billing)
  CLIHOST_BILLING_INTERVAL  collector cadence in seconds (default: 300); used as
                            the gap-detection base (dt > 2.5x interval = server down)
  CLIHOST_APP_PREFIX        container/app name prefix to account (default: clihost-)
EOF
}

require_python() {
  command -v python3 >/dev/null 2>&1 || die "python3 not found"
  [ -f "${BILLING_LIB}" ] || die "billing library not found: ${BILLING_LIB}"
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker CLI not found"
}

validate_app_name() {
  local app="$1"
  [[ "${app}" =~ ^clihost-[a-z0-9_-]+$ ]] \
    || die "invalid app name '${app}'; expected ^clihost-[a-z0-9_-]+$"
}

require_app_container() {
  local app="$1"
  local container="${app}.web.1"

  validate_app_name "${app}"
  require_docker
  docker ps --format '{{.Names}}' | grep -Fqx -- "${container}" \
    || die "container is not running or not found in docker ps: ${container}"
}

ensure_dirs() {
  mkdir -p "${SAMPLES_DIR}" "${STATE_DIR}"
}

current_month() {
  date -u '+%Y-%m'
}

iso_now() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

# collect: sample every clihost-* container once and append JSONL lines.
cmd_collect() {
  [ "$#" -eq 0 ] || die "collect accepts no arguments"
  require_python
  require_docker
  ensure_dirs

  # Serialize concurrent collectors (cron overlap) with a non-blocking flock.
  exec 9>"${LOCK_FILE}"
  if ! flock -n 9; then
    echo "another collect run holds the lock; skipping" >&2
    return 0
  fi

  local stats_json ps_json inspect_json ts sample_file
  ts="$(iso_now)"
  sample_file="${SAMPLES_DIR}/$(current_month).jsonl"

  # docker stats only lists RUNNING containers; docker ps -a lists all (the
  # source of truth for the container set). inspect gives restart_count/status.
  # Each may be empty (no containers yet) — that is not an error.
  stats_json="$(docker stats --no-stream --format '{{json .}}' 2>/dev/null || true)"
  ps_json="$(docker ps -a -s --format '{{json .}}' 2>/dev/null || true)"
  inspect_json="$(docker ps -a --filter "name=${CLIHOST_APP_PREFIX}" --format '{{.Names}}' 2>/dev/null \
    | while IFS= read -r name; do
        [ -n "${name}" ] || continue
        docker inspect --format \
          '{"name":{{printf "%q" .Name}},"restart_count":{{.RestartCount}},"status":{{printf "%q" .State.Status}},"exit_code":{{.State.ExitCode}},"oom_killed":{{.State.OOMKilled}}}' \
          "${name}" 2>/dev/null || true
      done)"

  local out
  out="$(
    CLIHOST_TS="${ts}" \
    CLIHOST_PREFIX="${CLIHOST_APP_PREFIX}" \
    CLIHOST_STATS_JSON="${stats_json}" \
    CLIHOST_PS_JSON="${ps_json}" \
    CLIHOST_INSPECT_JSON="${inspect_json}" \
    CLIHOST_BILLING_LIB="${BILLING_LIB}" \
    python3 <<'PY'
import json
import os
import sys

lib_path = os.environ["CLIHOST_BILLING_LIB"]
lib_dir = os.path.dirname(lib_path)
sys.path.insert(0, lib_dir)
import clihost_billing_lib as lib  # noqa: E402

ts = os.environ["CLIHOST_TS"]
prefix = os.environ["CLIHOST_PREFIX"]


def parse_json_lines(text):
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


stats_rows = parse_json_lines(os.environ.get("CLIHOST_STATS_JSON", ""))
ps_rows = parse_json_lines(os.environ.get("CLIHOST_PS_JSON", ""))
inspect_rows = parse_json_lines(os.environ.get("CLIHOST_INSPECT_JSON", ""))


def strip_slash(name):
    # docker inspect .Name has a leading slash ("/clihost-axisrow.web.1").
    return name[1:] if name.startswith("/") else name


def app_of(container):
    # clihost-axisrow.web.1 -> clihost-axisrow ; strip the .web.N suffix.
    base = container
    dot = base.find(".")
    return base[:dot] if dot != -1 else base


# Index stats and ps by container name.
stats_by_name = {}
for row in stats_rows:
    name = row.get("Name") or row.get("Container") or ""
    if name:
        stats_by_name[name] = row

ps_by_name = {}
for row in ps_rows:
    names = row.get("Names") or ""
    for name in names.split(","):
        name = name.strip()
        if name:
            ps_by_name[name] = row

inspect_by_name = {}
for row in inspect_rows:
    name = strip_slash(row.get("name") or "")
    if name:
        inspect_by_name[name] = row

# The container set is every clihost-* container in `docker ps -a`.
lines = []
for name, ps_row in sorted(ps_by_name.items()):
    if not name.startswith(prefix):
        continue
    stats_row = stats_by_name.get(name, {})
    inspect_row = inspect_by_name.get(name, {})

    status = (inspect_row.get("status") or ps_row.get("State") or "").lower()
    running = status == "running"

    cpu_perc = lib.parse_cpu_perc(stats_row.get("CPUPerc")) if running else 0.0
    mem_used, _mem_limit = lib.parse_mem_usage(stats_row.get("MemUsage")) if running else (0, 0)
    rootfs_bytes, virtual_bytes = lib.parse_size_field(ps_row.get("Size"))
    image_bytes = max(virtual_bytes - rootfs_bytes, 0)

    sample = {
        "ts": ts,
        "app": app_of(name),
        "container": name,
        "running": running,
        "status": status,
        "cpu_perc": cpu_perc,
        "mem_bytes": mem_used,
        "rootfs_bytes": rootfs_bytes,
        "image_bytes": image_bytes,
        "restart_count": inspect_row.get("restart_count", 0),
        "oom_killed": bool(inspect_row.get("oom_killed", False)),
        "exit_code": inspect_row.get("exit_code", 0),
    }
    lines.append(json.dumps(sample, sort_keys=True))

sys.stdout.write("\n".join(lines))
if lines:
    sys.stdout.write("\n")
PY
  )"

  # Append atomically-ish: write via >> (single write per line is small enough
  # to be atomic on local fs; the flock already serializes collectors).
  if [ -n "${out}" ]; then
    printf '%s' "${out}" >> "${sample_file}"
  fi

  # Record last-collect metadata for the "collector down" warning in report.
  printf '{"ts":%s,"samples":%s}\n' \
    "\"${ts}\"" \
    "$(printf '%s' "${out}" | grep -c . || true)" \
    > "${LAST_COLLECT_FILE}"

  local n
  n="$(printf '%s' "${out}" | grep -c . || true)"
  echo "collected ${n} sample(s) at ${ts} -> ${sample_file}"
}

# cron-line: print a crontab line the operator installs manually (no sudo, we do
# NOT auto-install into anyone's crontab).
cmd_cron_line() {
  [ "$#" -eq 0 ] || die "cron-line accepts no arguments"
  local self minutes
  self="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"
  # Default cadence 5 min; keep in step with CLIHOST_BILLING_INTERVAL=300.
  minutes=$(( CLIHOST_BILLING_INTERVAL / 60 ))
  [ "${minutes}" -ge 1 ] || minutes=1
  cat <<EOF
# clihost billing collector (issue #37) — paste into: crontab -e  (as the dokku user)
*/${minutes} * * * * ${self} collect >> ${CLIHOST_BILLING_DIR}/state/collect.log 2>&1
EOF
}

# Gather every samples/*.jsonl file (all months) for aggregation.
list_sample_files() {
  [ -d "${SAMPLES_DIR}" ] || return 0
  find "${SAMPLES_DIR}" -maxdepth 1 -type f -name '*.jsonl' | sort
}

cmd_report() {
  local want_json="false"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --json) want_json="true"; shift ;;
      --) shift; break ;;
      -*) die "unknown option: $1" ;;
      *) die "report takes no operands" ;;
    esac
  done
  require_python

  local files
  files="$(list_sample_files)"
  if [ -z "${files}" ]; then
    if [ "${want_json}" = "true" ]; then
      echo "[]"
    else
      echo "no samples yet under ${SAMPLES_DIR}; run 'collect' (or install the cron-line)." >&2
    fi
    return 0
  fi

  CLIHOST_WANT_JSON="${want_json}" \
  CLIHOST_INTERVAL="${CLIHOST_BILLING_INTERVAL}" \
  CLIHOST_LAST_COLLECT="${LAST_COLLECT_FILE}" \
  CLIHOST_BILLING_LIB="${BILLING_LIB}" \
  CLIHOST_SAMPLE_FILES="${files}" \
  python3 <<'PY'
import json
import os
import sys
import time

lib_path = os.environ["CLIHOST_BILLING_LIB"]
sys.path.insert(0, os.path.dirname(lib_path))
import clihost_billing_lib as lib  # noqa: E402

want_json = os.environ.get("CLIHOST_WANT_JSON") == "true"
interval = int(os.environ.get("CLIHOST_INTERVAL") or lib.DEFAULT_INTERVAL_SECONDS)

samples = []
for path in os.environ.get("CLIHOST_SAMPLE_FILES", "").splitlines():
    path = path.strip()
    if not path:
        continue
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for sample in lib.iter_samples(handle):
                samples.append(sample)
    except OSError:
        continue

rows = lib.aggregate(samples, interval_seconds=interval)
rows = lib.apply_rates(rows, rates=None)  # stage-2 hook: no rates.json yet.

# Warn if the newest sample is older than 2x the interval (collector likely
# stopped) — mirrors the plan's verification requirement.
warning = None
newest = None
for row in rows:
    epoch = lib.parse_ts(row.get("last_ts"))
    if epoch is not None and (newest is None or epoch > newest):
        newest = epoch
if newest is not None:
    age = time.time() - newest
    if age > 2 * interval:
        warning = ("last sample is %d s old (> 2x interval %d s); "
                   "collector likely not running" % (int(age), interval))

if want_json:
    print(json.dumps({"rows": rows, "warning": warning}, indent=2, sort_keys=True))
else:
    print(lib.format_report_table(rows))
    if warning:
        sys.stderr.write("WARNING: %s\n" % warning)
PY
}

# diagnose: read Docker state only; never restart or otherwise mutate it.
cmd_diagnose() {
  local app=""
  case "$#:${1:-}" in
    1:*) app="$1" ;;
    2:--app) app="$2" ;;
    *) die "diagnose requires [--app] APP" ;;
  esac

  validate_app_name "${app}"
  require_docker
  command -v python3 >/dev/null 2>&1 || die "python3 not found"

  local container="${app}.web.1"
  local restart_count status exit_code oom_killed state_error started_at finished_at
  restart_count="$(docker inspect --format '{{.RestartCount}}' -- "${container}")"
  status="$(docker inspect --format '{{.State.Status}}' -- "${container}")"
  exit_code="$(docker inspect --format '{{.State.ExitCode}}' -- "${container}")"
  oom_killed="$(docker inspect --format '{{.State.OOMKilled}}' -- "${container}")"
  state_error="$(docker inspect --format '{{.State.Error}}' -- "${container}")"
  started_at="$(docker inspect --format '{{.State.StartedAt}}' -- "${container}")"
  finished_at="$(docker inspect --format '{{.State.FinishedAt}}' -- "${container}")"

  CLIHOST_DIAG_CONTAINER="${container}" \
  CLIHOST_DIAG_RESTART_COUNT="${restart_count}" \
  CLIHOST_DIAG_STATUS="${status}" \
  CLIHOST_DIAG_EXIT_CODE="${exit_code}" \
  CLIHOST_DIAG_OOM_KILLED="${oom_killed}" \
  CLIHOST_DIAG_ERROR="${state_error}" \
  CLIHOST_DIAG_STARTED_AT="${started_at}" \
  CLIHOST_DIAG_FINISHED_AT="${finished_at}" \
  python3 <<'PY'
import os

restart_count = int(os.environ["CLIHOST_DIAG_RESTART_COUNT"])
status = os.environ["CLIHOST_DIAG_STATUS"]
oom_killed = os.environ["CLIHOST_DIAG_OOM_KILLED"].lower() == "true"

print("Container: " + os.environ["CLIHOST_DIAG_CONTAINER"])
print("RestartCount: " + str(restart_count))
print("State.Status: " + status)
print("State.ExitCode: " + os.environ["CLIHOST_DIAG_EXIT_CODE"])
print("State.OOMKilled: " + str(oom_killed).lower())
print("State.Error: " + os.environ["CLIHOST_DIAG_ERROR"])
print("State.StartedAt: " + os.environ["CLIHOST_DIAG_STARTED_AT"])
print("State.FinishedAt: " + os.environ["CLIHOST_DIAG_FINISHED_AT"])

if oom_killed:
    print("Verdict: OOM: поднять mem limit (dokku resource:limit --memory N)")
elif restart_count > 0 and status == "exited":
    print("Verdict: crash-loop: dokku logs APP --tail")
elif status == "running" and restart_count == 0:
    print("Verdict: healthy")
else:
    print("Verdict: needs investigation")
PY
}

cmd_restart() {
  local app=""
  local apply="false"
  local yes="false"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --apply) apply="true" ;;
      --yes) yes="true" ;;
      --)
        shift
        [ -z "${app}" ] || die "restart accepts exactly one APP"
        [ "$#" -le 1 ] || die "restart accepts exactly one APP"
        if [ "$#" -eq 1 ]; then
          app="$1"
          shift
        fi
        break
        ;;
      -*) die "unknown option: $1" ;;
      *)
        [ -z "${app}" ] || die "restart accepts exactly one APP"
        app="$1"
        ;;
    esac
    shift
  done
  [ "$#" -eq 0 ] || die "restart accepts exactly one APP"
  [ -n "${app}" ] || die "restart requires APP"

  require_app_container "${app}"
  if [ "${apply}" != "true" ]; then
    echo "would run: dokku ps:restart ${app}"
    return 0
  fi
  if [ ! -t 0 ] && [ "${yes}" != "true" ]; then
    die "restart --apply in non-TTY mode requires --yes"
  fi

  if command -v dokku >/dev/null 2>&1; then
    if dokku ps:restart "${app}"; then
      return 0
    fi
    echo "dokku ps:restart ${app} failed; falling back to docker restart ${app}.web.1" >&2
  else
    echo "dokku not found; falling back to docker restart ${app}.web.1" >&2
  fi
  docker restart -- "${app}.web.1"
}

main() {
  local command="${1:-}"
  case "${command}" in
    collect)
      shift
      cmd_collect "$@"
      ;;
    cron-line)
      shift
      cmd_cron_line "$@"
      ;;
    report)
      shift
      cmd_report "$@"
      ;;
    raw)
      shift
      [ "$#" -eq 0 ] || die "raw accepts no arguments"
      cmd_report --json
      ;;
    diagnose)
      shift
      cmd_diagnose "$@"
      ;;
    restart)
      shift
      cmd_restart "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    "")
      usage
      exit 2
      ;;
    *)
      die "unknown subcommand: ${command} (try 'help')"
      ;;
  esac
}

main "$@"
