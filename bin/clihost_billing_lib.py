"""Pure stdlib helpers for host-side clihost billing (issue #37).

This module is imported by ``bin/clihost-billing.sh`` (via an inline
``python3`` block) and by ``tests/unit/test_clihost_billing_agg.py``. It holds
*only* pure functions — parsers for the human-formatted numbers that
``docker stats`` / ``docker ps -s`` emit, the container-hours aggregation, the
report table formatter, and the (stage-2) rates hook. No I/O, no docker calls,
no filesystem access lives here; the bash dispatcher owns all of that so this
module stays trivially unit-testable without root or Docker.

Design notes tied to the approved plan (37-quizzical-storm.md):

* Container-hours use **left-Riemann** integration over the *actual* ``dt``
  between consecutive samples of one container, with **gap detection**
  (``dt > 2.5 * interval`` means the collector/server was down for that stretch,
  so the interval is not billed) and rejection of non-positive ``dt``.
* A stopped container writes ``running: false`` samples: those seconds are not
  counted as billable *running* hours, but disk (rootfs/image) is still tracked.
* stdlib only — no third-party deps (matches the repo-wide Python convention).
"""

from __future__ import annotations

import datetime
import json


# Default collector cadence in seconds; the bash dispatcher passes the real
# interval through, but the aggregation falls back to this so a bare call still
# has a sane gap threshold.
DEFAULT_INTERVAL_SECONDS = 300

# A dt larger than this multiple of the sampling interval is treated as a gap
# (collector down / server asleep) and excluded from billed time.
GAP_INTERVAL_MULTIPLE = 2.5


# --------------------------------------------------------------------------- #
# Field parsers — turn docker's human-formatted strings into raw numbers.
# --------------------------------------------------------------------------- #

# Binary (IEC) and decimal (SI) unit multipliers. docker stats emits IEC units
# (MiB/GiB); docker ps -s emits SI units (MB/GB). Both are handled so a parser
# never silently mis-scales a value.
_UNIT_MULTIPLIERS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000 ** 2,
    "gb": 1000 ** 3,
    "tb": 1000 ** 4,
    "pb": 1000 ** 5,
    "kib": 1024,
    "mib": 1024 ** 2,
    "gib": 1024 ** 3,
    "tib": 1024 ** 4,
    "pib": 1024 ** 5,
    # docker occasionally prints a bare "kB"/"B" already covered above; the
    # plain-byte "B" maps to 1.
}


def parse_cpu_perc(value):
    """Parse a ``docker stats`` CPUPerc field like ``"9.28%"`` into a float.

    Returns the percentage as a number (``9.28``), not a fraction. The caller
    divides by 100 when it wants CPU-core units. ``"--"`` / empty / unparseable
    input returns ``0.0`` (a stopped container reports ``--``).
    """
    if value is None:
        return 0.0
    text = str(value).strip()
    if not text or text in ("--", "-"):
        return 0.0
    text = text.rstrip("%").strip()
    try:
        return float(text)
    except ValueError:
        return 0.0


def _parse_one_size(token):
    """Parse a single ``<number><unit>`` token (e.g. ``512.4MiB``) into bytes."""
    token = token.strip()
    if not token:
        return 0
    # Split the numeric prefix from the unit suffix.
    idx = 0
    while idx < len(token) and (token[idx].isdigit() or token[idx] in ".+-eE"):
        idx += 1
    number_part = token[:idx].strip()
    unit_part = token[idx:].strip().lower()
    if not number_part:
        return 0
    try:
        number = float(number_part)
    except ValueError:
        return 0
    if not unit_part:
        # A bare number with no unit is already bytes.
        return int(round(number))
    multiplier = _UNIT_MULTIPLIERS.get(unit_part)
    if multiplier is None:
        # Unknown unit — treat the number as bytes rather than crash.
        return int(round(number))
    return int(round(number * multiplier))


def parse_mem_usage(value):
    """Parse a ``docker stats`` MemUsage field into (used_bytes, limit_bytes).

    Input looks like ``"512.4MiB / 2GiB"``; the left side is the used memory,
    the right side the limit. ``"--"`` or a missing side yields ``0`` for that
    component. Only the used side matters for billing, but the limit is returned
    too so a caller can compute headroom if it wants.
    """
    if value is None:
        return (0, 0)
    text = str(value).strip()
    if not text or text in ("--", "-"):
        return (0, 0)
    parts = text.split("/")
    used = _parse_one_size(parts[0]) if len(parts) >= 1 else 0
    limit = _parse_one_size(parts[1]) if len(parts) >= 2 else 0
    return (used, limit)


def parse_net_io(value):
    """Parse Docker's cumulative ``NetIO`` field into total transferred bytes.

    Return ``None`` unless both received and transmitted counters are present,
    allowing safety-sensitive callers to treat missing data as indeterminate.
    """
    if value is None:
        return None
    parts = str(value).split("/")
    if len(parts) != 2 or not parts[0].strip() or not parts[1].strip():
        return None
    return _parse_one_size(parts[0]) + _parse_one_size(parts[1])


def parse_size_field(value):
    """Parse a ``docker ps -s`` Size field into (rootfs_bytes, virtual_bytes).

    Input looks like ``"2.54GB (virtual 5.73GB)"`` where the first number is the
    container's writable layer and ``virtual`` is the total (image + writable
    layer). A field with no ``(virtual …)`` part returns ``0`` for the virtual
    component. This is how disk usage is measured without ``sudo du`` (the
    ``dokku`` user can't read the root storage mount).
    """
    if value is None:
        return (0, 0)
    text = str(value).strip()
    if not text or text in ("--", "-"):
        return (0, 0)
    virtual = 0
    rootfs_part = text
    # Extract the parenthetical "(virtual X)" if present.
    open_idx = text.find("(")
    if open_idx != -1:
        rootfs_part = text[:open_idx]
        close_idx = text.find(")", open_idx)
        inner = text[open_idx + 1:close_idx if close_idx != -1 else len(text)]
        inner = inner.strip()
        # inner looks like "virtual 5.73GB"
        lowered = inner.lower()
        if lowered.startswith("virtual"):
            inner = inner[len("virtual"):].strip()
        virtual = _parse_one_size(inner)
    rootfs = _parse_one_size(rootfs_part)
    return (rootfs, virtual)


# --------------------------------------------------------------------------- #
# Timestamp helpers.
# --------------------------------------------------------------------------- #

def parse_ts(value):
    """Parse an ISO-8601 UTC timestamp (``...Z`` or ``+00:00``) to epoch seconds."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp()


# --------------------------------------------------------------------------- #
# Aggregation — the billing core.
# --------------------------------------------------------------------------- #

def iter_samples(lines):
    """Yield parsed sample dicts from an iterable of JSONL lines/strings.

    Blank lines and lines that fail to parse (truncated append, partial write)
    are skipped silently — the store is append-only and a crashed collector can
    leave a torn final line, which must not poison a whole report.
    """
    for line in lines:
        if line is None:
            continue
        text = line.strip() if isinstance(line, str) else line
        if not text:
            continue
        if isinstance(text, (bytes, bytearray)):
            try:
                text = text.decode("utf-8")
            except UnicodeDecodeError:
                continue
            text = text.strip()
            if not text:
                continue
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            yield obj


def aggregate(samples, interval_seconds=DEFAULT_INTERVAL_SECONDS):
    """Aggregate per-container samples into billable rows keyed by app.

    ``samples`` is an iterable of dicts as written by ``collect`` (see
    ``clihost-billing.sh``). Returns a list of row dicts, one per app, sorted by
    app name. Each row carries:

    * ``app``
    * ``running_hours``      — billed running container-hours (left-Riemann,
                               gaps excluded, only intervals whose left sample
                               had ``running: true``)
    * ``billed_hours``       — total billed span (running + stopped, gaps
                               excluded); the denominator for uptime%
    * ``uptime_pct``         — 100 * running_hours / billed_hours (or 0)
    * ``cpu_core_hours``     — integral of (cpu_perc/100) dt over running span
    * ``avg_cpu_cores``      — cpu_core_hours / running_hours (avg busy cores)
    * ``mem_byte_hours``     — integral of mem_bytes dt over running span
    * ``avg_mem_bytes``      — mem_byte_hours / running_hours
    * ``last_rootfs_bytes``  — most recent writable-layer size seen
    * ``last_image_bytes``   — most recent image (virtual - rootfs, floored at 0)
                               size seen
    * ``last_ts``            — most recent sample timestamp (ISO string)
    * ``sample_count``       — number of samples for this app

    The gap threshold is ``GAP_INTERVAL_MULTIPLE * interval_seconds``; any
    ``dt`` above it (server down / collector stopped) is excluded from billed
    time, as is any non-positive ``dt`` (clock skew / duplicate sample).
    """
    if not interval_seconds or interval_seconds <= 0:
        interval_seconds = DEFAULT_INTERVAL_SECONDS
    gap_threshold = GAP_INTERVAL_MULTIPLE * interval_seconds

    # Group samples first by app, then by container within the app. Integration
    # is per-container (so consecutive samples of the SAME container bound a real
    # interval); an app with several web.N instances sums each container's
    # contribution. Grouping only by app would fabricate bogus intervals between
    # interleaved samples of different containers.
    by_app = {}
    for sample in samples:
        app = sample.get("app")
        if not app:
            continue
        epoch = parse_ts(sample.get("ts"))
        if epoch is None:
            continue
        container = sample.get("container") or app
        by_app.setdefault(app, {}).setdefault(container, []).append((epoch, sample))

    rows = []
    for app in sorted(by_app):
        running_seconds = 0.0
        billed_seconds = 0.0
        cpu_core_seconds = 0.0
        mem_byte_seconds = 0.0
        # Disk is a point-in-time size, not an integral: track the newest sample
        # per container and sum the latest per-container sizes for the app.
        last_rootfs_by_container = {}
        last_image_by_container = {}
        last_ts = None
        last_ts_epoch = None
        sample_count = 0

        for container in sorted(by_app[app]):
            entries = sorted(by_app[app][container], key=lambda item: item[0])
            sample_count += len(entries)

            for idx, (epoch, sample) in enumerate(entries):
                if last_ts_epoch is None or epoch >= last_ts_epoch:
                    last_ts_epoch = epoch
                    last_ts = sample.get("ts")
                rootfs = int(sample.get("rootfs_bytes") or 0)
                image = int(sample.get("image_bytes") or 0)
                last_rootfs_by_container[container] = rootfs
                last_image_by_container[container] = image

                if idx == 0:
                    continue
                prev_epoch, prev_sample = entries[idx - 1]
                dt = epoch - prev_epoch
                if dt <= 0:
                    continue
                if dt > gap_threshold:
                    # Collector/server was down across this interval; don't bill it.
                    continue
                # Left-Riemann: attribute the interval to the previous sample's state.
                billed_seconds += dt
                if prev_sample.get("running"):
                    running_seconds += dt
                    cpu = parse_cpu_perc(prev_sample.get("cpu_perc"))
                    cpu_core_seconds += (cpu / 100.0) * dt
                    mem_byte_seconds += int(prev_sample.get("mem_bytes") or 0) * dt

        last_rootfs = sum(last_rootfs_by_container.values())
        last_image = sum(last_image_by_container.values())
        running_hours = running_seconds / 3600.0
        billed_hours = billed_seconds / 3600.0
        cpu_core_hours = cpu_core_seconds / 3600.0
        mem_byte_hours = mem_byte_seconds / 3600.0
        uptime_pct = (100.0 * running_seconds / billed_seconds) if billed_seconds > 0 else 0.0
        avg_cpu_cores = (cpu_core_seconds / running_seconds) if running_seconds > 0 else 0.0
        avg_mem_bytes = (mem_byte_seconds / running_seconds) if running_seconds > 0 else 0.0

        rows.append({
            "app": app,
            "running_hours": running_hours,
            "billed_hours": billed_hours,
            "uptime_pct": uptime_pct,
            "cpu_core_hours": cpu_core_hours,
            "avg_cpu_cores": avg_cpu_cores,
            "mem_byte_hours": mem_byte_hours,
            "avg_mem_bytes": avg_mem_bytes,
            "last_rootfs_bytes": last_rootfs,
            "last_image_bytes": last_image,
            "last_ts": last_ts,
            "sample_count": sample_count,
        })
    return rows


# --------------------------------------------------------------------------- #
# Rates hook (stage 2) — not wired to any rates.json yet.
# --------------------------------------------------------------------------- #

def apply_rates(rows, rates=None):
    """Attach a ``cost`` field to each row from a rates table (stage-2 hook).

    ``rates`` is either ``None`` (no ``rates.json`` yet → every ``cost`` is
    ``None``, rendered as an em dash) or a dict with per-unit prices:
    ``{"cpu_core_hour": <float>, "mem_gib_hour": <float>, "image_gib": <float>,
    "rootfs_gib": <float>}``. Missing keys are treated as ``0``. This lets
    stage 2 turn on billing without touching ``aggregate`` or ``report``.

    Returns the same list (rows mutated in place) for convenience.
    """
    for row in rows:
        if not rates:
            row["cost"] = None
            continue
        gib = float(1024 ** 3)
        cpu_price = float(rates.get("cpu_core_hour", 0) or 0)
        mem_price = float(rates.get("mem_gib_hour", 0) or 0)
        image_price = float(rates.get("image_gib", 0) or 0)
        rootfs_price = float(rates.get("rootfs_gib", 0) or 0)
        cost = (
            cpu_price * row.get("cpu_core_hours", 0.0)
            + mem_price * (row.get("mem_byte_hours", 0.0) / gib)
            + image_price * (row.get("last_image_bytes", 0) / gib)
            + rootfs_price * (row.get("last_rootfs_bytes", 0) / gib)
        )
        row["cost"] = cost
    return rows


# --------------------------------------------------------------------------- #
# Report formatting.
# --------------------------------------------------------------------------- #

def _human_bytes(num):
    """Format a byte count as a short human string (IEC units)."""
    try:
        num = float(num)
    except (TypeError, ValueError):
        return "0B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024.0 or unit == "TiB":
            if unit == "B":
                return "%dB" % int(num)
            return "%.1f%s" % (num, unit)
        num /= 1024.0
    return "%.1fTiB" % num


def _format_cost(cost):
    if cost is None:
        return "—"
    return "%.2f" % cost


def format_report_table(rows):
    """Render aggregated (+ rated) rows as a fixed-width text table.

    Columns: app / avg CPU (cores) / avg mem / disk (image+rootfs) / container-
    hours / uptime% / COST. COST is an em dash until a rates.json exists.
    """
    headers = ["APP", "AVG CPU", "AVG MEM", "DISK", "CONT-HRS", "UPTIME%", "COST"]
    table = []
    for row in rows:
        disk = row.get("last_image_bytes", 0) + row.get("last_rootfs_bytes", 0)
        table.append([
            str(row.get("app", "")),
            "%.3f" % row.get("avg_cpu_cores", 0.0),
            _human_bytes(row.get("avg_mem_bytes", 0.0)),
            _human_bytes(disk),
            "%.2f" % row.get("running_hours", 0.0),
            "%.1f" % row.get("uptime_pct", 0.0),
            _format_cost(row.get("cost")),
        ])

    widths = [len(h) for h in headers]
    for line in table:
        for i, cell in enumerate(line):
            widths[i] = max(widths[i], len(cell))

    def render(cells):
        return "  ".join(cell.ljust(widths[i]) for i, cell in enumerate(cells)).rstrip()

    out = [render(headers)]
    out.append("  ".join("-" * widths[i] for i in range(len(headers))).rstrip())
    for line in table:
        out.append(render(line))
    return "\n".join(out)
