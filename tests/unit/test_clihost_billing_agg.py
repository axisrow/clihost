"""Unit tests for the pure billing helpers (bin/clihost_billing_lib.py, #37).

These exercise the parsers on the exact strings the Dokku server emits, the
container-hours aggregation (left-Riemann + gap detection + running:false
exclusion + multi-instance summing), the torn-JSONL-line tolerance, and the
stage-2 rates hook / table formatting.
"""
import datetime
import pathlib
import sys
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN_DIR = REPO_ROOT / "bin"
# The billing library lives in bin/, not app/ (conftest only wires app/).
sys.path.insert(0, str(BIN_DIR))

import clihost_billing_lib as lib  # noqa: E402


def ts(minutes):
    """Return an ISO-8601 Z timestamp `minutes` after a fixed base."""
    base = datetime.datetime(2026, 7, 9, 12, 0, 0, tzinfo=datetime.timezone.utc)
    return (base + datetime.timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def sample(app, minutes, running=True, cpu="10.00%", mem_bytes=1024 ** 3,
           rootfs=1000, image=4661408563, container=None):
    return {
        "ts": ts(minutes),
        "app": app,
        "container": container or (app + ".web.1"),
        "running": running,
        "cpu_perc": cpu,
        "mem_bytes": mem_bytes,
        "rootfs_bytes": rootfs,
        "image_bytes": image,
    }


class TestParsers(unittest.TestCase):
    def test_parse_cpu_perc_real_string(self):
        self.assertAlmostEqual(lib.parse_cpu_perc("9.28%"), 9.28)
        self.assertAlmostEqual(lib.parse_cpu_perc("0.00%"), 0.0)
        self.assertAlmostEqual(lib.parse_cpu_perc("125.4%"), 125.4)

    def test_parse_cpu_perc_dashes_and_junk(self):
        self.assertEqual(lib.parse_cpu_perc("--"), 0.0)
        self.assertEqual(lib.parse_cpu_perc(""), 0.0)
        self.assertEqual(lib.parse_cpu_perc(None), 0.0)
        self.assertEqual(lib.parse_cpu_perc("garbage"), 0.0)

    def test_parse_mem_usage_real_string(self):
        used, limit = lib.parse_mem_usage("512.4MiB / 2GiB")
        self.assertEqual(used, int(round(512.4 * 1024 ** 2)))
        self.assertEqual(limit, 2 * 1024 ** 3)

    def test_parse_mem_usage_edge(self):
        self.assertEqual(lib.parse_mem_usage("--"), (0, 0))
        self.assertEqual(lib.parse_mem_usage(None), (0, 0))

    def test_parse_net_io(self):
        self.assertEqual(lib.parse_net_io("1.2MB / 34kB"), 1_234_000)
        self.assertEqual(lib.parse_net_io("50B / 50B"), 100)
        self.assertIsNone(lib.parse_net_io("--"))
        used, limit = lib.parse_mem_usage("1.5GiB / 7.6GiB")
        self.assertEqual(used, int(round(1.5 * 1024 ** 3)))

    def test_parse_size_field_real_string(self):
        rootfs, virtual = lib.parse_size_field("2.54GB (virtual 5.73GB)")
        self.assertEqual(rootfs, int(round(2.54 * 1000 ** 3)))
        self.assertEqual(virtual, int(round(5.73 * 1000 ** 3)))

    def test_parse_size_field_no_virtual(self):
        rootfs, virtual = lib.parse_size_field("0B (virtual 4.34GB)")
        self.assertEqual(rootfs, 0)
        self.assertEqual(virtual, int(round(4.34 * 1000 ** 3)))

    def test_parse_size_field_edge(self):
        self.assertEqual(lib.parse_size_field("--"), (0, 0))
        self.assertEqual(lib.parse_size_field(None), (0, 0))

    def test_parse_ts_roundtrip(self):
        epoch = lib.parse_ts("2026-07-09T12:00:00Z")
        self.assertIsNotNone(epoch)
        epoch2 = lib.parse_ts("2026-07-09T12:05:00Z")
        self.assertAlmostEqual(epoch2 - epoch, 300)

    def test_parse_ts_junk(self):
        self.assertIsNone(lib.parse_ts("not-a-date"))
        self.assertIsNone(lib.parse_ts(""))
        self.assertIsNone(lib.parse_ts(None))


class TestAggregate(unittest.TestCase):
    def test_basic_running_hours_left_riemann(self):
        # Three samples 5 min apart at 100% CPU (1 core), 1 GiB mem.
        samples = [
            sample("clihost-a", 0, cpu="100.00%", mem_bytes=1024 ** 3),
            sample("clihost-a", 5, cpu="100.00%", mem_bytes=1024 ** 3),
            sample("clihost-a", 10, cpu="100.00%", mem_bytes=1024 ** 3),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # Two 5-min intervals = 10 min = 1/6 hour billed running.
        self.assertAlmostEqual(row["running_hours"], 10 / 60.0, places=6)
        self.assertAlmostEqual(row["billed_hours"], 10 / 60.0, places=6)
        self.assertAlmostEqual(row["uptime_pct"], 100.0, places=6)
        # 100% CPU = 1 core on average.
        self.assertAlmostEqual(row["avg_cpu_cores"], 1.0, places=6)
        self.assertAlmostEqual(row["avg_mem_bytes"], float(1024 ** 3), places=1)

    def test_gap_interval_is_excluded(self):
        # A dt of 20 min with interval 300s (5 min) exceeds 2.5x -> excluded.
        samples = [
            sample("clihost-a", 0, cpu="100.00%"),
            sample("clihost-a", 5, cpu="100.00%"),   # +5 min: billed
            sample("clihost-a", 25, cpu="100.00%"),  # +20 min gap: excluded
            sample("clihost-a", 30, cpu="100.00%"),  # +5 min: billed
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        row = rows[0]
        # Only two 5-min intervals count; the 20-min gap is dropped.
        self.assertAlmostEqual(row["running_hours"], 10 / 60.0, places=6)

    def test_running_false_excluded_from_running_hours_but_billed(self):
        # Left sample stopped -> interval is billed (denominator) but not running.
        samples = [
            sample("clihost-a", 0, running=False, cpu="0.00%"),
            sample("clihost-a", 5, running=True, cpu="100.00%"),
            sample("clihost-a", 10, running=True, cpu="100.00%"),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        row = rows[0]
        # First interval (left=stopped): billed, not running.
        # Second interval (left=running): billed and running.
        self.assertAlmostEqual(row["billed_hours"], 10 / 60.0, places=6)
        self.assertAlmostEqual(row["running_hours"], 5 / 60.0, places=6)
        self.assertAlmostEqual(row["uptime_pct"], 50.0, places=6)

    def test_non_positive_dt_skipped(self):
        # Duplicate timestamps / clock skew must not create negative or zero dt.
        samples = [
            sample("clihost-a", 0, cpu="100.00%"),
            sample("clihost-a", 0, cpu="100.00%"),  # dt == 0 -> skipped
            sample("clihost-a", 5, cpu="100.00%"),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        row = rows[0]
        self.assertAlmostEqual(row["running_hours"], 5 / 60.0, places=6)

    def test_multi_instance_summing(self):
        # Two containers of the same app run in parallel: their running-hours sum,
        # and their per-container intervals are NOT interleaved into fake ones.
        samples = [
            sample("clihost-a", 0, cpu="100.00%", container="clihost-a.web.1"),
            sample("clihost-a", 5, cpu="100.00%", container="clihost-a.web.1"),
            sample("clihost-a", 0, cpu="100.00%", container="clihost-a.web.2"),
            sample("clihost-a", 5, cpu="100.00%", container="clihost-a.web.2"),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # Each container contributes one 5-min interval -> 10 min total.
        self.assertAlmostEqual(row["running_hours"], 10 / 60.0, places=6)
        # 2 cores busy across both -> 2 core-hours' worth per elapsed hour;
        # avg_cpu_cores = cpu_core_seconds / running_seconds = 1.0 per container.
        self.assertAlmostEqual(row["avg_cpu_cores"], 1.0, places=6)

    def test_multi_instance_disk_sums_latest_per_container(self):
        samples = [
            sample("clihost-a", 0, container="clihost-a.web.1", rootfs=100, image=1000),
            sample("clihost-a", 5, container="clihost-a.web.1", rootfs=150, image=1000),
            sample("clihost-a", 5, container="clihost-a.web.2", rootfs=200, image=2000),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        row = rows[0]
        # Latest per container: web.1 rootfs=150 image=1000, web.2 rootfs=200 image=2000.
        self.assertEqual(row["last_rootfs_bytes"], 350)
        self.assertEqual(row["last_image_bytes"], 3000)

    def test_multiple_apps_sorted(self):
        samples = [
            sample("clihost-b", 0), sample("clihost-b", 5),
            sample("clihost-a", 0), sample("clihost-a", 5),
        ]
        rows = lib.aggregate(samples, interval_seconds=300)
        self.assertEqual([r["app"] for r in rows], ["clihost-a", "clihost-b"])

    def test_single_sample_has_no_billed_time(self):
        rows = lib.aggregate([sample("clihost-a", 0)], interval_seconds=300)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["running_hours"], 0.0)
        self.assertEqual(rows[0]["billed_hours"], 0.0)
        self.assertEqual(rows[0]["uptime_pct"], 0.0)

    def test_empty_input(self):
        self.assertEqual(lib.aggregate([]), [])


class TestIterSamples(unittest.TestCase):
    def test_torn_jsonl_line_is_skipped(self):
        lines = [
            '{"ts":"2026-07-09T12:00:00Z","app":"clihost-a","running":true}',
            '{"ts":"2026-07-09T12:05:00Z","app":"clihost-a"',  # torn/truncated
            '',
            '   ',
            'not json at all',
            '{"ts":"2026-07-09T12:10:00Z","app":"clihost-a","running":true}',
        ]
        parsed = list(lib.iter_samples(lines))
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["ts"], "2026-07-09T12:00:00Z")
        self.assertEqual(parsed[1]["ts"], "2026-07-09T12:10:00Z")

    def test_non_dict_json_skipped(self):
        parsed = list(lib.iter_samples(["[1,2,3]", '"a string"', "42"]))
        self.assertEqual(parsed, [])


class TestApplyRates(unittest.TestCase):
    def test_no_rates_yields_none_cost(self):
        rows = lib.aggregate(
            [sample("clihost-a", 0), sample("clihost-a", 5)],
            interval_seconds=300,
        )
        lib.apply_rates(rows, rates=None)
        self.assertIsNone(rows[0]["cost"])

    def test_rates_compute_cost(self):
        rows = [{
            "cpu_core_hours": 2.0,
            "mem_byte_hours": float(1024 ** 3),  # 1 GiB-hour
            "last_image_bytes": 2 * 1024 ** 3,   # 2 GiB
            "last_rootfs_bytes": 1024 ** 3,      # 1 GiB
        }]
        lib.apply_rates(rows, rates={
            "cpu_core_hour": 1.0,
            "mem_gib_hour": 0.5,
            "image_gib": 0.1,
            "rootfs_gib": 0.2,
        })
        # 2*1 + 1*0.5 + 2*0.1 + 1*0.2 = 2 + 0.5 + 0.2 + 0.2 = 2.9
        self.assertAlmostEqual(rows[0]["cost"], 2.9, places=6)


class TestFormatReportTable(unittest.TestCase):
    def test_table_has_headers_and_em_dash_cost_without_rates(self):
        rows = lib.aggregate(
            [sample("clihost-a", 0, cpu="100.00%"), sample("clihost-a", 5, cpu="100.00%")],
            interval_seconds=300,
        )
        lib.apply_rates(rows, rates=None)
        table = lib.format_report_table(rows)
        self.assertIn("APP", table)
        self.assertIn("AVG CPU", table)
        self.assertIn("UPTIME%", table)
        self.assertIn("COST", table)
        self.assertIn("clihost-a", table)
        # COST column is an em dash when there is no rates.json.
        self.assertIn("—", table)

    def test_table_empty_rows_is_just_headers(self):
        table = lib.format_report_table([])
        # Header line + separator line, no data rows.
        self.assertEqual(len(table.splitlines()), 2)
        self.assertIn("APP", table)


if __name__ == "__main__":
    unittest.main()
