"""Regression tests for the reviewed defects fixed in this change set."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
PY = sys.executable
# Import script modules under the same top-level identities the CLIs use.
sys.path.insert(0, str(SCRIPTS))

import correlate_events  # noqa: E402
import extract_log_events  # noqa: E402
import inventory_logs  # noqa: E402
from common import io_utils  # noqa: E402
from common.time_normalize import (  # noqa: E402
    clear_timezone_notes,
    parse_timestamp,
    timezone_notes,
    timezone_obj,
)


def run_cmd(args):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=True)


def run_inventory(paths, workdir, extra_args=()):
    result = run_cmd(
        [
            PY,
            "scripts/inventory_logs.py",
            *[str(p) for p in paths],
            "--mode",
            "quick-report",
            "--case-id",
            "regress",
            "--workdir",
            str(workdir),
            "--json",
            *extra_args,
        ]
    )
    return json.loads(result.stdout)


class AccessRegexRegressions(unittest.TestCase):
    def test_dash_prefixed_line_is_not_web_access(self):
        self.assertIsNone(inventory_logs.ACCESS_RE.match("-" * 40))
        self.assertIsNone(inventory_logs.ACCESS_RE.match("- - - comment style line"))

    def test_combined_log_with_dash_status_matches(self):
        line = '198.51.100.23 - - [15/Apr/2026:10:00:01 +0800] "GET /admin HTTP/1.1" - 123 "-" "sqlmap/1.7"'
        self.assertIsNotNone(inventory_logs.ACCESS_RE.match(line))

    def test_regular_access_line_still_matches(self):
        line = '198.51.100.23 - - [15/Apr/2026:10:00:01 +0800] "GET /admin HTTP/1.1" 404 123 "-" "sqlmap/1.7"'
        self.assertIsNotNone(inventory_logs.ACCESS_RE.match(line))

    def test_dashed_separator_file_is_not_detected_as_web_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "dashes.log"
            src.write_text("----------------\n---- section two ----\n", encoding="utf-8")
            manifest = run_inventory([src], Path(tmp) / "workdir")
            entry = manifest["files"][0]
            self.assertTrue(entry["include"])
            self.assertNotEqual(entry["detected_type"], "web_access")

    def test_combined_log_with_dash_status_is_counted_as_web_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "combined-dash.log"
            src.write_text(
                '198.51.100.23 - - [15/Apr/2026:10:00:01 +0800] "GET /admin HTTP/1.1" - 123 "-" "sqlmap/1.7"\n',
                encoding="utf-8",
            )
            manifest = run_inventory([src], Path(tmp) / "workdir")
            entry = manifest["files"][0]
            self.assertEqual(entry["detected_type"], "web_access")
            self.assertEqual(entry["type_confidence"], "high")
            self.assertEqual(entry["time_range"]["first"], "2026-04-15T10:00:01+08:00")


class DeclaredTypePrecedenceRegressions(unittest.TestCase):
    def _extract(self, tmp, content, declared, detected):
        src = Path(tmp) / "sample.log"
        src.write_text(content, encoding="utf-8")
        manifest = {
            "case_id": "regress",
            "default_timezone": "Asia/Shanghai",
            "files": [
                {
                    "path": str(src),
                    "include": True,
                    "declared_type": declared,
                    "detected_type": detected,
                }
            ],
        }
        return extract_log_events.extract(manifest, 100)

    def test_declared_type_wins_over_detection(self):
        nginx_line = '203.0.113.5 - - [15/Apr/2026:10:00:01 +0800] "GET /.git/config HTTP/1.1" 200 10 "-" "curl/8.0"\n'
        with tempfile.TemporaryDirectory() as tmp:
            result = self._extract(tmp, nginx_line, declared="nginx_access", detected="generic_text")
        self.assertEqual([s["module"] for s in result["parser_stats"]], ["parsers.nginx_access"])
        self.assertTrue(result["events"])
        self.assertEqual(result["events"][0]["log_type"], "nginx_access")
        self.assertEqual(result["events"][0]["event_type"], "web_probe")

    def test_declared_generic_text_overrides_detected_web_access(self):
        access_line = '203.0.113.5 - - [15/Apr/2026:10:00:01 +0800] "GET /x HTTP/1.1" 404 10 "-" "curl/8.0"\n'
        with tempfile.TemporaryDirectory() as tmp:
            result = self._extract(tmp, access_line, declared="generic_text", detected="web_access")
        self.assertEqual([s["module"] for s in result["parser_stats"]], ["parsers.generic_text"])
        self.assertTrue(result["events"])
        self.assertEqual(result["events"][0]["log_type"], "generic_text")

    def test_detected_type_used_when_no_declaration(self):
        spring_line = (
            "2026-04-15 10:00:01.123 ERROR 8 --- [main] com.x.LoginController:22 - login failed username=admin\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = self._extract(tmp, spring_line, declared=None, detected="spring_app")
        self.assertEqual([s["module"] for s in result["parser_stats"]], ["parsers.spring_app"])
        self.assertTrue(result["events"])

    def test_generic_text_fallback_when_both_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._extract(tmp, "Apr 15 10:00:01 host cron[1]: login session opened\n", declared=None, detected=None)
        self.assertEqual([s["module"] for s in result["parser_stats"]], ["parsers.generic_text"])


class ExtensionlessSyslogRegressions(unittest.TestCase):
    def test_well_known_extensionless_names_are_probably_text(self):
        for name in ["secure", "messages", "syslog", "auth", "kern", "daemon", "cron", "maillog", "debug"]:
            self.assertTrue(io_utils.is_probably_text(Path("logs") / name), name)
        # rotated variants
        self.assertTrue(io_utils.is_probably_text(Path("logs") / "secure.1"))
        self.assertTrue(io_utils.is_probably_text(Path("logs") / "messages.gz"))

    def test_binary_accounting_and_unknown_names_stay_excluded(self):
        for name in ["wtmp", "btmp", "lastlog", "faillog", "randomname", "image.png", "archive.tar"]:
            self.assertFalse(io_utils.is_probably_text(Path("logs") / name), name)

    def test_extensionless_syslog_files_are_included_and_typed(self):
        with tempfile.TemporaryDirectory() as tmp:
            src_dir = Path(tmp) / "logs"
            src_dir.mkdir()
            (src_dir / "secure").write_text(
                "Apr 15 09:59:59 host sshd[1234]: Failed password for root from 198.51.100.23 port 5000 ssh2\n",
                encoding="utf-8",
            )
            (src_dir / "messages").write_text(
                "Apr 15 10:00:01 host systemd[1]: Started Daily apt download activities.\n",
                encoding="utf-8",
            )
            (src_dir / "wtmp").write_bytes(b"\x00\x01\x02wtmp\x00\x7f")

            manifest = run_inventory([src_dir], Path(tmp) / "workdir")
            entries = {Path(f["path"]).name: f for f in manifest["files"]}

            secure = entries["secure"]
            self.assertTrue(secure["include"])
            self.assertEqual(secure["detected_type"], "auth_text")

            messages = entries["messages"]
            self.assertTrue(messages["include"])
            self.assertEqual(messages["detected_type"], "system_text")
            self.assertIn("well_known_system_log:no_extension", messages["notes"])

            wtmp = entries["wtmp"]
            self.assertFalse(wtmp["include"])
            self.assertIn("unsupported_or_binary_unknown", wtmp["notes"])


class TimezoneDegradationRegressions(unittest.TestCase):
    def setUp(self):
        clear_timezone_notes()

    def tearDown(self):
        clear_timezone_notes()

    def test_zoneinfo_failure_records_a_note(self):
        self.assertIsNone(timezone_obj("No/Such/Zone"))
        notes = timezone_notes()
        self.assertTrue(any("No/Such/Zone" in note and "tzdata" in note for note in notes))

    def test_parse_timestamp_marks_unknown_when_zone_missing(self):
        result = parse_timestamp("2026-04-15 10:00:00 login failed", "No/Such/Zone")
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(timezone_notes())

    def test_numeric_offsets_do_not_record_notes(self):
        self.assertIsNotNone(timezone_obj("+08:00"))
        self.assertEqual(timezone_notes(), [])

    def test_inventory_manifest_records_timezone_notes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "app-ish.log"
            src.write_text("2026-04-15 10:00:01 login failed for admin\n", encoding="utf-8")
            manifest = run_inventory([src], Path(tmp) / "workdir", extra_args=["--default-timezone", "No/Such/Zone"])
        self.assertTrue(manifest["timezone_notes"])
        self.assertTrue(any("No/Such/Zone" in note for note in manifest["timezone_notes"]))

    def test_extract_output_records_timezone_notes_and_unknown_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "app-ish.log"
            src.write_text("2026-04-15 10:00:01 login failed for admin\n", encoding="utf-8")
            result = extract_log_events.extract(
                {
                    "case_id": "regress",
                    "default_timezone": "No/Such/Zone",
                    "files": [
                        {"path": str(src), "include": True, "declared_type": None, "detected_type": "generic_text"}
                    ],
                },
                100,
            )
        self.assertTrue(result["events"])
        self.assertEqual(result["events"][0]["timestamp_status"], "unknown")
        self.assertTrue(result.get("timezone_notes"))
        self.assertTrue(all("warnings" in stat for stat in result["parser_stats"]))


class BadLineCountRegressions(unittest.TestCase):
    def test_undecodable_lines_are_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "mixed-encoding.log"
            src.write_bytes("2026-04-15 10:00:01 ok line\n".encode("ascii") + b"\xff\xfe\xfd raw bytes\n")
            manifest = run_inventory([src], Path(tmp) / "workdir")
        entry = manifest["files"][0]
        self.assertTrue(entry["include"])
        self.assertEqual(entry["bad_line_count"], 1)


class MonthNameRegressions(unittest.TestCase):
    def test_unknown_month_is_unknown_not_january(self):
        result = parse_timestamp("[15/Xyz/2026:10:00:01 +0800] GET /x")
        self.assertIsNone(result["timestamp"])
        self.assertEqual(result["status"], "unknown")

    def test_lowercase_month_is_accepted(self):
        result = parse_timestamp("[15/jan/2026:10:00:01 +0800] GET /x")
        self.assertEqual(result["timestamp"], "2026-01-15T10:00:01+08:00")
        self.assertEqual(result["status"], "explicit")

    def test_valid_month_still_parses(self):
        result = parse_timestamp("[15/Apr/2026:10:00:01 +0800] GET /x")
        self.assertEqual(result["timestamp"], "2026-04-15T10:00:01+08:00")


class ZSuffixCorrelationRegressions(unittest.TestCase):
    def test_parse_dt_accepts_z_suffix(self):
        dt = correlate_events.parse_dt("2026-04-15T10:00:00Z")
        self.assertIsNotNone(dt)
        self.assertEqual(dt.utcoffset(), timedelta(0))

    def test_parse_dt_handles_naive_and_invalid(self):
        self.assertIsNotNone(correlate_events.parse_dt("2026-04-15 10:00:00"))
        self.assertIsNone(correlate_events.parse_dt("garbage"))
        self.assertIsNone(correlate_events.parse_dt(None))

    def test_z_suffixed_events_are_clustered(self):
        events = [
            {"event_id": "evt-000001", "timestamp": "2026-04-15T10:00:00Z", "actor_ip_normalized": "198.51.100.23"},
            {"event_id": "evt-000002", "timestamp": "2026-04-15T10:01:00Z", "actor_ip_normalized": "198.51.100.23"},
        ]
        result = correlate_events.correlate(events)
        self.assertTrue(any("same_ip" in basis for c in result["correlations"] for basis in c["basis"]))


if __name__ == "__main__":
    unittest.main()
