from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "gold_attack_case"
PY = sys.executable


def run_cmd(args):
    return subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=True)


class AttackAnalysisContractTests(unittest.TestCase):
    def test_generated_case_outputs_are_gitignored(self):
        for relative_path in [
            "cache/review-case/analysis-manifest.json",
            "report/review-case/log-analysis-report.md",
        ]:
            result = subprocess.run(
                ["git", "check-ignore", "--quiet", relative_path],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, f"expected Git to ignore {relative_path}")

    def test_skill_frontmatter_and_agent_metadata(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: attack-analysis", skill)
        self.assertIn("description:", skill)
        self.assertIn("quick-report", skill)
        self.assertIn("interactive", skill)
        self.assertIn("Do not send externally by default", skill)
        agent = (ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("$attack-analysis", agent)

    def test_skill_docs_use_case_output_layout(self):
        for relative_path in ["SKILL.md", "references/workflow.md"]:
            content = (ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn("output/attack-analysis/<case-id>", content)
            self.assertIn("$PWD/cache/<case-id>/", content)
            self.assertIn("$PWD/report/<case-id>/log-analysis-report.md", content)
            self.assertIn("<skill-root>/scripts/inventory_logs.py", content)
            self.assertIn("<skill-root>/scripts/extract_log_events.py", content)
            self.assertIn("<skill-root>/scripts/correlate_events.py", content)
            self.assertNotIn("python3 scripts/inventory_logs.py", content)

    def test_inventory_detects_verified_log_types_and_privacy_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "workdir"
            result = run_cmd([
                PY,
                "scripts/inventory_logs.py",
                str(FIXTURE),
                "--mode",
                "quick-report",
                "--case-id",
                "gold",
                "--workdir",
                str(workdir),
                "--json",
            ])
            manifest = json.loads(result.stdout)
            detected = {Path(f["path"]).name: f["detected_type"] for f in manifest["files"]}
            self.assertEqual(detected["access.log"], "web_access")
            self.assertEqual(detected["app.log"], "spring_app")
            self.assertEqual(detected["p6spy.log"], "p6spy_sql")
            self.assertEqual(detected["login.xlsx"], "xlsx_login")
            self.assertEqual(detected["operate.xlsx"], "xlsx_operate")
            self.assertEqual(manifest["network_assist"], "enabled")
            self.assertIn("full_log", manifest["privacy"]["excluded_external_data_classes"])
            resolved_workdir = workdir.resolve()
            self.assertEqual(manifest["invocation_cwd"], str(resolved_workdir))
            self.assertEqual(
                manifest["output_paths"],
                {
                    "cache_dir": str(resolved_workdir / "cache" / "gold"),
                    "report_dir": str(resolved_workdir / "report" / "gold"),
                    "report_path": str(resolved_workdir / "report" / "gold" / "log-analysis-report.md"),
                },
            )
            self.assertTrue((workdir / "cache" / "gold" / "analysis-manifest.json").is_file())
            for entry in manifest["files"]:
                self.assertIn("timezone", entry)
                self.assertIn("time_parse_status", entry)

    def test_inventory_prints_manifest_without_json_when_no_legacy_output_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "workdir"
            result = run_cmd([
                PY,
                "scripts/inventory_logs.py",
                str(FIXTURE),
                "--mode",
                "quick-report",
                "--case-id",
                "stdout-case",
                "--workdir",
                str(workdir),
            ])

            self.assertTrue(result.stdout.strip(), "expected manifest JSON on stdout")
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["case_id"], "stdout-case")

    def test_inventory_legacy_output_dir_stays_quiet_without_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            output_dir = tmp_path / "legacy-cache"
            workdir = tmp_path / "workdir"
            parent_policy = b"!preserve-parent-policy\n\xff\n"
            (tmp_path / ".gitignore").write_bytes(parent_policy)
            result = run_cmd([
                PY,
                "scripts/inventory_logs.py",
                str(FIXTURE),
                "--mode",
                "quick-report",
                "--case-id",
                "legacy-case",
                "--workdir",
                str(workdir),
                "--output-dir",
                str(output_dir),
            ])

            self.assertEqual(result.stdout, "")
            self.assertEqual((tmp_path / ".gitignore").read_bytes(), parent_policy)
            self.assertEqual((output_dir / ".gitignore").read_bytes(), b"*\n")
            manifest_path = output_dir / "analysis-manifest.json"
            self.assertTrue(manifest_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["case_id"], "legacy-case")
            self.assertEqual(
                manifest["output_paths"],
                {
                    "cache_dir": str(output_dir.resolve()),
                    "report_dir": str(workdir.resolve() / "report" / "legacy-case"),
                    "report_path": str(workdir.resolve() / "report" / "legacy-case" / "log-analysis-report.md"),
                },
            )

    def test_inventory_skips_case_cache_and_report_when_workdir_is_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "workdir"
            workdir.mkdir()
            (workdir / "input.log").write_text("2026-07-10 12:30:45 INFO request\n", encoding="utf-8")
            (workdir / "cache").mkdir()
            (workdir / "cache" / "old.log").write_text("cached\n", encoding="utf-8")
            (workdir / "report").mkdir()
            (workdir / "report" / "old.log").write_text("reported\n", encoding="utf-8")

            result = run_cmd([
                PY,
                "scripts/inventory_logs.py",
                str(workdir),
                "--mode",
                "quick-report",
                "--case-id",
                "gold",
                "--workdir",
                str(workdir),
                "--json",
            ])

            manifest = json.loads(result.stdout)
            self.assertEqual([Path(entry["path"]).name for entry in manifest["files"]], ["input.log"])


    def test_inventory_requires_explicit_mode(self):
        result = subprocess.run(
            [PY, "scripts/inventory_logs.py", str(FIXTURE), "--json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--mode", result.stderr)

    def test_extract_and_correlate_gold_attack_case(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            workdir = tmp_path / "workdir"
            cache_dir = workdir / "cache" / "gold"
            run_cmd([
                PY,
                "scripts/inventory_logs.py",
                str(FIXTURE),
                "--mode",
                "quick-report",
                "--case-id",
                "gold",
                "--workdir",
                str(workdir),
            ])
            extract = run_cmd([
                PY,
                "scripts/extract_log_events.py",
                "--manifest",
                str(cache_dir / "analysis-manifest.json"),
                "--output-dir",
                str(cache_dir),
                "--json",
            ])
            events = json.loads(extract.stdout)
            event_types = {event["event_type"] for event in events["events"]}
            ips = {event["actor_ip_normalized"] for event in events["events"] if event.get("actor_ip_normalized")}
            self.assertIn("198.51.100.23", ips)
            self.assertIn("web_probe", event_types)
            self.assertIn("login_signal", event_types)
            self.assertIn("sql_suspicious", event_types)
            self.assertIn("login_record", event_types)
            self.assertIn("operation_record", event_types)
            corr = run_cmd([
                PY,
                "scripts/correlate_events.py",
                "--events",
                str(cache_dir / "event-candidates.json"),
                "--output-dir",
                str(cache_dir),
                "--json",
            ])
            correlations = json.loads(corr.stdout)["correlations"]
            self.assertTrue(correlations)
            self.assertTrue(any("same_ip" in c["basis"] for c in correlations))

    def test_boundaries_are_explicit(self):
        log_types = (ROOT / "references" / "log-types.md").read_text(encoding="utf-8")
        self.assertIn("v1 Verified", log_types)
        self.assertIn("v1 Best-Effort", log_types)
        self.assertIn("Future Interface Only", log_types)
        self.assertIn("Windows", log_types)
        self.assertIn("Kubernetes", log_types)
        reporting = (ROOT / "references" / "reporting.md").read_text(encoding="utf-8")
        self.assertIn("No threat score", reporting)


if __name__ == "__main__":
    unittest.main()
