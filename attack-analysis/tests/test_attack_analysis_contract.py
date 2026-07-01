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
    def test_skill_frontmatter_and_agent_metadata(self):
        skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: attack-analysis", skill)
        self.assertIn("description:", skill)
        self.assertIn("quick-report", skill)
        self.assertIn("interactive", skill)
        self.assertIn("Do not send externally by default", skill)
        agent = (ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertIn("$attack-analysis", agent)

    def test_inventory_detects_verified_log_types_and_privacy_contract(self):
        result = run_cmd([PY, "scripts/inventory_logs.py", str(FIXTURE), "--mode", "quick-report", "--case-id", "gold", "--json"])
        manifest = json.loads(result.stdout)
        detected = {Path(f["path"]).name: f["detected_type"] for f in manifest["files"]}
        self.assertEqual(detected["access.log"], "web_access")
        self.assertEqual(detected["app.log"], "spring_app")
        self.assertEqual(detected["p6spy.log"], "p6spy_sql")
        self.assertEqual(detected["login.xlsx"], "xlsx_login")
        self.assertEqual(detected["operate.xlsx"], "xlsx_operate")
        self.assertEqual(manifest["network_assist"], "enabled")
        self.assertIn("full_log", manifest["privacy"]["excluded_external_data_classes"])
        for entry in manifest["files"]:
            self.assertIn("timezone", entry)
            self.assertIn("time_parse_status", entry)


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
            run_cmd([PY, "scripts/inventory_logs.py", str(FIXTURE), "--mode", "quick-report", "--case-id", "gold", "--output-dir", str(tmp_path)])
            extract = run_cmd([
                PY,
                "scripts/extract_log_events.py",
                "--manifest",
                str(tmp_path / "analysis-manifest.json"),
                "--output-dir",
                str(tmp_path),
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
                str(tmp_path / "event-candidates.json"),
                "--output-dir",
                str(tmp_path),
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
