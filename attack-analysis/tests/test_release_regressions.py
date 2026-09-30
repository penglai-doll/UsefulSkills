"""Record-level gaps, bounded results, Unicode and evolution rollback."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import correlate_events
import extract_log_events
from common import evolution
from test_wiki_evolution import make_skill


class ReleaseRegressions(unittest.TestCase):
    def test_invalid_date_keeps_following_records_and_marks_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "access.log"
            source.write_text(
                '198.51.100.23 - - [32/Sep/2026:10:00:00 +0800] "GET /admin HTTP/1.1" 404 1\n'
                '198.51.100.23 - - [01/Oct/2026:10:00:00 +0800] "GET /login HTTP/1.1" 404 1\n',
                encoding="utf-8",
            )
            manifest = {"files": [{"path": str(source), "detected_type": "web_access"}]}
            result = extract_log_events.extract(manifest, 10)
            self.assertEqual(result["event_count"], 2)
            self.assertIsNone(result["events"][0]["timestamp"])
            self.assertIn("timestamp_error", result["events"][0])
            self.assertIsNotNone(result["events"][1]["timestamp"])
            self.assertTrue(result["partial"])
            self.assertFalse(result["truncated"])
            limited = extract_log_events.extract(manifest, 1)
            self.assertTrue(limited["truncated"])
            stats = limited["parser_stats"][0]
            self.assertEqual(stats["shown_count"], 1)
            self.assertIsNone(stats["total_count"])
            self.assertFalse(stats["scan_complete"])
            self.assertEqual(stats["last_ref"], "line:1")

    def test_unknown_timezone_is_excluded_without_crashing(self):
        events = [
            {"event_id": "local", "timestamp": "2026-10-01T10:00:00"},
            {"event_id": "offset", "timestamp": "2026-10-01T10:00:00+08:00"},
            {"event_id": "utc", "timestamp": "2026-10-01T02:00:01Z"},
        ]
        for event in events:
            event["actor_ip_normalized"] = "198.51.100.23"
        result = correlate_events.correlate(events)
        self.assertEqual(result["unresolved_time_event_ids"], ["local"])
        self.assertEqual(result["correlations"][0]["events"], ["offset", "utc"])

    def test_correlation_limit_is_visible(self):
        events = [
            {"event_id": str(i), "timestamp": f"2026-10-01T02:00:0{i}Z",
             "actor_ip_normalized": "198.51.100.23", "account_or_user": "account"}
            for i in range(3)
        ]
        result = correlate_events.correlate(events, max_clusters=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["correlation_count"], 1)

    def test_json_cli_is_utf8_even_with_a_legacy_console_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "events.json"
            source.write_text(json.dumps({"events": [
                {"event_id": str(i), "timestamp": f"2026-10-01T02:00:0{i}Z",
                 "account_or_user": "用户"} for i in range(2)
            ]}, ensure_ascii=False), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "correlate_events.py"),
                 "--events", str(source), "--json"], capture_output=True,
                env=dict(os.environ, PYTHONIOENCODING="cp936"), check=True,
            )
            result = json.loads(proc.stdout.decode("utf-8"))
            self.assertEqual(result["correlations"][0]["join_value"], "用户")

    def test_proposal_paths_cannot_escape_or_bypass_reserved_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            for proposal_id in ("../escape", "C:/escape", "prop-0001/child"):
                with self.subTest(proposal_id=proposal_id), self.assertRaises(evolution.EvolutionError):
                    evolution.stage_proposal(skill, {"kind": "no_action", "ops": [], "proposal_id": proposal_id})
            for target in ("wiki/./state.json", "C:/escape.md", "./SKILL.md"):
                with self.subTest(target=target), self.assertRaises(evolution.EvolutionError):
                    evolution._check_target_path(target)
            outside = Path(tmp) / "outside.md"
            outside.write_text("unchanged", encoding="utf-8")
            alias = skill / "alias.md"
            os.link(outside, alias)
            with self.assertRaises(evolution.EvolutionError):
                evolution.apply_images(skill, {"alias.md": "overwritten"})
            self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_failed_apply_restores_original_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            original = (skill / "SKILL.md").read_bytes()
            proposal = evolution.stage_proposal(skill, {
                "kind": "skill-edit", "target": "SKILL.md", "traces_read": ["a", "b", "c", "d"],
                "ops": [{"op": "append", "target": "SKILL.md", "content": "changed"}],
            })

            def partial_apply(root, images):
                (root / "SKILL.md").write_text("partially written", encoding="utf-8")
                raise OSError("simulated disk failure")

            with patch.object(evolution, "apply_images", side_effect=partial_apply), self.assertRaises(OSError):
                evolution.evaluate_proposal(skill, proposal, gate_mode="lite")
            self.assertEqual((skill / "SKILL.md").read_bytes(), original)

    def test_repeating_one_trace_does_not_satisfy_the_reading_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            with self.assertRaises(evolution.EvolutionError):
                evolution.stage_proposal(skill, {
                    "kind": "skill-edit", "target": "SKILL.md", "traces_read": ["a"] * 4,
                    "ops": [{"op": "append", "target": "SKILL.md", "content": "changed"}],
                })

    def test_invalid_score_is_rejected_before_applying_a_proposal(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            original = (skill / "SKILL.md").read_bytes()
            proposal = evolution.stage_proposal(skill, {
                "kind": "skill-edit", "target": "SKILL.md", "traces_read": ["a", "b", "c", "d"],
                "ops": [{"op": "append", "target": "SKILL.md", "content": "changed"}],
            })
            with patch.object(evolution, "apply_images") as apply:
                for score in (-1, 2, float("nan")):
                    with self.subTest(score=score), self.assertRaises(evolution.EvolutionError):
                        evolution.evaluate_proposal(skill, proposal, gate_mode="lite", rubric_score=score)
                apply.assert_not_called()
            self.assertEqual((skill / "SKILL.md").read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
