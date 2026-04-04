import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import skill_ledger


class SkillLedgerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ledger_path = Path(self.tmpdir.name) / "skill-ledger.json"

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_record_new_problem_creates_active_lesson(self) -> None:
        ledger = skill_ledger.load_ledger(self.ledger_path)

        updated = skill_ledger.record_problem(
            ledger,
            key="public-domain-false-positive",
            symptom="Raw string scan only finds public Google or license domains.",
            preferred_action="Trust first-party code inference before promoting IOC output.",
            avoid="Do not treat public or library URLs as final callback verdicts.",
            stage="callback",
            note="Observed while validating stage-one IOC output.",
        )

        self.assertEqual(len(updated["active_lessons"]), 1)
        self.assertEqual(updated["active_lessons"][0]["key"], "public-domain-false-positive")
        self.assertEqual(updated["active_lessons"][0]["count"], 1)
        self.assertEqual(len(updated["recent_incidents"]), 1)

    def test_record_duplicate_problem_increments_count_without_growing_log(self) -> None:
        ledger = skill_ledger.load_ledger(self.ledger_path)
        ledger = skill_ledger.record_problem(
            ledger,
            key="zipfile-unsupported-method",
            symptom="Python zipfile cannot unpack the APK.",
            preferred_action="Fallback to 7z or a stable JADX directory.",
            avoid="Do not rerun the same failing zipfile path unchanged.",
            stage="unpack",
            note="First failure.",
        )

        updated = skill_ledger.record_problem(
            ledger,
            key="zipfile-unsupported-method",
            symptom="Python zipfile cannot unpack the APK.",
            preferred_action="Fallback to 7z or a stable JADX directory.",
            avoid="Do not rerun the same failing zipfile path unchanged.",
            stage="unpack",
            note="Repeated failure after an unchanged retry.",
        )

        self.assertEqual(len(updated["active_lessons"]), 1)
        self.assertEqual(updated["active_lessons"][0]["count"], 2)
        self.assertEqual(len(updated["recent_incidents"]), 1)

    def test_compaction_moves_old_lessons_to_compressed_bucket(self) -> None:
        ledger = skill_ledger.load_ledger(self.ledger_path)
        for index in range(21):
            ledger = skill_ledger.record_problem(
                ledger,
                key=f"issue-{index}",
                symptom=f"Symptom {index}",
                preferred_action=f"Action {index}",
                avoid=f"Avoid {index}",
                stage="triage",
                note=f"Incident {index}",
            )

        self.assertLessEqual(len(ledger["active_lessons"]), skill_ledger.MAX_ACTIVE_LESSONS)
        self.assertGreaterEqual(len(ledger["compressed_lessons"]), 1)
        compressed_keys = {item["key"] for item in ledger["compressed_lessons"]}
        self.assertIn("issue-0", compressed_keys)

    def test_default_ledger_path_points_to_skill_root(self) -> None:
        expected = Path(skill_ledger.__file__).resolve().parents[1] / "skill-ledger.json"
        self.assertEqual(skill_ledger.default_ledger_path(), expected)


if __name__ == "__main__":
    unittest.main()
