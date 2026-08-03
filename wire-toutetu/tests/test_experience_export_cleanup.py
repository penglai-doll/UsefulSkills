from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


class ExperienceExportCleanupTests(unittest.TestCase):
    def test_experience_is_bounded_deduplicated_and_reviewed(self) -> None:
        from wiretoutetu_core.experience import ExperienceStore

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "经验.md"
            store = ExperienceStore(path)
            for index in range(20):
                store.merge_lesson(
                    {
                        "experience_key": f"http-{index % 13}",
                        "scope": "HTTP WebShell",
                        "trigger": f"http post signal-{index % 3}",
                        "action": "先按 stream 聚合，再读取命中的知识叶子。" * 10,
                        "avoid": "避免只凭 URI 判定。",
                        "validation": "synthetic fixture",
                        "knowledge_id": "webshell.behinder",
                    }
                )
                store.append_recent({"case_id": f"case-{index}", "summary": "完成离线分析", "signals": ["http"]})
            store.compact()

            data = store.load()
            reviewed = store.review("http", limit=5)
            self.assertLessEqual(len(data["stable_lessons"]), 12)
            self.assertLessEqual(len(data["recent_rounds"]), 4)
            self.assertLessEqual(path.stat().st_size, 12 * 1024)
            self.assertLessEqual(len(reviewed), 5)
            self.assertGreaterEqual(max(row["hits"] for row in data["stable_lessons"]), 2)

    def test_bundle_reopens_and_verifies_hash_manifest(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.exporter import export_bundle

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            bundle = root / "case.zip"

            result = export_bundle(state, bundle)

            self.assertEqual(result["status"], "verified")
            with zipfile.ZipFile(bundle) as archive:
                self.assertIn("manifest.sha256.json", archive.namelist())
                self.assertNotIn("source.pcap", archive.namelist())

    def test_cleanup_preserves_original_inputs_even_inside_case(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.cleanup import cleanup_case

        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "case"
            case.mkdir()
            capture = case / "original.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(case, capture, [])
            state.write_records("flows", [{"id": "FLOW-1"}])

            result = cleanup_case(case)

            self.assertTrue(capture.is_file())
            self.assertEqual(capture.read_bytes(), b"original")
            self.assertFalse((case / "records" / "flows.jsonl").exists())
            self.assertIn(str(capture.resolve()), result["preserved_inputs"])


if __name__ == "__main__":
    unittest.main()
