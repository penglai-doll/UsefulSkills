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

    def test_bundle_does_not_pack_an_existing_destination_inside_case(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.exporter import export_bundle

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            bundle = state.root / "exports" / "case.zip"
            bundle.parent.mkdir()
            bundle.write_bytes(b"old bundle that must not be nested")

            export_bundle(state, bundle)

            with zipfile.ZipFile(bundle) as archive:
                self.assertNotIn("exports/case.zip", archive.namelist())

    def test_bundle_only_contains_registered_generated_files(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.exporter import export_bundle

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            unrelated = state.root / "unrelated-secret.txt"
            unrelated.write_text("must stay local", encoding="utf-8")
            bundle = root / "case.zip"

            export_bundle(state, bundle)

            with zipfile.ZipFile(bundle) as archive:
                self.assertNotIn("unrelated-secret.txt", archive.namelist())
            self.assertTrue(unrelated.is_file())

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

    def test_cleanup_preserves_unregistered_file_added_after_case_creation(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.cleanup import cleanup_case

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("flows", [{"id": "FLOW-1"}])
            unrelated = state.root / "unrelated.txt"
            unrelated.write_text("preserve", encoding="utf-8")

            cleanup_case(state.root)

            self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")

    def test_cleanup_rejects_tampered_ledger_path_traversal(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.cleanup import cleanup_case

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            outside = root / "outside.txt"
            outside.write_text("preserve", encoding="utf-8")
            state = CaseState.create(root / "case", capture, [])
            ledger = json.loads(state.generated_ledger_path.read_text(encoding="utf-8"))
            ledger["files"].insert(0, {"path": "../outside.txt", "owner": "inventory"})
            state.generated_ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "inside the case root"):
                cleanup_case(state.root)
            self.assertEqual(outside.read_text(encoding="utf-8"), "preserve")

    def test_markdown_export_appends_truncation_note_with_real_totals(self) -> None:
        from wiretoutetu_core.case_state import MAX_QUERY_ITEMS, CaseState
        from wiretoutetu_core.exporter import export_markdown

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            state.write_records("timeline", [{"id": f"EVT-{index}", "time": float(index)} for index in range(MAX_QUERY_ITEMS + 25)])
            state.write_records("objects", [{"id": "OBJ-1", "filename": "a.bin", "sha256": "0" * 64}])
            markdown = root / "report.md"

            export_markdown(state, markdown)

            text = markdown.read_text(encoding="utf-8")
            self.assertIn(f"⚠ 截断：仅导出前 {MAX_QUERY_ITEMS}/{MAX_QUERY_ITEMS + 25} 条", text)
            self.assertIn("完整数据见 case 目录 records/timeline.jsonl", text)
            self.assertEqual(text.count("⚠ 截断"), 1)

    def test_markdown_export_omits_truncation_note_when_complete(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.exporter import export_markdown

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            state.write_records("timeline", [{"id": "EVT-1", "time": 1.0}])
            markdown = root / "report.md"

            export_markdown(state, markdown)

            self.assertNotIn("⚠ 截断", markdown.read_text(encoding="utf-8"))

    def test_exports_inside_case_are_registered_and_removed_by_cleanup(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.cleanup import cleanup_case
        from wiretoutetu_core.exporter import export_bundle, export_markdown

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "source.pcap"
            capture.write_bytes(b"original")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("summary", [{"completeness": "complete"}])
            markdown = state.root / "exports" / "report.md"
            bundle = state.root / "exports" / "case.zip"

            export_markdown(state, markdown)
            export_bundle(state, bundle)
            registered = {item["path"] for item in state.generated_files()}

            self.assertIn("exports/report.md", registered)
            self.assertIn("exports/case.zip", registered)
            cleanup_case(state.root)
            self.assertFalse(markdown.exists())
            self.assertFalse(bundle.exists())


if __name__ == "__main__":
    unittest.main()
