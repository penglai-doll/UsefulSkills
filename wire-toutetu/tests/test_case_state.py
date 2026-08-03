from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


class CaseStateTests(unittest.TestCase):
    def test_create_rejects_nonempty_directory_with_unrelated_files(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            case = root / "case"
            case.mkdir()
            (case / "unrelated.txt").write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "unrelated pre-existing content"):
                CaseState.create(case, capture, [])

    def test_create_rejects_input_colliding_with_reserved_case_state(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            case = Path(tmp) / "case"
            case.mkdir()
            capture = case / "case.json"
            capture.write_bytes(b"original capture")

            with self.assertRaisesRegex(ValueError, "collides with reserved case state"):
                CaseState.create(case, capture, [])

    def test_case_manifest_tracks_inputs_without_copying_them(self) -> None:
        from wiretoutetu_core.case_state import CaseState, sha256_file

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            keylog = root / "sslkeylog.txt"
            capture.write_bytes(b"pcap fixture")
            keylog.write_text("CLIENT_RANDOM fixture", encoding="utf-8")

            state = CaseState.create(root / "case", capture, [keylog])
            manifest = state.read_manifest()

            self.assertEqual(manifest["capture"]["sha256"], sha256_file(capture))
            self.assertEqual(manifest["sidecars"][0]["sha256"], sha256_file(keylog))
            self.assertFalse((state.root / "sample.pcap").exists())
            self.assertTrue((state.root / "records").is_dir())

    def test_records_are_atomic_queryable_and_paginated(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("flows", [{"id": f"FLOW-{i:016x}"} for i in range(4)])

            first = state.query_records("flows", limit=2)
            second = state.query_records("flows", limit=2, cursor=first["next_cursor"])

            self.assertEqual([row["id"] for row in first["items"]], ["FLOW-0000000000000000", "FLOW-0000000000000001"])
            self.assertEqual([row["id"] for row in second["items"]], ["FLOW-0000000000000002", "FLOW-0000000000000003"])
            self.assertIsNone(second["next_cursor"])

    def test_checkpoint_key_changes_when_sidecar_changes(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            sidecar = root / "keys.json"
            capture.write_bytes(b"fixture")
            sidecar.write_text('{"key":"one"}', encoding="utf-8")
            state = CaseState.create(root / "case", capture, [sidecar])
            first = state.stage_cache_key("decode", include_sidecars=True)
            inventory = state.stage_cache_key("inventory", include_sidecars=False)

            sidecar.write_text('{"key":"two"}', encoding="utf-8")
            state.refresh_inputs()

            self.assertNotEqual(first, state.stage_cache_key("decode", include_sidecars=True))
            self.assertEqual(inventory, state.stage_cache_key("inventory", include_sidecars=False))

    def test_query_hard_caps_at_500_items(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("events", [{"id": f"EVT-{index}"} for index in range(600)])

            result = state.query_records("events", limit=999)

            self.assertEqual(len(result["items"]), 500)
            self.assertIsNotNone(result["next_cursor"])
            self.assertLessEqual(result["returned_bytes"], 4 * 1024 * 1024)

    def test_query_rejects_one_record_larger_than_byte_cap(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("events", [{"id": "EVT-large", "value": "x" * (4 * 1024 * 1024)}])

            with self.assertRaisesRegex(ValueError, "exceeds the 4 MiB query boundary"):
                state.query_records("events")

    def test_find_record_scans_beyond_first_page(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("evidence", [{"id": f"EVT-{index}"} for index in range(80)])

            self.assertEqual(state.find_record("evidence", "EVT-79"), {"id": "EVT-79"})
            self.assertIsNone(state.find_record("evidence", "EVT-missing"))

    def test_generated_ledger_tracks_owner_and_can_clear_one_stage(self) -> None:
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "sample.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            inventory = state.root / "objects" / "inventory.bin"
            decode = state.root / "objects" / "decode.bin"
            state.write_artifact(inventory, b"inventory", owner="inventory")
            state.write_artifact(decode, b"decode", owner="decode")

            removed = state.clear_generated("decode")

            self.assertEqual(removed, [str(decode.resolve())])
            self.assertTrue(inventory.is_file())
            self.assertFalse(decode.exists())


if __name__ == "__main__":
    unittest.main()
