from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


class CaseStateTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
