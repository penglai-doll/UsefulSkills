from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
CLI = SKILL_ROOT / "scripts" / "wiretoutetu.py"


class CliContractTests(unittest.TestCase):
    def run_cli(self, *arguments: str) -> tuple[int, dict]:
        completed = subprocess.run(
            [sys.executable, str(CLI), *arguments], capture_output=True, text=True, encoding="utf-8"
        )
        return completed.returncode, json.loads(completed.stdout)

    def test_preflight_and_catalog_use_fixed_envelope(self) -> None:
        code, preflight = self.run_cli("preflight", "--json")
        catalog_code, catalog = self.run_cli("catalog", "--signal", "http", "--json")

        self.assertEqual(code, 0)
        self.assertEqual(catalog_code, 0)
        self.assertEqual(set(preflight), set(catalog))
        self.assertIn("webshell.behinder", [row["plugin_id"] for row in catalog["summary"]["plugins"]])

    def test_invalid_arguments_still_return_json_envelope(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(CLI), "query"], capture_output=True, text=True, encoding="utf-8"
        )

        result = json.loads(completed.stdout)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["stage"], "arguments")

    def test_query_enforces_view_and_pagination(self) -> None:
        sys.path.insert(0, str(SKILL_ROOT / "scripts"))
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "x.pcap"
            capture.write_bytes(b"x")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("events", [{"id": f"EVT-{i}"} for i in range(3)])

            code, result = self.run_cli("query", "--case-dir", str(state.root), "--view", "timeline", "--limit", "2")

            self.assertEqual(code, 0)
            self.assertEqual(result["counts"]["returned"], 2)
            self.assertTrue(result["summary"]["next_cursor"])

    def test_query_id_is_not_limited_to_the_first_page(self) -> None:
        sys.path.insert(0, str(SKILL_ROOT / "scripts"))
        from wiretoutetu_core.case_state import CaseState

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "x.pcap"
            capture.write_bytes(b"x")
            state = CaseState.create(root / "case", capture, [])
            state.write_records("evidence", [{"id": f"EVT-{i}"} for i in range(80)])

            code, result = self.run_cli(
                "query", "--case-dir", str(state.root), "--view", "evidence", "--id", "EVT-79"
            )

            self.assertEqual(code, 0)
            self.assertEqual(result["summary"]["items"], [{"id": "EVT-79"}])
            self.assertIsNone(result["summary"]["next_cursor"])


if __name__ == "__main__":
    unittest.main()
