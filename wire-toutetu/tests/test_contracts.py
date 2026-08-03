from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


class ContractTests(unittest.TestCase):
    def test_envelope_has_fixed_shape_without_confidence(self) -> None:
        from wiretoutetu_core.contracts import make_envelope

        envelope = make_envelope(
            status="ok",
            case_dir="C:/case",
            stage="preflight",
            summary={"message": "ready"},
            completeness="complete",
        )

        self.assertEqual(
            set(envelope),
            {
                "schema_version",
                "status",
                "case_dir",
                "stage",
                "summary",
                "counts",
                "routes",
                "next_actions",
                "errors",
                "completeness",
            },
        )
        self.assertNotIn("confidence", json.dumps(envelope))
        self.assertEqual(
            set(envelope["routes"]),
            {
                "selected_plugins",
                "recommended_references",
                "optional_references",
                "recommended_experience",
            },
        )

    def test_evidence_ids_are_deterministic_and_namespaced(self) -> None:
        from wiretoutetu_core.contracts import stable_evidence_id

        material = {"capture_sha256": "abc", "stream": 7}
        first = stable_evidence_id("FLOW", material)
        second = stable_evidence_id("FLOW", dict(reversed(list(material.items()))))

        self.assertEqual(first, second)
        self.assertRegex(first, r"^FLOW-[0-9a-f]{16}$")
        self.assertNotEqual(first, stable_evidence_id("TXN", material))

    def test_unknown_status_values_are_rejected(self) -> None:
        from wiretoutetu_core.contracts import make_envelope

        with self.assertRaisesRegex(ValueError, "completeness"):
            make_envelope(status="ok", stage="x", completeness="mostly")


if __name__ == "__main__":
    unittest.main()
