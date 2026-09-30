"""Permission denial is not proof that an evidence device is read-only."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import case_state


class MountRevalidationTests(unittest.TestCase):
    def test_access_denied_stays_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mount = root / "mounted"
            mount.mkdir()
            (root / "mounts.json").write_text(json.dumps({"path": str(mount), "claimed_read_only": True}) + "\n", encoding="utf-8")
            with patch.object(case_state, "load_session", return_value={"case_id": "test"}), \
                 patch.object(case_state, "evidence_still_matches", return_value=True), \
                 patch.object(case_state.os, "access", return_value=False):
                result = case_state.resume(root, 50)
            record = result["revalidation"]["mounts"]["items"][0]
            self.assertIsNone(record["read_only"])
            self.assertFalse(record["access_writable"])
            self.assertTrue(record["claimed_read_only"])
            self.assertEqual(record["read_only_confidence"], "not-verified")


if __name__ == "__main__":
    unittest.main()
