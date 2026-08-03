from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


class PreflightTests(unittest.TestCase):
    def test_missing_tshark_is_unavailable_with_install_gate(self) -> None:
        from wiretoutetu_core.preflight import run_preflight

        with mock.patch("wiretoutetu_core.preflight.shutil.which", return_value=None):
            result = run_preflight()

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["tools"]["tshark"]["status"], "unavailable")
        self.assertIn("confirm", " ".join(result["next_actions"]).lower())

    def test_platform_route_distinguishes_wsl(self) -> None:
        from wiretoutetu_core.preflight import detect_platform_route

        with mock.patch("wiretoutetu_core.preflight.platform.system", return_value="Linux"), mock.patch(
            "wiretoutetu_core.preflight.platform.release", return_value="6.1.0-microsoft-standard-WSL2"
        ):
            self.assertEqual(detect_platform_route(), "wsl")


if __name__ == "__main__":
    unittest.main()
