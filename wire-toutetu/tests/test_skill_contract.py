from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
CLI = SKILL_ROOT / "scripts" / "wiretoutetu.py"


class SkillSurfaceTests(unittest.TestCase):
    def test_skill_has_discoverable_entrypoints(self) -> None:
        self.assertTrue((SKILL_ROOT / "SKILL.md").is_file())
        self.assertTrue((SKILL_ROOT / "agents" / "openai.yaml").is_file())
        self.assertTrue(CLI.is_file())

    def test_cli_help_lists_every_public_command(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CLI), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "preflight",
            "analyze",
            "query",
            "catalog",
            "export",
            "cleanup",
            "experience",
        ):
            self.assertIn(command, result.stdout)


if __name__ == "__main__":
    unittest.main()
