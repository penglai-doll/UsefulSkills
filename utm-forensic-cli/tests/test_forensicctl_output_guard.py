"""Tests for forensicctl.py output-directory guard and plan generation.

SKILL.md requires the case output directory to live OUTSIDE the directory
that contains the evidence file (no artifacts or temp files next to the
evidence). These tests pin that contract plus the plan ssh-branch cleanup.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import forensicctl  # noqa: E402


def ns(output_dir: str | None) -> argparse.Namespace:
    return argparse.Namespace(output_dir=output_dir)


class OutputDirGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        self.evidence = self.evidence_dir / "case.E01"
        self.evidence.write_bytes(b"x" * 1024)

    def test_rejects_evidence_parent_directory(self) -> None:
        with self.assertRaises(ValueError):
            forensicctl.output_dir_for(ns(str(self.evidence_dir)), self.evidence, "preflight")

    def test_rejects_subdirectory_of_evidence_parent(self) -> None:
        with self.assertRaises(ValueError):
            forensicctl.output_dir_for(ns(str(self.evidence_dir / "out")), self.evidence, "preflight")

    def test_rejects_path_under_the_evidence_file(self) -> None:
        with self.assertRaises(ValueError):
            forensicctl.output_dir_for(ns(str(self.evidence / "sub")), self.evidence, "preflight")

    def test_rejects_the_evidence_path_itself(self) -> None:
        with self.assertRaises(ValueError):
            forensicctl.output_dir_for(ns(str(self.evidence)), self.evidence, "preflight")

    def test_allows_directory_outside_the_evidence_directory(self) -> None:
        outside = self.root / "case-out"
        path = forensicctl.output_dir_for(ns(str(outside)), self.evidence, "preflight")
        self.assertEqual(path, outside.resolve())
        self.assertTrue(outside.is_dir())
        # nothing may have been created next to the evidence
        self.assertEqual(sorted(p.name for p in self.evidence_dir.iterdir()), ["case.E01"])

    def test_cli_rejected_output_dir_exits_2(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "forensicctl.py"), "preflight", str(self.evidence),
             "--output-dir", str(self.evidence_dir), "--json"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=60,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("outside the evidence directory", proc.stderr)


class PlanGenerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir()
        self.evidence = self.evidence_dir / "case.E01"
        self.evidence.write_bytes(b"x" * 1024)

    def plan_args(self, transport: str) -> argparse.Namespace:
        return argparse.Namespace(
            evidence=str(self.evidence),
            vm="case-vm",
            transport=transport,
            guest_evidence=None,
            guest_output=None,
            output_dir=str(self.root / "case-out"),
            disposable=False,
        )

    def test_ssh_plan_has_single_start_command(self) -> None:
        result = forensicctl.plan(self.plan_args("ssh"))
        steps = {step["id"]: step for step in result["steps"]}
        start_cmd = steps["start-vm"]["command"]
        self.assertEqual(start_cmd.count("utmctl start"), 1)
        self.assertIn("ssh", steps["health-check"]["command"])

    def test_guest_agent_plan_exec_command(self) -> None:
        result = forensicctl.plan(self.plan_args("guest-agent"))
        steps = {step["id"]: step for step in result["steps"]}
        self.assertIn("utmctl exec", steps["health-check"]["command"])
        self.assertEqual(steps["start-vm"]["command"].count("utmctl start"), 1)


if __name__ == "__main__":
    unittest.main()
