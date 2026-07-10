from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.common.output_layout import (
    default_case_id,
    prepare_case_paths,
    resolve_case_paths,
    safe_case_id,
)


class OutputLayoutV1Tests(unittest.TestCase):
    def test_case_paths_live_under_invocation_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            resolved_root = root.resolve()
            paths = resolve_case_paths(root, "incident-01")
            self.assertEqual(paths.cache_dir, resolved_root / "cache" / "incident-01")
            self.assertEqual(paths.report_dir, resolved_root / "report" / "incident-01")
            self.assertEqual(paths.report_path, paths.report_dir / "log-analysis-report.md")

    def test_existing_case_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = resolve_case_paths(Path(tmp), "incident-01")
            prepare_case_paths(paths, allow_existing=False)
            with self.assertRaises(FileExistsError):
                prepare_case_paths(paths, allow_existing=False)

    def test_prepare_case_paths_self_ignores_outputs_in_any_git_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=workdir, check=True)

            paths = resolve_case_paths(workdir, "incident-01")
            prepare_case_paths(paths, allow_existing=False)
            cache_ignore = paths.cache_dir / ".gitignore"
            report_ignore = paths.report_dir / ".gitignore"
            self.assertTrue(cache_ignore.is_file(), "expected case-local cache .gitignore")
            self.assertTrue(report_ignore.is_file(), "expected case-local report .gitignore")
            self.assertEqual(cache_ignore.read_bytes(), b"*\n")
            self.assertEqual(report_ignore.read_bytes(), b"*\n")
            self.assertFalse((paths.cache_dir.parent / ".gitignore").exists())
            self.assertFalse((paths.report_dir.parent / ".gitignore").exists())
            paths.manifest_path.write_text("{}", encoding="utf-8")
            (paths.cache_dir / "log-inventory.json").write_text("{}", encoding="utf-8")
            paths.report_path.write_text("# report\n", encoding="utf-8")

            status = subprocess.run(
                ["git", "status", "--short", "--untracked-files=all"],
                cwd=workdir,
                text=True,
                capture_output=True,
                check=True,
            )

            self.assertEqual(status.stdout, "")

    def test_prepare_case_paths_preserves_existing_case_local_gitignores(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = resolve_case_paths(Path(tmp), "incident-01")
            paths.cache_dir.mkdir(parents=True)
            paths.report_dir.mkdir(parents=True)
            cache_policy = b"!keep-cache.txt\n\xff\n"
            report_policy = b"!keep-report.txt\n\x00\n"
            (paths.cache_dir / ".gitignore").write_bytes(cache_policy)
            (paths.report_dir / ".gitignore").write_bytes(report_policy)

            prepare_case_paths(paths, allow_existing=True)

            self.assertEqual((paths.cache_dir / ".gitignore").read_bytes(), cache_policy)
            self.assertEqual((paths.report_dir / ".gitignore").read_bytes(), report_policy)

    def test_default_case_id_is_safe_and_deterministic_for_fixed_time(self):
        now = datetime(2026, 7, 10, 12, 30, 45)
        case_id = default_case_id([Path("/srv/logs/nginx")], now=now)
        self.assertEqual(case_id, "nginx-20260710-123045")
        self.assertEqual(safe_case_id("趣工宝 / incident #1"), "incident-1")


if __name__ == "__main__":
    unittest.main()
