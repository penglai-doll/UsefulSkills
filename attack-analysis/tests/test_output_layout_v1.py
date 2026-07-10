from __future__ import annotations

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

    def test_default_case_id_is_safe_and_deterministic_for_fixed_time(self):
        now = datetime(2026, 7, 10, 12, 30, 45)
        case_id = default_case_id([Path("/srv/logs/nginx")], now=now)
        self.assertEqual(case_id, "nginx-20260710-123045")
        self.assertEqual(safe_case_id("趣工宝 / incident #1"), "incident-1")


if __name__ == "__main__":
    unittest.main()
