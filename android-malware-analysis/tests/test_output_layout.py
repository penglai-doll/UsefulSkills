import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import investigate_android_app


class OutputLayoutTests(unittest.TestCase):
    def test_default_layout_uses_report_and_cache_directories_in_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.apk"
            target.write_bytes(b"not-a-real-apk")

            layout = investigate_android_app.build_output_layout(target, None)

            self.assertEqual(layout["root"], Path(tmpdir).resolve())
            self.assertEqual(layout["report_dir"], (Path(tmpdir) / "报告" / "sample").resolve())
            self.assertEqual(layout["cache_dir"], (Path(tmpdir) / "cache" / "sample").resolve())

    def test_custom_output_dir_keeps_report_and_cache_split_under_given_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "sample.apk"
            target.write_bytes(b"not-a-real-apk")
            output_root = Path(tmpdir) / "artifacts"

            layout = investigate_android_app.build_output_layout(target, str(output_root))

            self.assertEqual(layout["root"], output_root.resolve())
            self.assertEqual(layout["report_dir"], (output_root / "报告" / "sample").resolve())
            self.assertEqual(layout["cache_dir"], (output_root / "cache" / "sample").resolve())


if __name__ == "__main__":
    unittest.main()
