import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


class RefactorStructureTests(unittest.TestCase):
    def test_pipeline_modules_are_importable(self) -> None:
        import pipeline
        from pipeline import behaviors, callbacks, flow, frameworks, manifest, native, report, sdk_keys

        self.assertIsNotNone(pipeline)
        self.assertIsNotNone(manifest)
        self.assertIsNotNone(frameworks)
        self.assertIsNotNone(behaviors)
        self.assertIsNotNone(callbacks)
        self.assertIsNotNone(sdk_keys)
        self.assertIsNotNone(flow)
        self.assertIsNotNone(report)
        self.assertIsNotNone(native)

    def test_cli_help_still_works_after_refactor(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "investigate_android_app.py"), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("investigate_android_app.py", result.stdout)
        self.assertIn("--output-dir", result.stdout)
        self.assertIn("--mode", result.stdout)


if __name__ == "__main__":
    unittest.main()
