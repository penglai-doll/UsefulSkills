"""Simulation outputs must never alter the original image through aliases."""
import contextlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from nbd_evidence_server import DiffLayer
from make_qcow2_overlay import main as make_overlay


class OutputIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base.img"
        self.original = b"evidence" * 512
        self.base.write_bytes(self.original)

    def test_same_paths_rejected_before_any_write(self):
        for diff, bitmap in [(self.base, self.root / "bitmap"), (self.root / "diff", self.base), (self.root / "shared", self.root / "shared")]:
            with self.subTest(diff=diff, bitmap=bitmap), self.assertRaises(ValueError):
                DiffLayer(str(self.base), str(diff), str(bitmap))
            self.assertEqual(self.base.read_bytes(), self.original)
        with self.assertRaises(ValueError):
            make_overlay(str(self.base), str(self.base))
        self.assertEqual(self.base.read_bytes(), self.original)

    def test_hardlink_alias_rejected(self):
        alias = self.root / "alias.img"
        try:
            os.link(self.base, alias)
        except OSError as exc:
            self.skipTest(str(exc))
        with self.assertRaises(ValueError):
            DiffLayer(str(self.base), str(alias), str(self.root / "bitmap"))
        with self.assertRaises(ValueError):
            make_overlay(str(self.base), str(alias))
        self.assertEqual(self.base.read_bytes(), self.original)

    def test_bitmap_alias_added_after_startup_cannot_modify_evidence(self):
        bitmap = self.root / "bitmap"
        with contextlib.redirect_stdout(io.StringIO()):
            layer = DiffLayer(str(self.base), str(self.root / "diff"), str(bitmap))
        self.addCleanup(layer.close)
        os.link(self.base, bitmap)
        with self.assertRaises(ValueError):
            layer.save_bitmap()
        self.assertEqual(self.base.read_bytes(), self.original)

    def test_overlay_refuses_existing_output_and_creates_new_one(self):
        output = self.root / "overlay.qcow2"
        output.write_bytes(b"existing")
        with self.assertRaises(FileExistsError):
            make_overlay(str(self.base), str(output))
        self.assertEqual(output.read_bytes(), b"existing")
        output.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            make_overlay(str(self.base), str(output))
        self.assertEqual(output.read_bytes()[:4], b"QFI\xfb")
        self.assertEqual(self.base.read_bytes(), self.original)


if __name__ == "__main__":
    unittest.main()
