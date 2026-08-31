"""Tests for nbd_evidence_server.py durability and consistency fixes.

Covers (stdlib unittest only):
- the dirty bitmap is saved on abnormal disconnect (ConnectionError), on
  clean CMD_DISC, on CMD_FLUSH and by the periodic every-200-writes path;
- a failed bitmap save never crashes the connection handler;
- startup repairs a bitmap/diff pair that cannot be trusted (missing diff,
  wrong bitmap length, dirty blocks beyond the diff length) so reads fall
  back to the base image instead of silently returning zeros;
- a dirty block damaged after startup fails the read with EIO, never zeros;
- CLI port parsing exits 2 with a clean message;
- nbd_selftest.py still passes against a live server (wire-format guard).
"""
from __future__ import annotations

import contextlib
import io
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import nbd_evidence_server as nbd  # noqa: E402

BLOCK = nbd.BLOCK


def make_base(directory: Path, blocks: int = 8) -> Path:
    """Base image whose block i is filled with the repeating byte 0x10 + i."""
    base = directory / "base.img"
    base.write_bytes(b"".join(bytes([0x10 + i]) * BLOCK for i in range(blocks)))
    return base


def bit_set(bitmap_bytes: bytes, idx: int) -> bool:
    return bool(bitmap_bytes[idx >> 3] & (0x80 >> (idx & 7)))


class FakeConn:
    """Socket stand-in: serves a scripted payload, then reports the peer gone."""

    def __init__(self, payload: bytes) -> None:
        self._buf = bytearray(payload)
        self.sent: list[bytes] = []
        self.closed = False
        self.timeout = None

    def recv(self, n: int) -> bytes:
        if not self._buf:
            raise ConnectionError("peer closed")
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def sendall(self, data: bytes) -> None:
        self.sent.append(bytes(data))

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def close(self) -> None:
        self.closed = True


def handshake() -> bytes:
    return struct.pack(">I", 1) + struct.pack(">QII", nbd.IHAVEOPT_MAGIC, nbd.OPT_EXPORT_NAME, 0)


def request(ctype: int, handle: int, offset: int = 0, length: int = 0) -> bytes:
    return struct.pack(">IHHQQI", nbd.REQUEST_MAGIC, 0, ctype, handle, offset, length)


def quiet_serve(conn: FakeConn, layer: nbd.DiffLayer) -> str:
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        nbd.serve_client(conn, ("test-client", 0), layer)
    return buf.getvalue()


def quiet_init(base: Path, diff: Path, bitmap: Path) -> tuple[nbd.DiffLayer, str]:
    with contextlib.redirect_stdout(io.StringIO()) as buf:
        layer = nbd.DiffLayer(str(base), str(diff), str(bitmap))
    return layer, buf.getvalue()


class BitmapDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.base = make_base(self.root)
        self.diff = self.root / "diff.bin"
        self.bitmap = self.root / "bitmap.bin"

    def fresh_layer(self) -> nbd.DiffLayer:
        layer, _ = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        return layer

    def test_bitmap_saved_on_abnormal_disconnect(self) -> None:
        layer = self.fresh_layer()
        payload = handshake()
        for idx in (1, 3, 5):
            payload += request(nbd.CMD_WRITE, 100 + idx, idx * BLOCK, 512) + bytes([0x41 + idx]) * 512
        conn = FakeConn(payload)
        out = quiet_serve(conn, layer)
        self.assertTrue(conn.closed)
        self.assertIn("abnormal disconnect", out)
        # only 3 writes: far below the periodic-200 threshold, so the on-disk
        # bitmap can only have come from the abnormal-disconnect save path
        bits = self.bitmap.read_bytes()
        for idx in (1, 3, 5):
            self.assertTrue(bit_set(bits, idx), "block %d must stay dirty" % idx)
        self.assertFalse(bit_set(bits, 0))
        # diff bytes were flushed too, not just the bitmap
        with open(self.diff, "rb") as f:
            f.seek(3 * BLOCK)
            self.assertEqual(f.read(512), bytes([0x44]) * 512)

    def test_bitmap_saved_on_clean_disconnect(self) -> None:
        layer = self.fresh_layer()
        payload = (handshake()
                   + request(nbd.CMD_WRITE, 1, 2 * BLOCK, 512) + b"C" * 512
                   + request(nbd.CMD_DISC, 2))
        conn = FakeConn(payload)
        out = quiet_serve(conn, layer)
        self.assertIn("client disconnect", out)
        self.assertTrue(bit_set(self.bitmap.read_bytes(), 2))

    def test_cmd_flush_saves_bitmap(self) -> None:
        layer = self.fresh_layer()
        calls: list[int] = []
        original = layer.save_bitmap

        def counting_save() -> None:
            calls.append(1)
            original()

        layer.save_bitmap = counting_save
        payload = (handshake()
                   + request(nbd.CMD_WRITE, 1, 2 * BLOCK, 512) + b"C" * 512
                   + request(nbd.CMD_FLUSH, 2))
        conn = FakeConn(payload)
        quiet_serve(conn, layer)
        # one save from CMD_FLUSH + one from the disconnect finally-block
        self.assertEqual(len(calls), 2)
        self.assertTrue(bit_set(self.bitmap.read_bytes(), 2))
        replies = conn.sent
        self.assertEqual(struct.unpack(">IIQ", replies[-1]), (nbd.REPLY_MAGIC, 0, 2))

    def test_periodic_save_every_200_writes(self) -> None:
        layer = self.fresh_layer()
        calls: list[int] = []
        original = layer.save_bitmap

        def counting_save() -> None:
            calls.append(1)
            original()

        layer.save_bitmap = counting_save
        payload = handshake()
        for i in range(200):
            payload += request(nbd.CMD_WRITE, i, (i % 7) * BLOCK, 16) + b"P" * 16
        conn = FakeConn(payload)
        quiet_serve(conn, layer)
        # one periodic save at write #200 + one from the disconnect finally-block
        self.assertEqual(len(calls), 2)
        self.assertTrue(bit_set(self.bitmap.read_bytes(), 6))

    def test_failed_bitmap_save_does_not_crash_handler(self) -> None:
        layer = self.fresh_layer()

        def boom() -> None:
            raise OSError("disk full")

        layer.save_bitmap = boom
        payload = handshake() + request(nbd.CMD_WRITE, 1, BLOCK, 512) + b"X" * 512
        conn = FakeConn(payload)
        out = quiet_serve(conn, layer)  # must not raise
        self.assertTrue(conn.closed)
        self.assertIn("failed to save bitmap", out)

    def test_socket_timeout_applied_to_connection(self) -> None:
        layer = self.fresh_layer()
        conn = FakeConn(handshake())
        quiet_serve(conn, layer)
        self.assertEqual(conn.timeout, nbd.CONN_IDLE_TIMEOUT)


class StartupConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.base = make_base(self.root)
        self.diff = self.root / "diff.bin"
        self.bitmap = self.root / "bitmap.bin"

    def test_dirty_bitmap_with_missing_diff_resets_clean(self) -> None:
        self.bitmap.write_bytes(bytes([0x80]))  # block 0 dirty, diff file absent
        layer, out = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        self.assertIn("missing", out)
        self.assertFalse(layer._dirty(0))
        # falls back to the untouched base, never to silent zeros
        self.assertEqual(layer.read(0, BLOCK), bytes([0x10]) * BLOCK)

    def test_bitmap_length_mismatch_resets_clean(self) -> None:
        self.bitmap.write_bytes(b"\xff\xff\xff")  # 3 bytes, 8 blocks need 1
        layer, out = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        self.assertIn("resetting to all-clean", out)
        self.assertEqual(layer._dirty_count(), 0)
        self.assertEqual(layer.read(2 * BLOCK, BLOCK), bytes([0x12]) * BLOCK)

    def test_dirty_blocks_beyond_diff_length_are_cleared(self) -> None:
        self.diff.write_bytes(b"D" * BLOCK + b"E" * BLOCK)  # covers blocks 0-1
        self.bitmap.write_bytes(bytes([0x84]))               # blocks 0 and 5 dirty
        layer, out = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        self.assertIn("clearing", out)
        self.assertTrue(layer._dirty(0))   # backed by diff bytes: kept
        self.assertFalse(layer._dirty(5))  # bytes missing: cleared
        self.assertEqual(layer.read(0, BLOCK), b"D" * BLOCK)
        self.assertEqual(layer.read(5 * BLOCK, BLOCK), bytes([0x15]) * BLOCK)

    def test_damaged_dirty_block_raises_instead_of_returning_zeros(self) -> None:
        layer, _ = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        layer._set(0)
        layer.diff.truncate(100)  # damage after startup: bytes are now short
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(nbd.DiffReadError):
                layer.read(0, BLOCK)
        self.assertEqual(layer.read_failures, 1)

    def test_server_replies_eio_for_damaged_dirty_block(self) -> None:
        layer, _ = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        layer._set(0)
        layer.diff.truncate(100)
        conn = FakeConn(handshake() + request(nbd.CMD_READ, 9, 0, 512))
        out = quiet_serve(conn, layer)
        self.assertIn("EIO", out)
        magic, err, handle = struct.unpack(">IIQ", conn.sent[-1])
        self.assertEqual((magic, err, handle), (nbd.REPLY_MAGIC, nbd.NBD_EIO, 9))
        self.assertEqual(len(conn.sent[-1]), 16)  # error reply carries no data

    def test_healthy_dirty_block_still_serves_diff_bytes(self) -> None:
        layer, _ = quiet_init(self.base, self.diff, self.bitmap)
        self.addCleanup(layer.close)
        self.assertTrue(layer.write(4 * BLOCK, b"Z" * 512))
        self.assertEqual(layer.read(4 * BLOCK, 512), b"Z" * 512)
        self.assertEqual(layer.read(4 * BLOCK + 512, 512), bytes([0x14]) * 512)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.base = make_base(root)
        self.diff = root / "diff.bin"
        self.bitmap = root / "bitmap.bin"

    def run_server_cli(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "nbd_evidence_server.py"), str(self.base),
             str(self.diff), str(self.bitmap), *extra],
            capture_output=True, encoding="utf-8", errors="replace", timeout=30,
        )

    def test_non_numeric_port_exits_2(self) -> None:
        proc = self.run_server_cli("not-a-port")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("port", proc.stderr.lower())

    def test_port_out_of_range_exits_2(self) -> None:
        proc = self.run_server_cli("70000")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("range", proc.stderr.lower())

    def test_missing_arguments_exit_2(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "nbd_evidence_server.py"), str(self.base)],
            capture_output=True, encoding="utf-8", errors="replace", timeout=30,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage", proc.stderr.lower())


class SelftestIntegrationTests(unittest.TestCase):
    def test_selftest_passes_against_live_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmpname:
            root = Path(tmpname)
            base = make_base(root)
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            server = subprocess.Popen(
                [sys.executable, str(SCRIPTS_DIR / "nbd_evidence_server.py"), str(base),
                 str(root / "diff.bin"), str(root / "bitmap.bin"), str(port)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail("server did not start listening")
                        time.sleep(0.1)
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS_DIR / "nbd_selftest.py"), str(port)],
                    capture_output=True, encoding="utf-8", errors="replace", timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("SELF-TEST PASS", result.stdout)
            finally:
                server.terminate()
                try:
                    server.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.communicate()


if __name__ == "__main__":
    unittest.main()
