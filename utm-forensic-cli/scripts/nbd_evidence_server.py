#!/usr/bin/env python3
"""Read-only-evidence NBD server with an optional writable diff layer.

Battle-tested forensic transport for UTM simulation boots: the App Store
(sandboxed) build of UTM cannot open evidence files outside its container,
but QEMU may open outbound TCP connections. Serving the image over NBD on
loopback therefore gives the VM a disk channel that the sandbox cannot
block, while keeping the evidence file physically read-only.

Safety contract:
- The base image is opened O_RDONLY and never reopened otherwise. Pair this
  with `chflags uchg` on the evidence for kernel-level enforcement.
- Guest WRITE/FLUSH/TRIM commands are served from a sparse diff file in the
  case output directory (4 KiB-block granularity, bitmap-indexed). The base
  file has no write code path at all.
- Transmission flags advertise a writable export so the guest kernel and
  journalled filesystems behave normally; every write lands in the diff.
- Durability: the dirty bitmap is persisted on CMD_FLUSH, every 200 writes,
  and on every disconnect (clean or abnormal), so a killed QEMU/VM never
  loses diff writes to a stale bitmap.
- Consistency: startup validates the bitmap against the diff and clears,
  with a loud warning, any dirty bit whose diff bytes are missing; reads
  never fabricate zeros for a dirty extent (EIO is returned instead).

Protocol: NBD fixed-newstyle. Supports NBD_OPT_EXPORT_NAME and NBD_OPT_GO
handshakes; replies ERR_UNSUP to modern options, which QEMU handles by
falling back to EXPORT_NAME.

Wire-format notes (verified against QEMU 9.x in production use):
- Server handshake flags are u16; client flags are u32 (asymmetric!).
- Every client option frame carries the 8-byte IHAVEOPT magic before the
  u32 option and u32 length: parse the 16-byte header as ">QII".
- NBD_REP_INFO payload for export info is ">HQH" (u16 type, u64 size, u16
  transmission flags); reply headers are ">QIII" (20 bytes).

Usage:
    python3 nbd_evidence_server.py <base-image> <diff-file> <bitmap-file> <port>

Always run scripts/nbd_selftest.py against the server BEFORE booting the VM;
the self-test catches wire-format regressions in seconds instead of wasting
slow TCG boot cycles.
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time

BLOCK = 4096
NBD_MAGIC = 0x4E42444D41474943
IHAVEOPT_MAGIC = 0x49484156454F5054
REPLY_MAGIC = 0x67446698
REQUEST_MAGIC = 0x25609513
REP_MAGIC = 0x3E889045565A9
NBD_EIO = 5     # unreadable extent (dirty block with missing diff bytes)
NBD_EINVAL = 22

# Idle seconds before a (possibly half-open) connection is dropped. Generous
# enough for a booted but idle VM, bounded so threads cannot hang forever.
CONN_IDLE_TIMEOUT = 600.0

OPT_EXPORT_NAME = 1
OPT_ABORT = 2
OPT_GO = 5
REP_ACK = 1
REP_INFO = 3
REP_ERR_UNSUP = 0x80000001
INFO_EXPORT = 0

CMD_READ = 0
CMD_WRITE = 1
CMD_DISC = 2
CMD_FLUSH = 3
CMD_TRIM = 4

def log(msg: str) -> None:
    sys.stdout.write("[nbd %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()

def pread_readonly(handle, n: int, offset: int) -> bytes:
    """Positional read on the read-only base; os.pread where available.

    Windows has no os.pread; every caller holds the DiffLayer lock and the
    handle is opened read-only, so seek+read is equivalent there. The base
    still has no write code path on any platform.
    """
    if hasattr(os, "pread"):
        return os.pread(handle.fileno(), n, offset)
    handle.seek(offset)
    return handle.read(n)

class DiffReadError(Exception):
    """An extent marked dirty is missing its diff bytes; refuse to invent data."""

class DiffLayer:
    """Sparse 4 KiB-block diff over a read-only base file."""

    def __init__(self, base_path: str, diff_path: str, bitmap_path: str) -> None:
        self.base = open(base_path, "rb", buffering=0)
        self.base.seek(0, os.SEEK_END)
        self.size = self.base.tell()
        self.nblocks = (self.size + BLOCK - 1) // BLOCK
        self.diff_path = diff_path
        self.bitmap_path = bitmap_path
        self.lock = threading.Lock()
        self.read_failures = 0  # extents failed with EIO instead of fabricated data
        expected = (self.nblocks + 7) // 8
        self.bitmap = bytearray(expected)
        if os.path.exists(bitmap_path):
            with open(bitmap_path, "rb") as f:
                raw = f.read()
            if len(raw) != expected:
                log("WARNING: bitmap is %d bytes but %d blocks need %d; dirty state "
                    "is unprovable -> resetting to all-clean" % (len(raw), self.nblocks, expected))
            else:
                self.bitmap = bytearray(raw)
                if self.nblocks % 8:
                    # drop stray bits that index blocks beyond the base size
                    self.bitmap[-1] &= (0xFF << (8 - self.nblocks % 8)) & 0xFF
        diff_exists = os.path.exists(diff_path)
        self.diff = open(diff_path, "r+b" if diff_exists else "w+b")
        self.diff.seek(0, os.SEEK_END)
        diff_size = self.diff.tell()
        # A dirty bit whose diff bytes do not exist must never be served (that
        # would silently return zeros); clear such bits loudly instead so reads
        # fall back to the untouched base image.
        dropped = self._clear_dirty_beyond(diff_size // BLOCK)
        if dropped:
            if not diff_exists:
                log("WARNING: diff file %s is missing but the bitmap had %d dirty "
                    "blocks; those simulation writes are LOST -> clearing the bits, "
                    "reads fall back to the base image" % (diff_path, dropped))
            else:
                log("WARNING: diff file is only %d bytes; clearing %d dirty blocks "
                    "whose bytes are missing, reads fall back to the base image"
                    % (diff_size, dropped))
            self.save_bitmap()
        log("loaded bitmap: %d dirty blocks" % self._dirty_count())

    def _dirty_count(self) -> int:
        if hasattr(int, "bit_count"):  # Python 3.10+: C-speed for large bitmaps
            return int.from_bytes(self.bitmap, "big").bit_count()
        return sum(bin(b).count("1") for b in self.bitmap)

    def _dirty(self, idx: int) -> bool:
        return bool(self.bitmap[idx >> 3] & (0x80 >> (idx & 7)))

    def _set(self, idx: int) -> None:
        self.bitmap[idx >> 3] |= 0x80 >> (idx & 7)

    def _clear_dirty_beyond(self, limit: int) -> int:
        """Clear dirty bits for blocks >= limit (their bytes cannot exist)."""
        if limit >= self.nblocks:
            return 0
        if not any(self.bitmap[limit >> 3:]):
            return 0
        dropped = 0
        for idx in range(limit, self.nblocks):
            if self._dirty(idx):
                self.bitmap[idx >> 3] &= ~(0x80 >> (idx & 7)) & 0xFF
                dropped += 1
        return dropped

    def flush(self) -> None:
        """Push diff bytes out of Python buffers down to stable storage."""
        self.diff.flush()
        os.fsync(self.diff.fileno())

    def save_bitmap(self) -> None:
        # Order matters: diff bytes must reach the disk before the bitmap
        # claims them. If we crash between the two steps, the startup guard
        # clears dirty bits without data (safe fallback to base) instead of
        # the reverse (dirty bits whose data never existed).
        self.flush()
        with self.lock:
            snapshot = bytes(self.bitmap)
        with open(self.bitmap_path, "wb") as f:
            f.write(snapshot)
            f.flush()
            os.fsync(f.fileno())
        log("bitmap saved (%d dirty blocks)" % self._dirty_count())

    def close(self) -> None:
        self.base.close()
        self.diff.close()

    def read(self, offset: int, length: int) -> bytes | None:
        if offset < 0 or offset + length > self.size:
            return None
        out = bytearray(length)
        pos = 0
        with self.lock:
            while pos < length:
                off = offset + pos
                idx = off // BLOCK
                inblock = off % BLOCK
                n = min(BLOCK - inblock, length - pos)
                if self._dirty(idx):
                    self.diff.seek(idx * BLOCK + inblock)
                    chunk = self.diff.read(n)
                    if len(chunk) == n:
                        out[pos:pos + n] = chunk
                    else:
                        # Forensic rule: never fabricate zeros for a dirty
                        # extent. Fail the read (client sees EIO) instead.
                        self.read_failures += 1
                        log("ERROR: dirty block %d: diff has %d of %d bytes; "
                            "failing the read with EIO instead of returning zeros"
                            % (idx, len(chunk), n))
                        raise DiffReadError("dirty block %d is missing diff bytes" % idx)
                else:
                    chunk = pread_readonly(self.base, n, off)
                    if len(chunk) == n:
                        out[pos:pos + n] = chunk
                    else:
                        self.read_failures += 1
                        log("ERROR: base read at %d returned %d of %d bytes; "
                            "failing the read with EIO" % (off, len(chunk), n))
                        raise DiffReadError("base extent at %d is short" % off)
                pos += n
        return bytes(out)

    def write(self, offset: int, data: bytes) -> bool:
        if offset < 0 or offset + len(data) > self.size:
            return False
        with self.lock:
            pos = 0
            while pos < len(data):
                off = offset + pos
                idx = off // BLOCK
                inblock = off % BLOCK
                n = min(BLOCK - inblock, len(data) - pos)
                if not self._dirty(idx):
                    # initialize the block from base so partial writes merge
                    base_blk = pread_readonly(self.base, BLOCK, idx * BLOCK)
                    base_blk = base_blk.ljust(BLOCK, b"\x00")
                    self.diff.seek(idx * BLOCK)
                    self.diff.write(base_blk)
                    self._set(idx)
                self.diff.seek(idx * BLOCK + inblock)
                self.diff.write(data[pos:pos + n])
                pos += n
        return True

def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf

def _save_bitmap_safe(layer: DiffLayer) -> None:
    """Best-effort bitmap save; a failed save must never kill the handler."""
    try:
        layer.save_bitmap()
    except Exception as exc:
        log("ERROR: failed to save bitmap: %s: %s" % (type(exc).__name__, exc))

def serve_client(conn: socket.socket, addr, layer: DiffLayer) -> None:
    log("client %s connected" % (addr,))
    # Bound every recv/send so a half-open connection cannot pin a thread.
    conn.settimeout(CONN_IDLE_TIMEOUT)
    try:
        try:
            conn.sendall(struct.pack(">QQH", NBD_MAGIC, IHAVEOPT_MAGIC, 1))  # fixed newstyle, u16 flags
            _ = recv_exact(conn, 4)                                          # client flags, u32 per spec

            export_ok = False
            while not export_ok:
                head = recv_exact(conn, 16)
                ihaveopt, opt, olen = struct.unpack(">QII", head[0:16])
                if ihaveopt != IHAVEOPT_MAGIC:
                    log("bad option magic 0x%x; dropping client" % ihaveopt)
                    return
                payload = recv_exact(conn, olen) if olen else b""
                if opt == OPT_EXPORT_NAME:
                    log("EXPORT_NAME %r" % payload[:32])
                    conn.sendall(struct.pack(">QH", layer.size, 0) + b"\x00" * 124)
                    export_ok = True
                elif opt == OPT_GO:
                    log("OPT_GO %r" % payload[:32])
                    info = struct.pack(">HQH", INFO_EXPORT, layer.size, 0)
                    conn.sendall(struct.pack(">QIII", REP_MAGIC, opt, REP_INFO, len(info)) + info)
                    conn.sendall(struct.pack(">QIII", REP_MAGIC, opt, REP_ACK, 0))
                    export_ok = True
                elif opt == OPT_ABORT:
                    log("client aborted negotiation")
                    return
                else:
                    # QEMU probes structured replies / block-status first and falls
                    # back to EXPORT_NAME when it receives ERR_UNSUP here.
                    log("unsupported option %d -> ERR_UNSUP" % opt)
                    conn.sendall(struct.pack(">QIII", REP_MAGIC, opt, REP_ERR_UNSUP, 0))

            log("transmission phase start")
            dirty_writes = 0
            while True:
                try:
                    hdr = recv_exact(conn, 28)
                except socket.timeout:
                    log("connection idle for %ds; closing" % int(CONN_IDLE_TIMEOUT))
                    break
                except (ConnectionError, OSError):
                    log("client gone (abnormal disconnect)")
                    break
                magic, cflags, ctype, handle, off, length = struct.unpack(">IHHQQI", hdr)
                if magic != REQUEST_MAGIC:
                    log("bad request magic; dropping")
                    break
                if ctype == CMD_READ:
                    try:
                        data = layer.read(off, length)
                    except DiffReadError:
                        conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, NBD_EIO, handle))
                        continue
                    if data is None:
                        conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, NBD_EINVAL, handle))
                        continue
                    conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle) + data)
                elif ctype == CMD_WRITE:
                    try:
                        data = recv_exact(conn, length)
                    except (ConnectionError, OSError):
                        log("client gone mid-write (abnormal disconnect)")
                        break
                    ok = layer.write(off, data)
                    dirty_writes += 1
                    conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0 if ok else NBD_EINVAL, handle))
                    if dirty_writes % 200 == 0:
                        _save_bitmap_safe(layer)
                elif ctype == CMD_FLUSH:
                    # A guest FLUSH means "make it durable": diff bytes AND the
                    # bitmap that indexes them. Reply EIO if we cannot honor it.
                    try:
                        layer.save_bitmap()
                    except Exception as exc:
                        log("ERROR: flush failed: %s: %s" % (type(exc).__name__, exc))
                        conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, NBD_EIO, handle))
                    else:
                        conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle))
                elif ctype == CMD_TRIM:
                    conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle))
                elif ctype == CMD_DISC:
                    log("client disconnect (after %d writes)" % dirty_writes)
                    break
                else:
                    conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, NBD_EINVAL, handle))
        except (ConnectionError, OSError) as exc:
            log("connection error (%s); closing" % type(exc).__name__)
        except Exception as exc:
            log("unexpected error (%s: %s); closing" % (type(exc).__name__, exc))
    finally:
        # Whatever ended the session -- clean DISC, killed QEMU, socket error,
        # idle timeout -- persist the dirty bitmap so a restart never reloads
        # a stale one and silently drops diff writes.
        _save_bitmap_safe(layer)
        try:
            conn.close()
        except OSError:
            pass

def main() -> None:
    if len(sys.argv) != 5:
        print("usage: nbd_evidence_server.py <base-image> <diff-file> <bitmap-file> <port>",
              file=sys.stderr)
        sys.exit(2)
    base, diff_path, bitmap_path = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        port = int(sys.argv[4])
    except ValueError:
        print("nbd_evidence_server: invalid port %r (expected an integer between "
              "1 and 65535)" % sys.argv[4], file=sys.stderr)
        sys.exit(2)
    if not 1 <= port <= 65535:
        print("nbd_evidence_server: port %d out of range 1-65535" % port, file=sys.stderr)
        sys.exit(2)
    layer = DiffLayer(base, diff_path, bitmap_path)
    log("base=%s (%d bytes, O_RDONLY) diff=%s" % (base, layer.size, diff_path))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    log("listening on 127.0.0.1:%d" % port)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=serve_client, args=(conn, addr, layer), daemon=True).start()

if __name__ == "__main__":
    main()
