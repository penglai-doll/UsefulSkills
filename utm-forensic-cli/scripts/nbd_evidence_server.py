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

def log(msg):
    sys.stdout.write("[nbd %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()

class DiffLayer:
    """Sparse 4 KiB-block diff over a read-only base file."""

    def __init__(self, base_path, diff_path, bitmap_path):
        self.base = open(base_path, "rb", buffering=0)
        self.base.seek(0, os.SEEK_END)
        self.size = self.base.tell()
        self.nblocks = (self.size + BLOCK - 1) // BLOCK
        self.diff_path = diff_path
        self.bitmap_path = bitmap_path
        self.lock = threading.Lock()
        if os.path.exists(bitmap_path):
            with open(bitmap_path, "rb") as f:
                self.bitmap = bytearray(f.read())
            log("loaded bitmap: %d dirty blocks" % self._dirty_count())
        else:
            self.bitmap = bytearray((self.nblocks + 7) // 8)
        self.diff = open(diff_path, "r+b" if os.path.exists(diff_path) else "w+b")

    def _dirty_count(self):
        return sum(bin(b).count("1") for b in self.bitmap)

    def _dirty(self, idx):
        return self.bitmap[idx >> 3] & (0x80 >> (idx & 7))

    def _set(self, idx):
        self.bitmap[idx >> 3] |= 0x80 >> (idx & 7)

    def save_bitmap(self):
        with open(self.bitmap_path, "wb") as f:
            f.write(self.bitmap)
        log("bitmap saved (%d dirty blocks)" % self._dirty_count())

    def read(self, offset, length):
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
                    chunk = os.pread(self.base.fileno(), n, off)
                    if len(chunk) == n:
                        out[pos:pos + n] = chunk
                pos += n
        return bytes(out)

    def write(self, offset, data):
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
                    base_blk = os.pread(self.base.fileno(), BLOCK, idx * BLOCK)
                    base_blk = base_blk.ljust(BLOCK, b"\x00")
                    self.diff.seek(idx * BLOCK)
                    self.diff.write(base_blk)
                    self._set(idx)
                self.diff.seek(idx * BLOCK + inblock)
                self.diff.write(data[pos:pos + n])
                pos += n
        return True

def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf

def serve_client(conn, addr, layer):
    log("client %s connected" % (addr,))
    conn.sendall(struct.pack(">QQH", NBD_MAGIC, IHAVEOPT_MAGIC, 1))  # fixed newstyle, u16 flags
    _ = recv_exact(conn, 4)                                          # client flags, u32 per spec

    export_ok = False
    while not export_ok:
        head = recv_exact(conn, 16)
        ihaveopt, opt, olen = struct.unpack(">QII", head[0:16])
        if ihaveopt != IHAVEOPT_MAGIC:
            log("bad option magic 0x%x; dropping client" % ihaveopt)
            conn.close()
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
            conn.close()
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
        except ConnectionError:
            log("client gone")
            break
        magic, cflags, ctype, handle, off, length = struct.unpack(">IHHQQI", hdr)
        if magic != REQUEST_MAGIC:
            log("bad request magic; dropping")
            break
        if ctype == CMD_READ:
            data = layer.read(off, length)
            if data is None:
                conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 22, handle))
                continue
            conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle) + data)
        elif ctype == CMD_WRITE:
            data = recv_exact(conn, length)
            ok = layer.write(off, data)
            dirty_writes += 1
            conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0 if ok else 22, handle))
            if dirty_writes % 200 == 0:
                layer.save_bitmap()
        elif ctype == CMD_FLUSH:
            layer.diff.flush()
            conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle))
        elif ctype == CMD_TRIM:
            conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 0, handle))
        elif ctype == CMD_DISC:
            log("client disconnect (after %d writes)" % dirty_writes)
            layer.save_bitmap()
            break
        else:
            conn.sendall(struct.pack(">IIQ", REPLY_MAGIC, 22, handle))
    try:
        conn.close()
    except OSError:
        pass

def main():
    if len(sys.argv) != 5:
        print("usage: nbd_evidence_server.py <base-image> <diff-file> <bitmap-file> <port>",
              file=sys.stderr)
        sys.exit(2)
    base, diff_path, bitmap_path, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
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
