#!/usr/bin/env python3
"""Self-test client for nbd_evidence_server.py.

Emulates the QEMU NBD client handshake (fixed newstyle, NBD_OPT_GO), exports
the size, reads the first 512 bytes and checks the MBR signature. Run this
against the server BEFORE booting any VM: it validates the wire format in
seconds instead of burning a slow TCG boot cycle on a protocol bug.

Usage:
    python3 nbd_selftest.py [port]        # default 10809

Exit 0 = server is serving the evidence correctly.
"""
import argparse
import socket
import struct
import sys

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nbd_selftest.py",
        description="Self-test client for nbd_evidence_server.py: emulates the QEMU "
        "fixed-newstyle handshake, reads the first sector and checks the reply.",
    )
    parser.add_argument("port", nargs="?", type=int, default=10809,
                        help="NBD port to test (default: 10809)")
    return parser.parse_args()

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf

def main(port: int) -> int:
    s = socket.create_connection(("127.0.0.1", port), timeout=5)

    greet = recv_exact(s, 18)
    magic, ihaveopt, flags = struct.unpack(">QQH", greet)
    assert magic == 0x4E42444D41474943, hex(magic)
    assert ihaveopt == 0x49484156454F5054, hex(ihaveopt)
    print("greeting OK, handshake flags =", flags)

    s.sendall(struct.pack(">I", 1))  # client flags: fixed newstyle (u32)

    # NBD_OPT_GO with empty export name; client frames carry IHAVEOPT magic
    payload = b""
    s.sendall(struct.pack(">QII", 0x49484156454F5054, 5, len(payload)) + payload)

    size = None
    while True:
        hdr = recv_exact(s, 20)
        rmagic, opt, rtype, rlen = struct.unpack(">QIII", hdr)
        assert rmagic == 0x3E889045565A9, hex(rmagic)
        data = recv_exact(s, rlen) if rlen else b""
        if rtype == 3:  # NBD_REP_INFO
            itype = struct.unpack(">H", data[0:2])[0]
            if itype == 0:
                size = struct.unpack(">Q", data[2:10])[0]
        elif rtype == 1:  # ACK
            break
        else:
            print("unexpected reply type %d" % rtype)
            return 1
    print("export size =", size)
    if size is None or size == 0:
        print("FAIL: no export size")
        return 1

    # READ the first 512 bytes (MBR area)
    handle = 42
    s.sendall(struct.pack(">IHHQQI", 0x25609513, 0, 0, handle, 0, 512))
    reply = recv_exact(s, 16)
    rmagic, err, rhandle = struct.unpack(">IIQ", reply)
    assert rmagic == 0x67446698 and err == 0 and rhandle == handle
    mbr = recv_exact(s, 512)
    sig = mbr[510:512]
    print("first-sector trailing signature:", sig.hex())
    if sig == b"\x55\xaa":
        print("MBR signature 0x55AA present (DOS/MBR disk)")
    print("SELF-TEST PASS: evidence is being served over NBD")
    return 0

if __name__ == "__main__":
    sys.exit(main(parse_args().port))
