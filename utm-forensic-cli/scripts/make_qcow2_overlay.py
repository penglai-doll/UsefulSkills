#!/usr/bin/env python3
"""Hand-craft a minimal qcow2 v3 overlay whose backing file is a raw image.

Use case: give a UTM VM a writable-disk experience while QEMU opens the
evidence only as a qcow2 backing file, which QEMU always opens READ-ONLY by
design. The overlay itself is a few hundred KiB regardless of disk size.

Sandbox caveat (verified on the App Store build of UTM 4.7.x): QEMU inherits
the app sandbox and cannot open backing files outside
~/Library/Containers/com.utmapp.UTM — you will see
`Could not open backing file ... Operation not permitted`. In that
environment use the NBD channel (nbd_evidence_server.py) instead; this
overlay is for environments where QEMU can legally read the backing path
(e.g. direct-download UTM, or evidence staged inside the container).

UTM bundles qemu-img only as an MH_BUNDLE framework (not directly
executable: `exec format error`), so the overlay is written by hand. The
virtual size is derived from the base image; the backing reference is
absolute so the overlay survives being moved or copied into a .utm bundle.

Layout (4 clusters of 64 KiB):
  cluster 0: header + backing name + backing-format extension
  cluster 1: L1 table (all zero => every read goes to backing)
  cluster 2: refcount table
  cluster 3: refcount block

Usage:
    python3 make_qcow2_overlay.py <base-raw-image> <output-overlay.qcow2>
"""
import os
import struct
import sys

CLUSTER = 65536
CLUSTER_BITS = 16

def main(base_path, out_path):
    base_size = os.path.getsize(base_path)
    if base_size % 512:
        print("warning: base size is not sector-aligned", file=sys.stderr)
    # each L1 entry covers cluster_size * cluster_size / 8 = 512 MiB
    l1_size = (base_size + (512 * 1024 * 1024) - 1) // (512 * 1024 * 1024)

    backing = os.path.abspath(base_path).encode("utf-8")
    backing_off = 112                    # right after the v3 base header
    ext_off = (backing_off + len(backing) + 7) & ~7
    ext = struct.pack(">II", 0xE2792ACA, 3) + b"raw" + b"\x00" * 5  # backing-format ext
    ext += struct.pack(">II", 0, 0)      # end-of-extensions marker

    hdr = struct.pack(">IIQIIQIIQQIIQQQQII",
        0x514649FB,        # magic
        3,                 # version
        backing_off,       # backing_file_offset
        len(backing),      # backing_file_size
        CLUSTER_BITS,      # cluster_bits
        base_size,         # virtual size = base size
        0,                 # crypt_method
        l1_size,           # l1_size
        CLUSTER * 1,       # l1_table_offset
        CLUSTER * 2,       # refcount_table_offset
        1,                 # refcount_table_clusters
        0,                 # nb_snapshots
        0,                 # snapshots_offset
        0,                 # incompatible_features
        0,                 # compatible_features
        0,                 # autoclear_features
        4,                 # refcount_order (16-bit refcounts)
        104,               # header_length (v3 base)
    )
    assert len(hdr) == 104, len(hdr)

    c0 = bytearray(CLUSTER)
    c0[0:104] = hdr
    c0[backing_off:backing_off + len(backing)] = backing
    c0[ext_off:ext_off + len(ext)] = ext
    assert ext_off + len(ext) <= CLUSTER, "backing path too long for cluster 0"

    c1 = bytearray(CLUSTER)              # L1 table, all unallocated
    c2 = bytearray(CLUSTER)              # refcount table -> one block
    c2[0:8] = struct.pack(">Q", CLUSTER * 3)
    c3 = bytearray(CLUSTER)              # refcount block
    for i in range(4):
        c3[i * 2:i * 2 + 2] = struct.pack(">H", 1)

    with open(out_path, "wb") as f:
        for c in (c0, c1, c2, c3):
            f.write(c)

    # parse-back self check
    with open(out_path, "rb") as f:
        data = f.read(512)
    magic, ver, boff, blen, cbits, size = struct.unpack(">IIQIIQ", data[0:32])
    assert magic == 0x514649FB and ver == 3 and cbits == CLUSTER_BITS
    assert size == base_size
    assert data[boff:boff + blen].decode() == os.path.abspath(base_path)
    print("overlay written: %s (%d bytes), virtual size %d, backing=%s"
          % (out_path, 4 * CLUSTER, base_size, os.path.abspath(base_path)))
    print("self-check OK")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: make_qcow2_overlay.py <base-raw-image> <output-overlay.qcow2>", file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
