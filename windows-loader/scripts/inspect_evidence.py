"""Inspect evidence image metadata without mounting or modifying the image."""

from __future__ import annotations

import argparse
from pathlib import Path

from common import (
    AVAILABLE_HASH_ALGORITHMS,
    SCHEMA,
    bounded_list,
    deterministic_segment_set_sha256,
    emit,
    evidence_segments,
    sha256_file,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--hash", choices=("now", "later", "skip"), default="later")
    parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    image = args.image
    try:
        image_format, segments = evidence_segments(image)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    canonical = segments[0]
    metadata = [segment.stat() for segment in segments]
    evidence = {
        "path": str(canonical),
        "format": image_format,
        "size": sum(item.st_size for item in metadata),
        "mtime": max(item.st_mtime for item in metadata),
        "segment_count": len(segments),
        "segments": bounded_list([segment.name for segment in segments], args.limit),
        "available_hash_algorithms": list(AVAILABLE_HASH_ALGORITHMS),
        "hash": {"policy": args.hash},
    }
    if args.hash == "now":
        if image_format == "e01":
            hashes = [{"name": segment.name, "sha256": sha256_file(segment)} for segment in segments]
            evidence["hash"].update({
                "segment_hashes": bounded_list(hashes, args.limit),
                "set_sha256": deterministic_segment_set_sha256(hashes),
            })
            if len(hashes) == 1:
                evidence["sha256"] = hashes[0]["sha256"]
        else:
            evidence["sha256"] = sha256_file(canonical)
    emit({
        "schema": SCHEMA,
        "available_hash_algorithms": list(AVAILABLE_HASH_ALGORITHMS),
        "evidence": evidence,
    })


if __name__ == "__main__":
    main()
