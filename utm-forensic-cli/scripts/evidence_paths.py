"""Keep writable simulation artifacts distinct from read-only evidence."""
from __future__ import annotations

import os
from pathlib import Path


def require_distinct_paths(*paths: str | Path) -> None:
    resolved = [Path(path).expanduser().resolve() for path in paths]
    for index, path in enumerate(resolved):
        for other in resolved[:index]:
            if path == other or (path.exists() and other.exists() and os.path.samefile(path, other)):
                raise ValueError(f"evidence and output paths must be distinct: {path} aliases {other}")
    for raw in paths[1:]:
        path = Path(raw)
        if path.is_symlink() or (path.exists() and path.stat().st_nlink > 1):
            raise ValueError(f"writable output must not be a symlink or hard link: {path}")


def open_diff(path: str | Path, base):
    """Open without truncation, then compare identities before any write."""
    path = Path(path)
    try:
        handle = path.open("x+b")
    except FileExistsError:
        handle = path.open("r+b")
    identity = os.fstat(handle.fileno())
    if os.path.samestat(identity, os.fstat(base.fileno())) or identity.st_nlink > 1:
        handle.close()
        raise ValueError(f"diff output aliases evidence or has multiple links: {path}")
    return handle
