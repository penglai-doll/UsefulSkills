"""Case cleanup constrained to generated files under the case root."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .case_state import CaseState, sha256_file


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def cleanup_case(case_dir: str | Path) -> dict[str, Any]:
    state = CaseState.open(case_dir)
    root = state.root.resolve()
    manifest = state.read_manifest()
    inputs = [Path(manifest["capture"]["path"]).resolve()]
    inputs.extend(Path(item["path"]).resolve() for item in manifest["sidecars"])
    before = {str(path): sha256_file(path) for path in inputs if path.is_file()}
    preserved_inside = {path for path in inputs if _inside(path, root)}
    removed: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        resolved = path.resolve()
        if path.is_file() and resolved not in preserved_inside:
            path.unlink()
            removed.append(str(resolved))
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass
    after = {str(path): sha256_file(path) for path in inputs if path.is_file()}
    if before != after:
        raise RuntimeError("original input hash changed during cleanup")
    return {"removed_files": removed, "preserved_inputs": sorted(after), "input_hashes": after}
