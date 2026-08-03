"""Case cleanup constrained to generated files under the case root."""

from __future__ import annotations

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
    removed: list[str] = []
    entries = state.generated_files()
    protected_inputs = {path for path in inputs if _inside(path, root)}
    case_metadata = {"case.json", ".wiretoutetu-generated.json"}
    for item in entries:
        if item["path"] in case_metadata:
            continue
        path, _ = state._artifact_relative(item["path"])
        resolved = path.resolve()
        if resolved in protected_inputs:
            continue
        if path.is_file() or path.is_symlink():
            path.unlink()
            removed.append(str(resolved))
    for directory in (state.records_dir, state.root / "objects", state.root / "streams", state.checkpoints_dir):
        try:
            directory.rmdir()
        except OSError:
            pass
    after = {str(path): sha256_file(path) for path in inputs if path.is_file()}
    if before != after:
        raise RuntimeError("original input hash changed during cleanup")
    for item in entries:
        if item["path"] not in case_metadata:
            continue
        path, _ = state._artifact_relative(item["path"])
        if path.is_file():
            path.unlink()
            removed.append(str(path.resolve()))
    return {"removed_files": removed, "preserved_inputs": sorted(after), "input_hashes": after}
