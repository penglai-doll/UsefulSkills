"""Markdown and integrity-verified bundle exports."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .case_state import CaseState, sha256_file


def export_markdown(state: CaseState, output: str | Path) -> dict[str, Any]:
    summary = state.query_records("summary", limit=1)["items"]
    events = state.query_records("timeline", limit=500)["items"]
    objects = state.query_records("objects", limit=500)["items"]
    failures = state.query_records("failures", limit=500)["items"]
    lines = ["# WireToutetu 离线流量分析", "", "## 摘要", ""]
    lines.append(f"```json\n{json.dumps(summary[0] if summary else {}, ensure_ascii=False, indent=2)}\n```")
    lines.extend(["", "## 事件链", ""])
    for event in events:
        lines.append(f"- `{event.get('id')}` {event.get('time')}：{event.get('operation')} → {event.get('result')}")
    lines.extend(["", "## 恢复对象", ""])
    for item in objects:
        lines.append(f"- `{item.get('id')}` `{item.get('filename')}` SHA-256 `{item.get('sha256')}`")
    lines.extend(["", "## 失败与缺口", ""])
    lines.extend(f"- {json.dumps(item, ensure_ascii=False)}" for item in failures)
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"status": "verified", "path": str(path), "sha256": sha256_file(path)}


def _bundle_files(state: CaseState) -> list[Path]:
    manifest = state.read_manifest()
    excluded = {Path(manifest["capture"]["path"]).resolve()}
    excluded.update(Path(item["path"]).resolve() for item in manifest["sidecars"])
    files = []
    for path in state.root.rglob("*"):
        if path.is_file() and path.resolve() not in excluded:
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(state.root).as_posix())


def export_bundle(state: CaseState, output: str | Path) -> dict[str, Any]:
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = _bundle_files(state)
    hashes = {path.relative_to(state.root).as_posix(): sha256_file(path) for path in files}
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(fd)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                archive.write(path, path.relative_to(state.root).as_posix())
            archive.writestr("manifest.sha256.json", json.dumps(hashes, sort_keys=True, indent=2) + "\n")
        with zipfile.ZipFile(temporary) as archive:
            names = archive.namelist()
            for name in names:
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise ValueError(f"unsafe bundle path: {name}")
            packed_hashes = json.loads(archive.read("manifest.sha256.json"))
            for name, expected in packed_hashes.items():
                actual = hashlib.sha256(archive.read(name)).hexdigest()
                if actual != expected:
                    raise ValueError(f"bundle hash mismatch: {name}")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {
        "status": "verified",
        "path": str(destination),
        "sha256": sha256_file(destination),
        "files": len(files),
    }
