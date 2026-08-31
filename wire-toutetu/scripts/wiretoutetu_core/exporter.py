"""Markdown and integrity-verified bundle exports."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from .case_state import MAX_QUERY_ITEMS, CaseState, sha256_file


def _register_case_export(state: CaseState, path: Path) -> None:
    try:
        path.relative_to(state.root)
    except ValueError:
        return
    state.register_generated(path, owner="export")


def _truncation_note(state: CaseState, collection: str, exported: int) -> str | None:
    """Explicit incompleteness note when a markdown section was capped."""
    total = state.count_records(collection)
    if total > exported:
        return (
            f"⚠ 截断：仅导出前 {exported}/{total} 条（分页上限 {MAX_QUERY_ITEMS}），"
            f"完整数据见 case 目录 records/{collection}.jsonl"
        )
    return None


def export_markdown(state: CaseState, output: str | Path) -> dict[str, Any]:
    summary = state.query_records("summary", limit=1)["items"]
    events = state.query_records("timeline", limit=MAX_QUERY_ITEMS)["items"]
    objects = state.query_records("objects", limit=MAX_QUERY_ITEMS)["items"]
    failures = state.query_records("failures", limit=MAX_QUERY_ITEMS)["items"]
    lines = ["# WireToutetu 离线流量分析", "", "## 摘要", ""]
    lines.append(f"```json\n{json.dumps(summary[0] if summary else {}, ensure_ascii=False, indent=2)}\n```")
    lines.extend(["", "## 事件链", ""])
    for event in events:
        lines.append(f"- `{event.get('id')}` {event.get('time')}：{event.get('operation')} → {event.get('result')}")
    if note := _truncation_note(state, "timeline", len(events)):
        lines.append(note)
    lines.extend(["", "## 恢复对象", ""])
    for item in objects:
        lines.append(f"- `{item.get('id')}` `{item.get('filename')}` SHA-256 `{item.get('sha256')}`")
    if note := _truncation_note(state, "objects", len(objects)):
        lines.append(note)
    lines.extend(["", "## 失败与缺口", ""])
    lines.extend(f"- {json.dumps(item, ensure_ascii=False)}" for item in failures)
    if note := _truncation_note(state, "failures", len(failures)):
        lines.append(note)
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _register_case_export(state, path)
    return {"status": "verified", "path": str(path), "sha256": sha256_file(path)}


def _bundle_files(state: CaseState, *, extra_excluded: set[Path] | None = None) -> list[Path]:
    manifest = state.read_manifest()
    excluded = {Path(manifest["capture"]["path"]).resolve()}
    excluded.update(Path(item["path"]).resolve() for item in manifest["sidecars"])
    excluded.update(path.resolve() for path in (extra_excluded or set()))
    files: list[Path] = []
    for item in state.generated_files():
        relative = PurePosixPath(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"unsafe generated artifact path: {item['path']}")
        path = state.root.joinpath(*relative.parts)
        if path.resolve() in excluded:
            continue
        if path.is_symlink():
            raise ValueError(f"bundle source must not be a link: {path}")
        if not path.is_file():
            raise FileNotFoundError(f"registered bundle artifact is missing: {path}")
        resolved = path.resolve()
        try:
            resolved.relative_to(state.root)
        except ValueError as exc:
            raise ValueError(f"bundle source escapes case root: {path}") from exc
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(state.root).as_posix())


def export_bundle(state: CaseState, output: str | Path) -> dict[str, Any]:
    destination = Path(output).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    files = _bundle_files(state, extra_excluded={destination})
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
    _register_case_export(state, destination)
    return {
        "status": "verified",
        "path": str(destination),
        "sha256": sha256_file(destination),
        "files": len(files),
    }
