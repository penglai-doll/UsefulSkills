"""Durable, restartable case state with atomic files and bounded queries."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


MAX_QUERY_ITEMS = 500
MAX_QUERY_BYTES = 4 * 1024 * 1024


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _input_entry(path: Path) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    stat = resolved.stat()
    return {
        "path": str(resolved),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": sha256_file(resolved),
    }


class CaseState:
    """Access case artifacts while keeping original capture and sidecars external."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.manifest_path = self.root / "case.json"
        self.records_dir = self.root / "records"
        self.checkpoints_dir = self.root / "checkpoints"

    @classmethod
    def create(
        cls, root: str | Path, capture: str | Path, sidecars: Iterable[str | Path]
    ) -> "CaseState":
        state = cls(root)
        state.root.mkdir(parents=True, exist_ok=True)
        state.records_dir.mkdir(exist_ok=True)
        state.checkpoints_dir.mkdir(exist_ok=True)
        (state.root / "objects").mkdir(exist_ok=True)
        (state.root / "streams").mkdir(exist_ok=True)
        manifest = {
            "schema_version": "1.0",
            "created_at": _utc_now(),
            "updated_at": _utc_now(),
            "capture": _input_entry(Path(capture)),
            "sidecars": [_input_entry(Path(path)) for path in sidecars],
            "stages": {},
        }
        _atomic_json(state.manifest_path, manifest)
        return state

    @classmethod
    def open(cls, root: str | Path) -> "CaseState":
        state = cls(root)
        if not state.manifest_path.is_file():
            raise FileNotFoundError(f"not a WireToutetu case: {state.root}")
        return state

    def read_manifest(self) -> dict[str, Any]:
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        manifest["updated_at"] = _utc_now()
        _atomic_json(self.manifest_path, manifest)

    def refresh_inputs(self) -> None:
        manifest = self.read_manifest()
        manifest["capture"] = _input_entry(Path(manifest["capture"]["path"]))
        manifest["sidecars"] = [_input_entry(Path(item["path"])) for item in manifest["sidecars"]]
        self.write_manifest(manifest)

    def set_sidecars(self, sidecars: Iterable[str | Path]) -> None:
        manifest = self.read_manifest()
        manifest["sidecars"] = [_input_entry(Path(path)) for path in sidecars]
        self.write_manifest(manifest)

    def stage_cache_key(self, stage: str, *, include_sidecars: bool) -> str:
        manifest = self.read_manifest()
        material: dict[str, Any] = {
            "schema_version": manifest["schema_version"],
            "stage": stage,
            "capture": manifest["capture"]["sha256"],
        }
        if include_sidecars:
            material["sidecars"] = [item["sha256"] for item in manifest["sidecars"]]
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def mark_stage(self, stage: str, *, cache_key: str, status: str, counts: dict[str, int] | None = None) -> None:
        manifest = self.read_manifest()
        manifest["stages"][stage] = {
            "cache_key": cache_key,
            "status": status,
            "counts": counts or {},
            "updated_at": _utc_now(),
        }
        self.write_manifest(manifest)

    def write_records(self, name: str, records: Iterable[dict[str, Any]]) -> Path:
        if not name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("invalid record collection name")
        path = self.records_dir / f"{name}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                for record in records:
                    handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return path

    @staticmethod
    def _decode_cursor(cursor: str | None) -> int:
        if not cursor:
            return 0
        try:
            return int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("ascii"))
        except (ValueError, UnicodeError) as exc:
            raise ValueError("invalid cursor") from exc

    @staticmethod
    def _encode_cursor(offset: int) -> str:
        return base64.urlsafe_b64encode(str(offset).encode("ascii")).decode("ascii")

    def query_records(self, name: str, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        limit = min(max(int(limit), 1), MAX_QUERY_ITEMS)
        offset = self._decode_cursor(cursor)
        path = self.records_dir / f"{name}.jsonl"
        if not path.is_file():
            return {"items": [], "next_cursor": None, "returned_bytes": 0}
        items: list[dict[str, Any]] = []
        total_bytes = 0
        next_offset: int | None = None
        with path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle):
                if index < offset:
                    continue
                if len(items) >= limit or total_bytes + len(line.encode("utf-8")) > MAX_QUERY_BYTES:
                    next_offset = index
                    break
                items.append(json.loads(line))
                total_bytes += len(line.encode("utf-8"))
        return {
            "items": items,
            "next_cursor": self._encode_cursor(next_offset) if next_offset is not None else None,
            "returned_bytes": total_bytes,
        }

    def read_all_records(self, name: str) -> list[dict[str, Any]]:
        path = self.records_dir / f"{name}.jsonl"
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
