"""Durable, restartable case state with atomic files and bounded queries."""

from __future__ import annotations

import base64
import binascii
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
        self.generated_ledger_path = self.root / ".wiretoutetu-generated.json"
        self.records_dir = self.root / "records"
        self.checkpoints_dir = self.root / "checkpoints"

    @classmethod
    def create(
        cls, root: str | Path, capture: str | Path, sidecars: Iterable[str | Path]
    ) -> "CaseState":
        sidecars = tuple(sidecars)
        state = cls(root)
        input_paths = {Path(capture).resolve(strict=True)}
        input_paths.update(Path(path).resolve(strict=True) for path in sidecars)
        reserved_roots = {"records", "objects", "streams", "checkpoints"}
        reserved_files = {"case.json", ".wiretoutetu-generated.json", "experience-pending.json"}
        for input_path in input_paths:
            try:
                relative = input_path.relative_to(state.root)
            except ValueError:
                continue
            if relative.as_posix() in reserved_files or (relative.parts and relative.parts[0] in reserved_roots):
                raise ValueError(f"input path collides with reserved case state: {input_path}")
        if state.root.exists():
            unexpected: list[str] = []
            for existing in state.root.rglob("*"):
                if existing.is_dir() and not existing.is_symlink():
                    continue
                try:
                    resolved = existing.resolve(strict=True)
                except OSError:
                    unexpected.append(str(existing))
                    continue
                if resolved not in input_paths:
                    unexpected.append(str(existing))
            if unexpected:
                raise ValueError(
                    "case directory contains unrelated pre-existing content: " + ", ".join(unexpected[:3])
                )
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
        _atomic_json(state.generated_ledger_path, {
            "schema_version": "1.0",
            "files": [
                {"path": "case.json", "owner": "case"},
                {"path": ".wiretoutetu-generated.json", "owner": "case"},
            ],
        })
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

    def _read_generated_ledger(self) -> dict[str, Any]:
        if not self.generated_ledger_path.is_file():
            raise FileNotFoundError(f"missing generated-file ledger: {self.generated_ledger_path}")
        value = json.loads(self.generated_ledger_path.read_text(encoding="utf-8"))
        if not isinstance(value.get("files"), list):
            raise ValueError("invalid generated-file ledger")
        return value

    def generated_files(self) -> list[dict[str, str]]:
        return list(self._read_generated_ledger()["files"])

    def _artifact_relative(self, path: str | Path) -> tuple[Path, str]:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        candidate = candidate.resolve()
        try:
            relative = candidate.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ValueError("generated artifact must remain inside the case root") from exc
        return candidate, relative

    def register_generated(self, path: str | Path, *, owner: str) -> None:
        _, relative = self._artifact_relative(path)
        ledger = self._read_generated_ledger()
        entries = [item for item in ledger["files"] if item.get("path") != relative]
        entries.append({"path": relative, "owner": owner})
        ledger["files"] = sorted(entries, key=lambda item: item["path"])
        _atomic_json(self.generated_ledger_path, ledger)

    def write_artifact(self, path: str | Path, data: bytes, *, owner: str) -> Path:
        destination, _ = self._artifact_relative(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        self.register_generated(destination, owner=owner)
        return destination

    def clear_generated(self, owner: str) -> list[str]:
        ledger = self._read_generated_ledger()
        retained: list[dict[str, str]] = []
        removed: list[str] = []
        protected = {"case.json", ".wiretoutetu-generated.json"}
        for item in ledger["files"]:
            if item.get("owner") != owner or item.get("path") in protected:
                retained.append(item)
                continue
            candidate, relative = self._artifact_relative(str(item["path"]))
            if candidate.is_file() or candidate.is_symlink():
                candidate.unlink()
                removed.append(str(candidate))
            elif candidate.exists():
                raise ValueError(f"generated artifact is not a file: {relative}")
        ledger["files"] = retained
        _atomic_json(self.generated_ledger_path, ledger)
        return sorted(removed)

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
        path = self._record_path(name)
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
        self.register_generated(path, owner="records")
        return path

    @staticmethod
    def _decode_cursor(cursor: str | None) -> int:
        if not cursor:
            return 0
        try:
            return int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("ascii"))
        except (ValueError, UnicodeError, binascii.Error) as exc:
            raise ValueError("invalid cursor") from exc

    @staticmethod
    def _encode_cursor(offset: int) -> str:
        return base64.urlsafe_b64encode(str(offset).encode("ascii")).decode("ascii")

    def _record_path(self, name: str) -> Path:
        if not name.replace("_", "").replace("-", "").isalnum():
            raise ValueError("invalid record collection name")
        return self.records_dir / f"{name}.jsonl"

    def query_records(self, name: str, *, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        limit = min(max(int(limit), 1), MAX_QUERY_ITEMS)
        offset = self._decode_cursor(cursor)
        path = self._record_path(name)
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
                    if not items:
                        raise ValueError(
                            "record exceeds the 4 MiB query boundary; export the case instead"
                        )
                    next_offset = index
                    break
                items.append(json.loads(line))
                total_bytes += len(line.encode("utf-8"))
        return {
            "items": items,
            "next_cursor": self._encode_cursor(next_offset) if next_offset is not None else None,
            "returned_bytes": total_bytes,
        }

    def count_records(self, name: str) -> int:
        """Cheap total row count for a collection, without loading records."""
        path = self._record_path(name)
        if not path.is_file():
            return 0
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def find_record(self, name: str, evidence_id: str) -> dict[str, Any] | None:
        """Find one evidence record without making the caller walk every page."""
        path = self._record_path(name)
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if len(line.encode("utf-8")) > MAX_QUERY_BYTES:
                    raise ValueError("record exceeds the 4 MiB query boundary; export the case instead")
                record = json.loads(line)
                if record.get("id") == evidence_id:
                    return record
        return None

    def read_all_records(self, name: str) -> list[dict[str, Any]]:
        path = self._record_path(name)
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
