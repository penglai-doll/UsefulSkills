"""Small, dependency-free primitives shared by the Windows Loader CLIs.

These helpers intentionally treat guest Windows paths as strings.  A mounted
root is a host filesystem path, but paths reported to investigators retain
Windows separators and Windows' case-insensitive matching semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator


SCHEMA = "windows-loader.v1"
REPARSE_POINT = 0x0400
AVAILABLE_HASH_ALGORITHMS = ("sha256",)
EVIDENCE_FORMATS = {
    ".raw": "raw",
    ".dd": "raw",
    ".img": "raw",
    ".vhd": "vhd",
    ".vhdx": "vhdx",
}
EWF_NUMERIC_EXTENSION = re.compile(r"E(\d{2})", flags=re.IGNORECASE)
EWF_LETTER_EXTENSION = re.compile(r"([E-Z])([A-Z])([A-Z])", flags=re.IGNORECASE)


def bounded_list(items: Iterable[object], limit: int = 50, details_path: str | None = None) -> dict:
    """Return the standard bounded-result envelope without discarding count."""
    values = list(items)
    limit = max(0, int(limit))
    shown = values[:limit]
    return {
        "items": shown,
        "total_count": len(values),
        "shown_count": len(shown),
        "truncated": len(values) > len(shown),
        "details_path": details_path,
    }


def infer_evidence_format(path: Path) -> str:
    """Infer a supported image format from its filename only."""
    image_format = EVIDENCE_FORMATS.get(path.suffix.casefold())
    if image_format is not None:
        extension = path.suffix.removeprefix(".")
        if EWF_LETTER_EXTENSION.fullmatch(extension):
            index = ewf_segment_index(path)
            previous = path.with_suffix("." + ewf_segment_extension(index - 1))
            first = path.with_suffix(".E01")
            if previous.is_file() and first.is_file():
                return "e01"
        return image_format
    extension = path.suffix.removeprefix(".")
    if EWF_NUMERIC_EXTENSION.fullmatch(extension) or EWF_LETTER_EXTENSION.fullmatch(extension):
        return "e01"
    raise ValueError("unsupported evidence image format")


def ewf_segment_index(path: Path) -> int:
    """Map EWF segment extensions to one contiguous, one-based sequence."""
    extension = path.suffix.removeprefix(".").upper()
    numeric = EWF_NUMERIC_EXTENSION.fullmatch(extension)
    if numeric is not None:
        value = int(numeric.group(1))
        if value == 0:
            raise ValueError("EWF numeric segments start at E01")
        return value
    lettered = EWF_LETTER_EXTENSION.fullmatch(extension)
    if lettered is None:
        raise ValueError(f"invalid EWF segment extension: {path.suffix}")
    first, second, third = (ord(value) for value in lettered.groups())
    return (
        100
        + (first - ord("E")) * 26 * 26
        + (second - ord("A")) * 26
        + (third - ord("A"))
    )


def ewf_segment_extension(index: int) -> str:
    """Return the canonical extension for a one-based EWF segment index."""
    index = int(index)
    if 1 <= index <= 99:
        return f"E{index:02d}"
    maximum = 100 + (ord("Z") - ord("E") + 1) * 26 * 26 - 1
    if index < 100 or index > maximum:
        raise ValueError(f"EWF segment index outside supported range: {index}")
    offset = index - 100
    first_offset, remainder = divmod(offset, 26 * 26)
    second_offset, third_offset = divmod(remainder, 26)
    return "".join((
        chr(ord("E") + first_offset),
        chr(ord("A") + second_offset),
        chr(ord("A") + third_offset),
    ))


def evidence_segments(image: Path) -> tuple[str, list[Path]]:
    """Return a canonical, complete image set, normalizing any E01 segment to E01."""
    image = image.expanduser().absolute()
    if is_reparse(image):
        raise ValueError("explicit reparse evidence inputs are refused")
    image = image.resolve()
    if not image.is_file():
        raise ValueError("evidence image does not exist or is not a regular file")
    image_format = infer_evidence_format(image)
    if image_format != "e01":
        return image_format, [image]
    prefix = image.stem
    try:
        indexed: dict[int, Path] = {}
        deferred: dict[int, Path] = {}
        for candidate in image.parent.iterdir():
            if candidate.stem.casefold() != prefix.casefold():
                continue
            try:
                index = ewf_segment_index(candidate)
            except ValueError:
                continue
            collision = candidate.suffix.casefold() in EVIDENCE_FORMATS
            if is_reparse(candidate):
                raise ValueError(f"reparse EWF segment refused: {candidate}")
            if not candidate.is_file():
                raise ValueError(
                    f"EWF segment candidate is not a regular file: {candidate}"
                )
            target = deferred if collision else indexed
            if index in indexed or index in deferred:
                previous = indexed.get(index) or deferred[index]
                raise ValueError(
                    f"ambiguous EWF segment index {index}: "
                    f"{previous.name}, {candidate.name}"
                )
            target[index] = candidate.resolve()
    except OSError as error:
        raise ValueError(f"E01 set is unavailable: {error}") from error
    strong_max = max(indexed, default=0)
    sequence: list[Path] = []
    expected = 1
    while expected <= strong_max:
        candidate = indexed.get(expected) or deferred.get(expected)
        if candidate is None:
            raise ValueError(
                "EWF set must contain ordered, contiguous segments starting at E01 "
                "through its highest discovered continuation"
            )
        sequence.append(candidate)
        expected += 1
    while expected in deferred:
        sequence.append(deferred[expected])
        expected += 1
    if not sequence:
        raise ValueError(
            "EWF set must contain ordered, contiguous segments starting at E01 "
            "through its highest discovered continuation"
        )
    if image not in sequence:
        raise ValueError(
            "unsupported evidence image format: the requested lettered extension "
            "is not part of the contiguous EWF set"
        )
    return image_format, sequence


def segment_metadata(segments: Iterable[Path]) -> list[dict]:
    """Capture exact per-segment filesystem metadata without reading content."""
    records = []
    for segment in segments:
        metadata = segment.stat()
        records.append({
            "name": segment.name,
            "size": metadata.st_size,
            "mtime": metadata.st_mtime,
            "mtime_ns": metadata.st_mtime_ns,
        })
    return records


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def deterministic_segment_set_sha256(segment_hashes: Iterable[dict]) -> str:
    """Hash an ordered name/hash manifest; file content hashing happens separately."""
    aggregate = hashlib.sha256()
    for item in segment_hashes:
        aggregate.update(str(item["name"]).encode("utf-8"))
        aggregate.update(b"\x00")
        aggregate.update(str(item["sha256"]).encode("ascii"))
        aggregate.update(b"\n")
    return aggregate.hexdigest()


def normalize_guest_path(path: str) -> str:
    """Normalize a guest Windows path without using host ``Path`` semantics."""
    text = str(path).strip().replace("/", "\\")
    drive = ""
    if len(text) >= 2 and text[1] == ":":
        drive = text[0].upper() + ":"
        text = text[2:]
    absolute = text.startswith("\\")
    segments: list[str] = []
    for segment in text.split("\\"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    prefix = drive + ("\\" if drive or absolute else "")
    return prefix + "\\".join(segments)


def guest_join(*parts: str) -> str:
    """Join Windows guest path components with a single normalized separator."""
    if not parts:
        return ""
    first = normalize_guest_path(parts[0])
    remainder = [str(part).replace("/", "\\").strip("\\") for part in parts[1:] if str(part)]
    return normalize_guest_path("\\".join([first.rstrip("\\"), *remainder]))


def root_drive(root: Path) -> str:
    """Use the mounted root folder's name as its synthetic guest drive."""
    name = root.name
    return (name.upper() if len(name) == 1 and name.isalpha() else "C") + ":"


def guest_path(root: Path, local_path: Path) -> str:
    relative = local_path.relative_to(root)
    return guest_join(root_drive(root), *relative.parts)


def windows_path_hit(root: Path, path: Path) -> dict:
    """Describe one located Windows guest path using the catalog field contract."""
    reported = guest_path(root, path)
    lower = reported.casefold()
    scope = "machine"
    category = "APPLICATION_DATA"
    priority = "high"
    common_files = path.name
    cautions = "read only; do not execute guest content"
    if "\\users\\public\\" in lower:
        scope, category, priority = "shared", "PORTABLE_APPLICATIONS", "medium"
    elif "\\users\\" in lower:
        scope = "user"
    if "\\serviceprofiles\\" in lower or "\\systemprofile\\" in lower:
        scope, category = "service", "SERVICE_PROFILES"
    elif "\\winevt\\logs\\" in lower:
        category, common_files = "EVENT_LOGS", "Security.evtx, System.evtx"
        cautions = "claim parsed events only when a supported parser is available"
    elif "\\system32\\tasks\\" in lower or "\\startup\\" in lower:
        category = "SCHEDULED_TASKS" if "\\tasks\\" in lower else "STARTUP"
        common_files = "task XML" if category == "SCHEDULED_TASKS" else ".lnk, .bat, .cmd, .ps1"
    elif "\\prefetch\\" in lower or "amcache.hve" in lower:
        category = "EXECUTION_ARTIFACTS"
        priority = "medium" if "\\prefetch\\" in lower else "high"
    elif "srudb.dat" in lower:
        category = "USAGE_ARTIFACTS"
    elif any(token in lower for token in ("\\google\\chrome\\", "\\microsoft\\edge\\", "\\mozilla\\firefox\\")):
        category, common_files = "BROWSER_HISTORY", "History, Login Data, Cookies"
        cautions = "DPAPI use requires separate confirmation"
    elif "\\psreadline\\" in lower:
        category, common_files = "POWERSHELL_HISTORY", "ConsoleHost_history.txt"
        cautions = "may contain plaintext tokens or passwords"
    elif "automaticdestinations" in lower or "customdestinations" in lower:
        category, priority = "JUMP_LISTS", "medium"
    elif path.name.casefold() in {
        "software", "system", "sam", "security", "default", "ntuser.dat", "usrclass.dat",
    }:
        category, common_files = "REGISTRY_HIVES", path.name
    elif "\\portableapps\\" in lower or "\\tools\\" in lower:
        category, priority = "PORTABLE_APPLICATIONS", "medium"
    elif "\\appdata\\local\\packages\\" in lower:
        category = "UWP_DATA"
    elif any(token in lower for token in ("\\documents\\", "\\downloads\\", "\\saved games\\", "\\desktop\\")):
        category, priority = "USER_CONTENT", "medium"
        cautions = "content may be large or untrusted; keep bounded"
    elif "\\appdata\\" in lower:
        category = "USER_DATA"
    elif "\\wlansvc\\profiles\\" in lower or lower.endswith("\\hosts"):
        category = "NETWORK"
    return {
        "guest_path": reported,
        "guest_path_segments": reported.split("\\"),
        "scope": scope,
        "category": category,
        "priority": priority,
        "common_files": common_files,
        "cautions": cautions,
    }


def child_casefold(directory: Path, wanted: str, summary: "ScanSummary | None" = None) -> Path | None:
    """Find one immediate host entry by Windows-style case-insensitive name."""
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if summary is not None:
                    if summary.entries_seen >= summary.entry_budget:
                        summary.truncated = True
                        return None
                    summary.entries_seen += 1
                if entry.name.casefold() == wanted.casefold():
                    path = Path(entry.path)
                    if is_reparse(path, entry, summary):
                        return None
                    return path
    except OSError as error:
        if summary is not None:
            summary.errors.append(f"scan unavailable at {directory}: {error}")
        return None
    return None


def guest_to_local(root: Path, requested: str, summary: "ScanSummary | None" = None) -> Path | None:
    """Resolve a guest path beneath ``root`` segment-by-segment and casefolded."""
    normalized = normalize_guest_path(requested)
    drive, separator, tail = normalized.partition("\\")
    if not separator or drive.casefold() != root_drive(root).casefold():
        return None
    current = root
    for segment in (value for value in tail.split("\\") if value):
        candidate = child_casefold(current, segment, summary)
        if candidate is None:
            return None
        current = candidate
    return current


def is_reparse(
    path: Path,
    dir_entry: os.DirEntry[str] | None = None,
    summary: "ScanSummary | None" = None,
) -> bool:
    """Return true for a symlink or Windows reparse point, without following it."""
    try:
        if dir_entry is not None:
            symbolic = dir_entry.is_symlink()
            metadata = dir_entry.stat(follow_symlinks=False)
        else:
            metadata = path.lstat()
            symbolic = stat.S_ISLNK(metadata.st_mode)
        reparsed = symbolic or bool(getattr(metadata, "st_file_attributes", 0) & REPARSE_POINT)
        if reparsed and summary is not None:
            summary.errors.append(f"reparse point refused: {path}")
        return reparsed
    except OSError as error:
        if summary is not None:
            summary.errors.append(f"reparse/stat probe failed at {path}: {error}")
        return True


def safe_is_dir(path: Path, summary: "ScanSummary | None" = None) -> bool:
    try:
        return stat.S_ISDIR(path.stat().st_mode)
    except OSError as error:
        if summary is not None:
            summary.errors.append(f"directory stat failed at {path}: {error}")
        return False


def safe_is_file(path: Path, summary: "ScanSummary | None" = None) -> bool:
    try:
        return stat.S_ISREG(path.stat().st_mode)
    except OSError as error:
        if summary is not None:
            summary.errors.append(f"file stat failed at {path}: {error}")
        return False


@dataclass
class ScanSummary:
    depth_limit: int
    entry_budget: int
    entries_seen: int = 0
    directories_seen: int = 0
    truncated: bool = False
    errors: list[str] = field(default_factory=list)

    def document(self) -> dict:
        return {
            "depth_limit": self.depth_limit,
            "entry_budget": self.entry_budget,
            "entries_seen": self.entries_seen,
            "directories_seen": self.directories_seen,
            "truncated": self.truncated,
            "enumeration_order": "host-filesystem-order",
            "deterministic_order_guaranteed": False,
        }


def safe_walk(root: Path, max_depth: int | None = None, entry_budget: int = 2000,
              summary: ScanSummary | None = None) -> Iterator[tuple[Path, list[Path]]]:
    """Yield directories and their non-reparse children; never descend a link."""
    depth_limit = max_depth if max_depth is not None else 64
    state = summary or ScanSummary(depth_limit=depth_limit, entry_budget=max(0, entry_budget))
    if is_reparse(root, summary=state):
        state.errors.append(f"reparse root refused: {root}")
        yield root, []
        return
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        if state.entries_seen >= state.entry_budget:
            state.truncated = True
            return
        current, depth = pending.pop()
        state.directories_seen += 1
        children: list[Path] = []
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if state.entries_seen >= state.entry_budget:
                        state.truncated = True
                        break
                    state.entries_seen += 1
                    path = Path(entry.path)
                    children.append(path)
                    if is_reparse(path, entry, state):
                        continue
                    try:
                        is_directory = entry.is_dir(follow_symlinks=False)
                    except OSError as error:
                        state.errors.append(f"directory probe failed at {path}: {error}")
                        is_directory = False
                    if is_directory and (max_depth is None or depth < max_depth):
                        pending.append((path, depth + 1))
        except OSError as error:
            state.errors.append(f"scan unavailable at {current}: {error}")
            children = []
        yield current, children


def reparse_children(root: Path, max_depth: int | None = None, entry_budget: int = 2000,
                     summary: ScanSummary | None = None) -> Iterator[Path]:
    """List reparse entries encountered by the same non-following traversal."""
    state = summary or ScanSummary(
        depth_limit=max_depth if max_depth is not None else 64,
        entry_budget=max(0, entry_budget),
    )
    if is_reparse(root, summary=state):
        yield root
        return
    for _, children in safe_walk(root, max_depth=max_depth, entry_budget=entry_budget, summary=state):
        for child in children:
            if is_reparse(child, summary=state):
                yield child


def environment() -> dict:
    system = platform.system()
    release = platform.release().casefold()
    if system == "Windows":
        kind = "Windows"
    elif system == "Linux" and ("microsoft" in release or os.environ.get("WSL_DISTRO_NAME")):
        kind = "WSL"
    elif system == "Linux":
        kind = "Linux"
    else:
        kind = system or "Unknown"
    return {"kind": kind, "python": platform.python_version(), "platform": system}


def case_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return "wl-" + stamp + "-" + uuid.uuid4().hex[:8]


def emit(document: dict) -> None:
    document.setdefault("schema", SCHEMA)
    document.setdefault("case_id", None)
    document.setdefault("evidence", None)
    evidence = document.get("evidence")
    if isinstance(evidence, dict):
        document.setdefault("format", evidence.get("format"))
        hash_value = evidence.get("hash")
        document.setdefault("hash_policy", hash_value.get("policy") if isinstance(hash_value, dict) else evidence.get("hash_policy"))
    else:
        document.setdefault("format", None)
        document.setdefault("hash_policy", None)
    document.setdefault("environment", environment())
    for key in ("mounts", "windows_installations", "users", "path_hits", "artifacts", "routes", "cleanup", "errors"):
        document.setdefault(key, bounded_list([]))
    document.setdefault("scan", ScanSummary(depth_limit=0, entry_budget=0).document())
    # ASCII-escaped JSON remains lossless after parsing and avoids Windows
    # console-codepage failures for non-ASCII guest evidence strings.
    print(json.dumps(document, ensure_ascii=True, sort_keys=True))
