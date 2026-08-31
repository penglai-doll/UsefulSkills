"""Create and resume a small, explicit investigation case state directory."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import sys
import time
import uuid
from pathlib import Path

from common import (
    AVAILABLE_HASH_ALGORITHMS,
    bounded_list,
    case_id,
    deterministic_segment_set_sha256,
    emit,
    environment,
    evidence_segments,
    segment_metadata,
    sha256_file,
)

MAX_SECRET_CHARACTERS = 1024 * 1024


def atomic_write_text(destination: Path, contents: str) -> None:
    """Replace a text file only after a complete neighbouring temporary write."""
    temporary_path = destination.with_name(destination.name + ".tmp-" + uuid.uuid4().hex)
    try:
        with temporary_path.open("w", encoding="utf-8", newline="\n") as temporary_file:
            temporary_file.write(contents)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_path, destination)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()


LOCK_OWNER_NAME = "owner.json"
LOCK_STALE_AFTER_SECONDS = 600.0
LOCK_PERMISSION_RETRY_SECONDS = 10.0
LOCK_RELEASE_RETRY_SECONDS = 5.0


def _pid_is_alive(pid: int) -> bool | None:
    """Report whether ``pid`` still runs, or None when that cannot be determined.

    Windows must never use ``os.kill`` for probing: it terminates the target.
    ``_winapi`` provides the same stdlib-only OpenProcess(SYNCHRONIZE) probe
    without importing a forbidden process bridge such as ctypes.
    """
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import _winapi

            synchronize = 0x00100000
            query_limited = 0x1000
            wait_timeout = 258
            access_denied = 5
            try:
                handle = _winapi.OpenProcess(synchronize | query_limited, False, pid)
            except OSError as error:
                return getattr(error, "winerror", None) == access_denied
            try:
                # A process handle signals exactly once, on termination.
                return _winapi.WaitForSingleObject(handle, 0) == wait_timeout
            finally:
                _winapi.CloseHandle(handle)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True
    except (ImportError, AttributeError, OSError):
        return None


def _lock_owner(lock_path: Path) -> dict:
    try:
        document = json.loads((lock_path / LOCK_OWNER_NAME).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return document if isinstance(document, dict) else {}


def _write_lock_owner(lock_path: Path) -> None:
    # Best effort: a missing owner file simply falls back to age-based staleness.
    try:
        atomic_write_text(
            lock_path / LOCK_OWNER_NAME,
            json.dumps({"pid": os.getpid(), "created": time.time()}),
        )
    except OSError:
        pass


def _lock_is_stale(lock_path: Path) -> bool:
    """A lock is stale when it is old enough and its owner process is gone."""
    try:
        age = max(0.0, time.time() - lock_path.stat().st_mtime)
    except OSError:
        return False
    if age < LOCK_STALE_AFTER_SECONDS:
        return False
    pid = _lock_owner(lock_path).get("pid")
    if not isinstance(pid, int):
        return True
    alive = _pid_is_alive(pid)
    if alive is None:
        return True
    return not alive


def _reclaim_stale_lock(lock_path: Path) -> bool:
    """Steal a provably stale lock by renaming it aside (atomic, race-safe)."""
    if not _lock_is_stale(lock_path):
        return False
    victim = lock_path.with_name(lock_path.name + ".stale-" + uuid.uuid4().hex)
    try:
        os.rename(lock_path, victim)
    except OSError:
        return False
    deadline = time.monotonic() + LOCK_RELEASE_RETRY_SECONDS
    while True:
        try:
            owner = victim / LOCK_OWNER_NAME
            try:
                owner.unlink()
            except FileNotFoundError:
                pass
            victim.rmdir()
            return True
        except FileNotFoundError:
            return True
        except PermissionError:
            if time.monotonic() >= deadline:
                return True
            time.sleep(0.01)
        except OSError:
            return True


def _release_lock(lock_path: Path) -> None:
    """Remove the owner file and lock directory, tolerating Windows races."""
    deadline = time.monotonic() + LOCK_RELEASE_RETRY_SECONDS
    while True:
        try:
            recorded_pid = _lock_owner(lock_path).get("pid")
            if isinstance(recorded_pid, int) and recorded_pid != os.getpid():
                return
            try:
                (lock_path / LOCK_OWNER_NAME).unlink()
            except FileNotFoundError:
                pass
            lock_path.rmdir()
            return
        except FileNotFoundError:
            return
        except PermissionError:
            if time.monotonic() >= deadline:
                return
            time.sleep(0.01)


@contextmanager
def case_mutex(case_dir: Path, wait_seconds: float = 30.0):
    """Serialize case mutations with a portable, transient lock directory.

    Windows briefly raises PermissionError from mkdir while a concurrent
    rmdir leaves the directory in delete-pending state, so that case is
    retried like FileExistsError instead of escaping to the caller.
    """
    lock_path = case_dir / ".case-state-lock"
    deadline = time.monotonic() + wait_seconds
    permission_deadline = time.monotonic() + min(wait_seconds, LOCK_PERMISSION_RETRY_SECONDS)
    while True:
        try:
            lock_path.mkdir()
            break
        except FileExistsError:
            if _reclaim_stale_lock(lock_path):
                continue
            if time.monotonic() >= deadline:
                raise ValueError("case state is busy; retry the mutation")
            time.sleep(0.01)
        except PermissionError:
            if time.monotonic() >= permission_deadline:
                raise
            time.sleep(0.01)
    try:
        _write_lock_owner(lock_path)
        yield
    finally:
        _release_lock(lock_path)


def evidence_metadata(
    path: Path,
    hash_policy: str,
    segment_limit: int = 50,
    details_dir: Path | None = None,
) -> tuple[dict, str, list[dict], list[dict]]:
    image_format, segments = evidence_segments(path)
    manifest = segment_metadata(segments)
    total_size = sum(item["size"] for item in manifest)
    segment_details = (
        str((details_dir / "evidence-segments.json").resolve())
        if details_dir is not None
        else None
    )
    hash_details = (
        str((details_dir / "evidence-hashes.json").resolve())
        if details_dir is not None
        else None
    )
    result = {
        "path": str(segments[0]),
        "size": total_size,
        "total_size": total_size,
        "mtime": max(item["mtime"] for item in manifest),
        "segment_count": len(manifest),
        "segments": bounded_list(
            manifest,
            segment_limit,
            details_path=segment_details,
        ),
        "available_hash_algorithms": list(AVAILABLE_HASH_ALGORITHMS),
    }
    hashes: list[dict] = []
    if hash_policy == "now":
        hashes = [{"name": segment.name, "sha256": sha256_file(segment)} for segment in segments]
        result["hash"] = {
            "policy": "now",
            "segment_hashes": bounded_list(
                hashes,
                segment_limit,
                details_path=hash_details,
            ),
            "set_sha256": deterministic_segment_set_sha256(hashes),
        }
        if len(hashes) == 1:
            result["sha256"] = hashes[0]["sha256"]
    return result, image_format, manifest, hashes


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n")


def append_record(path: Path, value: dict) -> None:
    previous = path.read_text(encoding="utf-8") if path.exists() else ""
    atomic_write_text(path, previous + json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def session_path(case_dir: Path) -> Path:
    return case_dir / "session.json"


def load_session(case_dir: Path) -> dict:
    path = session_path(case_dir)
    if not path.is_file():
        raise ValueError("case directory has not been initialized")
    session = load_json(path)
    if not isinstance(session, dict):
        raise ValueError("session.json must contain an object")
    return session


def with_session(session: dict, **extensions: object) -> dict:
    document = dict(session)
    document.update(extensions)
    document["case"] = session
    return document


def initialize(
    case_dir: Path,
    image: Path | None,
    hash_policy: str,
    mode: str | None = None,
) -> dict:
    image_format = None
    evidence = None
    segment_manifest: list[dict] = []
    segment_hashes: list[dict] = []
    if image is not None:
        evidence, image_format, segment_manifest, segment_hashes = evidence_metadata(
            image,
            hash_policy,
            details_dir=case_dir.resolve() / "raw",
        )
    case_dir.mkdir(parents=True, exist_ok=True)
    with case_mutex(case_dir):
        if any(path.name != ".case-state-lock" for path in case_dir.iterdir()):
            raise ValueError("case directory already contains state; resume it instead of re-initializing")
        (case_dir / "raw").mkdir(exist_ok=True)
        session = {
            "schema": "windows-loader.v1",
            "case_id": case_id(),
            "evidence": None,
            "hash_policy": hash_policy,
            "available_hash_algorithms": list(AVAILABLE_HASH_ALGORITHMS),
            "environment": environment(),
            "format": image_format,
            "mounts": bounded_list([]),
            "windows_installations": bounded_list([]),
            "users": bounded_list([]),
            "path_hits": bounded_list([]),
            "artifacts": bounded_list([]),
            "routes": bounded_list([]),
            "cleanup": bounded_list([]),
            "errors": bounded_list([]),
            "mode": mode,
            "plaintext_acknowledged": False,
        }
        if evidence is not None:
            session["evidence"] = evidence
            write_json(case_dir / "raw" / "evidence-segments.json", segment_manifest)
            if hash_policy == "now":
                write_json(case_dir / "raw" / "evidence-hashes.json", segment_hashes)
        write_json(session_path(case_dir), session)
        atomic_write_text(case_dir / "notes.md", "# Case notes\n")
        for name in ("commands.jsonl", "findings.jsonl", "secrets.jsonl", "inspect.json", "mounts.json"):
            atomic_write_text(case_dir / name, "")
        return session


def require_case(case_dir: Path) -> None:
    if not session_path(case_dir).is_file():
        raise ValueError("case directory has not been initialized")


def read_records(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def evidence_still_matches(case_dir: Path, session: dict) -> bool:
    evidence = session.get("evidence")
    if evidence is None:
        return True
    path = Path(evidence["path"])
    hash_policy = session.get("hash_policy", "later")
    current, image_format, current_manifest, _ = evidence_metadata(
        path,
        "skip",
        details_dir=case_dir.resolve() / "raw",
    )
    recorded_manifest = load_json(case_dir / "raw" / "evidence-segments.json")
    if not isinstance(recorded_manifest, list) or recorded_manifest != current_manifest:
        return False
    if image_format != session.get("format") or current["path"] != evidence.get("path"):
        return False
    if current["total_size"] != evidence.get("total_size", evidence.get("size")):
        return False
    if hash_policy == "now":
        current, _, hash_manifest, current_hashes = evidence_metadata(
            path,
            "now",
            details_dir=case_dir.resolve() / "raw",
        )
        if hash_manifest != current_manifest:
            return False
        recorded_hashes = load_json(case_dir / "raw" / "evidence-hashes.json")
        recorded_hash = evidence.get("hash", {})
        return (
            isinstance(recorded_hashes, list)
            and recorded_hashes == current_hashes
            and recorded_hash.get("set_sha256") == current["hash"]["set_sha256"]
        )
    return "hash" not in evidence and "sha256" not in evidence


def resume(case_dir: Path, limit: int) -> dict:
    session = load_session(case_dir)
    try:
        evidence_matches = evidence_still_matches(case_dir, session)
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        evidence_matches = False
    mounts = []
    for record in read_records(case_dir / "mounts.json"):
        path = Path(record["path"])
        exists = path.is_dir()
        claimed = bool(record.get("claimed_read_only", record.get("read_only", False)))
        if not exists:
            mounts.append({"path": str(path), "exists": False, "claimed_read_only": claimed, "read_only": False, "probe_status": "unavailable", "probe_method": "exists"})
            continue
        try:
            writable = os.access(path, os.W_OK)
            mounts.append({"path": str(path), "exists": True, "claimed_read_only": claimed, "read_only": not writable, "probe_status": "best-effort", "probe_method": "os.access(W_OK)", "read_only_confidence": "not-verified"})
        except OSError as error:
            mounts.append({"path": str(path), "exists": True, "claimed_read_only": claimed, "read_only": None, "probe_status": "unverifiable", "probe_method": "os.access(W_OK)", "probe_error": str(error)})
    document = dict(session)
    document["mounts"] = bounded_list(
        mounts,
        limit,
        details_path=str(case_dir.resolve() / "mounts.json"),
    )
    document["revalidation"] = {
        "evidence_matches": evidence_matches,
        "mounts": document["mounts"],
    }
    return with_session(document)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    init = subparsers.add_parser("init")
    init.add_argument("--case-dir", required=True, type=Path)
    init.add_argument("--image", type=Path)
    init.add_argument("--hash", choices=("now", "later", "skip"), default="later")
    init.add_argument(
        "--mode",
        choices=("mount-only", "fast-path", "mount-and-analyze"),
        default=None,
    )
    acknowledge = subparsers.add_parser("acknowledge-plaintext-risk")
    acknowledge.add_argument("--case-dir", required=True, type=Path)
    secret = subparsers.add_parser("record-secret")
    secret.add_argument("--case-dir", required=True, type=Path)
    secret.add_argument("--name", required=True)
    secret.add_argument(
        "--stdin",
        action="store_true",
        required=True,
        help="read the complete secret from standard input; the value is never echoed",
    )
    mount = subparsers.add_parser("record-mount")
    mount.add_argument("--case-dir", required=True, type=Path)
    mount.add_argument("--path", required=True, type=Path)
    mount.add_argument("--read-only", action="store_true")
    finding = subparsers.add_parser("record-finding")
    finding.add_argument("--case-dir", required=True, type=Path)
    finding.add_argument("--text", required=True)
    command = subparsers.add_parser("record-command")
    command.add_argument("--case-dir", required=True, type=Path)
    command.add_argument("--text", required=True)
    cleanup = subparsers.add_parser("record-cleanup")
    cleanup.add_argument("--case-dir", required=True, type=Path)
    cleanup.add_argument("--text", required=True)
    resume_parser = subparsers.add_parser("resume")
    resume_parser.add_argument("--case-dir", required=True, type=Path)
    resume_parser.add_argument("--limit", type=int, default=50)
    args = parser.parse_args()
    try:
        if args.command == "init":
            session = initialize(args.case_dir, args.image, args.hash, args.mode)
            emit(with_session(session))
        elif args.command == "acknowledge-plaintext-risk":
            with case_mutex(args.case_dir):
                session = load_session(args.case_dir)
                warning = "Plaintext secret values will be persisted in secrets.jsonl; anyone able to read the case directory may read them."
                print("WARNING: " + warning, file=sys.stderr)
                session["plaintext_acknowledged"] = True
                write_json(session_path(args.case_dir), session)
                emit(with_session(
                    session,
                    plaintext_acknowledged=True,
                    plaintext_risk=warning,
                ))
        elif args.command == "record-secret":
            with case_mutex(args.case_dir):
                session = load_session(args.case_dir)
                if not session.get("plaintext_acknowledged"):
                    raise ValueError("acknowledge plaintext risk before recording a secret")
                value = sys.stdin.read(MAX_SECRET_CHARACTERS + 1)
                if len(value) > MAX_SECRET_CHARACTERS:
                    raise ValueError(
                        f"secret exceeds the {MAX_SECRET_CHARACTERS} character input bound"
                    )
                append_record(
                    args.case_dir / "secrets.jsonl",
                    {"name": args.name, "value": value},
                )
                emit(with_session(session, recorded="secret"))
        elif args.command == "record-mount":
            with case_mutex(args.case_dir):
                session = load_session(args.case_dir)
                mount_path = args.path.resolve()
                record = {"path": str(mount_path), "claimed_read_only": bool(args.read_only)}
                append_record(args.case_dir / "mounts.json", record)
                mounts = read_records(args.case_dir / "mounts.json")
                session["mounts"] = bounded_list(
                    mounts,
                    50,
                    details_path=str((args.case_dir.resolve() / "mounts.json")),
                )
                write_json(session_path(args.case_dir), session)
                emit(with_session(session, recorded="mount"))
        elif args.command in {"record-finding", "record-command", "record-cleanup"}:
            with case_mutex(args.case_dir):
                require_case(args.case_dir)
                if args.command == "record-cleanup":
                    session = load_session(args.case_dir)
                    cleanup = session.get("cleanup", bounded_list([]))
                    record = {"kind": "cleanup", "text": args.text}
                    append_record(args.case_dir / "commands.jsonl", record)
                    items = list(cleanup.get("items", [])) + [record]
                    shown = items[-50:]
                    total = int(cleanup.get("total_count", 0)) + 1
                    session["cleanup"] = {
                        "items": shown,
                        "total_count": total,
                        "shown_count": len(shown),
                        "truncated": total > len(shown),
                        "details_path": str(args.case_dir.resolve() / "commands.jsonl"),
                    }
                    write_json(session_path(args.case_dir), session)
                else:
                    target = {"record-finding": "findings.jsonl", "record-command": "commands.jsonl"}[args.command]
                    append_record(args.case_dir / target, {"kind": args.command.removeprefix("record-"), "text": args.text})
                    session = load_session(args.case_dir)
                emit(with_session(session, recorded=args.command.removeprefix("record-")))
        else:
            emit(resume(args.case_dir, args.limit))
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
