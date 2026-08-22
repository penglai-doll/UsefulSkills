"""Read-only inventory of one or more already-mounted Windows roots."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from common import (
    ScanSummary,
    bounded_list,
    child_casefold,
    emit,
    guest_path,
    guest_to_local,
    is_reparse,
    safe_is_dir,
    safe_is_file,
    safe_walk,
    windows_path_hit,
)


def files_under(root: Path, depth: int, summary: ScanSummary, cap: int) -> tuple[list[Path], list[Path]]:
    found: list[Path] = []
    skipped: list[Path] = []
    for _, children in safe_walk(root, max_depth=depth, entry_budget=summary.entry_budget, summary=summary):
        for child in children:
            if is_reparse(child, summary=summary):
                skipped.append(child)
                continue
            if safe_is_file(child, summary):
                found.append(child)
                if len(found) >= cap:
                    summary.truncated = True
                    return found, skipped
    return found, skipped


def safe_directory_names(directory: Path, summary: ScanSummary, excluded: set[str] | None = None) -> list[str]:
    values: list[str] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if summary.entries_seen >= summary.entry_budget:
                    summary.truncated = True
                    break
                summary.entries_seen += 1
                path = Path(entry.path)
                if is_reparse(path, entry, summary):
                    continue
                try:
                    directory = entry.is_dir(follow_symlinks=False)
                except OSError as error:
                    summary.errors.append(f"directory probe failed at {path}: {error}")
                    continue
                if not directory:
                    continue
                if entry.name.casefold() not in (excluded or set()):
                    values.append(entry.name)
    except OSError as error:
        summary.errors.append(f"scan unavailable at {directory}: {error}")
    return sorted(values, key=str.casefold)


def inspect_root(root: Path, limit: int, depth: int, summary: ScanSummary) -> tuple[dict | None, list[Path], list[Path], list[str], list[str]]:
    errors: list[str] = []
    if is_reparse(root, summary=summary) or not safe_is_dir(root, summary):
        return None, [], [], [f"root is unavailable: {root}"], []
    windows = child_casefold(root, "Windows", summary)
    if windows is None or not safe_is_dir(windows, summary):
        return None, [], [], [f"Windows directory not found: {root}"], []
    users_root = child_casefold(root, "Users", summary)
    normal_users: list[str] = []
    if users_root and safe_is_dir(users_root, summary):
        normal_users = safe_directory_names(users_root, summary, {"default", "public", "all users"})
    services = child_casefold(windows, "ServiceProfiles", summary)
    service_users: list[str] = []
    if services and safe_is_dir(services, summary):
        service_users = safe_directory_names(services, summary)
    key_directories = {}
    for label, components in {
        "registry": ("Windows", "System32", "config"),
        "users": ("Users",),
        "program_data": ("ProgramData",),
        "program_files": ("Program Files",),
        "service_profiles": ("Windows", "ServiceProfiles"),
    }.items():
        current = root
        for component in components:
            current = child_casefold(current, component, summary) if current else None
        key_directories[label] = bool(current and safe_is_dir(current, summary))
    installation = {
        "root": str(root),
        "guest_root": guest_path(root, root),
        "windows_path": guest_path(root, windows),
        "users": bounded_list(normal_users, limit),
        "service_users": bounded_list(service_users, limit),
        "key_directories": key_directories,
    }
    found: list[Path] = []
    skipped: list[Path] = []
    candidates = [child_casefold(windows, "ServiceProfiles", summary)]
    candidates.extend(
        descend(root, ("Users", name, "AppData", "Local", "Packages"), summary)
        for name in normal_users
    )
    candidates.append(root)
    for candidate in candidates:
        if candidate is None or summary.truncated:
            continue
        files, reparse = files_under(candidate, depth, summary, max(limit * 3, limit))
        found.extend(files)
        skipped.extend(reparse)
    return installation, found, skipped, errors, normal_users


def descend(root: Path, names: tuple[str, ...], summary: ScanSummary) -> Path | None:
    current: Path | None = root
    for name in names:
        current = child_casefold(current, name, summary) if current else None
    return current


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, type=Path, help="an existing mounted root")
    parser.add_argument("--guest-path", action="append", default=[])
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--depth", type=int, default=4)
    parser.add_argument("--entry-budget", type=int, default=2000)
    args = parser.parse_args()
    installations: list[dict] = []
    hits: dict[str, tuple[Path, Path]] = {}
    skipped: list[str] = []
    errors: list[str] = []
    all_users: list[str] = []
    summary = ScanSummary(depth_limit=max(0, args.depth), entry_budget=max(0, args.entry_budget))
    for root in args.root:
        installation, discovered, reparse, root_errors, root_users = inspect_root(root, args.limit, max(0, args.depth), summary)
        if installation is not None:
            installations.append(installation)
            all_users.extend(root_users)
            for path in discovered:
                hits[guest_path(root, path)] = (root, path)
            skipped.extend(guest_path(root, path) for path in reparse)
            for requested in args.guest_path:
                local = guest_to_local(root, requested, summary)
                if local is not None and (safe_is_file(local, summary) or safe_is_dir(local, summary)):
                    canonical = guest_path(root, local)
                    hits[canonical] = (root, local)
        errors.extend(root_errors)
    errors.extend(summary.errors)
    requested_hits: list[str] = []
    for root in args.root:
        for requested in args.guest_path:
            local = guest_to_local(root, requested, summary)
            if local is not None and (safe_is_file(local, summary) or safe_is_dir(local, summary)):
                canonical = guest_path(root, local)
                requested_hits.append(canonical)
                hits[canonical] = (root, local)
    priority_hits = [
        hit for hit in hits
        if "\\ServiceProfiles\\" in hit or "\\Packages\\" in hit
    ]
    remaining_hits = [hit for hit in hits if hit not in requested_hits and hit not in priority_hits]
    ordered_hits = list(dict.fromkeys(requested_hits + priority_hits + sorted(remaining_hits, key=str.casefold)))
    emit({
        "windows_installations": bounded_list(installations, args.limit),
        "users": bounded_list(sorted(set(all_users), key=str.casefold), args.limit),
        "path_hits": bounded_list(
            [windows_path_hit(*hits[path]) for path in ordered_hits],
            args.limit,
        ),
        "hits": bounded_list(ordered_hits, args.limit),
        "skipped": bounded_list(["reparse skipped: " + item for item in sorted(set(skipped), key=str.casefold)], args.limit),
        "errors": bounded_list(errors, args.limit),
        "routes": bounded_list(["inspect-existing-mounted-root", "per-user-uwp-packages"], args.limit),
        "scan": summary.document(),
    })


if __name__ == "__main__":
    main()
