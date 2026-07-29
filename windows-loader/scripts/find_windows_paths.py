"""Search high-value paths beneath an already-mounted Windows root."""

from __future__ import annotations

import argparse
import os
import re
from pathlib import Path

from common import (
    ScanSummary,
    bounded_list,
    child_casefold,
    emit,
    guest_path,
    is_reparse,
    safe_is_dir,
    safe_is_file,
    safe_walk,
    windows_path_hit,
)


def descend(root: Path, names: tuple[str, ...], summary: ScanSummary | None = None) -> Path | None:
    current: Path | None = root
    for name in names:
        current = child_casefold(current, name, summary) if current else None
        if current is None:
            return None
    return current


def regular_files(directory: Path | None, depth: int, summary: ScanSummary, cap: int) -> list[Path]:
    if directory is None or not safe_is_dir(directory, summary):
        return []
    found: list[Path] = []
    for _, children in safe_walk(directory, max_depth=depth, entry_budget=summary.entry_budget, summary=summary):
        for child in children:
            try:
                if not is_reparse(child, summary=summary) and safe_is_file(child, summary):
                    found.append(child)
                    if len(found) >= cap:
                        summary.truncated = True
                        return found
            except OSError as error:
                summary.errors.append(f"file probe failed at {child}: {error}")
                continue
    return found


def matches_kind(path: Path, kind: str) -> bool:
    if kind == "all":
        return True
    suffix = path.suffix.casefold()
    if kind == "config":
        return suffix in {
            ".config", ".conf", ".dat", ".db", ".ini", ".json",
            ".sqlite", ".toml", ".xml", ".yaml", ".yml",
        }
    if kind == "data":
        return suffix in {".db", ".sqlite", ".dat", ".csv"}
    if kind == "logs":
        return suffix in {".log", ".evtx", ".etl"}
    if kind == "secret":
        return any(token in path.name.casefold() for token in ("credential", "token", "secret", "key", "login"))
    return True


def discover_users(root: Path, user: str | None, summary: ScanSummary) -> list[str]:
    if user:
        return [user]
    users: list[str] = []
    users_root = child_casefold(root, "Users", summary)
    if users_root:
        try:
            with os.scandir(users_root) as entries:
                for entry in entries:
                    if summary.entries_seen >= summary.entry_budget:
                        summary.truncated = True
                        break
                    summary.entries_seen += 1
                    path = Path(entry.path)
                    if is_reparse(path, entry, summary):
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            users.append(entry.name)
                    except OSError as error:
                        summary.errors.append(f"directory probe failed at {path}: {error}")
        except OSError as error:
            summary.errors.append(f"scan unavailable at {users_root}: {error}")
    return sorted(set(users), key=str.casefold)


def named_software_directories(
    root: Path,
    base: tuple[str, ...],
    software: str,
    publisher: str,
    summary: ScanSummary,
) -> list[Path | None]:
    candidates: list[Path | None] = []
    if software:
        candidates.append(descend(root, (*base, software), summary))
    if publisher and software:
        candidates.append(descend(root, (*base, publisher, software), summary))
    elif publisher:
        candidates.append(descend(root, (*base, publisher), summary))
    return candidates


def catalog_directories(
    root: Path,
    software: str,
    publisher: str,
    user: str | None,
    summary: ScanSummary,
) -> tuple[list[Path], list[str]]:
    software = software.strip()
    publisher = publisher.strip()
    candidates: list[Path | None] = []
    for base in (
        ("ProgramData",),
        ("Program Files",),
        ("Program Files (x86)",),
        ("Tools", "Portable"),
        ("PortableApps",),
        ("Users", "Public", "Tools"),
    ):
        candidates.extend(named_software_directories(root, base, software, publisher, summary))
    users = discover_users(root, user, summary)
    for name in users:
        for appdata in ("Roaming", "Local", "LocalLow"):
            base = ("Users", name, "AppData", appdata)
            candidates.extend(named_software_directories(root, base, software, publisher, summary))
        packages = descend(root, ("Users", name, "AppData", "Local", "Packages"), summary)
        package_terms = [term.casefold() for term in (software, publisher) if term]
        if packages and package_terms:
            try:
                with os.scandir(packages) as entries:
                    for entry in entries:
                        if summary.entries_seen >= summary.entry_budget:
                            summary.truncated = True
                            break
                        summary.entries_seen += 1
                        package_path = Path(entry.path)
                        if (
                            is_reparse(package_path, entry, summary)
                            or not any(term in entry.name.casefold() for term in package_terms)
                        ):
                            continue
                        try:
                            if not entry.is_dir(follow_symlinks=False):
                                continue
                        except OSError as error:
                            summary.errors.append(f"directory probe failed at {package_path}: {error}")
                            continue
                        for state in ("LocalState", "RoamingState", "Settings"):
                            candidates.append(descend(package_path, (state,), summary))
            except OSError as error:
                summary.errors.append(f"scan unavailable at {packages}: {error}")
    return [candidate for candidate in candidates if candidate is not None], users


def existing_catalog_paths(
    root: Path,
    users: list[str],
    summary: ScanSummary,
) -> tuple[list[Path], list[Path], list[Path]]:
    """Return explicit Stage 1 dirs/files and the only roots Stage 2 may scan."""
    stage1_directory_segments = [
        ("Windows", "System32", "winevt", "Logs"),
        ("Windows", "System32", "Tasks"),
        ("Windows", "Prefetch"),
        ("Windows", "ServiceProfiles", "LocalService"),
        ("Windows", "ServiceProfiles", "NetworkService"),
        ("Windows", "System32", "config", "systemprofile"),
        ("ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        ("ProgramData", "Microsoft", "Wlansvc", "Profiles", "Interfaces"),
    ]
    direct_file_segments = [
        ("Windows", "AppCompat", "Programs", "Amcache.hve"),
        ("Windows", "System32", "sru", "SRUDB.dat"),
        ("Windows", "System32", "drivers", "etc", "hosts"),
    ]
    stage2_directory_segments = [
        ("ProgramData",),
        ("Program Files",),
        ("Program Files (x86)",),
        ("Tools",),
        ("PortableApps",),
        ("Users", "Public", "Tools"),
    ]
    for name in users:
        stage1_directory_segments.extend([
            ("Users", name, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
            ("Users", name, "AppData", "Local", "Google", "Chrome", "User Data"),
            ("Users", name, "AppData", "Local", "Microsoft", "Edge", "User Data"),
            ("Users", name, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles"),
            ("Users", name, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine"),
            ("Users", name, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "AutomaticDestinations"),
            ("Users", name, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "CustomDestinations"),
        ])
        direct_file_segments.extend([
            ("Users", name, "NTUSER.DAT"),
            ("Users", name, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
        ])
        stage2_directory_segments.extend([
            ("Users", name, "AppData", "Roaming"),
            ("Users", name, "AppData", "Local"),
            ("Users", name, "AppData", "LocalLow"),
            ("Users", name, "Documents"),
            ("Users", name, "Downloads"),
            ("Users", name, "Saved Games"),
            ("Users", name, "Desktop"),
        ])

    def resolve_many(values: list[tuple[str, ...]], file_only: bool = False) -> list[Path]:
        resolved: list[Path] = []
        for components in values:
            candidate = descend(root, components, summary)
            if candidate is None:
                continue
            valid = safe_is_file(candidate, summary) if file_only else safe_is_dir(candidate, summary)
            if valid:
                resolved.append(candidate)
        return sorted(set(resolved), key=lambda path: guest_path(root, path).casefold())

    stage1_directories = resolve_many(stage1_directory_segments)
    direct_files = resolve_many(direct_file_segments, file_only=True)
    stage2_directories = resolve_many(stage2_directory_segments)
    stage2_directories = sorted(
        set([*stage1_directories, *stage2_directories]),
        key=lambda path: guest_path(root, path).casefold(),
    )
    return stage1_directories, direct_files, stage2_directories


def registry_hives(root: Path, users: list[str], summary: ScanSummary) -> list[Path]:
    candidates = [
        descend(root, ("Windows", "System32", "config", name), summary)
        for name in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY", "DEFAULT")
    ]
    for name in users:
        candidates.extend([
            descend(root, ("Users", name, "NTUSER.DAT"), summary),
            descend(
                root,
                ("Users", name, "AppData", "Local", "Microsoft", "Windows", "UsrClass.dat"),
                summary,
            ),
        ])
    hives: list[Path] = []
    for candidate in candidates:
        try:
            if (
                candidate is not None
                and not is_reparse(candidate, summary=summary)
                and safe_is_file(candidate, summary)
            ):
                hives.append(candidate)
        except OSError as error:
            summary.errors.append(f"registry hive unavailable at {candidate}: {error}")
    return sorted(set(hives), key=lambda path: guest_path(root, path).casefold())


def bounded_registry_strings(
    root: Path,
    hives: list[Path],
    terms: list[str],
    byte_budget: int,
    match_cap: int,
) -> tuple[list[dict], dict, list[str]]:
    matches: list[dict] = []
    errors: list[str] = []
    bytes_read = 0
    hives_examined = 0
    truncated = False
    patterns = (
        ("ascii", re.compile(rb"[\x20-\x7e]{4,}")),
        ("utf-16le", re.compile(rb"(?:[\x20-\x7e]\x00){4,}")),
    )
    ordered_hives = sorted(hives, key=lambda path: guest_path(root, path).casefold())
    base_quota, remainder = divmod(byte_budget, len(ordered_hives)) if ordered_hives else (0, 0)
    for index, hive in enumerate(ordered_hives):
        quota = base_quota + (1 if index < remainder else 0)
        if quota <= 0:
            truncated = True
            continue
        try:
            with hive.open("rb") as source:
                data = source.read(quota + 1)
        except OSError as error:
            errors.append(f"registry read unavailable at {hive}: {error}")
            continue
        hives_examined += 1
        if len(data) > quota:
            truncated = True
            data = data[:quota]
        bytes_read += len(data)
        direct_terms = [term for term in terms if any(ord(character) > 127 for character in term)]
        for term in direct_terms:
            needle = term.encode("utf-16le")
            search_from = 0
            while len(matches) < match_cap:
                offset = data.find(needle, search_from)
                if offset < 0:
                    break
                alignment = offset % 2
                preview_start = max(alignment, offset - 160)
                preview_start -= (preview_start - alignment) % 2
                preview_end = min(len(data), offset + len(needle) + 160)
                preview_end -= (preview_end - preview_start) % 2
                decoded = data[preview_start:preview_end].decode("utf-16le", errors="ignore")
                value = "".join(
                    character if character.isprintable() else " "
                    for character in decoded
                ).strip()
                matched_terms = sorted(
                    {candidate for candidate in terms if candidate.casefold() in value.casefold()},
                    key=str.casefold,
                )
                matches.append({
                    "hive": guest_path(root, hive),
                    "encoding": "utf-16le-direct",
                    "offset": offset,
                    "value": value[:240],
                    "matched_terms": bounded_list(matched_terms or [term], len(terms)),
                })
                search_from = offset + max(2, len(needle))
            if len(matches) >= match_cap:
                truncated = True
                break
        if len(matches) >= match_cap:
            break
        for encoding, pattern in patterns:
            for candidate in pattern.finditer(data):
                value = candidate.group().decode(encoding, errors="ignore")
                matched_terms = sorted(
                    {term for term in terms if term.casefold() in value.casefold()},
                    key=str.casefold,
                )
                if not matched_terms:
                    continue
                positions = [
                    value.casefold().find(term.casefold())
                    for term in matched_terms
                ]
                first_match = min(position for position in positions if position >= 0)
                preview_start = max(0, first_match - 80)
                matches.append({
                    "hive": guest_path(root, hive),
                    "encoding": encoding,
                    "offset": candidate.start(),
                    "value": value[preview_start:preview_start + 240],
                    "matched_terms": bounded_list(matched_terms, len(terms)),
                })
                if len(matches) >= match_cap:
                    truncated = True
                    break
            if len(matches) >= match_cap:
                break
        if len(matches) >= match_cap:
            break
    scan = {
        "byte_budget": byte_budget,
        "bytes_read": bytes_read,
        "hives_examined": hives_examined,
        "truncated": truncated,
    }
    return matches, scan, errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--software", default="")
    parser.add_argument("--publisher", default="")
    parser.add_argument("--user")
    parser.add_argument(
        "--kind",
        choices=("all", "config", "data", "logs", "secret"),
        default="all",
    )
    parser.add_argument("--depth", type=int, default=4)
    parser.add_argument(
        "--expand",
        action="store_true",
        help="authorize bounded Stage 2 scanning within explicit catalog roots",
    )
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--entry-budget", type=int, default=2000)
    parser.add_argument(
        "--registry-byte-budget",
        type=int,
        default=4 * 1024 * 1024,
        help="maximum total registry bytes inspected during Stage 1",
    )
    args = parser.parse_args()
    root = args.root
    depth = max(0, args.depth)
    limit = max(0, args.limit)
    entry_budget = max(0, args.entry_budget)
    total_scan = ScanSummary(depth_limit=depth, entry_budget=entry_budget)
    if is_reparse(root, summary=total_scan) or not safe_is_dir(root, total_scan):
        parser.error("root is unavailable or unsafe")
    hits: list[Path] = []
    hit_cap = max(1, limit * 5)
    software_directories, users = catalog_directories(
        root,
        args.software,
        args.publisher,
        args.user,
        total_scan,
    )
    fixed_directories, direct_files, stage2_roots = existing_catalog_paths(
        root,
        users,
        total_scan,
    )
    registry_candidates = registry_hives(root, users, total_scan)
    routing_entries = total_scan.entries_seen
    routing_directories = total_scan.directories_seen
    routing_truncated = total_scan.truncated
    directories = sorted(
        set([*software_directories, *fixed_directories]),
        key=lambda path: guest_path(root, path).casefold(),
    )
    for directory in directories:
        if total_scan.truncated:
            break
        hits.extend(regular_files(directory, depth, total_scan, max(1, limit * 3)))
        if len(hits) >= hit_cap:
            hits = hits[:hit_cap]
            total_scan.truncated = True
            break

    hits.extend(direct_files)
    if args.kind == "all":
        hits.extend(registry_candidates)
    registry_hints = [guest_path(root, path) for path in registry_candidates]
    registry_terms = [term for term in (args.software.strip(), args.publisher.strip()) if term]
    registry_matches, registry_scan, registry_errors = bounded_registry_strings(
        root,
        registry_candidates,
        registry_terms,
        max(0, args.registry_byte_budget),
        hit_cap,
    )
    stage1_end_entries = total_scan.entries_seen
    stage1_end_directories = total_scan.directories_seen
    stage1_truncated = total_scan.truncated
    stage1_hits = sorted(
        {guest_path(root, path) for path in hits if matches_kind(path, args.kind)},
        key=str.casefold,
    )
    hit_paths = {guest_path(root, path): path for path in hits if matches_kind(path, args.kind)}

    terms = [term.casefold() for term in (args.software, args.publisher) if term]
    registry_matches_relevant = args.kind in {"all", "config", "data"}
    registry_scan["semantically_relevant_to_kind"] = registry_matches_relevant
    stage1_has_hits = bool(stage1_hits or (registry_matches and registry_matches_relevant))
    stage2_authorized = bool(args.expand)
    stage2_executed = stage2_authorized
    normalized_hits = list(stage1_hits)
    if stage2_executed:
        generic_hit_paths: dict[str, Path] = {}
        for catalog_root in stage2_roots:
            if total_scan.truncated:
                break
            for _, children in safe_walk(
                catalog_root,
                max_depth=depth,
                entry_budget=total_scan.entry_budget,
                summary=total_scan,
            ):
                for child in children:
                    if (
                        is_reparse(child, summary=total_scan)
                        or not safe_is_file(child, total_scan)
                        or not matches_kind(child, args.kind)
                    ):
                        continue
                    reported = guest_path(root, child)
                    if not terms or any(term in reported.casefold() for term in terms):
                        generic_hit_paths[reported] = child
                        if len(generic_hit_paths) >= hit_cap:
                            total_scan.truncated = True
                            break
                if total_scan.truncated:
                    break
        hit_paths.update(generic_hit_paths)
        normalized_hits = sorted(set([*stage1_hits, *generic_hit_paths]), key=str.casefold)

    stage2_contract = {
        "authorization_flag": "--expand",
        "authorization_required": not stage1_has_hits and not stage2_authorized,
        "authorized": stage2_authorized,
        "executed": stage2_executed,
        "proposed_scope": guest_path(root, root),
        "catalog_roots": bounded_list(
            [guest_path(root, path) for path in stage2_roots],
            limit,
        ),
        "estimated_cost": {
            "depth_limit": depth,
            "maximum_entries": entry_budget,
            "result_limit": limit,
            "entry_budget_scope": "routing+stage1+stage2-total",
        },
    }
    stage2_entries = total_scan.entries_seen - stage1_end_entries
    stage2_directories = total_scan.directories_seen - stage1_end_directories
    stage1_entries = stage1_end_entries - routing_entries
    stage1_directories = stage1_end_directories - routing_directories
    budget_exhausted = total_scan.truncated and total_scan.entries_seen >= entry_budget

    def phase_scan(entries: int, directories_seen: int, truncated: bool) -> dict:
        return {
            "depth_limit": depth,
            "entry_budget": entry_budget,
            "entries_seen": entries,
            "directories_seen": directories_seen,
            "truncated": truncated,
        }

    routing_scan = phase_scan(routing_entries, routing_directories, routing_truncated)
    stage1_scan = phase_scan(stage1_entries, stage1_directories, stage1_truncated)
    routes = ["high-value-catalog"]
    if stage2_executed:
        routes.append("bounded-catalog-scan")
    elif not stage1_has_hits:
        routes.append("stage2-authorization-required")
    budget_errors = []
    if budget_exhausted:
        routes.append("entry-budget-exhausted")
        budget_errors.append(
            "total entry budget exhausted; routing or search results are incomplete"
        )
    emit({
        "search": {
            "depth": depth,
            "expanded": stage2_authorized,
            "kind": args.kind,
            "software": args.software,
            "publisher": args.publisher,
            "user": args.user,
            "budget": {
                "scope": "routing+stage1+stage2-total",
                "authorized_total_entries": entry_budget,
                "routing_entries": routing_entries,
                "stage1_entries": stage1_entries,
                "stage2_entries": stage2_entries,
                "total_entries_seen": total_scan.entries_seen,
                "truncated": total_scan.truncated,
            },
            "stage1": {
                "hit_count": len(stage1_hits) + (
                    len(registry_matches) if registry_matches_relevant else 0
                ),
                "path_hit_count": len(stage1_hits),
                "registry_match_count": len(registry_matches),
                "relevant_registry_match_count": (
                    len(registry_matches) if registry_matches_relevant else 0
                ),
                "scan": stage1_scan,
                "routing_scan": routing_scan,
                "registry_scan": registry_scan,
            },
            "stage2": stage2_contract,
        },
        "hits": bounded_list(normalized_hits, limit),
        "path_hits": bounded_list(
            [windows_path_hit(root, hit_paths[path]) for path in normalized_hits],
            limit,
        ),
        "registry_hints": bounded_list(sorted(registry_hints, key=str.casefold), limit),
        "registry_matches": bounded_list(registry_matches, limit),
        "routes": bounded_list(routes, limit),
        "errors": bounded_list(
            [*total_scan.errors, *registry_errors, *budget_errors],
            limit,
        ),
        "scan": total_scan.document(),
    })


if __name__ == "__main__":
    main()
