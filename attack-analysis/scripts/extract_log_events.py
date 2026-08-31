#!/usr/bin/env python3
"""Dispatch parser modules and write compact event candidates."""

from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common.time_normalize import clear_timezone_notes, timezone_notes

PARSER_MAP = {
    "web_access": ["parsers.apache_access"],
    "apache_access": ["parsers.apache_access"],
    "nginx_access": ["parsers.nginx_access"],
    "spring_app": ["parsers.spring_app"],
    "p6spy_sql": ["parsers.p6spy_sql", "parsers.spring_app"],
    "xlsx_login": ["parsers.xlsx_login"],
    "xlsx_operate": ["parsers.xlsx_operate"],
    "auth_text": ["parsers.generic_text"],
    "firewall_text": ["parsers.generic_text"],
    "waf_text": ["parsers.generic_text"],
    "system_text": ["parsers.generic_text"],
    "service_text": ["parsers.generic_text"],
    "mysqlbinlog_text": ["parsers.generic_text"],
    "generic_text": ["parsers.generic_text"],
}


def load_manifest(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def call_parser(module_name: str, path: str, file_entry: dict[str, Any], limit: int) -> dict[str, Any]:
    module = importlib.import_module(module_name)
    return module.parse(path, file_entry, limit=limit)


def extract(manifest: dict[str, Any], limit_per_file: int) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    parser_stats: list[dict[str, Any]] = []
    default_tz = manifest.get("default_timezone")
    clear_timezone_notes()
    for file_entry in manifest.get("files", []):
        if not file_entry.get("include", True):
            continue
        path = file_entry.get("path")
        # Interactive contract (SKILL.md): a user-confirmed declared_type wins
        # over detection; detection stays the fallback for quick-report runs.
        log_type = file_entry.get("declared_type") or file_entry.get("detected_type") or "generic_text"
        modules = PARSER_MAP.get(log_type, ["parsers.generic_text"])
        enriched_entry = dict(file_entry)
        enriched_entry["default_timezone"] = default_tz
        enriched_entry["log_type"] = log_type
        for module_name in modules:
            try:
                result = call_parser(module_name, path, enriched_entry, limit_per_file)
                parser_stats.append({"path": path, "module": module_name, **result.get("stats", {})})
                events.extend(result.get("events", []))
            except Exception as exc:  # noqa: BLE001 - keep case running
                parser_stats.append({"path": path, "module": module_name, "error": str(exc)})
    for idx, event in enumerate(events, 1):
        event["event_id"] = f"evt-{idx:06d}"
    result = {
        "case_id": manifest.get("case_id"),
        "mode": manifest.get("mode"),
        "event_count": len(events),
        "events": events,
        "parser_stats": parser_stats,
    }
    tz_notes = timezone_notes()
    if tz_notes:
        # Surface timezone degradation (e.g. missing tzdata on Windows) loudly
        # instead of leaving silently naive timestamps in the events.
        result["timezone_notes"] = tz_notes
        for stat in parser_stats:
            stat.setdefault("warnings", []).extend(tz_notes)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract compact event candidates from attack-analysis manifest.")
    parser.add_argument("--manifest", required=True, help="Path to analysis-manifest.json")
    parser.add_argument("--output-dir", help="Directory for event-candidates.json")
    parser.add_argument("--limit-per-file", type=int, default=10000)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    data = extract(load_manifest(args.manifest), args.limit_per_file)
    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "event-candidates.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json or not args.output_dir:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
