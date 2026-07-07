#!/usr/bin/env python3
"""Inventory logs for attack-analysis."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common.io_utils import is_gzip, is_probably_text, is_xlsx, iter_text_lines, safe_relpath
from common.time_normalize import parse_timestamp
from common.xlsx_utils import iter_rows, read_header

ACCESS_RE = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ [^"]+" \d{3}|-')
SPRING_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(ERROR|WARN|INFO|DEBUG|TRACE)\s+")

SECURITY_KEYWORDS = [
    "login",
    "auth",
    "error",
    "exception",
    "union",
    "select",
    "sleep(",
    "upload",
    "shell",
    "cmd=",
    "admin",
    "token",
    "passwd",
    ".git",
    "backup",
    ".zip",
    ".sql",
    "SQL 语句",
    "登录",
    "密码错误",
]


def discover(paths: list[str], include_hidden: bool = False) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_dir():
            for item in sorted(path.rglob("*")):
                if not item.is_file():
                    continue
                if not include_hidden and any(part.startswith(".") for part in item.parts):
                    continue
                files.append(item)
        elif path.is_file():
            if include_hidden or not path.name.startswith("."):
                files.append(path)
    return files


def size_strategy(size_bytes: int) -> str:
    if size_bytes < 100 * 1024 * 1024:
        return "full_stream_ok"
    if size_bytes < 2 * 1024 * 1024 * 1024:
        return "stream_with_candidate_filters"
    return "inventory_then_windowed_chunks"


def detect_xlsx(path: Path, default_timezone: str, sample_limit: int) -> dict[str, Any]:
    try:
        header = read_header(path)
    except Exception as exc:  # noqa: BLE001 - inventory must continue
        return {"detected_type": "xlsx_unknown", "confidence": "low", "header": [], "error": str(exc)}
    header_upper = {h.upper() for h in header}
    if {"LOGIN_TIME", "IP"} & header_upper and {"USER_NAME", "LOGIN_NAME", "USERNAME"} & header_upper:
        detected = "xlsx_login"
        confidence = "high"
    elif {"OPER_DESC", "FUNC_NAME", "MODULE_NAME"} & header_upper:
        detected = "xlsx_operate"
        confidence = "high"
    else:
        detected = "xlsx_table"
        confidence = "low"
    time_priority = ["LOGIN_TIME", "CREATE_TIME", "OPER_TIME", "CHECK_DATE", "LAST_UPDATE_TIME", "OPER_DATE"]
    header_lookup = {name.upper(): idx for idx, name in enumerate(header)}
    time_indexes = [header_lookup[name] for name in time_priority if name in header_lookup]
    first_ts = None
    last_ts = None
    try:
        rows = iter_rows(path, max_rows=sample_limit)
        next(rows, None)
        for _, row in rows:
            for idx in time_indexes:
                if idx >= len(row):
                    continue
                ts = parse_timestamp(row[idx], default_timezone).get("timestamp")
                if ts:
                    first_ts = first_ts or ts
                    last_ts = ts
                    break
    except Exception as exc:  # noqa: BLE001
        return {
            "detected_type": detected,
            "confidence": confidence,
            "header": header,
            "time_range": {"first": first_ts, "last": last_ts},
            "error": f"xlsx_time_scan_error:{exc}",
        }
    return {
        "detected_type": detected,
        "confidence": confidence,
        "header": header,
        "time_range": {"first": first_ts, "last": last_ts},
    }


def detect_text(path: Path, default_timezone: str, sample_limit: int) -> dict[str, Any]:
    first_lines: list[str] = []
    first_ts: str | None = None
    last_ts: str | None = None
    line_count = 0
    keyword_hits: dict[str, int] = {}
    bad = 0
    try:
        for line_no, line in iter_text_lines(path, max_lines=sample_limit):
            line_count = line_no
            if len(first_lines) < 20 and line.strip():
                first_lines.append(line)
            ts = parse_timestamp(line, default_timezone).get("timestamp")
            if ts:
                first_ts = first_ts or ts
                last_ts = ts
            lower = line.lower()
            for kw in SECURITY_KEYWORDS:
                if kw.lower() in lower:
                    keyword_hits[kw] = keyword_hits.get(kw, 0) + 1
    except Exception as exc:  # noqa: BLE001
        return {"detected_type": "unreadable", "confidence": "low", "error": str(exc), "bad_line_count": bad}

    sample = "\n".join(first_lines)
    if any(ACCESS_RE.match(line) for line in first_lines):
        detected = "web_access"
        confidence = "high"
    elif "p6spy" in sample.lower() or "SQL 语句" in sample:
        detected = "p6spy_sql"
        confidence = "high"
    elif any(SPRING_RE.match(line) for line in first_lines):
        detected = "spring_app"
        confidence = "high"
    elif re.search(r"\b(sshd|sudo|pam_unix|failed password|accepted password)\b", sample, re.I):
        detected = "auth_text"
        confidence = "medium"
    elif re.search(r"\b(ufw|iptables|firewall|waf|blocked|denied|DROP|REJECT)\b", sample, re.I):
        detected = "firewall_text"
        confidence = "medium"
    else:
        detected = "generic_text"
        confidence = "low" if first_lines else "unknown"
    return {
        "detected_type": detected,
        "confidence": confidence,
        "sampled_line_count": line_count,
        "time_range": {"first": first_ts, "last": last_ts},
        "keyword_hits": keyword_hits,
    }


def inventory_file(path: Path, default_timezone: str, sample_limit: int) -> dict[str, Any]:
    stat = path.stat()
    base: dict[str, Any] = {
        "path": safe_relpath(path),
        "include": True,
        "declared_type": None,
        "detected_type": "unknown",
        "type_confidence": "unknown",
        "timezone": default_timezone,
        "time_parse_status": "inferred",
        "time_range": {"first": None, "last": None},
        "size_bytes": stat.st_size,
        "size_strategy": size_strategy(stat.st_size),
        "compressed": is_gzip(path),
        "notes": [],
    }
    if is_xlsx(path):
        detected = detect_xlsx(path, default_timezone, sample_limit)
        base["detected_type"] = detected["detected_type"]
        base["type_confidence"] = detected["confidence"]
        base["header"] = detected.get("header", [])
        base["time_range"] = detected.get("time_range", base["time_range"])
        if not base["time_range"].get("first"):
            base["time_parse_status"] = "unknown"
        if detected.get("error"):
            base["notes"].append(f"xlsx_read_error:{detected['error']}")
        return base
    if is_probably_text(path):
        detected = detect_text(path, default_timezone, sample_limit)
        base["detected_type"] = detected["detected_type"]
        base["type_confidence"] = detected["confidence"]
        base["time_range"] = detected.get("time_range", base["time_range"])
        base["sampled_line_count"] = detected.get("sampled_line_count")
        base["keyword_hits"] = detected.get("keyword_hits", {})
        if detected.get("error"):
            base["notes"].append(f"text_read_error:{detected['error']}")
        if not base["time_range"].get("first"):
            base["time_parse_status"] = "unknown"
        return base
    base["include"] = False
    base["notes"].append("unsupported_or_binary_unknown")
    return base


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    files = [inventory_file(path, args.default_timezone, args.sample_limit) for path in discover(args.paths, args.include_hidden)]
    case_id = args.case_id or f"case-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    return {
        "case_id": case_id,
        "mode": args.mode,
        "default_timezone": args.default_timezone,
        "network_assist": "enabled",
        "network_status": "unknown",
        "created_at": datetime.now().astimezone().isoformat(),
        "files": files,
        "privacy": {
            "allowed_external_data_classes": ["ip", "domain", "asn", "public_keyword", "user_agent_fragment"],
            "excluded_external_data_classes": ["full_log", "token", "cookie", "request_body", "password", "private_account", "business_parameter", "database_result"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory server logs for attack-analysis.")
    parser.add_argument("paths", nargs="+", help="Files or directories to inventory")
    parser.add_argument(
        "--mode",
        choices=["quick-report", "interactive"],
        required=True,
        help="Required explicit workflow mode. The skill must confirm this before running tools.",
    )
    parser.add_argument("--case-id")
    parser.add_argument("--default-timezone", default="Asia/Shanghai")
    parser.add_argument("--sample-limit", type=int, default=20000, help="Maximum lines sampled per text file during inventory")
    parser.add_argument("--include-hidden", action="store_true")
    parser.add_argument("--output-dir", help="Directory for log-inventory.json and analysis-manifest.json")
    parser.add_argument("--json", action="store_true", help="Print manifest JSON")
    args = parser.parse_args()

    manifest = build_manifest(args)
    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "analysis-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        (out / "log-inventory.json").write_text(json.dumps({"files": manifest["files"]}, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json or not args.output_dir:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
