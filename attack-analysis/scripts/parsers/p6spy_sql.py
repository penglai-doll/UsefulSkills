"""P6Spy SQL line parser."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from common.event_schema import make_event
from common.io_utils import iter_text_lines
from common.ip_normalize import extract_ip_chain

SQL_RE = re.compile(r"(?P<inner_ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s*\|.*?SQL\s*语句：(?P<sql>.*)$", re.I)
OP_RE = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE)\b", re.I)
TABLE_RE = re.compile(r"\b(?:FROM|INTO|UPDATE|TABLE)\s+([`\w.]+)", re.I)
SUSPICIOUS_SQL_RE = re.compile(r"(union\s+select|sleep\s*\(|benchmark\s*\(|or\s+1\s*=\s*1|information_schema|load_file|outfile|xp_cmdshell)", re.I)
TABLE_SIGNAL_RE = re.compile(
    r"(user|login|auth|role|permission|sms_code|upload|file|admin|account|session|token)",
    re.I,
)
CREDENTIAL_PREDICATE_RE = re.compile(r"\b(password|passwd|token|login_name|username|phone_no)\b", re.I)


def parse(path: str | Path, file_entry: dict[str, Any], limit: int = 10000) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    bad = 0
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for line_no, line in iter_text_lines(path):
        if "p6spy" not in line.lower() and "SQL 语句" not in line:
            continue
        match = SQL_RE.search(line)
        if not match:
            if "SQL" in line:
                bad += 1
            continue
        sql = (match.group("sql") or "").strip()
        op_match = OP_RE.search(sql)
        table_match = TABLE_RE.search(sql)
        event_type = "sql_query"
        if SUSPICIOUS_SQL_RE.search(sql):
            event_type = "sql_suspicious"
        elif op_match and op_match.group(1).upper() in {"INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE"}:
            event_type = "sql_mutation"
        else:
            table_name = table_match.group(1) if table_match else ""
            if not (TABLE_SIGNAL_RE.search(table_name) or CREDENTIAL_PREDICATE_RE.search(sql)):
                continue
        ips = extract_ip_chain(sql)
        events.append(
            make_event(
                timestamp_text=match.group("inner_ts"),
                source_file=str(path),
                log_type="p6spy_sql",
                event_type=event_type,
                actor_ip=ips[0] if ips else None,
                request_or_action=f"{op_match.group(1).upper() if op_match else 'SQL'} {table_match.group(1) if table_match else ''}".strip(),
                status_or_result="suspicious" if event_type == "sql_suspicious" else "observed",
                raw_ref=f"line:{line_no}",
                evidence=sql[:500],
                default_timezone=default_tz,
                extra={"sql_operation": op_match.group(1).upper() if op_match else None, "sql_table": table_match.group(1) if table_match else None},
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": bad, "parser": "p6spy_sql"}}
