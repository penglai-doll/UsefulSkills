"""Common/combined HTTP access log parser."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from common.event_schema import make_event
from common.io_utils import iter_text_lines

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ (?P<ts>\[[^\]]+\]) "(?P<method>\S+) (?P<path>[^" ]+)(?: (?P<proto>[^"]+))?" (?P<status>\d{3}|-) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
SUSPICIOUS_PATH_RE = re.compile(
    r"(\.git|\.env|wp-|php|admin|login|union|select|sleep\(|benchmark\(|cmd=|passwd|shell|upload|\.sql|backup|\.bak|\.zip|\.rar|actuator|swagger)",
    re.I,
)


def parse(path: str | Path, file_entry: dict[str, Any], limit: int = 10000) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    bad = 0
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for line_no, line in iter_text_lines(path):
        match = ACCESS_RE.match(line)
        if not match:
            bad += 1
            continue
        data = match.groupdict()
        status = data.get("status") or ""
        path_text = data.get("path") or ""
        event_type = "web_request"
        if SUSPICIOUS_PATH_RE.search(path_text):
            event_type = "web_probe"
        if status.startswith(("4", "5")):
            event_type = "web_error" if event_type == "web_request" else event_type
        if event_type == "web_request" and status.startswith(("2", "3")) and not SUSPICIOUS_PATH_RE.search(path_text):
            # Keep routine successful requests out of compact candidate output.
            continue
        events.append(
            make_event(
                timestamp_text=data.get("ts"),
                source_file=str(path),
                log_type=file_entry.get("detected_type") or "web_access",
                event_type=event_type,
                actor_ip=data.get("ip"),
                request_or_action=f"{data.get('method')} {path_text}",
                status_or_result=status,
                raw_ref=f"line:{line_no}",
                evidence=line[:500],
                default_timezone=default_tz,
                extra={"http_method": data.get("method"), "http_path": path_text, "user_agent": data.get("ua")},
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": bad, "parser": "apache_access"}}
