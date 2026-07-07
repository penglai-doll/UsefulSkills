"""Generic text parser for best-effort logs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from common.event_schema import make_event
from common.io_utils import iter_text_lines
from common.ip_normalize import extract_ip_chain

KEYWORD_RE = re.compile(r"(login|failed|failure|error|exception|denied|blocked|drop|reject|union|select|upload|shell|cmd|admin|token|passwd|攻击|失败|错误)", re.I)


def parse(path: str | Path, file_entry: dict[str, Any], limit: int = 5000) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for line_no, line in iter_text_lines(path):
        ips = extract_ip_chain(line)
        if not ips and not KEYWORD_RE.search(line):
            continue
        events.append(
            make_event(
                timestamp_text=line,
                source_file=str(path),
                log_type=file_entry.get("detected_type") or "generic_text",
                event_type="generic_signal",
                actor_ip=ips[0] if ips else None,
                request_or_action="keyword/ip signal",
                status_or_result="observed",
                raw_ref=f"line:{line_no}",
                evidence=line[:500],
                default_timezone=default_tz,
                extra={"ip_chain": ips},
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": 0, "parser": "generic_text"}}
