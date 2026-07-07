"""Login spreadsheet parser."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from common.event_schema import make_event
from common.xlsx_utils import iter_rows


def _index(header: list[str], *names: str) -> int | None:
    upper = [h.upper() for h in header]
    for name in names:
        if name.upper() in upper:
            return upper.index(name.upper())
    return None


def parse(path: str | Path, file_entry: dict[str, Any], limit: int = 10000) -> dict[str, Any]:
    rows = iter_rows(path)
    try:
        _, header = next(rows)
    except StopIteration:
        return {"events": [], "stats": {"bad_line_count": 0, "parser": "xlsx_login"}}
    login_time_i = _index(header, "LOGIN_TIME", "CREATE_TIME")
    ip_i = _index(header, "IP", "LOGIN_IP", "CLIENT_IP")
    user_i = _index(header, "USER_NAME", "LOGIN_NAME", "USERNAME")
    ua_i = _index(header, "USER_AGENT")
    events: list[dict[str, Any]] = []
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for row_no, row in rows:
        def val(i):
            return row[i] if i is not None and i < len(row) else None
        events.append(
            make_event(
                timestamp_text=val(login_time_i),
                source_file=str(path),
                log_type="xlsx_login",
                event_type="login_record",
                actor_ip=val(ip_i),
                account_or_user=val(user_i),
                request_or_action="login",
                status_or_result="recorded",
                raw_ref=f"row:{row_no}",
                evidence=str({h: row[i] for i, h in enumerate(header[: min(len(header), len(row))])})[:500],
                default_timezone=default_tz,
                extra={"user_agent": val(ua_i)},
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": 0, "parser": "xlsx_login"}}
