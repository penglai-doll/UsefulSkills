"""Operation spreadsheet parser."""

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
        return {"events": [], "stats": {"bad_line_count": 0, "parser": "xlsx_operate"}}
    time_i = _index(header, "CREATE_TIME", "OPER_TIME", "OPER_DATE")
    module_i = _index(header, "MODULE_NAME")
    func_i = _index(header, "FUNC_NAME")
    desc_i = _index(header, "OPER_DESC", "DESCRIPTION")
    user_i = _index(header, "CREATE_USER", "USER_NAME", "LOGIN_NAME")
    events: list[dict[str, Any]] = []
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for row_no, row in rows:
        def val(i):
            return row[i] if i is not None and i < len(row) else None
        action = " / ".join([x for x in [val(module_i), val(func_i), val(desc_i)] if x]) or "operation"
        events.append(
            make_event(
                timestamp_text=val(time_i),
                source_file=str(path),
                log_type="xlsx_operate",
                event_type="operation_record",
                account_or_user=val(user_i),
                request_or_action=action,
                status_or_result="recorded",
                raw_ref=f"row:{row_no}",
                evidence=str({h: row[i] for i, h in enumerate(header[: min(len(header), len(row))])})[:500],
                default_timezone=default_tz,
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": 0, "parser": "xlsx_operate"}}
