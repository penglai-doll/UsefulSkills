"""Timestamp parsing helpers."""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

ACCESS_TS_RE = re.compile(r"\[(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):(?P<hms>\d{2}:\d{2}:\d{2}) (?P<offset>[+-]\d{4})\]")
ISO_TS_RE = re.compile(r"(?P<dt>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(?:\s*(?P<offset>Z|[+-]\d{2}:?\d{2}))?")
DATE_COMPACT_RE = re.compile(r"^(?P<date>\d{8})$")

# Zone lookup failures are recorded here so callers can surface them in
# manifest/parser output instead of silently degrading to naive timestamps.
# Windows has no system tz database: install the `tzdata` pip package
# (see requirements.txt). Linux uses the system tz database.
_ZONE_ERROR_NOTES: set[str] = set()


def timezone_notes() -> list[str]:
    """Return unique notes about failed timezone lookups (kept until cleared)."""
    return sorted(_ZONE_ERROR_NOTES)


def clear_timezone_notes() -> None:
    _ZONE_ERROR_NOTES.clear()


def timezone_obj(name: str | None):
    if not name:
        return None
    if re.fullmatch(r"[+-]\d{2}:?\d{2}", name):
        sign = 1 if name[0] == "+" else -1
        digits = name[1:].replace(":", "")
        return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        _ZONE_ERROR_NOTES.add(
            f"tzdata_unavailable:{name} - cannot resolve IANA zone; "
            "install the 'tzdata' pip package (required on Windows; Linux uses the system tz database)"
        )
        return None
    except ValueError as exc:
        _ZONE_ERROR_NOTES.add(f"tz_lookup_failed:{name}:{exc}")
        return None


def _offset_to_tz(offset: str):
    sign = 1 if offset[0] == "+" else -1
    return timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        return dt.isoformat()
    return dt.isoformat()


def parse_timestamp(text: str | None, default_timezone: str | None = None) -> dict[str, str | None]:
    if not text:
        return {"timestamp": None, "status": "unknown", "raw": text}
    s = str(text)
    match = ACCESS_TS_RE.search(s)
    if match:
        parts = match.groupdict()
        month = MONTHS.get(parts["mon"].title())
        if month is None:
            # Unknown month name must not silently become January.
            return {"timestamp": None, "status": "unknown", "raw": match.group(0)}
        dt = datetime(
            int(parts["year"]),
            month,
            int(parts["day"]),
            *[int(x) for x in parts["hms"].split(":")],
            tzinfo=_offset_to_tz(parts["offset"]),
        )
        return {"timestamp": to_iso(dt), "status": "explicit", "raw": match.group(0)}
    match = ISO_TS_RE.search(s)
    if match:
        dt_text = match.group("dt").replace("T", " ")
        fmt = "%Y-%m-%d %H:%M:%S.%f" if "." in dt_text else "%Y-%m-%d %H:%M:%S"
        dt = datetime.strptime(dt_text, fmt)
        offset = match.group("offset")
        if offset:
            if offset == "Z":
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                off = offset.replace(":", "")
                dt = dt.replace(tzinfo=_offset_to_tz(off))
            status = "explicit"
        else:
            tz = timezone_obj(default_timezone)
            if tz:
                dt = dt.replace(tzinfo=tz)
                status = "inferred"
            else:
                status = "unknown"
        return {"timestamp": to_iso(dt), "status": status, "raw": match.group(0)}
    compact = DATE_COMPACT_RE.match(s.strip())
    if compact:
        dt = datetime.strptime(compact.group("date"), "%Y%m%d")
        tz = timezone_obj(default_timezone)
        if tz:
            dt = dt.replace(tzinfo=tz)
            status = "inferred"
        else:
            status = "unknown"
        return {"timestamp": to_iso(dt), "status": status, "raw": compact.group("date")}
    return {"timestamp": None, "status": "unknown", "raw": text}


def first_timestamp(text: str | None, default_timezone: str | None = None) -> str | None:
    return parse_timestamp(text, default_timezone).get("timestamp")
