"""Event candidate construction helpers."""

from __future__ import annotations

from typing import Any

from common.ip_normalize import normalize_ip
from common.time_normalize import parse_timestamp


def make_event(
    *,
    timestamp_text: str | None,
    source_file: str,
    log_type: str,
    event_type: str,
    raw_ref: str,
    actor_ip: str | None = None,
    account_or_user: str | None = None,
    request_or_action: str | None = None,
    status_or_result: str | None = None,
    evidence: str | None = None,
    default_timezone: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ts = parse_timestamp(timestamp_text, default_timezone)
    ip = normalize_ip(actor_ip)
    event = {
        "event_id": None,
        "timestamp": ts["timestamp"],
        "timestamp_status": ts["status"],
        "timestamp_raw": ts["raw"],
        "source_file": source_file,
        "log_type": log_type,
        "event_type": event_type,
        "actor_ip": actor_ip,
        "actor_ip_normalized": ip["ip"],
        "actor_port": ip["port"],
        "account_or_user": account_or_user,
        "request_or_action": request_or_action,
        "status_or_result": status_or_result,
        "raw_ref": raw_ref,
        "event_status": "candidate",
        "evidence": evidence,
    }
    if extra:
        event.update(extra)
    return event
