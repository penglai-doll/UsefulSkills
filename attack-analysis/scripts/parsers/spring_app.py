"""Spring Boot style application log parser."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from common.event_schema import make_event
from common.io_utils import iter_text_lines
from common.ip_normalize import extract_ip_chain

SPRING_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)\s+(?P<level>ERROR|WARN|INFO|DEBUG|TRACE)\s+\d+\s+---\s+\[(?P<thread>[^\]]+)\]\s+(?P<logger>[^:]+):(?P<line>\d+)\s+-\s*(?P<msg>.*)$"
)
USERNAME_RE = re.compile(r"(?:username|user|loginName|LOGIN_NAME)\s*[:=]\s*['\"]?([^,'\"\s}]+)", re.I)
KEYWORD_RE = re.compile(r"(login|登录|error|exception|unauthori[sz]ed|token|upload|admin|sql|注入|密码错误|用户名或密码错误)", re.I)
LOGIN_SIGNAL_RE = re.compile(
    r"(doGetAuthenticationInfo|login\s+(?:failed|error|success|model)|username\s*=|loginName\s*=|登录|密码错误|用户名)",
    re.I,
)


def parse(path: str | Path, file_entry: dict[str, Any], limit: int = 10000) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    bad = 0
    default_tz = file_entry.get("timezone") or file_entry.get("default_timezone")
    for line_no, line in iter_text_lines(path):
        match = SPRING_RE.match(line)
        if not match:
            if line.strip() and line.startswith("20"):
                bad += 1
            continue
        data = match.groupdict()
        logger = data.get("logger") or ""
        if "p6spy" in logger.lower():
            continue
        msg = data.get("msg") or ""
        level = data.get("level") or "INFO"
        if level not in {"ERROR", "WARN"} and not KEYWORD_RE.search(msg):
            continue
        event_type = "app_error" if level == "ERROR" else "app_warning" if level == "WARN" else "app_signal"
        if LOGIN_SIGNAL_RE.search(msg):
            event_type = "login_signal"
        user_match = USERNAME_RE.search(msg)
        ips = extract_ip_chain(msg)
        events.append(
            make_event(
                timestamp_text=data.get("ts"),
                source_file=str(path),
                log_type="spring_app",
                event_type=event_type,
                actor_ip=ips[0] if ips else None,
                account_or_user=user_match.group(1) if user_match else None,
                request_or_action=f"{logger}:{data.get('line')}",
                status_or_result=level,
                raw_ref=f"line:{line_no}",
                evidence=line[:500],
                default_timezone=default_tz,
                extra={"thread": data.get("thread"), "logger": logger},
            )
        )
        if len(events) >= limit:
            break
    return {"events": events, "stats": {"bad_line_count": bad, "parser": "spring_app"}}
