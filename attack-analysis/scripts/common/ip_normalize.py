"""IP extraction and normalization helpers."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

IPV4_RE = re.compile(r"(?<!\d)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?::(?P<port>\d{1,5}))?(?!\d)")
BRACKET_IPV6_RE = re.compile(r"\[(?P<ip>[0-9a-fA-F:.]+)\](?::(?P<port>\d{1,5}))?")


def normalize_ip(value: str | None) -> dict[str, Any]:
    if not value:
        return {"original": value, "ip": None, "port": None, "valid": False}
    text = str(value).strip()
    match = BRACKET_IPV6_RE.search(text) or IPV4_RE.search(text)
    if not match:
        candidate = text.split(",", 1)[0].strip()
        try:
            ip = str(ipaddress.ip_address(candidate))
            return {"original": value, "ip": ip, "port": None, "valid": True}
        except ValueError:
            return {"original": value, "ip": None, "port": None, "valid": False}
    ip_text = match.group("ip")
    port_text = match.groupdict().get("port")
    try:
        ip = str(ipaddress.ip_address(ip_text))
    except ValueError:
        return {"original": value, "ip": None, "port": None, "valid": False}
    port = None
    if port_text:
        try:
            port_num = int(port_text)
            if 0 <= port_num <= 65535:
                port = port_num
        except ValueError:
            port = None
    return {"original": value, "ip": ip, "port": port, "valid": True}


def extract_ip_chain(text: str | None) -> list[str]:
    if not text:
        return []
    ips: list[str] = []
    for match in IPV4_RE.finditer(str(text)):
        norm = normalize_ip(match.group(0))
        if norm["valid"] and norm["ip"] not in ips:
            ips.append(norm["ip"])
    for match in BRACKET_IPV6_RE.finditer(str(text)):
        norm = normalize_ip(match.group(0))
        if norm["valid"] and norm["ip"] not in ips:
            ips.append(norm["ip"])
    return ips
