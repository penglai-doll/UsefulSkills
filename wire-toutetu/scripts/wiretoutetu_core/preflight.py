"""Platform-aware dependency and TShark capability probing."""

from __future__ import annotations

import importlib.util
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def detect_platform_route() -> str:
    system = platform.system().lower()
    release = platform.release().lower()
    if system == "linux" and ("microsoft" in release or "wsl" in release):
        return "wsl"
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    return system or "unknown"


def _command_output(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _version(text: str) -> str | None:
    match = re.search(r"(\d+\.\d+\.\d+)", text)
    return match.group(1) if match else None


def run_preflight(*, deep_probe: bool = False) -> dict[str, Any]:
    route = detect_platform_route()
    tools: dict[str, Any] = {}
    next_actions: list[str] = []
    tshark = shutil.which("tshark")
    if not tshark:
        tools["tshark"] = {"status": "unavailable", "path": None, "version": None}
        next_actions.append(f"Confirm installation of Wireshark/TShark for {route}; do not install automatically.")
        return {"status": "unavailable", "platform_route": route, "tools": tools, "next_actions": next_actions}

    version_result = _command_output([tshark, "--version"])
    version = _version(version_result.stdout + version_result.stderr)
    tools["tshark"] = {
        "status": "available" if version_result.returncode == 0 else "unavailable",
        "path": str(Path(tshark).resolve()),
        "version": version,
    }
    for name in ("capinfos", "editcap", "mergecap"):
        path = shutil.which(name)
        tools[name] = {"status": "available" if path else "unavailable", "path": path}
    tools["cryptography"] = {
        "status": "available" if importlib.util.find_spec("cryptography") else "unavailable"
    }
    tools["scapy"] = {
        "status": "available" if importlib.util.find_spec("scapy") else "unavailable",
        "scope": "fixture-generation-only",
    }

    capabilities: dict[str, Any] = {"field_count": None, "export_object_types": []}
    if deep_probe:
        fields = _command_output([tshark, "-G", "fields"], timeout=60)
        capabilities["field_count"] = sum(1 for line in fields.stdout.splitlines() if line.startswith("F\t"))
        exports = _command_output([tshark, "--export-objects", "help"], timeout=30)
        export_text = exports.stdout + exports.stderr
        capabilities["export_object_types"] = sorted(
            set(re.findall(r"(?m)^\s*([a-zA-Z0-9_-]+)\s", export_text))
        )
    tools["tshark"]["capabilities"] = capabilities

    if version and version.startswith("4.6.") and tuple(map(int, version.split("."))) < (4, 6, 7):
        next_actions.append("TShark 4.6 patch is behind 4.6.7; confirm upgrade separately if desired.")
    elif version and version.startswith("4.4.") and tuple(map(int, version.split("."))) < (4, 4, 17):
        next_actions.append("TShark 4.4 patch is behind 4.4.17; confirm upgrade separately if desired.")

    status = "ok" if tools["tshark"]["status"] == "available" else "unavailable"
    return {
        "status": status,
        "platform_route": route,
        "tools": tools,
        "next_actions": next_actions,
    }
