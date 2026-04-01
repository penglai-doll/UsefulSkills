#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from urllib.parse import urlparse

ASCII_STRING_RE = re.compile(rb"[ -~]{6,}")
UTF16_STRING_RE = re.compile(rb"(?:[\x20-\x7E]\x00){6,}")
URL_RE = re.compile(r"(?:https?|wss?|mqtt)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
PERMISSION_RE = re.compile(r"android\.permission\.[A-Z0-9_]+")
CALLBACK_HINT_RE = re.compile(
    r"(?:\b(?:base[_-]?url|api[_-]?(?:host|url)|server|domain|host|socket|port|upload|download|gateway|endpoint)\b|"
    r"\b[a-zA-Z0-9_$]*(?:dom|host|server|socket|endpoint|gateway|url|ws|mqtt)[a-zA-Z0-9_$]*\b|"
    r"ws://|wss://|mqtt://)",
    re.IGNORECASE,
)
IGNORED_DOMAIN_PREFIXES = (
    "android.",
    "androidx.",
    "com.",
    "com.android.",
    "com.google.",
    "dalvik.",
    "io.flutter.",
    "java.",
    "javax.",
    "kotlin.",
    "net.",
    "org.",
    "org.apache.",
)
IGNORED_DOMAIN_LABELS = {
    "activity",
    "android",
    "androidx",
    "app",
    "classes",
    "component",
    "dex",
    "google",
    "manifest",
    "permission",
    "provider",
    "receiver",
    "resource",
    "resources",
    "runtime",
    "sample",
    "service",
    "widget",
}
COMMON_TLDS = {
    "app",
    "biz",
    "cc",
    "club",
    "com",
    "icu",
    "info",
    "io",
    "live",
    "me",
    "net",
    "online",
    "org",
    "pro",
    "pw",
    "shop",
    "site",
    "store",
    "tech",
    "top",
    "vip",
    "work",
    "xyz",
}
IGNORED_PUBLIC_HOSTS = {
    "developer.android.com",
    "developers.google.com",
    "play.google.com",
    "schemas.android.com",
    "support.google.com",
    "www.apache.org",
    "www.w3.org",
}
IGNORED_PUBLIC_HOST_SUFFIXES = (
    ".apache.org",
    ".w3.org",
)

SCANNABLE_SUFFIXES = {
    ".apk",
    ".apks",
    ".arsc",
    ".bin",
    ".dat",
    ".dex",
    ".ec",
    ".html",
    ".java",
    ".jar",
    ".js",
    ".json",
    ".kt",
    ".properties",
    ".rsa",
    ".sh",
    ".so",
    ".smali",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    ".zip",
}
NESTED_ARCHIVE_SUFFIXES = {".apk", ".apks", ".jar", ".xapk", ".zip"}
MAX_SCAN_BYTES = 4 * 1024 * 1024
MAX_NESTED_BYTES = 128 * 1024 * 1024
MAX_STRINGS_PER_BLOB = 2500
MAX_IOCS_PER_TYPE = 25
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 10, "low": 4, "info": 0}
TOOL_NAMES = ["jadx", "apktool", "aapt", "aapt2", "apksigner", "apkanalyzer", "adb"]
SEVEN_Z_NAMES = ("7z", "7zz")

PERMISSION_RULES = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("critical", "Can read and manipulate UI content; common in banker and overlay malware."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Can draw overlay windows over other apps."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Can stage or install secondary payloads."),
    "android.permission.QUERY_ALL_PACKAGES": ("medium", "Can enumerate installed apps for targeting or evasion."),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("high", "Can restore execution after reboot."),
    "android.permission.SEND_SMS": ("high", "Can send SMS, including premium-rate abuse."),
    "android.permission.RECEIVE_SMS": ("high", "Can intercept inbound SMS messages."),
    "android.permission.READ_SMS": ("high", "Can read OTP and SMS content."),
    "android.permission.READ_CONTACTS": ("medium", "Can access contact data for exfiltration or propagation."),
    "android.permission.READ_CALL_LOG": ("medium", "Can inspect call history."),
    "android.permission.RECORD_AUDIO": ("medium", "Can record microphone audio."),
    "android.permission.CAMERA": ("medium", "Can access device camera."),
    "android.permission.READ_PHONE_STATE": ("medium", "Can collect device and telephony identifiers."),
    "android.permission.MANAGE_EXTERNAL_STORAGE": ("medium", "Can read and modify broad external storage content."),
    "android.permission.POST_NOTIFICATIONS": ("low", "Can abuse notifications for lures, but is common in legitimate apps."),
}

BEHAVIOR_RULES = [
    ("critical", "dynamic-loader", "Dynamic code loading", re.compile(r"\b(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader|loadDex)\b", re.IGNORECASE), "Can load code at runtime and hide the real payload."),
    ("high", "accessibility-abuse", "Accessibility automation", re.compile(r"\b(?:AccessibilityService|AccessibilityNodeInfo|performGlobalAction|dispatchGesture)\b", re.IGNORECASE), "Common in banker and credential-theft malware."),
    ("high", "overlay-abuse", "Overlay or phishing UI", re.compile(r"\b(?:TYPE_APPLICATION_OVERLAY|SYSTEM_ALERT_WINDOW|draw over other apps)\b", re.IGNORECASE), "Can place content over victim apps."),
    ("high", "dropper-install", "Installer or dropper behavior", re.compile(r"\b(?:PackageInstaller(?:\.Session)?|REQUEST_INSTALL_PACKAGES|ACTION_INSTALL_PACKAGE|pm install)\b", re.IGNORECASE), "Can stage and install secondary payloads."),
    ("high", "sms-fraud", "SMS interception or fraud", re.compile(r"\b(?:SmsManager|SEND_SMS|READ_SMS|RECEIVE_SMS|SMS_RECEIVED|Telephony\.Sms)\b", re.IGNORECASE), "Can intercept OTPs or send SMS."),
    ("high", "boot-persistence", "Boot persistence", re.compile(r"\b(?:BOOT_COMPLETED|RECEIVE_BOOT_COMPLETED|QUICKBOOT_POWERON)\b", re.IGNORECASE), "Can relaunch after reboot."),
    ("medium", "ssl-bypass", "TLS or certificate tampering", re.compile(r"\b(?:ALLOW_ALL_HOSTNAME_VERIFIER|HostnameVerifier|X509TrustManager|SSLSocketFactory|TrustAll)\b", re.IGNORECASE), "Can weaken certificate validation."),
    ("medium", "webview-bridge", "Risky WebView bridge", re.compile(r'(?:addJavascriptInterface|setJavaScriptEnabled|WebViewClient|loadUrl\("javascript:)', re.IGNORECASE), "Can expose native methods to remote content."),
    ("medium", "shell-or-root", "Shell or root execution", re.compile(r"\b(?:/system/bin/sh|Runtime\.getRuntime|ProcessBuilder|su\b|chmod 777|mount -o)\b", re.IGNORECASE), "Can execute commands or attempt privilege escalation."),
    ("medium", "anti-analysis", "Anti-analysis or hook detection", re.compile(r"\b(?:frida|xposed|substrate|ptrace|isDebuggerConnected|tracerpid)\b", re.IGNORECASE), "Can resist sandboxing or reversing."),
    ("medium", "screen-capture", "Screen capture capability", re.compile(r"\b(?:MediaProjection|createScreenCaptureIntent|VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR)\b", re.IGNORECASE), "Can capture sensitive user activity."),
    ("medium", "device-admin", "Device admin control", re.compile(r"\b(?:DeviceAdminReceiver|ACTION_ADD_DEVICE_ADMIN|USES_POLICY_FORCE_LOCK)\b", re.IGNORECASE), "Can harden persistence or lock the device."),
    ("low", "crypto-wallet", "Crypto or ransomware keywords", re.compile(r"\b(?:encrypt|decrypt|AES|RSA|wallet|seed phrase|mnemonic|bitcoin|usdt)\b", re.IGNORECASE), "Context-dependent indicator that needs corroboration."),
]

PACKER_HINTS = {
    "jiagu": "360 Jiagu protector artifact",
    "ijiami": "iJiami protector artifact",
    "bangcle": "Bangcle protector artifact",
    "secshell": "Tencent SecShell protector artifact",
    "chaosvmp": "Virtualized protector artifact",
}


def hash_file(path: Path) -> dict[str, str]:
    hashes = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for digest in hashes.values():
                digest.update(chunk)
    return {name: digest.hexdigest() for name, digest in hashes.items()}


def read_prefix(path: Path, size: int = MAX_SCAN_BYTES) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def extract_ascii_strings(blob: bytes) -> list[str]:
    return [match.decode("ascii", errors="ignore") for match in ASCII_STRING_RE.findall(blob)]


def extract_utf16le_strings(blob: bytes) -> list[str]:
    strings = []
    for match in UTF16_STRING_RE.findall(blob):
        strings.append(match.decode("utf-16le", errors="ignore"))
    return strings


def normalized_strings(blob: bytes) -> list[str]:
    values = []
    seen = set()
    for item in extract_ascii_strings(blob) + extract_utf16le_strings(blob):
        cleaned = " ".join(item.split())
        if len(cleaned) < 6 or cleaned in seen:
            continue
        seen.add(cleaned)
        values.append(cleaned)
        if len(values) >= MAX_STRINGS_PER_BLOB:
            break
    return values


def clip(values: set[str], limit: int = MAX_IOCS_PER_TYPE) -> list[str]:
    return sorted(values)[:limit]


def guess_package_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if path.is_dir():
        return "directory"
    return {
        ".apk": "apk",
        ".apks": "apks",
        ".xapk": "xapk",
        ".dex": "dex",
        ".jar": "jar",
        ".zip": "zip",
    }.get(suffix, suffix.lstrip(".") or "file")


def find_7z_binary() -> str | None:
    for name in SEVEN_Z_NAMES:
        location = shutil.which(name)
        if location:
            return location
    return None


def extract_archive_with_7z(path: Path, destination: Path) -> tuple[bool, str]:
    seven_zip = find_7z_binary()
    if not seven_zip:
        return False, "7z/7zz is not available on PATH."

    command = [seven_zip, "x", "-y", f"-o{destination}", str(path)]
    completed = subprocess.run(command, capture_output=True, text=True)
    detail = (completed.stderr or completed.stdout or "").strip()
    extracted_any = destination.exists() and any(destination.rglob("*"))
    if completed.returncode != 0 and not extracted_any:
        return False, detail or f"{Path(seven_zip).name} exited with code {completed.returncode}."
    if completed.returncode != 0:
        partial = detail or f"{Path(seven_zip).name} exited with code {completed.returncode} after partially extracting files."
        return True, partial
    return True, detail


def empty_result(target: Path) -> dict:
    return {
        "target": str(target),
        "target_type": "directory" if target.is_dir() else "file",
        "package_type": guess_package_type(target),
        "hashes": {},
        "file_size": None,
        "archive_summary": {
            "entry_count": 0,
            "suffix_counts": {},
            "embedded_archives": [],
            "top_level_apks": [],
            "native_libs": [],
        },
        "permissions": {"critical": set(), "high": set(), "medium": set(), "low": set(), "other": set()},
        "iocs": {"urls": set(), "domains": set(), "ips": set(), "emails": set()},
        "signals": [],
        "signal_index": set(),
        "available_tools": {name: shutil.which(name) for name in TOOL_NAMES},
        "notes": [],
    }


def add_signal(result: dict, severity: str, category: str, title: str, evidence: str, rationale: str) -> None:
    key = (severity, category, title, evidence)
    if key in result["signal_index"]:
        return
    result["signal_index"].add(key)
    result["signals"].append(
        {
            "severity": severity,
            "category": category,
            "title": title,
            "evidence": evidence,
            "rationale": rationale,
        }
    )


def add_permission(result: dict, permission: str) -> None:
    severity, rationale = PERMISSION_RULES.get(permission, ("other", "Manifest or code references a broad Android permission."))
    result["permissions"][severity].add(permission)
    if severity != "other":
        add_signal(result, severity, "permission", f"Suspicious permission: {permission}", permission, rationale)


def add_ioc(result: dict, category: str, value: str) -> None:
    value = value.rstrip(").,;\"'")
    if not value:
        return
    if category == "ips":
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved:
            return
    result["iocs"][category].add(value)


def is_ignored_public_host(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered in IGNORED_PUBLIC_HOSTS:
        return True
    return any(lowered.endswith(suffix) for suffix in IGNORED_PUBLIC_HOST_SUFFIXES)


def is_ignored_public_url(value: str) -> bool:
    try:
        host = (urlparse(value).hostname or "").lower()
    except ValueError:
        return True
    return bool(host) and is_ignored_public_host(host)


def is_probable_domain(value: str) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered.startswith(IGNORED_DOMAIN_PREFIXES):
        return False
    if is_ignored_public_host(lowered):
        return False
    if lowered.endswith((".dex", ".xml", ".so", ".class", ".java")):
        return False
    labels = lowered.split(".")
    if len(labels) < 2:
        return False
    if any(label in IGNORED_DOMAIN_LABELS for label in labels):
        return False
    if any(not re.fullmatch(r"[a-z0-9-]+", label) for label in labels):
        return False
    tld = labels[-1]
    if tld.startswith("xn--"):
        return True
    if len(tld) == 2:
        return True
    return tld in COMMON_TLDS


def looks_scannable(name: str, size: int) -> bool:
    lower = name.lower()
    suffix = Path(lower).suffix
    if size > MAX_SCAN_BYTES:
        return False
    if lower.endswith("androidmanifest.xml") or lower.endswith("resources.arsc"):
        return True
    if lower.startswith("assets/") or lower.startswith("res/raw/") or lower.startswith("meta-inf/"):
        return True
    return suffix in SCANNABLE_SUFFIXES


def record_suffix(result: dict, name: str) -> None:
    suffix = Path(name.lower()).suffix or "[no-ext]"
    counts = result["archive_summary"]["suffix_counts"]
    counts[suffix] = counts.get(suffix, 0) + 1
    result["archive_summary"]["entry_count"] += 1


def add_entry_name_signals(result: dict, name: str, container_type: str) -> None:
    lower = name.lower()
    file_name = Path(lower).name

    for marker, description in PACKER_HINTS.items():
        if marker in lower:
            add_signal(result, "low", "packer", "Protector or packer artifact", name, description)

    if lower.endswith(".so"):
        result["archive_summary"]["native_libs"].append(name)
    if lower.endswith((".apk", ".apks", ".xapk", ".jar", ".zip")):
        result["archive_summary"]["embedded_archives"].append(name)
    if lower.endswith(".apk") and "/" not in lower:
        result["archive_summary"]["top_level_apks"].append(name)

    if lower.endswith(".apk") and container_type not in {"apks", "xapk"}:
        add_signal(result, "high", "payload", "Embedded APK payload", name, "Secondary APK inside a standard APK can indicate staged delivery.")
    if lower.startswith(("assets/", "res/raw/")) and lower.endswith((".apk", ".dex", ".jar", ".bin", ".dat")):
        add_signal(result, "high", "payload", "Suspicious bundled payload", name, "Payload files in assets or raw resources often support droppers or loaders.")
    if lower.startswith(("assets/", "res/raw/")) and lower.endswith((".sh", ".js")):
        add_signal(result, "medium", "script", "Bundled script content", name, "Bundled scripts are uncommon in normal consumer APKs and deserve review.")
    if lower.endswith(".dex") and not re.fullmatch(r"classes\d*\.dex", file_name):
        add_signal(result, "medium", "payload", "Additional DEX payload", name, "Non-standard DEX naming can indicate a staged payload.")


def scan_text_blob(result: dict, text: str, source: str) -> None:
    for permission in sorted(set(PERMISSION_RE.findall(text))):
        add_permission(result, permission)

    for line in text.splitlines():
        for url in URL_RE.findall(line):
            if is_ignored_public_url(url):
                continue
            add_ioc(result, "urls", url)
            host = urlparse(url).hostname
            if host and is_probable_domain(host):
                add_ioc(result, "domains", host.lower())

        if not CALLBACK_HINT_RE.search(line):
            continue
        for domain in DOMAIN_RE.findall(line):
            if is_probable_domain(domain):
                add_ioc(result, "domains", domain.lower())

    for ip in IPV4_RE.findall(text):
        add_ioc(result, "ips", ip)

    for email in EMAIL_RE.findall(text):
        add_ioc(result, "emails", email.lower())

    for severity, category, title, pattern, rationale in BEHAVIOR_RULES:
        match = pattern.search(text)
        if match:
            add_signal(result, severity, category, title, f"{source}: {match.group(0)}", rationale)


def scan_blob(result: dict, blob: bytes, source: str) -> None:
    strings = normalized_strings(blob)
    if not strings:
        return
    scan_text_blob(result, "\n".join(strings), source)


def analyze_archive_stream(result: dict, stream, container_type: str, depth: int) -> None:
    with zipfile.ZipFile(stream) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            record_suffix(result, name)
            add_entry_name_signals(result, name, container_type)

            if not looks_scannable(name, info.file_size):
                continue

            with archive.open(info) as handle:
                blob = handle.read(min(info.file_size, MAX_SCAN_BYTES))
            scan_blob(result, blob, name)

            suffix = Path(name.lower()).suffix
            if depth >= 1 or suffix not in NESTED_ARCHIVE_SUFFIXES or info.file_size > MAX_NESTED_BYTES:
                continue
            try:
                analyze_archive_stream(result, io.BytesIO(blob), "apk" if suffix == ".apk" else suffix.lstrip("."), depth + 1)
            except zipfile.BadZipFile:
                continue


def analyze_directory(result: dict, path: Path) -> None:
    for entry in path.rglob("*"):
        if not entry.is_file():
            continue
        relative = entry.relative_to(path).as_posix()
        record_suffix(result, relative)
        add_entry_name_signals(result, relative, "directory")
        try:
            size = entry.stat().st_size
        except OSError as exc:
            result["notes"].append(f"Failed to stat {relative}: {exc}")
            continue
        if not looks_scannable(relative, size):
            continue
        try:
            blob = read_prefix(entry)
        except OSError as exc:
            result["notes"].append(f"Failed to read {relative}: {exc}")
            continue
        scan_blob(result, blob, relative)


def compound_signals(result: dict) -> None:
    permissions = result["permissions"]
    titles = {signal["title"] for signal in result["signals"]}
    categories = {signal["category"] for signal in result["signals"]}

    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions["critical"] or "Accessibility automation" in titles
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions["high"] or "Overlay or phishing UI" in titles
    has_boot = "android.permission.RECEIVE_BOOT_COMPLETED" in permissions["high"] or "Boot persistence" in titles
    has_sms = any(
        permission in permissions["high"]
        for permission in ("android.permission.SEND_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_SMS")
    ) or "SMS interception or fraud" in titles
    has_dropper = "Installer or dropper behavior" in titles or "payload" in categories
    has_loader = "Dynamic code loading" in titles
    has_network_ioc = bool(result["iocs"]["urls"] or result["iocs"]["domains"] or result["iocs"]["ips"])

    if has_accessibility and has_overlay:
        add_signal(
            result,
            "critical",
            "compound",
            "Accessibility plus overlay abuse",
            "permission/behavior combination",
            "This combination is common in credential theft and banker malware.",
        )
    if has_loader and has_dropper:
        add_signal(
            result,
            "critical",
            "compound",
            "Loader with staged payload",
            "dynamic loading plus embedded payload",
            "Runtime loading combined with bundled payloads strongly suggests staged malicious delivery.",
        )
    if has_boot and has_network_ioc:
        add_signal(
            result,
            "high",
            "compound",
            "Persistent network-capable implant behavior",
            "boot persistence plus hardcoded network indicators",
            "The app can likely resume communications after reboot.",
        )
    if has_sms and (has_accessibility or has_overlay):
        add_signal(
            result,
            "high",
            "compound",
            "OTP theft or banker-like capability cluster",
            "SMS plus accessibility/overlay behavior",
            "This capability cluster is common in banking trojans.",
        )


def finalize_result(result: dict) -> dict:
    compound_signals(result)
    result["signals"].sort(key=lambda item: (SEVERITY_WEIGHT[item["severity"]], item["title"]), reverse=True)
    score = min(100, sum(SEVERITY_WEIGHT[item["severity"]] for item in result["signals"]))
    result["risk_score"] = score
    if any(item["severity"] == "critical" for item in result["signals"]) or score >= 70:
        result["risk_level"] = "high-risk"
    elif score >= 30:
        result["risk_level"] = "suspicious"
    elif score > 0:
        result["risk_level"] = "low-signal"
    else:
        result["risk_level"] = "inconclusive"

    result["permissions"] = {level: sorted(values) for level, values in result["permissions"].items() if values}
    result["iocs"] = {kind: clip(values) for kind, values in result["iocs"].items() if values}
    result["archive_summary"]["embedded_archives"] = sorted(set(result["archive_summary"]["embedded_archives"]))[:20]
    result["archive_summary"]["top_level_apks"] = sorted(set(result["archive_summary"]["top_level_apks"]))[:20]
    result["archive_summary"]["native_libs"] = sorted(set(result["archive_summary"]["native_libs"]))[:20]
    result["available_tools"] = {name: path for name, path in result["available_tools"].items() if path}
    result.pop("signal_index", None)
    return result


def analyze_target(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Target does not exist: {path}")

    result = empty_result(path)
    if path.is_file():
        result["file_size"] = path.stat().st_size
        result["hashes"] = hash_file(path)

    if path.is_dir():
        analyze_directory(result, path)
        return finalize_result(result)

    suffix = path.suffix.lower()
    if suffix in NESTED_ARCHIVE_SUFFIXES:
        try:
            with path.open("rb") as handle:
                analyze_archive_stream(result, handle, guess_package_type(path), depth=0)
            return finalize_result(result)
        except (zipfile.BadZipFile, NotImplementedError) as exc:
            fallback_result = empty_result(path)
            fallback_result["file_size"] = result["file_size"]
            fallback_result["hashes"] = result["hashes"]
            fallback_result["notes"].append(
                f"{path.name} native ZIP parsing failed ({exc}); attempting 7z extraction fallback."
            )
            with tempfile.TemporaryDirectory(prefix="apk-triage-7z-") as temp_dir:
                success, detail = extract_archive_with_7z(path, Path(temp_dir))
                if success:
                    if detail:
                        fallback_result["notes"].append(f"7z fallback used for {path.name}.")
                    analyze_directory(fallback_result, Path(temp_dir))
                    return finalize_result(fallback_result)

                fallback_result["notes"].append(
                    f"7z fallback failed for {path.name}: {detail or 'unknown error'}; falling back to raw string scan."
                )
                result = fallback_result

    record_suffix(result, path.name)
    add_entry_name_signals(result, path.name, guess_package_type(path))
    try:
        blob = read_prefix(path)
    except OSError as exc:
        result["notes"].append(f"Failed to read {path.name}: {exc}")
        return finalize_result(result)
    scan_blob(result, blob, path.name)
    return finalize_result(result)


def render_markdown(result: dict) -> str:
    lines = [
        "# Android Package Triage Report",
        "",
        f"- Target: `{result['target']}`",
        f"- Type: `{result['package_type']}`",
        f"- Risk: `{result['risk_level']}` ({result['risk_score']})",
    ]

    if result["hashes"]:
        for name, value in result["hashes"].items():
            lines.append(f"- {name.upper()}: `{value}`")

    lines.extend(["", "## Top Signals"])
    if result["signals"]:
        for signal in result["signals"][:10]:
            lines.append(f"- `{signal['severity']}` {signal['title']}: {signal['evidence']} ({signal['rationale']})")
    else:
        lines.append("- No strong static heuristics fired.")

    lines.extend(["", "## IOCs"])
    if result["iocs"]:
        for category, values in result["iocs"].items():
            lines.append(f"- {category}: {', '.join(f'`{value}`' for value in values)}")
    else:
        lines.append("- No URLs, domains, IPs, or emails extracted from the scanned material.")

    lines.extend(["", "## Permissions"])
    if result["permissions"]:
        for severity, permissions in result["permissions"].items():
            lines.append(f"- {severity}: {', '.join(f'`{value}`' for value in permissions)}")
    else:
        lines.append("- No Android permission strings extracted.")

    summary = result["archive_summary"]
    lines.extend(
        [
            "",
            "## Archive Summary",
            f"- Entries scanned: `{summary['entry_count']}`",
            f"- Suffix counts: `{json.dumps(summary['suffix_counts'], sort_keys=True)}`",
        ]
    )
    if summary["embedded_archives"]:
        lines.append(f"- Embedded archives: {', '.join(f'`{value}`' for value in summary['embedded_archives'])}")
    if summary["native_libs"]:
        lines.append(f"- Native libraries: {', '.join(f'`{value}`' for value in summary['native_libs'])}")

    lines.extend(["", "## Tool Availability"])
    if result["available_tools"]:
        for name, location in result["available_tools"].items():
            lines.append(f"- `{name}`: `{location}`")
    else:
        lines.append("- No external Android reversing tools were detected on PATH.")

    if result["notes"]:
        lines.extend(["", "## Notes"])
        for note in result["notes"]:
            lines.append(f"- {note}")

    lines.extend(["", "## Caveat", "- This is automated static triage, not a definitive malware attribution."])
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Perform first-pass static triage for suspicious Android app packages.")
    parser.add_argument("target", help="Path to an APK/APKS/XAPK/ZIP, unpacked directory, or loose binary.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    parser.add_argument("--output", help="Optional path to write the rendered report.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target = Path(args.target).expanduser().resolve()
    result = analyze_target(target)
    rendered = render_markdown(result) if args.format == "markdown" else json.dumps(result, indent=2, sort_keys=True)

    if args.output:
        output_path = Path(args.output).expanduser().resolve()
        output_path.write_text(rendered, encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
