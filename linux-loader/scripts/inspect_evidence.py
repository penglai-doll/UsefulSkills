#!/usr/bin/env python3
"""Compact inspection helpers for the linux-loader skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "linux-loader.v1"
HASH_ALGORITHMS = ("md5", "sha1", "sha256")
DEFAULT_MOUNT_ROOT = "/mnt/evidence_mount"
BUILTIN_TOOLS = ("file", "stat", "fdisk", "parted", "blkid", "mount", "findmnt", "lsblk", "losetup")
HASH_TOOLS = ("md5sum", "sha1sum", "sha256sum")
OPTIONAL_TOOLS = (
    "ewfinfo",
    "ewfmount",
    "ewfexport",
    "fusermount",
    "fusermount3",
    "apt-get",
    "wget",
    "curl",
    "dpkg-deb",
    "tar",
    "pvs",
    "vgs",
    "lvs",
    "cryptsetup",
)


def parse_hash_policy(value: str | None) -> dict[str, Any]:
    raw = (value or "none").strip().lower()
    if raw in {"none", "skip", "no"}:
        return {"mode": "skip", "algorithms": []}
    if raw == "later":
        return {"mode": "later", "algorithms": []}

    algorithms = []
    for part in raw.split(","):
        algorithm = part.strip().lower()
        if not algorithm:
            continue
        if algorithm not in HASH_ALGORITHMS:
            raise ValueError(f"unsupported hash algorithm: {algorithm}")
        if algorithm not in algorithms:
            algorithms.append(algorithm)
    if not algorithms:
        return {"mode": "skip", "algorithms": []}
    return {"mode": "now", "algorithms": algorithms}


def bounded_items(items: Iterable[Any], limit: int = 50, details_path: str | None = None) -> dict[str, Any]:
    materialized = list(items)
    shown = materialized[: max(limit, 0)]
    result = {
        "items": shown,
        "total_count": len(materialized),
        "shown_count": len(shown),
        "truncated": len(shown) < len(materialized),
    }
    if details_path:
        result["details_path"] = details_path
    return result


def compute_hashes(path: Path, policy: dict[str, Any], chunk_size: int = 1024 * 1024) -> dict[str, Any]:
    mode = policy.get("mode", "skip")
    algorithms = list(policy.get("algorithms", []))
    result = {
        "requested": algorithms,
        "mode": mode,
        "values": {},
        "errors": {},
        "elapsed_seconds": 0.0,
    }
    if mode != "now" or not algorithms:
        result["skipped"] = mode
        return result

    hashers = {name: hashlib.new(name) for name in algorithms}
    started = time.time()
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                for hasher in hashers.values():
                    hasher.update(chunk)
    except OSError as exc:
        for name in algorithms:
            result["errors"][name] = str(exc)
    else:
        result["values"] = {name: hasher.hexdigest() for name, hasher in hashers.items()}
    result["elapsed_seconds"] = round(time.time() - started, 3)
    return result


def safe_case_id(path: Path, explicit: str | None = None) -> str:
    raw = explicit or path.stem or "case"
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip(".-")
    return value[:80] or "case"


def case_paths(output_dir: Path, case_id: str, mount_root: str | Path = DEFAULT_MOUNT_ROOT) -> dict[str, Any]:
    output_abs = (output_dir.expanduser().resolve() / case_id).resolve()
    requested_mount = (Path(mount_root).expanduser() / case_id).resolve()
    selected_mount = requested_mount
    conflict = False
    reason = None
    if requested_mount.exists():
        try:
            conflict = any(requested_mount.iterdir())
        except OSError:
            conflict = True
        if conflict:
            selected_mount = requested_mount.parent.parent / f"ev-mount-{case_id}"
            reason = "requested mount path exists and is not empty"
    return {
        "output_dir_abs": str(output_abs),
        "requested_mount_root": str(requested_mount),
        "selected_mount_root": str(selected_mount.resolve()),
        "mount_root_conflict": conflict,
        "alternate_path_reason": reason,
    }


def run_command(args: list[str], timeout: int = 10) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {
            "args": args,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "elapsed_seconds": round(time.time() - started, 3),
        }
    return {
        "args": args,
        "returncode": proc.returncode,
        "stdout": proc.stdout[:4000],
        "stderr": proc.stderr[:2000],
        "elapsed_seconds": round(time.time() - started, 3),
    }


def tool_inventory(format_kind: str | None = None) -> dict[str, Any]:
    tools = {}
    for name in BUILTIN_TOOLS + HASH_TOOLS + OPTIONAL_TOOLS:
        path = shutil.which(name)
        category = "built-in"
        required = name in BUILTIN_TOOLS
        if name in HASH_TOOLS:
            category = "built-in"
            required = False
        if name in OPTIONAL_TOOLS:
            category = "optional"
            required = format_kind == "E01" and name == "ewfmount"
        tools[name] = {"available": bool(path), "path": path, "category": category, "required": required}
    return tools


def preflight_snapshot(format_kind: str | None = None) -> dict[str, Any]:
    uname = platform.uname()
    proc_version = ""
    try:
        proc_version = Path("/proc/version").read_text(encoding="utf-8", errors="replace")[:500]
    except OSError:
        pass
    is_wsl = "microsoft" in proc_version.lower() or "wsl" in proc_version.lower()
    sudo = shutil.which("sudo")
    sudo_noninteractive = False
    if sudo:
        sudo_noninteractive = run_command(["sudo", "-n", "true"], timeout=3)["returncode"] == 0
    return {
        "platform": platform.platform(),
        "uname": " ".join(part for part in uname if part),
        "proc_version_excerpt": proc_version,
        "is_wsl": is_wsl,
        "sudo_available": bool(sudo),
        "sudo_noninteractive": sudo_noninteractive,
        "loop_attach_probe": "unknown" if not sudo_noninteractive else "not_run_by_inspect",
        "losetup_partition_scan": "unknown" if not sudo_noninteractive else "not_run_by_inspect",
        "fuse": fuse_snapshot(),
        "resume_state": "not_requested",
        "format_context": format_kind,
    }


def fuse_snapshot(dev_fuse: Path | None = None) -> dict[str, Any]:
    dev = dev_fuse or Path("/dev/fuse")
    fusermount = shutil.which("fusermount") or shutil.which("fusermount3")
    exists = dev.exists()
    readable = os.access(dev, os.R_OK) if exists else False
    writable = os.access(dev, os.W_OK) if exists else False
    reasons = []
    if not exists:
        reasons.append("/dev/fuse is missing")
    if exists and not readable:
        reasons.append("/dev/fuse is not readable by current user")
    if exists and not writable:
        reasons.append("/dev/fuse is not writable by current user")
    if not fusermount:
        reasons.append("fusermount/fusermount3 is missing")
    usable = exists and readable and writable and bool(fusermount)
    return {
        "dev_fuse": exists,
        "dev_fuse_readable": readable,
        "dev_fuse_writable": writable,
        "fusermount": bool(fusermount),
        "fusermount_path": fusermount,
        "usable": usable,
        "reason": "; ".join(reasons) if reasons else None,
    }


def detect_format(path: Path) -> dict[str, Any]:
    if path.is_dir():
        return {"kind": "mounted-tree", "confidence": 1.0, "evidence": ["path is a directory"]}
    suffix = path.suffix.lower()
    try:
        with path.open("rb") as fh:
            magic = fh.read(16)
    except OSError:
        magic = b""
    evidence = []
    if suffix in {".e01", ".ex01", ".e01x"}:
        evidence.append(f"extension {suffix}")
    if magic.startswith(b"EVF"):
        evidence.append("EWF EVF magic")
    if evidence:
        return {"kind": "E01", "confidence": 0.9, "evidence": evidence}
    return {"kind": "raw-style", "confidence": 0.55, "evidence": ["default raw/dd/img handling"]}


def estimate_ewf_export(media_size: int, free_space: int | None, throughput_mib_s: float | None = None) -> dict[str, Any]:
    throughput = throughput_mib_s or 80.0
    bytes_per_second = throughput * 1024 * 1024
    seconds = int(media_size / bytes_per_second) if bytes_per_second > 0 else None
    return {
        "estimated_export_size": int(media_size),
        "estimated_export_seconds": seconds,
        "estimated_export_time": seconds,
        "throughput_mib_s": throughput,
        "free_space": free_space,
        "space_available": None if free_space is None else free_space >= media_size,
    }


def ewf_snapshot(path: Path, format_info: dict[str, Any], output_abs: Path) -> dict[str, Any]:
    result = {
        "detected": format_info.get("kind") == "E01",
        "metadata": {},
        "exposed_raw_path": None,
        "estimated_export_size": None,
        "estimated_export_time": None,
        "export_space_available": None,
        "fallback": None,
        "errors": [],
    }
    if not result["detected"]:
        return result

    free_space = shutil.disk_usage(output_abs.parent if output_abs.parent.exists() else Path.cwd()).free
    estimate = estimate_ewf_export(path.stat().st_size, free_space)
    result.update(
        {
            "estimated_export_size": estimate["estimated_export_size"],
            "estimated_export_time": estimate["estimated_export_time"],
            "export_space_available": estimate["space_available"],
        }
    )
    if shutil.which("ewfinfo"):
        info = run_command(["ewfinfo", str(path)], timeout=20)
        result["metadata"] = {"ewfinfo_excerpt": info["stdout"][:2000], "returncode": info["returncode"]}
    else:
        result["errors"].append({"tool": "ewfinfo", "message": "ewfinfo is missing; ask before installing ewf-tools"})
    fuse = fuse_snapshot()
    if not fuse["usable"]:
        result["fallback"] = "ewfexport"
        result["errors"].append({"tool": "fuse", "message": f"ewfmount unavailable: {fuse['reason']}"})
    return result


def parse_parted_machine(output: str) -> list[dict[str, Any]]:
    partitions = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith(("BYT;", "/")):
            continue
        parts = line.rstrip(";").split(":")
        if not parts or not parts[0].isdigit():
            continue
        start = _bytes_from_parted(parts[1]) if len(parts) > 1 else None
        end = _bytes_from_parted(parts[2]) if len(parts) > 2 else None
        length = _bytes_from_parted(parts[3]) if len(parts) > 3 else None
        fs_type = parts[4] if len(parts) > 4 and parts[4] else None
        flags = parts[6].split(",") if len(parts) > 6 and parts[6] else []
        partitions.append(
            {
                "number": int(parts[0]),
                "start_offset": start,
                "end_offset": end,
                "length": length,
                "filesystem": fs_type,
                "role_guess": guess_partition_role(fs_type, flags),
                "lvm_indicator": "lvm" in flags or fs_type == "lvm2",
                "luks_indicator": fs_type in {"crypto_LUKS", "luks"},
                "mount_candidate": fs_type not in {"linux-swap(v1)", "swap", "crypto_LUKS", "luks", "lvm2"},
                "source": "parted",
                "flags": flags,
            }
        )
    return partitions


def _bytes_from_parted(value: str) -> int | None:
    value = value.strip()
    if value.endswith("B"):
        value = value[:-1]
    try:
        return int(float(value))
    except ValueError:
        return None


def guess_partition_role(fs_type: str | None, flags: list[str] | None = None) -> str:
    fs = (fs_type or "").lower()
    flags = flags or []
    if "boot" in flags or fs in {"fat16", "fat32", "vfat"}:
        return "boot"
    if fs in {"linux-swap(v1)", "swap"}:
        return "swap"
    if fs in {"crypto_luks", "luks"}:
        return "encrypted"
    if fs in {"lvm2", "lvm"} or "lvm" in flags:
        return "lvm"
    if fs:
        return "linux-data"
    return "unknown"


def enumerate_partitions(path: Path) -> dict[str, Any]:
    result = {"items": [], "source": None, "errors": []}
    if not path.is_file():
        return result
    if shutil.which("parted"):
        cmd = run_command(["parted", "-ms", str(path), "unit", "B", "print"], timeout=20)
        if cmd["returncode"] == 0:
            result["items"] = parse_parted_machine(cmd["stdout"])
            result["source"] = "parted"
            return result
        result["errors"].append({"command": cmd["args"], "stderr": cmd["stderr"][:500]})
    if shutil.which("fdisk"):
        cmd = run_command(["fdisk", "-l", str(path)], timeout=20)
        result["source"] = "fdisk"
        if cmd["returncode"] != 0:
            result["errors"].append({"command": cmd["args"], "stderr": cmd["stderr"][:500]})
    return result


def _exists(root: Path, rel: str) -> bool:
    return (root / rel.lstrip("/")).exists()


def classify_image_role(root: Path) -> dict[str, Any]:
    system_anchors = [
        "/etc/os-release",
        "/etc/passwd",
        "/etc/shadow",
        "/boot",
        "/etc/systemd",
        "/usr/lib/systemd",
    ]
    data_anchors = [
        "/www/wwwroot",
        "/www/server",
        "/opt/1panel",
        "/var/lib/1panel",
        "/var/www",
        "/srv",
        "/opt",
        "/home",
        "/var/lib/docker",
        "/var/lib/mysql",
        "/var/lib/postgresql",
        "/var/log",
    ]
    system_hits = [anchor for anchor in system_anchors if _exists(root, anchor)]
    data_hits = [anchor for anchor in data_anchors if _exists(root, anchor)]

    if system_hits and data_hits:
        role = "mixed"
        confidence = 0.85
        evidence = system_hits + data_hits
    elif system_hits:
        role = "system"
        confidence = 0.75
        evidence = system_hits
    elif data_hits:
        role = "data"
        confidence = 0.7
        evidence = data_hits
    else:
        role = "unknown"
        confidence = 0.2
        evidence = []
    return {"role": role, "confidence": confidence, "evidence": evidence}


def read_key_value_file(root: Path, rel: str, limit_bytes: int = 8192) -> dict[str, str]:
    path = root / rel.lstrip("/")
    try:
        raw = path.read_bytes()[:limit_bytes].decode("utf-8", errors="replace")
    except OSError:
        return {}
    values = {}
    for line in raw.splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    return values


def os_profile(root: Path, limit: int = 50) -> dict[str, Any]:
    os_release = read_key_value_file(root, "/etc/os-release")
    hostname = ""
    try:
        hostname = (root / "etc/hostname").read_text(encoding="utf-8", errors="replace").strip()[:200]
    except OSError:
        pass
    users = []
    passwd = root / "etc/passwd"
    try:
        for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 7:
                users.append({"name": parts[0], "uid": parts[2], "gid": parts[3], "home": parts[5], "shell": parts[6]})
    except OSError:
        pass
    clues = {
        "ssh": [p for p in ["/etc/ssh/sshd_config", "/root/.ssh", "/home"] if _exists(root, p)],
        "cron": [p for p in ["/etc/crontab", "/etc/cron.d", "/var/spool/cron"] if _exists(root, p)],
        "systemd": [p for p in ["/etc/systemd/system", "/usr/lib/systemd/system"] if _exists(root, p)],
        "shell_history": [p for p in ["/root/.bash_history", "/root/.zsh_history"] if _exists(root, p)],
    }
    return {
        "distribution": os_release.get("PRETTY_NAME") or os_release.get("NAME"),
        "hostname": hostname,
        "timezone": _first_existing_text(root, ["/etc/timezone"])[:200],
        "users": bounded_items(users, limit=limit),
        "sudo_admin_clues": [p for p in ["/etc/sudoers", "/etc/sudoers.d"] if _exists(root, p)],
        "ssh_clues": clues["ssh"],
        "cron_clues": clues["cron"],
        "systemd_clues": clues["systemd"],
        "shell_history_clues": clues["shell_history"],
    }


def _first_existing_text(root: Path, rels: list[str]) -> str:
    for rel in rels:
        try:
            return (root / rel.lstrip("/")).read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
    return ""


def path_summary(root: Path, rels: list[str], limit: int = 50) -> dict[str, Any]:
    rows = []
    for rel in rels:
        path = root / rel.lstrip("/")
        if not path.exists():
            continue
        row = {"path": rel, "type": "directory" if path.is_dir() else "file", "tags": _business_tags_for_path(rel)}
        try:
            if path.is_file():
                row["size"] = path.stat().st_size
            elif path.is_dir():
                count = 0
                for count, _ in enumerate(path.iterdir(), 1):
                    if count >= limit + 1:
                        break
                row["direct_child_count_sample"] = count
        except OSError as exc:
            row["error"] = str(exc)
        rows.append(row)
    return bounded_items(rows, limit=limit)


def detect_services(root: Path) -> dict[str, Any]:
    checks = {
        "web": ["/etc/nginx", "/etc/apache2", "/var/www", "/srv", "/www/wwwroot"],
        "database": ["/var/lib/mysql", "/var/lib/postgresql", "/var/lib/mongodb", "/var/lib/redis", "/www/server/data"],
        "cache": ["/var/lib/redis", "/etc/redis"],
        "runtime": ["/usr/bin/php", "/usr/local/bin/node", "/usr/bin/python3", "/usr/bin/java", "/www/server/php"],
    }
    result = {}
    for key, rels in checks.items():
        hits = [rel for rel in rels if _exists(root, rel)]
        result[key] = {"detected": bool(hits), "evidence": hits}
    return result


def detect_panels(root: Path) -> dict[str, Any]:
    bt_hits = [rel for rel in ["/www/server/panel", "/www/server/nginx", "/www/wwwroot", "/www/backup"] if _exists(root, rel)]
    onepanel_hits = [rel for rel in ["/opt/1panel", "/var/lib/1panel", "/etc/systemd/system/1panel.service"] if _exists(root, rel)]
    common_candidates = {
        "webmin": "/etc/webmin",
        "cyberpanel": "/usr/local/CyberCP",
        "cpanel": "/var/cpanel",
        "plesk": "/opt/psa",
        "directadmin": "/usr/local/directadmin",
        "nginx-proxy-manager": "/data/nginx/proxy_host",
    }
    common_hits = [name for name, rel in common_candidates.items() if _exists(root, rel)]
    return {
        "bt": {"detected": bool(bt_hits), "confidence": 0.85 if bt_hits else 0.0, "evidence": bt_hits},
        "onepanel": {"detected": bool(onepanel_hits), "confidence": 0.85 if onepanel_hits else 0.0, "evidence": onepanel_hits},
        "common": {"detected": bool(common_hits), "confidence": 0.7 if common_hits else 0.0, "evidence": common_hits},
    }


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _business_tags_for_path(path: str) -> list[str]:
    lowered = path.lower()
    tags = []
    if any(part in lowered for part in ("/www", "/var/www", "nginx/html", "/app", "/site")):
        tags.append("web")
    if any(part in lowered for part in ("mysql", "mariadb", "postgres", "mongodb", "redis")):
        tags.append("database")
    if any(part in lowered for part in ("config", "/etc/nginx", "conf")):
        tags.append("config")
    if any(part in lowered for part in ("backup", "dump")):
        tags.append("backup")
    return tags or ["data"]


def _split_bind(bind: str) -> tuple[str, str, str | None]:
    parts = bind.split(":")
    if len(parts) >= 2:
        return parts[0], parts[1], ":".join(parts[2:]) if len(parts) > 2 else None
    return bind, "", None


def _source_exists_in_evidence(source: str, evidence_root: Path | None = None) -> bool:
    if not source:
        return False
    # Pure-string POSIX-absolute check: Path("/srv/site").is_absolute() is False on
    # Windows, which used to make this helper resolve against the current drive.
    normalized = source.replace("\\", "/")
    if evidence_root and normalized.startswith("/"):
        return (evidence_root / normalized.lstrip("/")).exists()
    return Path(source).exists()


def extract_docker_mount_mappings(data_root: Path, limit: int = 50, evidence_root: Path | None = None) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    containers_root = data_root / "containers"
    for container_dir in sorted(containers_root.glob("*")):
        if not container_dir.is_dir():
            continue
        container_id = container_dir.name
        config = _load_json(container_dir / "config.v2.json")
        hostconfig = _load_json(container_dir / "hostconfig.json")
        name = str(config.get("Name") or "").lstrip("/")
        image = (config.get("Config") or {}).get("Image") or config.get("Image")
        labels = (config.get("Config") or {}).get("Labels") or {}
        compose_project = labels.get("com.docker.compose.project")

        for bind in hostconfig.get("Binds") or []:
            source, target, options = _split_bind(str(bind))
            mappings.append(
                {
                    "container_id": container_id,
                    "container_name": name,
                    "image": image,
                    "compose_project": compose_project,
                    "container_path": target,
                    "source": source,
                    "source_type": "bind",
                    "options": options,
                    "source_exists": _source_exists_in_evidence(source, evidence_root),
                    "likely_business_data": _business_tags_for_path(f"{source} {target}"),
                }
            )

        mount_points = config.get("MountPoints") or {}
        for target, info in sorted(mount_points.items()):
            if not isinstance(info, dict):
                continue
            source = info.get("Source") or info.get("Name") or ""
            mappings.append(
                {
                    "container_id": container_id,
                    "container_name": name,
                    "image": image,
                    "compose_project": compose_project,
                    "container_path": info.get("Destination") or target,
                    "source": source,
                    "source_type": info.get("Type") or "volume",
                    "volume_name": info.get("Name"),
                    "source_exists": _source_exists_in_evidence(source, evidence_root),
                    "likely_business_data": _business_tags_for_path(f"{source} {target}"),
                }
            )
    return mappings[:limit]


def detect_docker(root: Path, limit: int = 50) -> dict[str, Any]:
    daemon = _load_json(root / "etc/docker/daemon.json")
    data_root_rel = daemon.get("data-root") or "/var/lib/docker"
    data_root = root / str(data_root_rel).lstrip("/")
    containers_root = data_root / "containers"
    volumes_root = data_root / "volumes"
    container_count = _count_dirs(containers_root, limit=100000)
    volume_count = _count_dirs(volumes_root, limit=100000)
    mappings = extract_docker_mount_mappings(data_root, limit=limit, evidence_root=root) if data_root.exists() else []
    compose_candidates = []
    for base in [root / "opt", root / "srv", root / "www", root / "var/www", root / "home"]:
        compose_candidates.extend(find_named_files(base, {"docker-compose.yml", "docker-compose.yaml", "compose.yml"}, max_depth=4, limit=limit))
        if len(compose_candidates) >= limit:
            break
    return {
        "detected": data_root.exists() or _exists(root, "/etc/docker/daemon.json"),
        "data_root": data_root_rel,
        "daemon_config": "/etc/docker/daemon.json" if _exists(root, "/etc/docker/daemon.json") else None,
        "container_count": container_count,
        "volume_count": volume_count,
        "compose_candidates": bounded_items(compose_candidates, limit=limit),
        "mount_mappings": bounded_items(mappings, limit=limit),
    }


def _count_dirs(path: Path, limit: int = 100000) -> int:
    if not path.exists():
        return 0
    count = 0
    try:
        for child in path.iterdir():
            if child.is_dir():
                count += 1
                if count >= limit:
                    break
    except OSError:
        return count
    return count


def find_named_files(base: Path, names: set[str], max_depth: int = 4, limit: int = 50) -> list[str]:
    if not base.exists():
        return []
    if not base.is_absolute():
        # Relative bases used to crash on child.relative_to(base.anchor or "/");
        # resolving first guarantees a non-empty anchor (drive root or "/").
        base = base.absolute()
    results: list[str] = []
    base_depth = len(base.parts)
    stack = [base]
    while stack and len(results) < limit:
        current = stack.pop()
        try:
            for child in current.iterdir():
                depth = len(child.parts) - base_depth
                if child.is_file() and child.name in names:
                    results.append("/" + str(child.relative_to(base.anchor or "/")).lstrip("/"))
                elif child.is_dir() and depth < max_depth:
                    stack.append(child)
        except OSError:
            continue
    return results


def recommend_references(triage: dict[str, Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []

    def add(file: str, priority: str, reason: str) -> None:
        if file not in {item["file"] for item in refs}:
            refs.append({"file": file, "priority": priority, "reason": reason})

    panels = triage.get("panels", {}) or {}
    services = triage.get("services", {}) or {}
    goals = {str(goal).lower() for goal in triage.get("goals", []) or []}
    docker = triage.get("docker", {}) or {}

    if (panels.get("bt") or {}).get("detected"):
        add("panel-bt.md", "required", "BT/aaPanel indicators were detected")
    if (panels.get("onepanel") or {}).get("detected"):
        add("panel-1panel.md", "required", "1Panel indicators were detected")
    if (panels.get("common") or {}).get("detected"):
        add("panel-common.md", "required", "other hosting panel indicators were detected")
    if docker.get("detected") or "docker" in goals:
        add("docker-linux.md", "required", "Docker indicators or Docker-focused goal")
    if (services.get("web") or {}).get("detected") or goals.intersection({"web", "website", "site"}):
        add("web-recovery.md", "required", "web recovery indicators or goal")
    if (services.get("database") or {}).get("detected") or goals.intersection({"db", "database", "mysql", "postgresql"}):
        add("database-recovery.md", "required", "database indicators or goal")
    if goals.intersection({"log", "logs", "timeline", "incident", "webshell"}):
        add("log-analysis.md", "required", "log or incident timeline goal")
    return refs


def suggested_next_steps(role: str, refs: list[dict[str, str]], docker: dict[str, Any]) -> list[str]:
    steps = []
    if role == "data":
        steps.append("Treat this as a non-system data image and focus on service/application data paths.")
    if docker.get("detected"):
        steps.append("Review Docker mount mappings before reconstructing website or database data.")
    for ref in refs[:3]:
        steps.append(f"Read references/{ref['file']} only if continuing with: {ref['reason']}.")
    if not steps:
        steps.append("No common Linux service roots were detected; inspect partition layout and user-provided goals next.")
    return steps[:5]


def _fast_skipped_probe(label: str) -> dict[str, Any]:
    return {"skipped": True, "reason": f"{label} probe skipped by triage-level fast"}


def mounted_tree_triage(
    root: Path,
    limit: int = 50,
    goals: list[str] | None = None,
    triage_level: str = "full",
) -> dict[str, Any]:
    role = classify_image_role(root)
    if triage_level == "fast":
        # fast = mount planning only: skip deep content probes (os profile,
        # panel scan, Docker metadata/compose walk, path summaries) and keep
        # the cheap anchor checks needed for role classification and routing.
        services = detect_services(root)
        triage = {"panels": _fast_skipped_probe("panel"), "services": services, "docker": {"detected": False}, "goals": goals or []}
        refs = recommend_references(triage)
        return {
            "image_role": role,
            "os_profile": _fast_skipped_probe("os-profile"),
            "services": services,
            "paths": bounded_items([], limit=limit),
            "panels": _fast_skipped_probe("panel"),
            "docker": {
                "detected": False,
                "container_count": 0,
                "volume_count": 0,
                "mount_mappings": bounded_items([], limit=limit),
                "compose_candidates": bounded_items([], limit=limit),
                **_fast_skipped_probe("docker"),
            },
            "triage_level": "fast",
            "routes": {
                "recommended_references": refs,
                "suggested_next_steps": suggested_next_steps(role["role"], refs, {"detected": False}),
            },
        }
    profile = os_profile(root, limit=limit) if role["role"] in {"system", "mixed"} else {}
    services = detect_services(root)
    panels = detect_panels(root)
    docker = detect_docker(root, limit=limit)
    paths = path_summary(
        root,
        [
            "/www/wwwroot",
            "/www/server",
            "/www/backup",
            "/opt/1panel",
            "/var/lib/1panel",
            "/var/www",
            "/srv",
            "/opt",
            "/home",
            "/var/lib/docker",
            "/var/lib/mysql",
            "/var/lib/postgresql",
            "/var/log",
        ],
        limit=limit,
    )
    triage = {"panels": panels, "services": services, "docker": docker, "goals": goals or []}
    refs = recommend_references(triage)
    return {
        "image_role": role,
        "os_profile": profile,
        "services": services,
        "paths": paths,
        "panels": panels,
        "docker": docker,
        "routes": {
            "recommended_references": refs,
            "suggested_next_steps": suggested_next_steps(role["role"], refs, docker),
        },
    }


def inspect_path(
    path: Path,
    hash_policy: dict[str, Any],
    summary_limit: int = 50,
    case_id: str | None = None,
    output_dir: Path | None = None,
    mount_root: str | Path = DEFAULT_MOUNT_ROOT,
    goals: list[str] | None = None,
    triage_level: str = "full",
) -> dict[str, Any]:
    stat = path.stat()
    case = safe_case_id(path, case_id)
    output_root = output_dir or Path("output/linux-loader")
    paths = case_paths(output_root, case, mount_root=mount_root)
    format_info = detect_format(path)
    format_kind = format_info["kind"]
    output_abs = Path(paths["output_dir_abs"])
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case,
        "collection_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence_file": {
            "path": str(path.resolve()),
            "basename": path.name,
            "size": stat.st_size,
            "mtime": stat.st_mtime,
            "readable": os.access(path, os.R_OK),
            "detected_format": format_kind,
        },
        "hashes": compute_hashes(path, hash_policy) if path.is_file() else {"mode": "skip", "skipped": "directory"},
        "case_paths": paths,
        "tools": tool_inventory(format_kind),
        "preflight": preflight_snapshot(format_kind),
        "format": format_info,
        "ewf": ewf_snapshot(path, format_info, output_abs) if path.is_file() else {"detected": False},
        "partitions": enumerate_partitions(path) if path.is_file() else {"items": [], "source": "mounted-tree", "errors": []},
        "mounts": [],
        "image_role": "unknown",
        "os_profile": {},
        "services": {},
        "paths": bounded_items([], limit=summary_limit),
        "panels": {},
        "docker": {},
        "routes": {"recommended_references": [], "suggested_next_steps": []},
        "errors": [],
    }
    if path.is_dir():
        triage = mounted_tree_triage(path, limit=summary_limit, goals=goals, triage_level=triage_level)
        result.update(
            {
                "image_role": triage["image_role"]["role"],
                "image_role_detail": triage["image_role"],
                "os_profile": triage["os_profile"],
                "services": triage["services"],
                "paths": triage["paths"],
                "panels": triage["panels"],
                "docker": triage["docker"],
                "routes": triage["routes"],
            }
        )
        if triage.get("triage_level"):
            result["triage_level"] = triage["triage_level"]
    return result


def write_result(result: dict[str, Any], output_dir_abs: str, filename: str) -> str:
    outdir = Path(output_dir_abs)
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / filename
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)


def print_json(data: dict[str, Any]) -> None:
    """Print ensure_ascii=False JSON without crashing on gbk/other consoles."""
    text = json.dumps(data, ensure_ascii=False, indent=2)
    try:
        print(text)
    except UnicodeEncodeError:
        for stream in (sys.stdout,):
            if hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(errors="replace")
                except (AttributeError, OSError, ValueError):
                    pass
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Linux evidence images or mounted trees.")
    parser.add_argument("path", nargs="?", help="Evidence image or mounted filesystem path")
    parser.add_argument("--json", action="store_true", help="Write JSON to stdout (default behavior; flag kept for compatibility)")
    parser.add_argument("--output-dir", default="output/linux-loader", help="Output directory for artifacts")
    parser.add_argument("--case-id", default=None, help="Stable case id")
    parser.add_argument("--summary-limit", type=int, default=50, help="Maximum rows per model-facing category")
    parser.add_argument("--hash", default="none", help="none, later, md5, sha1, sha256, or comma-separated algorithms")
    parser.add_argument("--mount-root", default=DEFAULT_MOUNT_ROOT, help="Preferred mount root used for case path planning")
    parser.add_argument("--goal", action="append", default=[], help="Focused analysis goal used only for reference routing")
    parser.add_argument("--no-write", action="store_true", help="Do not write inspect.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.path:
        parser.print_help()
        return 0
    try:
        hash_policy = parse_hash_policy(args.hash)
    except ValueError as exc:
        result = {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": str(exc)}]}
        print_json(result)
        return 1

    path = Path(args.path)
    if not path.exists():
        result = {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": f"path not found: {path}"}]}
    else:
        result = inspect_path(
            path,
            hash_policy,
            summary_limit=args.summary_limit,
            case_id=args.case_id,
            output_dir=Path(args.output_dir),
            mount_root=args.mount_root,
            goals=args.goal,
        )
        if not args.no_write:
            result["output_files"] = {
                "inspect_json": write_result(result, result["case_paths"]["output_dir_abs"], "inspect.json")
            }
    print_json(result)
    return 1 if any(error.get("fatal") for error in result.get("errors") or []) else 0


if __name__ == "__main__":
    raise SystemExit(main())
