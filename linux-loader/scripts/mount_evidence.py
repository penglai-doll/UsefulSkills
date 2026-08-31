#!/usr/bin/env python3
"""Read-only mounting helpers for the linux-loader skill."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "linux-loader.v1"
DEFAULT_MOUNT_ROOT = "/mnt/evidence_mount"
sys.dont_write_bytecode = True


def _load_inspect_module():
    path = Path(__file__).resolve().with_name("inspect_evidence.py")
    spec = importlib.util.spec_from_file_location("linux_loader_inspect_evidence", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load inspect helper: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


inspect_helpers = _load_inspect_module()


def mount_options_for_fs(fs_type: str | None) -> list[str]:
    fs = (fs_type or "unknown").lower()
    if fs in {"ext2", "ext3", "ext4"}:
        return ["ro", "noload"]
    if fs == "xfs":
        return ["ro", "norecovery"]
    if fs == "btrfs":
        return ["ro", "norecovery", "skip_balance"]
    return ["ro"]


def validate_resume(run_meta: dict[str, Any], current: dict[str, Any], active_mounts: list[str]) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []

    evidence = run_meta.get("evidence") or {}
    if evidence.get("size") != current.get("size"):
        blockers.append("evidence size does not match run-meta.json")

    expected_mounts = [
        str(item.get("mount_path"))
        for item in run_meta.get("mounts", [])
        if item.get("active") and item.get("mount_path")
    ]
    missing_mounts = [path for path in expected_mounts if path not in set(active_mounts)]
    if missing_mounts:
        blockers.append(f"active mount state does not match run-meta.json: missing {missing_mounts}")

    if evidence.get("path") and current.get("path") and evidence.get("path") != current.get("path"):
        warnings.append("evidence path changed; continuing only because size and mount state match")
    if evidence.get("mtime") is not None and current.get("mtime") is not None and evidence.get("mtime") != current.get("mtime"):
        warnings.append("mtime changed; treating as warning, not a hard blocker")

    return {"can_resume": not blockers, "blockers": blockers, "warnings": warnings}


def select_mount_root(requested: str | Path, case_id: str) -> dict[str, Any]:
    requested_path = Path(requested).expanduser().resolve()
    conflict = False
    reason = None
    selected = requested_path

    if requested_path.exists():
        try:
            conflict = any(requested_path.iterdir())
        except OSError:
            conflict = True
        if conflict:
            reason = "requested mount root exists and is not empty"
            selected = requested_path.parent.parent / f"ev-mount-{case_id}"

    return {
        "requested": str(requested_path),
        "selected": str(selected.resolve()),
        "conflict": conflict,
        "alternate_reason": reason,
    }


def run_command(args: list[str], timeout: int = 60) -> dict[str, Any]:
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


def run_command_with_input(args: list[str], input_text: str, timeout: int = 60) -> dict[str, Any]:
    started = time.time()
    try:
        proc = subprocess.run(
            args,
            input=input_text,
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


def sudo_user_choices() -> list[dict[str, str]]:
    return [
        {
            "id": "manual_sudo",
            "label": "手动提供 sudo 权限",
            "description": "复制 manual_command 到可信 WSL 终端执行。",
        },
        {
            "id": "interactive_sudo",
            "label": "交互输入 sudo 密码",
            "description": "在可信 WSL 终端运行同一条 sudo 命令并输入密码。",
        },
    ]


def build_privilege_context() -> dict[str, Any]:
    is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    sudo_path = shutil.which("sudo")
    if is_root:
        return {
            "is_root": True,
            "sudo_available": bool(sudo_path),
            "sudo_noninteractive": True,
            "can_run_privileged": True,
            "prefix": [],
            "manual_prefix": [],
            "reason": None,
            "user_choices": [],
        }

    if not sudo_path:
        return {
            "is_root": False,
            "sudo_available": False,
            "sudo_noninteractive": False,
            "can_run_privileged": False,
            "prefix": [],
            "manual_prefix": ["sudo"],
            "reason": "sudo permission required but sudo is not installed or not in PATH",
            "user_choices": sudo_user_choices(),
        }

    sudo_noninteractive = run_command(["sudo", "-n", "true"], timeout=3)["returncode"] == 0
    if sudo_noninteractive:
        return {
            "is_root": False,
            "sudo_available": True,
            "sudo_noninteractive": True,
            "can_run_privileged": True,
            "prefix": ["sudo", "-n"],
            "manual_prefix": ["sudo"],
            "reason": None,
            "user_choices": [],
        }

    return {
        "is_root": False,
        "sudo_available": True,
        "sudo_noninteractive": False,
        "can_run_privileged": False,
        "prefix": [],
        "manual_prefix": ["sudo"],
        "reason": "sudo permission required: current session cannot use non-interactive sudo",
        "user_choices": sudo_user_choices(),
    }


def sudo_prefix() -> list[str]:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return []
    if shutil.which("sudo") and run_command(["sudo", "-n", "true"], timeout=3)["returncode"] == 0:
        return ["sudo", "-n"]
    return []


def active_mounts() -> list[str]:
    if shutil.which("findmnt"):
        cmd = run_command(["findmnt", "-rn", "-o", "TARGET"], timeout=10)
        if cmd["returncode"] == 0:
            return [line.strip() for line in cmd["stdout"].splitlines() if line.strip()]
    return []


def probe_loop_support(privilege: dict[str, Any] | None = None) -> dict[str, Any]:
    result = {
        "loop_attach": "unknown",
        "losetup_partition_scan": "unknown",
        "known_good_fixture": None,
        "reason": None,
    }
    if not platform.system().lower() == "linux":
        result["reason"] = "not running on Linux/WSL2"
        return result
    if not shutil.which("losetup"):
        result["reason"] = "losetup not found"
        return result
    privilege = privilege or build_privilege_context()
    if not privilege.get("can_run_privileged"):
        result["reason"] = privilege.get("reason") or "privileged loop attach unavailable"
        return result
    prefix = list(privilege.get("prefix") or [])
    with tempfile.TemporaryDirectory(prefix="linux-loader-loop-") as td:
        img = Path(td) / "known-good.img"
        try:
            img.write_bytes(b"\0" * 1024)
            with img.open("r+b") as fh:
                fh.truncate(50 * 1024 * 1024)
        except OSError as exc:
            result["reason"] = f"cannot create loop probe fixture: {exc}"
            return result

        attach = run_command(prefix + ["losetup", "--find", "--show", "--read-only", str(img)], timeout=20)
        loop_dev = attach["stdout"].strip().splitlines()[0] if attach["returncode"] == 0 and attach["stdout"].strip() else None
        if loop_dev:
            result["loop_attach"] = "passed"
            run_command(prefix + ["losetup", "-d", loop_dev], timeout=10)
        else:
            result["loop_attach"] = "failed"
            result["reason"] = attach["stderr"] or attach["stdout"] or "losetup attach failed"
            return result

        if not shutil.which("sfdisk"):
            result["losetup_partition_scan"] = "unknown"
            result["reason"] = "sfdisk not found for known-good partition fixture"
            return result
        sfdisk = run_command_with_input(["sfdisk", str(img)], "label: dos\n,40M,L,*\n", timeout=20)
        if sfdisk["returncode"] != 0:
            result["losetup_partition_scan"] = "unknown"
            result["reason"] = sfdisk["stderr"] or sfdisk["stdout"] or "sfdisk fixture creation failed"
            return result
        attach_p = run_command(prefix + ["losetup", "--find", "--show", "--read-only", "-P", str(img)], timeout=20)
        loop_p = attach_p["stdout"].strip().splitlines()[0] if attach_p["returncode"] == 0 and attach_p["stdout"].strip() else None
        if not loop_p:
            result["losetup_partition_scan"] = "failed"
            result["reason"] = attach_p["stderr"] or attach_p["stdout"] or "losetup -P attach failed"
            return result
        result["known_good_fixture"] = {"image_size": 50 * 1024 * 1024, "loop_device": loop_p}
        part_nodes = list(Path("/dev").glob(Path(loop_p).name + "p*"))
        result["losetup_partition_scan"] = "passed" if part_nodes else "failed"
        if not part_nodes:
            result["reason"] = "known-good fixture attached but no loop partition node was created"
        run_command(prefix + ["losetup", "-d", loop_p], timeout=10)
    return result


def stat_evidence(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {"path": str(path.resolve()), "size": st.st_size, "mtime": st.st_mtime}


def locate_prior_inspection(args: argparse.Namespace) -> Path:
    """Default location of the prior inspect.json: <output-dir>/<case-id>/inspect.json."""
    case = inspect_helpers.safe_case_id(Path(args.path or "case"), args.case_id)
    return Path(args.output_dir).expanduser().resolve() / case / "inspect.json"


def apply_resume_validation(saved: dict[str, Any], args: argparse.Namespace, inspect_file: Path) -> dict[str, Any]:
    """--resume: validate the saved inspection against the current evidence file.

    Reuses the saved inspection instead of re-running inspect_path. Evidence size
    mismatch is a hard blocker (fatal error); mtime drift and path changes are
    warnings. The active-mount check inside validate_resume is intentionally not
    applied here because --resume always re-plans mounts, and prior mounts may
    have been cleaned up on purpose; prior mount state is recorded for info only.
    """
    result = dict(saved)
    errors = list(saved.get("errors") or [])
    evidence = saved.get("evidence_file") or {}
    evidence_path = Path(args.path) if args.path else Path(evidence.get("path") or "")

    if not str(evidence_path) or not evidence_path.exists():
        result["resume"] = {
            "can_resume": False,
            "blockers": [f"--resume: prior evidence not found: {evidence_path}"],
            "warnings": [],
        }
        result["errors"] = errors + [
            {"fatal": True, "stage": "resume", "message": f"--resume: prior evidence not found: {evidence_path}"}
        ]
        return result

    prior_meta: dict[str, Any] = {}
    run_meta_file = inspect_file.parent / "run-meta.json"
    if run_meta_file.exists():
        try:
            prior_meta = json.loads(run_meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prior_meta = {}
    if not prior_meta.get("evidence"):
        prior_meta = {
            "evidence": {key: evidence.get(key) for key in ("path", "size", "mtime")},
            "mounts": [],
        }

    try:
        current = stat_evidence(evidence_path)
    except OSError as exc:
        result["resume"] = {
            "can_resume": False,
            "blockers": [f"--resume: cannot stat evidence: {exc}"],
            "warnings": [],
        }
        result["errors"] = errors + [
            {"fatal": True, "stage": "resume", "message": f"--resume: cannot stat evidence: {exc}"}
        ]
        return result

    current_mounts = active_mounts()
    report = validate_resume({"evidence": prior_meta.get("evidence") or {}, "mounts": []}, current, current_mounts)
    prior_active = [
        str(item.get("mount_path"))
        for item in (prior_meta.get("mounts") or [])
        if item.get("active") and item.get("mount_path")
    ]
    report["prior_mounts_still_active"] = [path for path in prior_active if path in set(current_mounts)]
    report["resumed_from"] = str(inspect_file)

    result["resume"] = report
    if not report["can_resume"]:
        result["errors"] = errors + [
            {"fatal": True, "stage": "resume", "message": f"--resume blocked: {blocker}"} for blocker in report["blockers"]
        ]
    return result


def load_inspection(args: argparse.Namespace) -> dict[str, Any]:
    if args.inspect_json:
        inspect_file = Path(args.inspect_json)
        try:
            saved = json.loads(inspect_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": f"cannot read inspect-json: {exc}"}]}
        if args.resume:
            return apply_resume_validation(saved, args, inspect_file)
        return saved
    if not args.path:
        if args.resume:
            return {
                "schema_version": SCHEMA_VERSION,
                "errors": [
                    {
                        "fatal": True,
                        "stage": "resume",
                        "message": "--resume requires the evidence path (prior inspection is read from <output-dir>/<case-id>/inspect.json) or --inspect-json",
                    }
                ],
            }
        return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": "path is required unless --inspect-json is supplied"}]}
    path = Path(args.path)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": f"path not found: {path}"}]}
    if args.resume:
        inspect_file = locate_prior_inspection(args)
        try:
            saved = json.loads(inspect_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {
                "schema_version": SCHEMA_VERSION,
                "errors": [
                    {
                        "fatal": True,
                        "stage": "resume",
                        "message": f"--resume cannot read prior inspection {inspect_file}: {exc}; run inspect first or pass --inspect-json",
                    }
                ],
            }
        return apply_resume_validation(saved, args, inspect_file)
    return inspect_helpers.inspect_path(
        path,
        inspect_helpers.parse_hash_policy(args.hash),
        summary_limit=args.summary_limit,
        case_id=args.case_id,
        output_dir=Path(args.output_dir),
        mount_root=args.mount_root,
        goals=args.goal,
        triage_level=args.triage_level,
    )


def command_entry(
    stage: str,
    command: list[str],
    description: str,
    *,
    requires_privilege: bool = False,
    privilege: dict[str, Any] | None = None,
    blocked: bool = False,
    block_reason: str | None = None,
    requires_user_confirmation: bool = False,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "stage": stage,
        "command": command,
        "description": description,
        "requires_privilege": requires_privilege,
        "blocked": blocked,
    }
    if requires_privilege:
        privilege = privilege or build_privilege_context()
        if privilege.get("can_run_privileged") and not blocked and not requires_user_confirmation:
            entry["command"] = list(privilege.get("prefix") or []) + command
        else:
            entry["blocked"] = True
            if requires_user_confirmation:
                entry["block_reason"] = block_reason or "requires explicit user confirmation before running"
            else:
                entry["block_reason"] = block_reason or privilege.get("reason") or "privileged execution unavailable"
            manual_prefix = list(privilege.get("manual_prefix") or [])
            entry["manual_command"] = manual_prefix + command if manual_prefix else command
            if (not privilege.get("can_run_privileged")) and privilege.get("user_choices"):
                entry["user_choices"] = privilege["user_choices"]
                entry["user_message"] = "当前会话没有可用 sudo 权限；请选择手动执行 manual_command，或在可信 WSL 终端交互输入 sudo 密码。"
            elif requires_user_confirmation:
                entry["user_message"] = "该命令涉及依赖安装或取证环境变更；需要用户确认后再执行。"
    elif block_reason:
        entry["block_reason"] = block_reason
    if requires_user_confirmation:
        entry["requires_user_confirmation"] = True
        entry["blocked"] = True
        entry.setdefault("block_reason", "requires explicit user confirmation before running")
    return entry


def fuse_user_choices(ewfmount_command: list[str], export_command: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "id": "retry_fuse_with_sudo",
            "label": "提权或修复 FUSE 后重试",
            "description": "在可信 WSL 终端检查 /dev/fuse 权限，必要时用 sudo 重试 ewfmount。",
            "manual_command": ["sudo"] + ewfmount_command,
        },
        {
            "id": "export_raw",
            "label": "使用 ewfexport 降级导出 raw",
            "description": "确认磁盘空间和耗时后，用 ewfexport 导出 raw 再继续挂载。",
            "manual_command": export_command,
        },
    ]


def missing_ewftools(inspect_result: dict[str, Any]) -> list[str]:
    tools = inspect_result.get("tools") or {}
    missing = []
    for name in ("ewfmount",):
        if not (tools.get(name) or {}).get("available"):
            missing.append(name)
    return missing


def _safe_cache_case_id(inspect_result: dict[str, Any]) -> str:
    raw = str(inspect_result.get("case_id") or "case")
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw).strip(".-")
    return safe[:80] or "case"


def default_ewftools_cache_dir(inspect_result: dict[str, Any]) -> Path:
    return Path(tempfile.gettempdir()).resolve() / "linux-loader-cache" / _safe_cache_case_id(inspect_result) / "ewf-tools"


def result_tool_available(inspect_result: dict[str, Any], name: str) -> bool:
    return bool(((inspect_result.get("tools") or {}).get(name) or {}).get("available"))


def portable_ewftools_choice(inspect_result: dict[str, Any], cache_dir: Path | None = None) -> dict[str, Any]:
    cache = (cache_dir or default_ewftools_cache_dir(inspect_result)).expanduser().resolve()
    downloads = cache / "downloads"
    root = cache / "root"
    download_tool = "wget" if result_tool_available(inspect_result, "wget") else None
    if not download_tool and result_tool_available(inspect_result, "curl"):
        download_tool = "curl"

    q_downloads = shlex.quote(str(downloads))
    q_root = shlex.quote(str(root))
    commands = [
        f"mkdir -p {q_downloads} {q_root}",
        ': "${LINUX_LOADER_EWFTOOLS_URLS:?set trusted ewf-tools .deb or tarball URL(s)}"',
    ]
    if download_tool == "wget":
        commands.append(f'for url in $LINUX_LOADER_EWFTOOLS_URLS; do wget -P {q_downloads} "$url"; done')
    elif download_tool == "curl":
        commands.append(f'for url in $LINUX_LOADER_EWFTOOLS_URLS; do curl -L -O --output-dir {q_downloads} "$url"; done')
    else:
        commands.append(f"echo 'wget/curl missing; download ewf-tools archives into {q_downloads} manually'")
    if result_tool_available(inspect_result, "dpkg-deb"):
        commands.append(f"for pkg in {q_downloads}/*.deb; do [ -e \"$pkg\" ] && dpkg-deb -x \"$pkg\" {q_root}; done")
    if result_tool_available(inspect_result, "tar"):
        commands.append(f"for arc in {q_downloads}/*.tar*; do [ -e \"$arc\" ] && tar -xf \"$arc\" -C {q_root}; done")
    commands.append(f"find {q_root} -type f \\( -name 'ewfmount' -o -name 'ewfexport' -o -name 'ewfinfo' \\) -print")

    return {
        "id": "download_portable_ewftools",
        "label": "无 sudo 下载便携 ewf-tools",
        "description": "apt 或 sudo 不可用时，用 wget/curl 将用户确认的 ewf-tools 包下载到临时缓存并解压使用。",
        "cache_dir": str(cache),
        "requires_sudo": False,
        "manual_command": ["sh", "-lc", " && ".join(commands)],
    }


def attach_portable_ewftools_choice(entry: dict[str, Any], inspect_result: dict[str, Any], privilege: dict[str, Any]) -> None:
    apt_available = result_tool_available(inspect_result, "apt-get")
    if apt_available and privilege.get("can_run_privileged"):
        return
    choices = list(entry.get("user_choices") or [])
    if not any(choice.get("id") == "download_portable_ewftools" for choice in choices):
        choices.append(portable_ewftools_choice(inspect_result))
    entry["user_choices"] = choices


def fuse_usable_for_ewfmount(inspect_result: dict[str, Any]) -> tuple[bool, str | None]:
    fuse = (inspect_result.get("preflight") or {}).get("fuse") or {}
    if "usable" in fuse:
        return bool(fuse.get("usable")), fuse.get("reason")
    if fuse.get("dev_fuse") and fuse.get("fusermount"):
        return True, None
    return False, fuse.get("reason") or "FUSE is unavailable or not writable by current user"


def plan_mounts(
    inspect_result: dict[str, Any],
    selected_mount_root: str,
    privilege: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    mounts: list[dict[str, Any]] = []
    privilege = privilege or build_privilege_context()
    evidence = inspect_result.get("evidence_file") or {}
    image_path = evidence.get("path")
    format_kind = (inspect_result.get("format") or {}).get("kind") or evidence.get("detected_format")
    partitions = (inspect_result.get("partitions") or {}).get("items") or []
    root = Path(selected_mount_root)

    if format_kind == "mounted-tree":
        mounts.append(
            {
                "partition_id": "mounted-tree",
                "mount_path": image_path,
                "filesystem": "existing",
                "options": ["ro-assumed"],
                "readonly": True,
                "success": True,
                "cleanup_command": None,
            }
        )
        return commands, mounts

    if format_kind == "E01":
        fuse_usable, fuse_reason = fuse_usable_for_ewfmount(inspect_result)
        ewfexport_available = ((inspect_result.get("tools") or {}).get("ewfexport") or {}).get("available")
        missing_tools = missing_ewftools(inspect_result)
        if fuse_usable and missing_tools:
            commands.append(
                command_entry(
                    "dependency",
                    ["apt-get", "install", "-y", "ewf-tools"],
                    f"install ewf-tools before E01 mounting; missing: {', '.join(missing_tools)}",
                    requires_privilege=True,
                    privilege=privilege,
                    blocked=True,
                    block_reason=f"ewf-tools required for E01 handling; missing: {', '.join(missing_tools)}",
                    requires_user_confirmation=True,
                )
            )
            attach_portable_ewftools_choice(commands[-1], inspect_result, privilege)
            return commands, mounts
        if not fuse_usable:
            if missing_tools and not ewfexport_available:
                commands.append(
                    command_entry(
                        "dependency",
                        ["apt-get", "install", "-y", "ewf-tools"],
                        f"install ewf-tools before E01 fallback; missing: {', '.join(missing_tools)}",
                        requires_privilege=True,
                        privilege=privilege,
                        blocked=True,
                        block_reason=(
                            f"ewf-tools required for E01 handling; missing: {', '.join(missing_tools)}; "
                            f"FUSE also unavailable: {fuse_reason}"
                        ),
                        requires_user_confirmation=True,
                    )
                )
                attach_portable_ewftools_choice(commands[-1], inspect_result, privilege)
                return commands, mounts
            export_path = str(root / "ewf-export.raw")
            ewf_dir = str(root / "ewf")
            ewfmount_command = ["ewfmount", str(image_path), ewf_dir]
            export_command = ["ewfexport", "-t", export_path, str(image_path)]
            if ewfexport_available:
                commands.append(
                    command_entry(
                        "expose-image",
                        export_command,
                        "export E01 to raw because ewfmount/FUSE is unavailable",
                        blocked=True,
                        block_reason=f"{fuse_reason}; choose FUSE privilege retry or raw export fallback",
                        requires_user_confirmation=True,
                    )
                )
                commands[-1]["user_choices"] = fuse_user_choices(ewfmount_command, export_command)
            else:
                commands.append(
                    {
                        "stage": "expose-image",
                        "command": [],
                        "description": "cannot expose E01 because FUSE is unavailable and ewfexport is missing",
                        "blocked": True,
                        "block_reason": fuse_reason or "FUSE unavailable and ewfexport missing",
                        "user_choices": [
                            {
                                "id": "retry_fuse_with_sudo",
                                "label": "提权或修复 FUSE 后重试",
                                "description": "在可信 WSL 终端检查 /dev/fuse 权限后再重试 ewfmount。",
                                "manual_command": ["sudo"] + ewfmount_command,
                            }
                        ],
                    }
                )
            return commands, mounts
        ewf_dir = str(root / "ewf")
        commands.append(
            command_entry(
                "expose-image",
                ["mkdir", "-p", ewf_dir],
                "create EWF expose directory",
                requires_privilege=str(Path(ewf_dir)).startswith("/mnt/"),
                privilege=privilege,
            )
        )
        commands.append(
            {
                "stage": "expose-image",
                "command": ["ewfmount", str(image_path), ewf_dir],
                "description": "expose E01 as read-only raw view when FUSE works",
            }
        )
        image_path = str(Path(ewf_dir) / "ewf1")

    mount_candidates = [p for p in partitions if p.get("mount_candidate", True)]
    if not mount_candidates and image_path:
        mount_path = str(root / "whole-image")
        options = ["ro", "loop"]
        commands.append(
            command_entry(
                "mount-read-only",
                ["mount", "-o", ",".join(options), str(image_path), mount_path],
                "mount whole image read-only when no partition table is available",
                requires_privilege=True,
                privilege=privilege,
            )
        )
        blocked = bool(commands[-1].get("blocked"))
        mounts.append(
            {
                "partition_id": "whole-image",
                "mount_path": mount_path,
                "filesystem": "unknown",
                "options": options,
                "readonly": True,
                "success": False if blocked else None,
                "blocked": blocked,
                "error": commands[-1].get("block_reason") if blocked else None,
                "cleanup_command": f"umount {mount_path}",
            }
        )
        return commands, mounts

    for part in mount_candidates:
        number = part.get("number") or len(mounts) + 1
        mount_path = str(root / f"p{number}")
        options = mount_options_for_fs(part.get("filesystem"))
        if part.get("start_offset") is not None:
            options = options + ["loop", f"offset={part['start_offset']}"]
        commands.append(
            command_entry(
                "mount-read-only",
                ["mount", "-o", ",".join(options), str(image_path), mount_path],
                f"mount partition {number} read-only",
                requires_privilege=True,
                privilege=privilege,
            )
        )
        blocked = bool(commands[-1].get("blocked"))
        mounts.append(
            {
                "partition_id": f"p{number}",
                "mount_path": mount_path,
                "filesystem": part.get("filesystem") or "unknown",
                "options": options,
                "readonly": True,
                "success": False if blocked else None,
                "blocked": blocked,
                "error": commands[-1].get("block_reason") if blocked else None,
                "cleanup_command": f"umount {mount_path}",
                "source_partition": part,
            }
        )
    return commands, mounts


def execute_plan(commands: list[dict[str, Any]], mounts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    for mount in mounts:
        if mount.get("blocked"):
            continue
        mount_path = mount.get("mount_path")
        if mount_path and mount.get("success") is None:
            try:
                Path(mount_path).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                mkdir_cmd = sudo_prefix() + ["mkdir", "-p", str(mount_path)]
                if mkdir_cmd and mkdir_cmd[0] == "sudo":
                    mkdir_result = run_command(mkdir_cmd, timeout=30)
                    if mkdir_result["returncode"] != 0:
                        mount["success"] = False
                        mount["error"] = mkdir_result["stderr"] or mkdir_result["stdout"] or str(exc)
                else:
                    mount["success"] = False
                    mount["error"] = str(exc)
    for command in commands:
        if command.get("blocked"):
            command["result"] = {"returncode": None, "stderr": command.get("block_reason"), "stdout": ""}
            continue
        args = command.get("command") or []
        if not args:
            continue
        result = run_command([str(item) for item in args], timeout=120)
        command["result"] = result
        if command.get("stage") == "mount-read-only":
            target = args[-1] if args else ""
            for mount in mounts:
                if mount.get("mount_path") == target:
                    mount["success"] = result["returncode"] == 0
                    if result["returncode"] != 0:
                        mount["error"] = result["stderr"] or result["stdout"]
    return commands, mounts


def build_run_meta(
    case_id: str,
    inspect_result: dict[str, Any],
    output_dir: Path,
    mount_root: Path,
    mounts: list[dict[str, Any]],
    hash_policy: dict[str, Any],
    output_files: dict[str, str],
) -> dict[str, Any]:
    evidence = inspect_result.get("evidence_file") or {}
    active = [item for item in mounts if item.get("success") is True]
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "last_completed_stage": "mount-read-only" if active else "preflight",
        "stage_status": {
            "preflight": "completed",
            "identify": "completed",
            "hash-decision": "completed",
            "mount-read-only": "completed" if active else "planned",
        },
        "resume_supported": True,
        "cleanup_commands": [item["cleanup_command"] for item in active if item.get("cleanup_command")],
        "loop_devices": [],
        "ewf_mounts": [],
        "mounts": [{**item, "active": item.get("success") is True} for item in mounts],
        "selected_hash_policy": hash_policy,
        "pending_hash_policy": hash_policy if hash_policy.get("mode") == "later" else None,
        "evidence": {
            "path": evidence.get("path"),
            "size": evidence.get("size"),
            "mtime": evidence.get("mtime"),
            "detected_format": evidence.get("detected_format"),
        },
        "output_dir_abs": str(output_dir.expanduser().resolve()),
        "mount_root_abs": str(mount_root.expanduser().resolve()),
        "output_files": output_files,
    }


def write_json(path: Path, data: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(path)


def loop_probe_skipped(reason: str) -> dict[str, Any]:
    return {
        "loop_attach": "unknown",
        "losetup_partition_scan": "unknown",
        "known_good_fixture": None,
        "reason": reason,
    }


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
    parser = argparse.ArgumentParser(description="Prepare or run read-only Linux evidence mount commands.")
    parser.add_argument("path", nargs="?", help="Evidence image path")
    parser.add_argument("--json", action="store_true", help="Write JSON to stdout (default behavior; flag kept for compatibility)")
    parser.add_argument("--output-dir", default="output/linux-loader", help="Output directory for artifacts")
    parser.add_argument("--case-id", default=None, help="Stable case id")
    parser.add_argument("--summary-limit", type=int, default=50, help="Maximum rows per model-facing category")
    parser.add_argument("--hash", default="none", help="none, later, md5, sha1, sha256, or comma-separated algorithms")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without mounting")
    parser.add_argument("--inspect-json", help="Reuse inspection result")
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume from a prior inspection: load it from --inspect-json or <output-dir>/<case-id>/inspect.json, "
            "re-validate evidence (size mismatch is fatal; mtime drift only warns), then re-plan mounts without re-inspecting"
        ),
    )
    parser.add_argument(
        "--triage-level",
        choices=["full", "fast"],
        default="full",
        help=(
            "full runs every triage probe; fast skips deep probes not needed for mount planning "
            "(os profile, panel scan, Docker metadata walk) and the privileged loop probe"
        ),
    )
    parser.add_argument("--mount-root", default=DEFAULT_MOUNT_ROOT, help="Preferred mount root")
    parser.add_argument("--goal", action="append", default=[], help="Focused analysis goal used only for reference routing")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.path and not args.resume and not args.inspect_json:
        parser.print_help()
        return 0

    inspect_result = load_inspection(args)
    if any(error.get("fatal") for error in inspect_result.get("errors") or []):
        print_json(inspect_result)
        return 1

    resume_report = inspect_result.get("resume")
    if args.resume and isinstance(inspect_result.get("preflight"), dict):
        inspect_result["preflight"]["resume_state"] = "validated" if (resume_report or {}).get("can_resume") else "blocked"

    case_id = inspect_result.get("case_id") or inspect_helpers.safe_case_id(Path(args.path or "case"), args.case_id)
    output_dir = Path(args.output_dir).expanduser().resolve() / case_id
    selected = select_mount_root(Path(args.mount_root) / case_id, case_id)
    selected_mount_root = selected["selected"]
    privilege = build_privilege_context()
    commands, mounts = plan_mounts(inspect_result, selected_mount_root, privilege=privilege)

    if args.dry_run:
        loop_probe = loop_probe_skipped("unknown (not probed in dry-run)")
    elif args.triage_level == "fast":
        loop_probe = loop_probe_skipped("skipped (triage-level fast)")
    else:
        loop_probe = probe_loop_support(privilege)
    hash_policy = inspect_helpers.parse_hash_policy(args.hash)
    if not args.dry_run:
        commands, mounts = execute_plan(commands, mounts)

    output_files: dict[str, str] = {}
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "dry_run": args.dry_run,
        "triage_level": args.triage_level,
        "resume": resume_report,
        "evidence_file": inspect_result.get("evidence_file"),
        "hashes": inspect_result.get("hashes"),
        "case_paths": {
            "output_dir_abs": str(output_dir),
            "requested_mount_root": selected["requested"],
            "selected_mount_root": selected_mount_root,
            "mount_root_conflict": selected["conflict"],
            "alternate_path_reason": selected["alternate_reason"],
        },
        "tools": inspect_result.get("tools") or {},
        "preflight": {**(inspect_result.get("preflight") or {}), **loop_probe, "privilege": privilege},
        "format": inspect_result.get("format") or {},
        "ewf": inspect_result.get("ewf") or {},
        "partitions": inspect_result.get("partitions") or {"items": [], "errors": []},
        "planned_commands": commands,
        "mounts": mounts,
        "image_role": inspect_result.get("image_role"),
        "os_profile": inspect_result.get("os_profile") or {},
        "services": inspect_result.get("services") or {},
        "paths": inspect_result.get("paths") or {},
        "panels": inspect_result.get("panels") or {},
        "docker": inspect_result.get("docker") or {},
        "routes": inspect_result.get("routes") or {"recommended_references": [], "suggested_next_steps": []},
        "errors": [
            {"fatal": False, "message": cmd.get("block_reason"), "stage": cmd.get("stage")}
            for cmd in commands
            if cmd.get("blocked") and cmd.get("block_reason")
        ],
    }
    output_files["mount_json"] = str(output_dir / "mount.json")
    output_files["inspect_json"] = write_json(output_dir / "inspect.json", inspect_result)
    run_meta = build_run_meta(case_id, inspect_result, output_dir, Path(selected_mount_root), mounts, hash_policy, output_files)
    output_files["run_meta_json"] = write_json(output_dir / "run-meta.json", run_meta)
    result["run_meta"] = run_meta
    result["output_files"] = output_files
    write_json(output_dir / "mount.json", result)

    print_json(result)
    if args.dry_run:
        return 0
    if any(cmd.get("blocked") for cmd in commands):
        return 1
    return 1 if any(item.get("success") is False for item in mounts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
