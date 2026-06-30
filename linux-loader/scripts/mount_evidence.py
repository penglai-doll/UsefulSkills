#!/usr/bin/env python3
"""Read-only mounting helpers for the linux-loader skill."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
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
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
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
        proc = subprocess.run(args, input=input_text, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
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


def probe_loop_support() -> dict[str, Any]:
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
    prefix = sudo_prefix()
    if not prefix and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        result["reason"] = "non-interactive sudo unavailable"
        return result
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


def load_inspection(args: argparse.Namespace) -> dict[str, Any]:
    if args.inspect_json:
        try:
            return json.loads(Path(args.inspect_json).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": f"cannot read inspect-json: {exc}"}]}
    if not args.path:
        return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": "path is required unless --inspect-json is supplied"}]}
    path = Path(args.path)
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "errors": [{"fatal": True, "message": f"path not found: {path}"}]}
    return inspect_helpers.inspect_path(
        path,
        inspect_helpers.parse_hash_policy(args.hash),
        summary_limit=args.summary_limit,
        case_id=args.case_id,
        output_dir=Path(args.output_dir),
        mount_root=args.mount_root,
        goals=args.goal,
    )


def plan_mounts(inspect_result: dict[str, Any], selected_mount_root: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    commands: list[dict[str, Any]] = []
    mounts: list[dict[str, Any]] = []
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
        ewf_dir = str(root / "ewf")
        commands.append(
            {
                "stage": "expose-image",
                "command": ["mkdir", "-p", ewf_dir],
                "description": "create EWF expose directory",
            }
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
            {
                "stage": "mount-read-only",
                "command": sudo_prefix() + ["mount", "-o", ",".join(options), str(image_path), mount_path],
                "description": "mount whole image read-only when no partition table is available",
            }
        )
        mounts.append(
            {
                "partition_id": "whole-image",
                "mount_path": mount_path,
                "filesystem": "unknown",
                "options": options,
                "readonly": True,
                "success": None,
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
            {
                "stage": "mount-read-only",
                "command": sudo_prefix() + ["mount", "-o", ",".join(options), str(image_path), mount_path],
                "description": f"mount partition {number} read-only",
            }
        )
        mounts.append(
            {
                "partition_id": f"p{number}",
                "mount_path": mount_path,
                "filesystem": part.get("filesystem") or "unknown",
                "options": options,
                "readonly": True,
                "success": None,
                "cleanup_command": f"umount {mount_path}",
                "source_partition": part,
            }
        )
    return commands, mounts


def execute_plan(commands: list[dict[str, Any]], mounts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    for mount in mounts:
        mount_path = mount.get("mount_path")
        if mount_path and mount.get("success") is None:
            try:
                Path(mount_path).mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                mount["success"] = False
                mount["error"] = str(exc)
    for command in commands:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare or run read-only Linux evidence mount commands.")
    parser.add_argument("path", nargs="?", help="Evidence image path")
    parser.add_argument("--json", action="store_true", help="Write JSON to stdout")
    parser.add_argument("--output-dir", default="output/linux-loader", help="Output directory for artifacts")
    parser.add_argument("--case-id", default=None, help="Stable case id")
    parser.add_argument("--summary-limit", type=int, default=50, help="Maximum rows per model-facing category")
    parser.add_argument("--hash", default="none", help="none, later, md5, sha1, sha256, or comma-separated algorithms")
    parser.add_argument("--dry-run", action="store_true", help="Print planned commands without mounting")
    parser.add_argument("--inspect-json", help="Reuse inspection result")
    parser.add_argument("--resume", action="store_true", help="Resume from run-meta.json")
    parser.add_argument("--triage-level", choices=["full", "fast"], default="full")
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
    if inspect_result.get("errors") and inspect_result["errors"][0].get("fatal"):
        print(json.dumps(inspect_result, ensure_ascii=False, indent=2))
        return 1

    case_id = inspect_result.get("case_id") or inspect_helpers.safe_case_id(Path(args.path or "case"), args.case_id)
    output_dir = Path(args.output_dir).expanduser().resolve() / case_id
    selected = select_mount_root(Path(args.mount_root) / case_id, case_id)
    selected_mount_root = selected["selected"]
    commands, mounts = plan_mounts(inspect_result, selected_mount_root)

    loop_probe = probe_loop_support()
    hash_policy = inspect_helpers.parse_hash_policy(args.hash)
    if not args.dry_run:
        commands, mounts = execute_plan(commands, mounts)

    output_files: dict[str, str] = {}
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "dry_run": args.dry_run,
        "triage_level": args.triage_level,
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
        "preflight": {**(inspect_result.get("preflight") or {}), **loop_probe},
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
        "errors": [],
    }
    output_files["mount_json"] = write_json(output_dir / "mount.json", result)
    output_files["inspect_json"] = write_json(output_dir / "inspect.json", inspect_result)
    run_meta = build_run_meta(case_id, inspect_result, output_dir, Path(selected_mount_root), mounts, hash_policy, output_files)
    output_files["run_meta_json"] = write_json(output_dir / "run-meta.json", run_meta)
    result["run_meta"] = run_meta
    result["output_files"] = output_files
    write_json(output_dir / "mount.json", result)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if any(item.get("success") is False for item in mounts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
