#!/usr/bin/env python3
"""Read-only host preflight and plan generator for the utm-forensic-cli skill.

This helper intentionally does not start VMs, mount evidence, copy images, or
execute guest commands. It collects deterministic host facts and emits a
bounded plan for the agent to review before performing the workflow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "1.0"
BASE_TOOLS = (
    "utmctl",
    "img_stat",
    "mmls",
    "fsstat",
    "fls",
    "icat",
    "istat",
    "tsk_recover",
    "ssh",
    "scp",
    "shasum",
    "file",
    "python3",
)
EWF_TOOLS = ("ewfinfo", "ewfverify", "ewfmount")
COMMAND_TIMEOUT = 8.0
IMAGE_COMMAND_TIMEOUT = 120.0


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_case_id(path: Path) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", path.stem).strip(".-")
    return value[:80] or "case"


def jsonable_path(path: Path) -> str:
    return str(path.expanduser().resolve())


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    omitted = len(text) - limit
    return text[:limit] + f"\n...[truncated {omitted} chars]"


def run_command(argv: Iterable[str], timeout: float) -> dict[str, Any]:
    command = [str(item) for item in argv]
    started = time.monotonic()
    result: dict[str, Any] = {
        "argv": command,
        "started_at_utc": now_utc(),
        "timeout_seconds": timeout,
    }
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        result.update(
            {
                "returncode": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "timed_out": False,
            }
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        result.update(
            {
                "returncode": None,
                "stdout": stdout,
                "stderr": stderr,
                "timed_out": True,
                "error": "timeout",
            }
        )
    except OSError as exc:
        result.update(
            {
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 1)
    return result


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="replace")


def digest_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        while True:
            block = handle.read(8 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def segment_candidates(path: Path) -> list[str]:
    """Return sibling EWF segments without assuming they all exist."""
    match = re.match(r"^(?P<base>.*)\.(?P<prefix>e|ex)(?P<number>\d{2})$", path.name, re.I)
    if not match:
        return [jsonable_path(path)]
    prefix = match.group("prefix")
    base = match.group("base")
    candidates: list[tuple[int, Path]] = []
    for sibling in path.parent.iterdir():
        sibling_match = re.match(
            rf"^{re.escape(base)}\.{re.escape(prefix)}(?P<number>\d{{2}})$",
            sibling.name,
            re.I,
        )
        if sibling_match and sibling.is_file():
            candidates.append((int(sibling_match.group("number")), sibling))
    candidates.sort(key=lambda item: item[0])
    return [jsonable_path(item[1]) for item in candidates] or [jsonable_path(path)]


def tool_inventory() -> dict[str, Any]:
    inventory: dict[str, Any] = {}
    for tool in (*BASE_TOOLS, *EWF_TOOLS):
        resolved = shutil.which(tool)
        entry: dict[str, Any] = {"present": bool(resolved), "path": resolved}
        if resolved:
            probe = run_command([resolved, "-V"], COMMAND_TIMEOUT)
            entry["version_probe"] = {
                "returncode": probe.get("returncode"),
                "timed_out": probe.get("timed_out", False),
                "stdout": truncate(probe.get("stdout", ""), 1200),
                "stderr": truncate(probe.get("stderr", ""), 1200),
            }
        inventory[tool] = entry
    return inventory


def help_probe(utmctl: str) -> dict[str, Any]:
    top = run_command([utmctl, "--help"], COMMAND_TIMEOUT)
    text = (top.get("stdout", "") + "\n" + top.get("stderr", "")).strip()
    subcommands = [
        name
        for name in ("list", "status", "start", "stop", "exec", "file")
        if re.search(rf"\b{name}\b", text)
    ]
    return {
        "available": top.get("returncode") == 0 and not top.get("timed_out", False),
        "subcommands_seen": subcommands,
        "help": truncate(text, 6000),
        "probe": {
            "returncode": top.get("returncode"),
            "timed_out": top.get("timed_out", False),
            "duration_ms": top.get("duration_ms"),
        },
    }


def image_probe(path: Path, output_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": jsonable_path(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
        "readable": os.access(path, os.R_OK),
        "resolved_segments": segment_candidates(path),
    }
    if path.exists():
        stat = path.stat()
        result.update(
            {
                "size_bytes": stat.st_size,
                "mode": oct(stat.st_mode & 0o7777),
                "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
    file_tool = shutil.which("file")
    if file_tool and path.exists():
        probe = run_command([file_tool, "--brief", str(path)], COMMAND_TIMEOUT)
        result["file"] = {
            "returncode": probe.get("returncode"),
            "text": truncate((probe.get("stdout", "") + probe.get("stderr", "")).strip(), args.summary_limit),
        }
    result["detected_kind"] = detect_kind(path, result.get("file", {}).get("text", ""))
    if args.hash != "none" and path.is_file():
        try:
            result[args.hash] = digest_file(path, args.hash)
        except OSError as exc:
            result["hash_error"] = f"{type(exc).__name__}: {exc}"
    if args.inspect_image and path.is_file():
        raw_dir = output_dir / "raw"
        for command_name, filename in (("img_stat", "host-img-stat.txt"), ("mmls", "host-mmls.txt")):
            tool = shutil.which(command_name)
            if not tool:
                result.setdefault("image_inspection", {})[command_name] = {"missing": True}
                continue
            probe = run_command([tool, str(path)], args.image_timeout)
            raw = (probe.get("stdout", "") or "") + (probe.get("stderr", "") or "")
            write_text(raw_dir / filename, raw)
            result.setdefault("image_inspection", {})[command_name] = {
                "returncode": probe.get("returncode"),
                "timed_out": probe.get("timed_out", False),
                "duration_ms": probe.get("duration_ms"),
                "artifact": jsonable_path(raw_dir / filename),
                "summary": truncate(raw, args.summary_limit),
            }
    return result


def detect_kind(path: Path, file_text: str) -> str:
    text = file_text.lower()
    suffix = path.suffix.lower()
    if suffix in {".e01", ".ex01", ".l01", ".lx01"} or "expert witness" in text or "ewf" in text:
        return "ewf"
    if "filesystem" in text or "disk image" in text or suffix in {".dd", ".raw", ".img", ".dmg"}:
        return "disk-or-raw"
    return "unknown"


def vm_probe(utmctl: str, vm: str | None, list_vms: bool, args: argparse.Namespace) -> dict[str, Any]:
    result: dict[str, Any] = {"binary": utmctl, "help": help_probe(utmctl)}

    def _tcc_flag(raw: str) -> bool:
        # Apple Events denial: OSStatus error -1743 (utmctl prints it and may
        # still emit an empty table header, which must not be read as "no VMs").
        return "-1743" in raw

    if list_vms:
        probe = run_command([utmctl, "list"], args.timeout)
        raw = (probe.get("stdout", "") or "") + (probe.get("stderr", "") or "")
        result["list"] = {
            "returncode": probe.get("returncode"),
            "timed_out": probe.get("timed_out", False),
            "duration_ms": probe.get("duration_ms"),
            "tcc_blocked": _tcc_flag(raw),
            "summary": truncate(raw, args.summary_limit),
        }
        if _tcc_flag(raw):
            result["list"]["note"] = (
                "utmctl is blocked by TCC (OSStatus -1743); an empty table here "
                "does NOT mean no VMs exist. Switch to the AppleScript channel: "
                "osascript -e 'tell application id \"com.utmapp.UTM\" to get name "
                "of every virtual machine' (see command-matrix.md)."
            )
    if vm:
        probe = run_command([utmctl, "status", "--hide", vm], args.timeout)
        raw = (probe.get("stdout", "") or "") + (probe.get("stderr", "") or "")
        result["status"] = {
            "identifier": vm,
            "returncode": probe.get("returncode"),
            "timed_out": probe.get("timed_out", False),
            "duration_ms": probe.get("duration_ms"),
            "tcc_blocked": _tcc_flag(raw),
            "summary": truncate(raw, args.summary_limit),
        }
    return result


def output_dir_for(args: argparse.Namespace, evidence: Path, suffix: str) -> Path:
    if args.output_dir:
        path = Path(args.output_dir).expanduser().resolve()
    else:
        path = Path.cwd().resolve() / "output" / f"{safe_case_id(evidence)}-{suffix}"
    try:
        common = os.path.commonpath((str(evidence), str(path)))
    except ValueError:
        common = ""
    if common == str(evidence):
        raise ValueError("output directory must be outside the evidence path")
    path.mkdir(parents=True, exist_ok=True)
    return path


def preflight(args: argparse.Namespace) -> dict[str, Any]:
    evidence = Path(args.evidence).expanduser().resolve()
    output_dir = output_dir_for(args, evidence, "preflight")
    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": "utm-forensic-cli/forensicctl",
        "generated_at_utc": now_utc(),
        "mode": "preflight",
        "output_dir": jsonable_path(output_dir),
        "evidence": image_probe(evidence, output_dir, args),
        "host_tools": tool_inventory(),
        "next_steps": [],
    }
    utmctl = shutil.which("utmctl")
    if utmctl:
        result["utm"] = vm_probe(utmctl, args.vm, args.list_vms, args)
    else:
        result["utm"] = {"binary": None, "help": {"available": False}}
    missing = [name for name, info in result["host_tools"].items() if not info["present"]]
    if missing:
        result["next_steps"].append({"action": "request-install-or-configure", "missing_tools": missing})
    if not evidence.exists() or not evidence.is_file() or not os.access(evidence, os.R_OK):
        result["next_steps"].append({"action": "stop", "reason": "evidence is missing, not a regular file, or unreadable"})
    elif result["evidence"]["detected_kind"] == "unknown":
        result["next_steps"].append({"action": "review", "reason": "image type is unknown; do not assume EWF or raw"})
    else:
        result["next_steps"].append({"action": "continue", "reason": "review preflight, choose transport, then start VM explicitly"})
    write_text(output_dir / "preflight.json", json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def plan(args: argparse.Namespace) -> dict[str, Any]:
    evidence = Path(args.evidence).expanduser().resolve()
    output_dir = output_dir_for(args, evidence, "plan")
    guest_evidence = args.guest_evidence or f"/evidence/{evidence.name}"
    guest_root = args.guest_output or "/case"
    quote = __import__("shlex").quote
    transport = args.transport
    start = f"utmctl start --hide {'--disposable ' if args.disposable else ''}{quote(args.vm)}"
    exec_cmd = f"utmctl exec --hide {quote(args.vm)} --cmd sh -lc <guest-command>"
    if transport == "ssh":
        start = f"utmctl start --hide {'--disposable ' if args.disposable else ''}{quote(args.vm)}"
        exec_cmd = f"ssh <ssh-target> 'sh -lc <guest-command>'"
    steps = [
        {"id": "preflight", "plane": "host", "command": f"python3 scripts/forensicctl.py preflight {quote(jsonable_path(evidence))} --hash sha256 --inspect-image --output-dir {quote(jsonable_path(output_dir))} --json"},
        {"id": "start-vm", "plane": "host", "command": start},
        {"id": "health-check", "plane": "guest", "command": exec_cmd.replace("<guest-command>", "'printf ready; id; uname -a'"), "transport": transport},
        {"id": "stage-evidence", "plane": "host-and-guest", "command": "copy or verify a read-only shared path; compare host and guest hashes", "guest_path": guest_evidence},
        {"id": "ewf", "plane": "guest", "command": f"ewfinfo {quote(guest_evidence)}; ewfverify {quote(guest_evidence)}; ewfmount {quote(guest_evidence)} /mnt/ewf", "transport": transport},
        {"id": "partitions", "plane": "guest", "command": "mmls <RAW>; record start sector and sector units", "transport": transport},
        {"id": "filesystem", "plane": "guest", "command": "fsstat -o <START_SECTOR> <RAW>; fls -o <START_SECTOR> -p <RAW>", "transport": transport},
        {"id": "bounded-triage", "plane": "guest", "command": f"fls -r -o <START_SECTOR> -p <RAW> > {guest_root}/raw/fls-recursive.txt; filter targeted paths", "transport": transport},
        {"id": "report", "plane": "host", "command": f"write manifest, artifact index, findings and report under {jsonable_path(output_dir)}"},
        {"id": "teardown", "plane": "host-and-guest", "command": f"unmount/FUSE cleanup, then utmctl stop --hide --request {quote(args.vm)}"},
    ]
    result = {
        "schema_version": SCHEMA_VERSION,
        "tool": "utm-forensic-cli/forensicctl",
        "generated_at_utc": now_utc(),
        "mode": "plan",
        "evidence": jsonable_path(evidence),
        "output_dir": jsonable_path(output_dir),
        "vm": args.vm,
        "transport": transport,
        "disposable": args.disposable,
        "guest_evidence": guest_evidence,
        "guest_output": guest_root,
        "executes": False,
        "steps": steps,
        "review_gate": "Review this plan and preflight before any VM start, evidence copy, or mount.",
    }
    write_text(output_dir / "plan.json", json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def emit(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"mode: {result.get('mode')}")
    print(f"output_dir: {result.get('output_dir')}")
    if result.get("mode") == "preflight":
        evidence = result.get("evidence", {})
        print(f"evidence: {evidence.get('path')} ({evidence.get('detected_kind')})")
        missing = [name for name, info in result.get("host_tools", {}).items() if not info.get("present")]
        print("missing_tools: " + (", ".join(missing) if missing else "none"))
        print("review: " + "; ".join(item.get("reason", item.get("action", "")) for item in result.get("next_steps", [])))
    else:
        print(f"vm: {result.get('vm')}")
        print(f"transport: {result.get('transport')}")
        print(f"steps: {len(result.get('steps', []))}; executes: {result.get('executes')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="forensicctl.py",
        description="Read-only UTM forensic preflight and plan generator; it never starts VMs or mounts evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    pre = subparsers.add_parser("preflight", help="Inspect host tools, evidence metadata, and optional UTM status.")
    pre.add_argument("evidence", help="Path to an E01/Ex01/raw image.")
    pre.add_argument("--hash", choices=("none", "sha256"), default="none", help="Hash the input file; default is none.")
    pre.add_argument("--inspect-image", action="store_true", help="Run img_stat and mmls with bounded timeouts and save raw output.")
    pre.add_argument("--output-dir", help="Absolute or relative case output directory; never the evidence directory.")
    pre.add_argument("--vm", help="Complete UTM VM name or UUID for a bounded status probe.")
    pre.add_argument("--list-vms", action="store_true", help="Run a bounded utmctl list probe.")
    pre.add_argument("--timeout", type=float, default=COMMAND_TIMEOUT, help="UTM/help command timeout in seconds.")
    pre.add_argument("--image-timeout", type=float, default=IMAGE_COMMAND_TIMEOUT, help="Image inspection timeout in seconds.")
    pre.add_argument("--summary-limit", type=int, default=4000, help="Maximum characters kept per command summary.")
    pre.add_argument("--json", action="store_true", help="Print compact machine-readable JSON.")
    pre.set_defaults(handler=preflight)

    pln = subparsers.add_parser("plan", help="Create a non-executing UTM forensic plan.")
    pln.add_argument("evidence", help="Path to an E01/Ex01/raw image.")
    pln.add_argument("--vm", required=True, help="Complete UTM VM name or UUID.")
    pln.add_argument("--transport", choices=("guest-agent", "ssh", "shared-readonly"), default="guest-agent")
    pln.add_argument("--guest-evidence", help="Guest-side evidence path.")
    pln.add_argument("--guest-output", help="Guest-side case output root.")
    pln.add_argument("--output-dir", help="Absolute or relative case output directory.")
    pln.add_argument("--disposable", action="store_true", help="Plan a disposable VM start.")
    pln.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    pln.set_defaults(handler=plan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (OSError, ValueError) as exc:
        print(f"forensicctl: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    emit(result, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
