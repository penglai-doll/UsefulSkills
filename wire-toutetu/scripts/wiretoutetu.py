#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from wiretoutetu_core.analyzer import analyze_capture
from wiretoutetu_core.case_state import CaseState, sha256_file
from wiretoutetu_core.cleanup import cleanup_case
from wiretoutetu_core.contracts import make_envelope
from wiretoutetu_core.experience import ExperienceStore
from wiretoutetu_core.exporter import export_bundle, export_markdown
from wiretoutetu_core.preflight import run_preflight
from wiretoutetu_core.registry import load_registry, select_plugins


PUBLIC_COMMANDS = (
    "preflight",
    "analyze",
    "query",
    "catalog",
    "export",
    "cleanup",
    "experience",
)


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = JsonArgumentParser(
        prog="wiretoutetu.py",
        description="Offline PCAP and WebShell traffic analysis.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--json", action="store_true")
    preflight.add_argument("--deep-probe", action="store_true")

    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("capture")
    analyze.add_argument("--case-dir")
    analyze.add_argument("--question")
    analyze.add_argument("--sidecar", action="append", default=[])
    analyze.add_argument("--network", choices=("offline", "on"), default="offline")
    analyze.add_argument("--memory-limit-mib", type=int, default=512)

    query = subparsers.add_parser("query")
    query.add_argument("--case-dir", required=True)
    query.add_argument("--view", choices=("summary", "timeline", "protocols", "webshell", "objects", "failures", "evidence", "knowledge"), required=True)
    query.add_argument("--id")
    query.add_argument("--cursor")
    query.add_argument("--limit", type=int, default=50)

    catalog = subparsers.add_parser("catalog")
    group = catalog.add_mutually_exclusive_group()
    group.add_argument("--signal")
    group.add_argument("--protocol")
    group.add_argument("--family")
    catalog.add_argument("--json", action="store_true")

    export = subparsers.add_parser("export")
    export.add_argument("--case-dir", required=True)
    export.add_argument("--format", choices=("markdown", "bundle"), required=True)
    export.add_argument("--output", required=True)

    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--case-dir", required=True)

    experience = subparsers.add_parser("experience")
    experience.add_argument("action", choices=("summarize", "merge", "review", "compact"))
    experience.add_argument("--file", default=str(Path(__file__).resolve().parents[1] / "经验.md"))
    experience.add_argument("--input")
    experience.add_argument("--signal")
    return parser


def _emit(envelope: dict) -> None:
    print(json.dumps(envelope, ensure_ascii=False, indent=2, sort_keys=True))


def _default_case(capture: Path) -> Path:
    digest = sha256_file(capture)[:8]
    return Path.cwd() / "tmp" / "WireToutetu" / f"{capture.stem}-{digest}"


def _run(args: argparse.Namespace) -> tuple[dict, int]:
    if args.command == "preflight":
        result = run_preflight(deep_probe=True)
        return make_envelope(
            status=result["status"], stage="preflight", summary={"platform_route": result["platform_route"], "tools": result["tools"]},
            counts={"available_tools": sum(item.get("status") == "available" for item in result["tools"].values())},
            next_actions=result["next_actions"], completeness="complete",
        ), 0 if result["status"] == "ok" else 2

    if args.command == "catalog":
        registry_path = Path(__file__).with_name("registry.yaml")
        registry = load_registry(registry_path)
        if args.signal:
            plugins = select_plugins(registry, {args.signal})
        elif args.protocol:
            needle = args.protocol.lower()
            plugins = [row for row in registry if row["plugin_id"] == f"proto.{needle}" or needle in row["trigger_signals"]]
        elif args.family:
            needle = args.family.lower()
            plugins = [row for row in registry if row["plugin_id"].startswith(f"webshell.{needle}") or row["plugin_id"].startswith(f"tunnel.{needle}")]
        else:
            plugins = registry
        plugins = sorted(plugins, key=lambda row: row["plugin_id"])
        return make_envelope(status="ok", stage="catalog", summary={"plugins": plugins}, counts={"plugins": len(plugins)}, completeness="complete"), 0

    if args.command == "analyze":
        capture = Path(args.capture).resolve(strict=True)
        case_dir = Path(args.case_dir).resolve() if args.case_dir else _default_case(capture)
        result = analyze_capture(
            capture, case_dir=case_dir, sidecars=args.sidecar, question=args.question,
            network=args.network, memory_limit_mib=args.memory_limit_mib,
        )
        if result["status"] == "ok":
            recent = {
                "case_id": result["state"].root.name,
                "summary": f"完成离线分析：{result['counts'].get('packets', 0)} 包、{result['counts'].get('transactions', 0)} 事务、完整性 {result['completeness']}。",
                "signals": result["routes"].get("selected_plugins", [])[:8],
            }
            experience_path = Path(__file__).resolve().parents[1] / "经验.md"
            try:
                ExperienceStore(experience_path).append_recent(recent)
            except (OSError, ValueError):
                pending = result["state"].root / "experience-pending.json"
                pending.write_text(json.dumps(recent, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                result["state"].register_generated(pending, owner="experience")
        return make_envelope(
            status=result["status"], case_dir=str(result["state"].root), stage="analysis",
            summary=result["summary"], counts=result["counts"], routes=result["routes"],
            next_actions=result["next_actions"], errors=result["errors"], completeness=result["completeness"],
        ), 0 if result["status"] == "ok" else 1

    if args.command == "query":
        state = CaseState.open(args.case_dir)
        collection = args.view
        if args.view == "timeline" and not (state.records_dir / "timeline.jsonl").is_file():
            collection = "events"
        if args.id:
            item = state.find_record(collection, args.id)
            result = {"items": [item] if item is not None else [], "next_cursor": None, "returned_bytes": 0}
            items = result["items"]
            if item is not None:
                result["returned_bytes"] = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
        else:
            result = state.query_records(collection, limit=args.limit, cursor=args.cursor)
            items = result["items"]
        return make_envelope(
            status="ok", case_dir=str(state.root), stage="query",
            summary={"view": args.view, "items": items, "next_cursor": result["next_cursor"], "returned_bytes": result["returned_bytes"]},
            counts={"returned": len(items)}, completeness="complete" if result["next_cursor"] is None else "partial",
            next_actions=["Continue with the returned cursor."] if result["next_cursor"] else [],
        ), 0

    if args.command == "export":
        state = CaseState.open(args.case_dir)
        result = export_markdown(state, args.output) if args.format == "markdown" else export_bundle(state, args.output)
        return make_envelope(status="ok", case_dir=str(state.root), stage="export", summary=result, counts={"files": result.get("files", 1)}, completeness="complete"), 0

    if args.command == "cleanup":
        root = str(Path(args.case_dir).resolve())
        result = cleanup_case(args.case_dir)
        return make_envelope(status="ok", case_dir=root, stage="cleanup", summary=result, counts={"removed_files": len(result["removed_files"])}, completeness="complete"), 0

    if args.command == "experience":
        store = ExperienceStore(args.file)
        if args.action in {"summarize", "merge"}:
            if not args.input:
                raise ValueError("--input JSON file is required")
            data = json.loads(Path(args.input).read_text(encoding="utf-8"))
            if args.action == "summarize":
                store.append_recent(data)
            else:
                store.merge_lesson(data)
            summary = {"updated": str(store.path.resolve())}
        elif args.action == "review":
            if not args.signal:
                raise ValueError("--signal is required")
            summary = {"items": store.review(args.signal)}
        else:
            store.compact()
            summary = {"compacted": str(store.path.resolve()), "bytes": store.path.stat().st_size}
        return make_envelope(status="ok", stage="experience", summary=summary, counts={"items": len(summary.get("items", []))}, completeness="complete"), 0
    raise AssertionError(args.command)


def main() -> int:
    args: argparse.Namespace | None = None
    try:
        args = build_parser().parse_args()
        envelope, code = _run(args)
    except Exception as exc:
        envelope = make_envelope(
            status="error", stage=getattr(args, "command", None) or "arguments",
            summary={"message": str(exc)}, errors=[{"type": type(exc).__name__, "message": str(exc)}],
            completeness="unknown", next_actions=["Inspect the error and retry the same stage."],
        )
        code = 1
    _emit(envelope)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
