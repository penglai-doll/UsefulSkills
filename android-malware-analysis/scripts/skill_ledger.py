#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

MAX_ACTIVE_LESSONS = 20
MAX_RECENT_INCIDENTS = 8
MAX_SYMPTOM_LEN = 160
MAX_ACTION_LEN = 160
MAX_AVOID_LEN = 140
MAX_NOTE_LEN = 120


def default_ledger_path() -> Path:
    return Path(__file__).resolve().parents[1] / "skill-ledger.json"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clip(value: str | None, limit: int) -> str:
    text = " ".join((value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def default_ledger() -> dict:
    now = utc_now()
    return {
        "version": 1,
        "scope": "apk-analysis",
        "updated_at": now,
        "total_events": 0,
        "active_lessons": [],
        "compressed_lessons": [],
        "recent_incidents": [],
    }


def load_ledger(path: Path) -> dict:
    if not path.exists():
        return default_ledger()

    loaded = json.loads(path.read_text(encoding="utf-8"))
    ledger = default_ledger()
    ledger.update({key: value for key, value in loaded.items() if key in ledger})
    for key in ("active_lessons", "compressed_lessons", "recent_incidents"):
        ledger[key] = list(loaded.get(key, ledger[key]))
    ledger["total_events"] = int(loaded.get("total_events", 0))
    ledger["updated_at"] = loaded.get("updated_at", ledger["updated_at"])
    ledger["scope"] = loaded.get("scope", "apk-analysis")
    compact_ledger(ledger)
    return ledger


def save_ledger(path: Path, ledger: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def lesson_index(lessons: list[dict], key: str) -> int:
    for index, lesson in enumerate(lessons):
        if lesson.get("key") == key:
            return index
    return -1


def compact_lesson(lesson: dict) -> dict:
    return {
        "key": lesson["key"],
        "preferred_action": clip(lesson.get("preferred_action"), MAX_ACTION_LEN),
        "avoid": clip(lesson.get("avoid"), MAX_AVOID_LEN),
        "stage": lesson.get("stage", ""),
        "count": int(lesson.get("count", 1)),
        "first_seen": lesson.get("first_seen", utc_now()),
        "last_seen": lesson.get("last_seen", utc_now()),
    }


def merge_into_compressed(ledger: dict, lesson: dict) -> None:
    compressed = ledger["compressed_lessons"]
    index = lesson_index(compressed, lesson["key"])
    entry = compact_lesson(lesson)
    if index == -1:
        compressed.append(entry)
        return

    existing = compressed[index]
    existing["count"] = max(existing.get("count", 1), entry["count"])
    existing["last_seen"] = max(existing.get("last_seen", ""), entry["last_seen"])
    if entry["preferred_action"]:
        existing["preferred_action"] = entry["preferred_action"]
    if entry["avoid"]:
        existing["avoid"] = entry["avoid"]
    if entry["stage"]:
        existing["stage"] = entry["stage"]


def compact_ledger(ledger: dict) -> None:
    while len(ledger["active_lessons"]) > MAX_ACTIVE_LESSONS:
        oldest_index = min(
            range(len(ledger["active_lessons"])),
            key=lambda index: ledger["active_lessons"][index].get("last_seen", ""),
        )
        lesson = ledger["active_lessons"].pop(oldest_index)
        merge_into_compressed(ledger, lesson)

    ledger["active_lessons"].sort(key=lambda item: item.get("last_seen", ""), reverse=True)
    ledger["compressed_lessons"].sort(key=lambda item: item.get("last_seen", ""), reverse=True)
    ledger["recent_incidents"] = sorted(
        ledger["recent_incidents"],
        key=lambda item: item.get("at", ""),
        reverse=True,
    )[:MAX_RECENT_INCIDENTS]


def record_problem(
    ledger: dict,
    *,
    key: str,
    symptom: str,
    preferred_action: str,
    avoid: str,
    stage: str = "",
    note: str = "",
) -> dict:
    working = deepcopy(ledger)
    now = utc_now()
    normalized_key = clip(key, 80)
    normalized_symptom = clip(symptom, MAX_SYMPTOM_LEN)
    normalized_action = clip(preferred_action, MAX_ACTION_LEN)
    normalized_avoid = clip(avoid, MAX_AVOID_LEN)
    normalized_stage = clip(stage, 40)
    normalized_note = clip(note or symptom, MAX_NOTE_LEN)

    active_index = lesson_index(working["active_lessons"], normalized_key)
    compressed_index = lesson_index(working["compressed_lessons"], normalized_key)

    if active_index != -1:
        lesson = working["active_lessons"][active_index]
        lesson["count"] = int(lesson.get("count", 1)) + 1
        lesson["last_seen"] = now
        if normalized_action:
            lesson["preferred_action"] = normalized_action
        if normalized_avoid:
            lesson["avoid"] = normalized_avoid
        if normalized_symptom:
            lesson["symptom"] = normalized_symptom
        if normalized_stage:
            lesson["stage"] = normalized_stage
    elif compressed_index != -1:
        archived = working["compressed_lessons"].pop(compressed_index)
        working["active_lessons"].append(
            {
                "key": normalized_key,
                "symptom": normalized_symptom,
                "preferred_action": normalized_action or archived.get("preferred_action", ""),
                "avoid": normalized_avoid or archived.get("avoid", ""),
                "stage": normalized_stage or archived.get("stage", ""),
                "count": int(archived.get("count", 1)) + 1,
                "first_seen": archived.get("first_seen", now),
                "last_seen": now,
            }
        )
    else:
        working["active_lessons"].append(
            {
                "key": normalized_key,
                "symptom": normalized_symptom,
                "preferred_action": normalized_action,
                "avoid": normalized_avoid,
                "stage": normalized_stage,
                "count": 1,
                "first_seen": now,
                "last_seen": now,
            }
        )
        working["recent_incidents"].append(
            {
                "at": now,
                "key": normalized_key,
                "note": normalized_note,
            }
        )

    working["total_events"] = int(working.get("total_events", 0)) + 1
    working["updated_at"] = now
    compact_ledger(working)
    return working


def render_review(ledger: dict, limit: int = 6) -> str:
    lines = [
        "# APK Skill Ledger",
        "",
        f"- Scope: `{ledger['scope']}`",
        f"- Active lessons: `{len(ledger['active_lessons'])}`",
        f"- Compressed lessons: `{len(ledger['compressed_lessons'])}`",
        f"- Total events seen: `{ledger['total_events']}`",
    ]
    if not ledger["active_lessons"]:
        lines.append("- No recorded lessons yet.")
        return "\n".join(lines)

    lines.extend(["", "## Avoid First"])
    for lesson in ledger["active_lessons"][:limit]:
        details = lesson.get("preferred_action") or lesson.get("avoid") or lesson.get("symptom", "")
        lines.append(f"- `{lesson['key']}`: {details}")
    return "\n".join(lines)


def run_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "skill-ledger.json"
        ledger = load_ledger(path)
        ledger = record_problem(
            ledger,
            key="public-domain-false-positive",
            symptom="Public domains drown out real callback findings.",
            preferred_action="Prefer first-party code inference for callback verdicts.",
            avoid="Do not promote public or library URLs into final IOC output.",
            stage="callback",
            note="Synthetic self-test event.",
        )
        for index in range(MAX_ACTIVE_LESSONS + 1):
            ledger = record_problem(
                ledger,
                key=f"synthetic-{index}",
                symptom=f"Symptom {index}",
                preferred_action=f"Action {index}",
                avoid=f"Avoid {index}",
                stage="triage",
                note=f"Incident {index}",
            )
        save_ledger(path, ledger)
        reloaded = load_ledger(path)
        assert len(reloaded["active_lessons"]) <= MAX_ACTIVE_LESSONS
        assert len(reloaded["compressed_lessons"]) >= 1
        print("Skill ledger self-test passed.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Maintain a compact persistent ledger for APK-analysis skill gotchas.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    default_path = str(default_ledger_path())

    review = subparsers.add_parser("review", help="Print a concise ledger summary for APK analysis.")
    review.add_argument("--path", default=default_path, help=f"Path to the ledger JSON file. Defaults to {default_path}.")
    review.add_argument("--limit", type=int, default=6, help="Maximum active lessons to print.")

    record = subparsers.add_parser("record", help="Record a newly discovered APK-analysis problem or fallback.")
    record.add_argument("--path", default=default_path, help=f"Path to the ledger JSON file. Defaults to {default_path}.")
    record.add_argument("--key", required=True, help="Stable problem key, ideally matching references/gotchas.md.")
    record.add_argument("--symptom", required=True, help="Short symptom description.")
    record.add_argument("--preferred-action", required=True, help="Preferred next action when this problem appears.")
    record.add_argument("--avoid", required=True, help="What not to do once this problem is recognized.")
    record.add_argument("--stage", default="", help="Pipeline stage where the problem appears.")
    record.add_argument("--note", default="", help="Optional short incident note for first-seen problems.")

    compact = subparsers.add_parser("compact", help="Re-compact an existing ledger without adding a new event.")
    compact.add_argument("--path", default=default_path, help=f"Path to the ledger JSON file. Defaults to {default_path}.")

    subparsers.add_parser("self-test", help="Run a deterministic smoke test for the ledger logic.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "self-test":
        run_self_test()
        return 0

    path = Path(args.path).expanduser()
    ledger = load_ledger(path)

    if args.command == "review":
        print(render_review(ledger, limit=max(1, args.limit)))
        return 0

    if args.command == "record":
        ledger = record_problem(
            ledger,
            key=args.key,
            symptom=args.symptom,
            preferred_action=args.preferred_action,
            avoid=args.avoid,
            stage=args.stage,
            note=args.note,
        )
        save_ledger(path, ledger)
        print(render_review(ledger))
        return 0

    compact_ledger(ledger)
    save_ledger(path, ledger)
    print(render_review(ledger))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
