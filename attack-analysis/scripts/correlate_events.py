#!/usr/bin/env python3
"""Build conservative cross-log correlation candidates."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from common.cli_utils import configure_stdio


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    # datetime.fromisoformat() only accepts the 'Z' suffix from Python 3.11;
    # normalize it so older runtimes parse UTC timestamps too.
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def cluster_by_time(events: list[dict[str, Any]], key_name: str, strong_window: int, weak_window: int, max_clusters: int) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    dated = [(parse_dt(e.get("timestamp")), e) for e in events]
    # Unknown local times cannot safely be ordered against absolute times.
    # Keep those events in the case, but exclude them from temporal joins.
    dated = [(dt.astimezone(timezone.utc), e) for dt, e in dated if dt is not None and dt.utcoffset() is not None]
    dated.sort(key=lambda pair: pair[0])
    used: set[tuple[str, str]] = set()
    for idx, (dt, event) in enumerate(dated):
        for window, strength in [(strong_window, "strong"), (weak_window, "weak")]:
            group = [event]
            for other_dt, other in dated[idx + 1 :]:
                delta = abs((other_dt - dt).total_seconds())
                if delta <= window:
                    group.append(other)
                elif other_dt > dt and delta > window:
                    break
            if len(group) >= 2:
                ids = tuple(e["event_id"] for e in group)
                dedupe = (key_name, ",".join(ids))
                if dedupe in used:
                    continue
                used.add(dedupe)
                clusters.append(
                    {
                        "basis": [key_name, f"time_window_{window}s"],
                        "events": list(ids),
                        "window_seconds": window,
                        "strength": strength,
                        "status": "candidate",
                        "notes": f"Grouped by {key_name} within {window} seconds.",
                    }
                )
                break
        if len(clusters) >= max_clusters:
            break
    return clusters


def correlate(events: list[dict[str, Any]], strong_window: int = 300, weak_window: int = 1800, max_clusters: int = 200) -> dict[str, Any]:
    if max_clusters < 1 or strong_window < 0 or weak_window < strong_window:
        raise ValueError("require max_clusters > 0 and 0 <= strong_window <= weak_window")
    correlations: list[dict[str, Any]] = []
    by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        ip = event.get("actor_ip_normalized")
        if ip:
            by_ip[ip].append(event)
        user = event.get("account_or_user")
        if user:
            by_user[str(user)].append(event)
        path = event.get("http_path")
        if path:
            by_path[str(path)].append(event)
    for key, group in by_ip.items():
        for corr in cluster_by_time(group, "same_ip", strong_window, weak_window, max_clusters + 1):
            corr["join_value"] = key
            correlations.append(corr)
    for key, group in by_user.items():
        for corr in cluster_by_time(group, "same_account", strong_window, weak_window, max_clusters + 1):
            corr["join_value"] = key
            correlations.append(corr)
    for key, group in by_path.items():
        if len(group) < 2:
            continue
        for corr in cluster_by_time(group, "same_path", strong_window, weak_window, max_clusters + 1):
            corr["join_value"] = key
            correlations.append(corr)
    for idx, corr in enumerate(correlations[:max_clusters], 1):
        corr["correlation_id"] = f"corr-{idx:06d}"
    unresolved = [e.get("event_id") for e in events if (dt := parse_dt(e.get("timestamp"))) is None or dt.utcoffset() is None]
    return {"correlation_count": min(len(correlations), max_clusters), "correlations": correlations[:max_clusters],
            "truncated": len(correlations) > max_clusters, "limit": max_clusters,
            "unresolved_time_event_ids": unresolved,
            "warnings": ["Events with unknown/invalid time zones were excluded from temporal joins."] if unresolved else []}


def main() -> int:
    configure_stdio()
    parser = argparse.ArgumentParser(description="Generate attack-analysis correlation candidates.")
    parser.add_argument("--events", required=True, help="Path to event-candidates.json")
    parser.add_argument("--output-dir", help="Directory for correlation-candidates.json")
    parser.add_argument("--strong-window", type=int, default=300)
    parser.add_argument("--weak-window", type=int, default=1800)
    parser.add_argument("--max-clusters", type=int, default=200)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.max_clusters < 1 or args.strong_window < 0 or args.weak_window < args.strong_window:
        parser.error("require --max-clusters > 0 and 0 <= --strong-window <= --weak-window")

    source = json.loads(Path(args.events).read_text(encoding="utf-8"))
    data = correlate(source.get("events", []), args.strong_window, args.weak_window, args.max_clusters)
    data["case_id"] = source.get("case_id")
    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "correlation-candidates.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json or not args.output_dir:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
