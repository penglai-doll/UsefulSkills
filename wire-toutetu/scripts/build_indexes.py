#!/usr/bin/env python3
"""Build deterministic human-readable indexes from the plugin registry."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from wiretoutetu_core.registry import load_registry


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "scripts" / "registry.yaml"
OUTPUT_PATH = ROOT / "scripts" / "index.md"
REFERENCE_REGISTRY_PATH = ROOT / "references" / "registry.yaml"


def render_scripts_index(registry: Iterable[dict[str, Any]]) -> str:
    lines = [
        "# WireToutetu Script Index",
        "",
        "此文件由 `build_indexes.py` 从 `registry.yaml` 确定性生成。",
        "",
        "| Plugin | Stage | Support | Signals | Knowledge |",
        "|---|---|---|---|---|",
    ]
    for item in sorted(registry, key=lambda row: row["plugin_id"]):
        signals = ", ".join(f"`{value}`" for value in item["trigger_signals"])
        knowledge = ", ".join(f"`{value}`" for value in item["knowledge_ids"])
        lines.append(
            f"| `{item['plugin_id']}` | {item['stage']} | {item['support_status']} | {signals} | {knowledge} |"
        )
    return "\n".join(lines) + "\n"


def render_reference_indexes(registry: Iterable[dict[str, Any]]) -> dict[Path, str]:
    rows = sorted(registry, key=lambda item: (item["domain"], item["knowledge_id"]))
    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in rows:
        by_domain[item["domain"]].append(item)
    outputs: dict[Path, str] = {}
    root_lines = [
        "# WireToutetu Knowledge Index",
        "",
        "先依据 CLI `routes.recommended_references` 读取命中的叶子；不要一次加载整个知识库。",
        "",
        "| Domain | Leaves | Index |",
        "|---|---:|---|",
    ]
    for domain in sorted(by_domain):
        root_lines.append(f"| `{domain}` | {len(by_domain[domain])} | [{domain}/index.md]({domain}/index.md) |")
        lines = [
            f"# {domain} Knowledge Index",
            "",
            "| Knowledge ID | Support | Signals | Read when |",
            "|---|---|---|---|",
        ]
        for item in by_domain[domain]:
            signals = ", ".join(f"`{signal}`" for signal in item["signals"])
            lines.append(
                f"| [`{item['knowledge_id']}`]({item['topic']}.md) | {item['support_status']} | {signals} | {item['read_when']} |"
            )
        outputs[ROOT / "references" / domain / "index.md"] = "\n".join(lines) + "\n"
    root_lines.extend(["", "## Signal lookup", "", "| Signal | Knowledge IDs |", "|---|---|"])
    by_signal: dict[str, list[str]] = defaultdict(list)
    for item in rows:
        for signal in item["signals"]:
            by_signal[signal].append(item["knowledge_id"])
    for signal in sorted(by_signal):
        ids = ", ".join(f"`{value}`" for value in sorted(by_signal[signal]))
        root_lines.append(f"| `{signal}` | {ids} |")
    outputs[ROOT / "references" / "index.md"] = "\n".join(root_lines) + "\n"
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated index differs")
    args = parser.parse_args()
    outputs = {OUTPUT_PATH: render_scripts_index(load_registry(REGISTRY_PATH))}
    references = json.loads(REFERENCE_REGISTRY_PATH.read_text(encoding="utf-8"))
    outputs.update(render_reference_indexes(references))
    if args.check:
        drifted = [path for path, rendered in outputs.items() if not path.is_file() or path.read_text(encoding="utf-8") != rendered]
        if drifted:
            for path in drifted:
                print(f"index drift: {path}")
            return 1
        print("indexes are current")
        return 0
    for path, rendered in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
