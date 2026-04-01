#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from android_tooling import detect_android_tooling, summarize_tooling


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect Android APK analysis tools and recommend full or best-effort analysis mode.")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown", help="Output format.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    tooling = detect_android_tooling()
    if args.format == "json":
        print(json.dumps(tooling, indent=2, ensure_ascii=False))
        return 0

    lines = ["# Android Tooling Check", ""]
    lines.extend(summarize_tooling(tooling))
    lines.extend(["", f"- Recommendation: {tooling['recommendation']}"])
    if tooling["question_for_user"]:
        lines.append(f"- Ask user: {tooling['question_for_user']}")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
