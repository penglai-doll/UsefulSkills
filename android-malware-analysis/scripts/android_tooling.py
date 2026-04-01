#!/usr/bin/env python3
from __future__ import annotations

import platform
import shutil

TOOL_SPECS = [
    {"name": "java", "label": "Java runtime", "role": "runtime"},
    {"name": "jadx", "label": "jadx", "role": "decompiler"},
    {"name": "apktool", "label": "apktool", "role": "apk decoder"},
    {"name": "apkanalyzer", "label": "apkanalyzer", "role": "manifest analyzer"},
    {"name": "aapt", "label": "aapt", "role": "build tools"},
    {"name": "aapt2", "label": "aapt2", "role": "build tools"},
    {"name": "apksigner", "label": "apksigner", "role": "signing"},
    {"name": "adb", "label": "adb", "role": "device bridge"},
]
FULL_REQUIREMENT_GROUPS = [
    ("runtime", ["java"]),
    ("decompiler", ["jadx"]),
    ("manifest-or-resource-decoder", ["apktool", "apkanalyzer", "aapt", "aapt2"]),
]


def detect_android_tooling() -> dict:
    tools = []
    tool_map = {}
    for spec in TOOL_SPECS:
        path = shutil.which(spec["name"])
        tool = {
            "name": spec["name"],
            "label": spec["label"],
            "role": spec["role"],
            "available": bool(path),
            "path": path,
        }
        tools.append(tool)
        tool_map[spec["name"]] = tool

    missing_groups = []
    available_groups = []
    for group_name, candidates in FULL_REQUIREMENT_GROUPS:
        present = [name for name in candidates if tool_map[name]["available"]]
        if present:
            available_groups.append({"group": group_name, "tools": present})
        else:
            missing_groups.append({"group": group_name, "tools": candidates})

    full_ready = not missing_groups
    best_effort_tools = [tool["name"] for tool in tools if tool["available"]]
    missing_full = [item["group"] for item in missing_groups]
    recommendation = (
        "当前环境已满足完整 APK 分析条件。"
        if full_ready
        else "完整 APK 分析工具不完整。应先询问是否安装缺失工具并重跑，否则以 best-effort 模式继续。"
    )
    question = (
        None
        if full_ready
        else "检测到完整模式缺少 APK 分析工具。要先安装缺失工具并重跑，还是直接以 best-effort 模式继续？"
    )
    return {
        "platform": platform.platform(),
        "tools": tools,
        "tool_map": tool_map,
        "full_ready": full_ready,
        "available_groups": available_groups,
        "missing_groups": missing_groups,
        "missing_full": missing_full,
        "best_effort_tools": best_effort_tools,
        "recommended_mode": "full" if full_ready else "best-effort",
        "recommendation": recommendation,
        "question_for_user": question,
    }


def summarize_tooling(tooling: dict) -> list[str]:
    lines = [
        f"- 平台: `{tooling['platform']}`",
        f"- 推荐模式: `{tooling['recommended_mode']}`",
        f"- 是否满足完整分析: `{str(tooling['full_ready']).lower()}`",
    ]
    for tool in tooling["tools"]:
        state = tool["path"] if tool["available"] else "missing"
        lines.append(f"- {tool['name']}: `{state}`")
    if tooling["missing_groups"]:
        lines.append(f"- 缺失的完整模式能力组: {', '.join(item['group'] for item in tooling['missing_groups'])}")
    return lines
