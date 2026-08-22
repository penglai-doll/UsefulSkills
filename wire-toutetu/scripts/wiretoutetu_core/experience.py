"""Small, deduplicated, atomic Markdown experience memory."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import date
from pathlib import Path
from typing import Any


MAX_BYTES = 12 * 1024
MAX_STABLE = 12
MAX_RECENT = 4
MARKER = "wiretoutetu-experience-v1"


def _today() -> str:
    return date.today().isoformat()


class ExperienceStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @staticmethod
    def empty() -> dict[str, Any]:
        return {"schema_version": "1.0", "stable_lessons": [], "recent_rounds": []}

    def load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self.empty()
        text = self.path.read_text(encoding="utf-8")
        match = re.search(rf"<!-- {MARKER}\n(.*?)\n-->", text, re.DOTALL)
        if not match:
            raise ValueError(f"invalid experience file: {self.path}")
        data = json.loads(match.group(1))
        data.setdefault("stable_lessons", [])
        data.setdefault("recent_rounds", [])
        return data

    @staticmethod
    def _render(data: dict[str, Any]) -> str:
        lines = [
            "# WireToutetu 经验",
            "",
            "> 仅保存可复用的短经验；题目答案、IOC、账号、密钥和完整载荷留在 case state。",
            "",
            "## 稳定经验",
            "",
        ]
        if not data["stable_lessons"]:
            lines.append("- 暂无。")
        for item in data["stable_lessons"]:
            lines.extend(
                [
                    f"### `{item['experience_key']}`（命中 {item['hits']} 次）",
                    f"- 适用：{item.get('scope', '')}",
                    f"- 触发：{item.get('trigger', '')}",
                    f"- 动作：{item.get('action', '')}",
                    f"- 避免：{item.get('avoid', '')}",
                    f"- 验证：{item.get('validation', '')}",
                    f"- 知识：`{item.get('knowledge_id', '')}`",
                    "",
                ]
            )
        lines.extend(["## 近期轮次", ""])
        if not data["recent_rounds"]:
            lines.append("- 暂无。")
        for item in data["recent_rounds"]:
            signals = ", ".join(item.get("signals", []))
            lines.append(f"- {item.get('date', '')} `{item.get('case_id', '')}`：{item.get('summary', '')}（{signals}）")
        compact_json = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        lines.extend(["", f"<!-- {MARKER}", compact_json, "-->", ""])
        return "\n".join(lines)

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rendered = self._render(data)
        if len(rendered.encode("utf-8")) > MAX_BYTES:
            raise ValueError("experience exceeds 12 KiB after compaction")
        fd, temporary = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(rendered)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def merge_lesson(self, lesson: dict[str, Any]) -> None:
        key = str(lesson["experience_key"])
        data = self.load()
        existing = next((row for row in data["stable_lessons"] if row["experience_key"] == key), None)
        if existing:
            existing.update({field: value for field, value in lesson.items() if field != "experience_key"})
            existing["hits"] = int(existing.get("hits", 1)) + 1
            existing["last_seen"] = _today()
        else:
            data["stable_lessons"].append(
                {
                    **lesson,
                    "experience_key": key,
                    "hits": 1,
                    "first_seen": _today(),
                    "last_seen": _today(),
                }
            )
        data["stable_lessons"] = sorted(
            data["stable_lessons"], key=lambda row: (row.get("hits", 1), row.get("last_seen", "")), reverse=True
        )[:MAX_STABLE]
        self._fit_data(data)
        self._write(data)

    def append_recent(self, recent: dict[str, Any]) -> None:
        data = self.load()
        entry = {**recent, "date": recent.get("date", _today())}
        data["recent_rounds"] = [
            row for row in data["recent_rounds"] if row.get("case_id") != entry.get("case_id")
        ]
        data["recent_rounds"].append(entry)
        data["recent_rounds"] = data["recent_rounds"][-MAX_RECENT:]
        self._fit_data(data)
        self._write(data)

    @staticmethod
    def _compact_data(data: dict[str, Any]) -> None:
        data["stable_lessons"] = data.get("stable_lessons", [])[:MAX_STABLE]
        data["recent_rounds"] = data.get("recent_rounds", [])[-MAX_RECENT:]
        limits = {"scope": 120, "trigger": 180, "action": 300, "avoid": 160, "validation": 160, "summary": 200}
        for collection in (data["stable_lessons"], data["recent_rounds"]):
            for item in collection:
                for field, limit in limits.items():
                    if isinstance(item.get(field), str):
                        item[field] = item[field][:limit]

    @classmethod
    def _fit_data(cls, data: dict[str, Any]) -> None:
        cls._compact_data(data)
        while len(cls._render(data).encode("utf-8")) > MAX_BYTES and data["stable_lessons"]:
            data["stable_lessons"].pop()
        while len(cls._render(data).encode("utf-8")) > MAX_BYTES and data["recent_rounds"]:
            data["recent_rounds"].pop(0)

    def compact(self) -> None:
        data = self.load()
        self._fit_data(data)
        self._write(data)

    def review(self, signal: str, *, limit: int = 5) -> list[dict[str, Any]]:
        needle = signal.lower()
        matches = []
        for row in self.load()["stable_lessons"]:
            haystack = " ".join(str(value) for value in row.values()).lower()
            if needle in haystack:
                matches.append(row)
        return matches[: min(max(limit, 1), 5)]
