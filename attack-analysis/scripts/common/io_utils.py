"""Shared file IO helpers for attack-analysis scripts."""

from __future__ import annotations

import gzip
from pathlib import Path
from typing import Iterator

TEXT_EXTENSIONS = {
    ".log",
    ".txt",
    ".out",
    ".err",
    ".access",
    ".csv",
    ".json",
    ".jsonl",
}


def is_gzip(path: str | Path) -> bool:
    p = Path(path)
    return p.suffix.lower() == ".gz"


def is_xlsx(path: str | Path) -> bool:
    return Path(path).suffix.lower() == ".xlsx"


def is_probably_text(path: str | Path) -> bool:
    p = Path(path)
    if is_gzip(p):
        inner = p.with_suffix("")
        return inner.suffix.lower() in TEXT_EXTENSIONS or ".log" in inner.name.lower()
    return p.suffix.lower() in TEXT_EXTENSIONS or ".log" in p.name.lower()


def open_text(path: str | Path):
    p = Path(path)
    if is_gzip(p):
        return gzip.open(p, "rt", encoding="utf-8", errors="replace")
    return p.open("r", encoding="utf-8", errors="replace")


def iter_text_lines(path: str | Path, max_lines: int | None = None) -> Iterator[tuple[int, str]]:
    with open_text(path) as fh:
        for idx, line in enumerate(fh, 1):
            yield idx, line.rstrip("\n")
            if max_lines is not None and idx >= max_lines:
                break


def safe_relpath(path: str | Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)
