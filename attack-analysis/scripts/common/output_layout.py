"""Deterministic, protected case output paths for attack-analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class CasePaths:
    workdir: Path
    cache_dir: Path
    report_dir: Path
    manifest_path: Path
    report_path: Path


def safe_case_id(value: str) -> str:
    ascii_value = value.encode("ascii", "ignore").decode("ascii").lower()
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", ascii_value).strip("-._")
    return cleaned or "case"


def default_case_id(source_paths: Sequence[Path], now: datetime | None = None) -> str:
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    first = source_paths[0] if source_paths else Path("case")
    base = first.name if first.name else first.parent.name
    return f"{safe_case_id(base)}-{stamp}"


def resolve_case_paths(workdir: Path, case_id: str) -> CasePaths:
    root = workdir.expanduser().resolve()
    safe_id = safe_case_id(case_id)
    cache_dir = root / "cache" / safe_id
    report_dir = root / "report" / safe_id
    return CasePaths(
        workdir=root,
        cache_dir=cache_dir,
        report_dir=report_dir,
        manifest_path=cache_dir / "analysis-manifest.json",
        report_path=report_dir / "log-analysis-report.md",
    )


def prepare_case_paths(paths: CasePaths, allow_existing: bool = False) -> None:
    exists = paths.cache_dir.exists() or paths.report_dir.exists()
    if exists and not allow_existing:
        raise FileExistsError(f"case output already exists: {paths.cache_dir.name}")
    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    paths.report_dir.mkdir(parents=True, exist_ok=True)
