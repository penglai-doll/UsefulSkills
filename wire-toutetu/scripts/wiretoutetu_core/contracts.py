"""Stable public data contracts used by every WireToutetu command."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


SCHEMA_VERSION = "1.0"
COMPLETENESS = frozenset({"complete", "partial", "truncated", "unknown"})
EVIDENCE_PREFIXES = frozenset({"FLOW", "TXN", "OBJ", "DEC", "EVT", "FIND"})


def make_envelope(
    *,
    status: str,
    stage: str,
    case_dir: str | None = None,
    summary: Mapping[str, Any] | None = None,
    counts: Mapping[str, int] | None = None,
    routes: Mapping[str, Any] | None = None,
    next_actions: list[str] | None = None,
    errors: list[Mapping[str, Any]] | None = None,
    completeness: str = "unknown",
) -> dict[str, Any]:
    """Build the fixed JSON envelope and reject contract drift."""
    if completeness not in COMPLETENESS:
        raise ValueError(f"invalid completeness: {completeness}")

    route_values: dict[str, Any] = {
        "selected_plugins": [],
        "recommended_references": [],
        "optional_references": [],
        "recommended_experience": [],
    }
    if routes:
        unknown = set(routes) - set(route_values)
        if unknown:
            raise ValueError(f"unknown routes: {sorted(unknown)}")
        route_values.update(routes)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "case_dir": case_dir,
        "stage": stage,
        "summary": dict(summary or {}),
        "counts": dict(counts or {}),
        "routes": route_values,
        "next_actions": list(next_actions or []),
        "errors": list(errors or []),
        "completeness": completeness,
    }


def stable_evidence_id(prefix: str, material: Mapping[str, Any]) -> str:
    """Return a deterministic, namespaced evidence identifier."""
    normalized = prefix.upper()
    if normalized not in EVIDENCE_PREFIXES:
        raise ValueError(f"invalid evidence prefix: {prefix}")
    payload = json.dumps(
        material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(normalized.encode("ascii") + b"\0" + payload).hexdigest()[:16]
    return f"{normalized}-{digest}"
