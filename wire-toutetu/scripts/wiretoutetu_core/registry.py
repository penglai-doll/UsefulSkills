"""Plugin registry loading, validation, and deterministic signal routing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


REGISTRY_FIELDS = frozenset(
    {
        "plugin_id",
        "stage",
        "consumes",
        "emits",
        "trigger_signals",
        "required_tools",
        "knowledge_ids",
        "fixture_ids",
        "support_status",
    }
)
SUPPORT_STATUSES = frozenset(
    {"verified-decode", "verified-extract", "best-effort", "metadata-only", "unavailable"}
)


def load_registry(path: str | Path) -> list[dict[str, Any]]:
    """Load the JSON-compatible YAML registry without adding a YAML dependency."""
    registry = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(registry, list):
        raise ValueError("registry root must be a list")
    seen: set[str] = set()
    for index, plugin in enumerate(registry):
        if not isinstance(plugin, dict) or set(plugin) != REGISTRY_FIELDS:
            raise ValueError(f"registry entry {index} has invalid fields")
        plugin_id = plugin["plugin_id"]
        if plugin_id in seen:
            raise ValueError(f"duplicate plugin_id: {plugin_id}")
        seen.add(plugin_id)
        if plugin["support_status"] not in SUPPORT_STATUSES:
            raise ValueError(f"invalid support_status for {plugin_id}")
        if plugin["support_status"].startswith("verified-") and not plugin["fixture_ids"]:
            raise ValueError(f"verified plugin has no fixture_ids: {plugin_id}")
        for key in ("consumes", "emits", "trigger_signals", "required_tools", "knowledge_ids", "fixture_ids"):
            if not isinstance(plugin[key], list):
                raise ValueError(f"{plugin_id}.{key} must be a list")
    return registry


def select_plugins(
    registry: Iterable[dict[str, Any]], signals: Iterable[str]
) -> list[dict[str, Any]]:
    """Select plugins whose signals intersect the observed normalized signals."""
    observed = {str(signal).lower() for signal in signals}
    selected = [
        plugin
        for plugin in registry
        if observed.intersection(str(signal).lower() for signal in plugin["trigger_signals"])
    ]
    return sorted(selected, key=lambda item: item["plugin_id"])
