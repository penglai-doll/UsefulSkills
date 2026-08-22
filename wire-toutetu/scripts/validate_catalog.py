#!/usr/bin/env python3
"""Validate plugin, knowledge, fixture, schema, and generated-index integrity."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from build_indexes import OUTPUT_PATH, REFERENCE_REGISTRY_PATH, render_reference_indexes, render_scripts_index
from wiretoutetu_core.registry import load_registry


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_REGISTRY = ROOT / "scripts" / "registry.yaml"
FIXTURE_MANIFEST = ROOT / "tests" / "fixture-manifest.json"
HEADINGS = (
    "## 读取时机", "## 版本矩阵", "## 观察特征", "## 反例", "## 提取方法",
    "## 解码状态机", "## 失败路径", "## 夹具", "## 来源",
)


def validate() -> list[str]:
    errors: list[str] = []
    try:
        plugins = load_registry(PLUGIN_REGISTRY)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [f"plugin registry: {exc}"]
    knowledge = json.loads(REFERENCE_REGISTRY_PATH.read_text(encoding="utf-8"))
    knowledge_ids: set[str] = set()
    paths: set[str] = set()
    required = {"knowledge_id", "domain", "topic", "title", "path", "signals", "read_when", "support_status", "fixture_ids", "sources"}
    for item in knowledge:
        if set(item) != required:
            errors.append(f"knowledge fields: {item.get('knowledge_id', '<unknown>')}")
            continue
        if item["knowledge_id"] in knowledge_ids:
            errors.append(f"duplicate knowledge_id: {item['knowledge_id']}")
        knowledge_ids.add(item["knowledge_id"])
        if item["path"] in paths:
            errors.append(f"duplicate knowledge path: {item['path']}")
        paths.add(item["path"])
        path = (ROOT / "references" / item["path"]).resolve()
        try:
            path.relative_to((ROOT / "references").resolve())
        except ValueError:
            errors.append(f"unsafe knowledge path: {item['path']}")
            continue
        if not path.is_file():
            errors.append(f"missing leaf: {item['path']}")
            continue
        text = path.read_text(encoding="utf-8")
        if f"knowledge_id: {item['knowledge_id']}" not in text:
            errors.append(f"frontmatter drift: {item['path']}")
        for heading in HEADINGS:
            if heading not in text:
                errors.append(f"missing heading {heading}: {item['path']}")
        if not item["sources"] or any(not value.startswith("https://") for value in item["sources"]):
            errors.append(f"invalid sources: {item['knowledge_id']}")
    for plugin in plugins:
        for knowledge_id in plugin["knowledge_ids"]:
            if knowledge_id not in knowledge_ids:
                errors.append(f"orphan plugin knowledge: {plugin['plugin_id']} -> {knowledge_id}")

    fixtures = json.loads(FIXTURE_MANIFEST.read_text(encoding="utf-8")) if FIXTURE_MANIFEST.is_file() else []
    fixture_ids = {item["fixture_id"] for item in fixtures}
    if len(fixture_ids) != len(fixtures):
        errors.append("duplicate fixture_id")
    for item in fixtures:
        test_path = ROOT / item["test_file"]
        if not test_path.is_file():
            errors.append(f"fixture test file missing: {item['fixture_id']}")
        elif item["test_name"] not in test_path.read_text(encoding="utf-8"):
            errors.append(f"fixture test name missing: {item['fixture_id']}")
    for plugin in plugins:
        if plugin["support_status"].startswith("verified-"):
            for fixture_id in plugin["fixture_ids"]:
                if fixture_id not in fixture_ids:
                    errors.append(f"verified fixture missing: {plugin['plugin_id']} -> {fixture_id}")

    schema_dir = ROOT / "references" / "schemas"
    for schema_path in schema_dir.glob("*.schema.json"):
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                errors.append(f"schema draft mismatch: {schema_path.name}")
            if "confidence" in json.dumps(schema):
                errors.append(f"forbidden confidence field: {schema_path.name}")
        except json.JSONDecodeError as exc:
            errors.append(f"invalid schema {schema_path.name}: {exc}")

    key_catalog_path = ROOT / "references" / "webshell" / "default-keys.json"
    try:
        key_catalog = json.loads(key_catalog_path.read_text(encoding="utf-8"))
        key_entries = key_catalog["entries"]
        families = [item["family"] for item in key_entries]
        if len(families) != len(set(families)):
            errors.append("duplicate default-key family")
        weevely = next(item for item in key_entries if item["family"] == "weevely3")
        if weevely.get("value") is not None or weevely.get("official_default"):
            errors.append("Weevely must not claim a universal official default password")
    except (OSError, KeyError, StopIteration, json.JSONDecodeError) as exc:
        errors.append(f"invalid default-key catalog: {exc}")

    expected = {OUTPUT_PATH: render_scripts_index(plugins)}
    expected.update(render_reference_indexes(knowledge))
    for path, rendered in expected.items():
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
            errors.append(f"index drift: {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate without writing")
    parser.parse_args()
    errors = validate()
    if errors:
        for error in errors:
            print(error)
        return 1
    print("catalog is valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
