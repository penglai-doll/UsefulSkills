from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]


class KnowledgeCatalogTests(unittest.TestCase):
    def test_leaf_documents_have_fixed_small_model_sections(self) -> None:
        registry = json.loads((SKILL_ROOT / "references" / "registry.yaml").read_text(encoding="utf-8"))
        required_headings = (
            "## 读取时机", "## 版本矩阵", "## 观察特征", "## 反例", "## 提取方法",
            "## 解码状态机", "## 失败路径", "## 夹具", "## 来源",
        )
        self.assertGreaterEqual(len(registry), 35)
        for item in registry:
            path = SKILL_ROOT / "references" / item["path"]
            text = path.read_text(encoding="utf-8")
            self.assertIn(f"knowledge_id: {item['knowledge_id']}", text)
            for heading in required_headings:
                self.assertIn(heading, text, str(path))

    def test_schemas_are_valid_and_forbid_confidence(self) -> None:
        schema_dir = SKILL_ROOT / "references" / "schemas"
        expected = {"case", "flow", "transaction", "object", "decode", "evidence", "timeline"}
        found = {path.name.removesuffix(".schema.json") for path in schema_dir.glob("*.schema.json")}
        self.assertEqual(found, expected)
        for path in schema_dir.glob("*.schema.json"):
            schema = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertNotIn("confidence", json.dumps(schema))

    def test_generated_indexes_and_catalog_validate(self) -> None:
        for script in ("build_indexes.py", "validate_catalog.py"):
            completed = subprocess.run(
                [sys.executable, str(SKILL_ROOT / "scripts" / script), "--check"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_default_key_catalog_separates_candidates_from_official_defaults(self) -> None:
        catalog = json.loads((SKILL_ROOT / "references" / "webshell" / "default-keys.json").read_text(encoding="utf-8"))
        by_family = {item["family"]: item for item in catalog["entries"]}

        self.assertEqual(by_family["behinder"]["value"], hashlib.md5(b"rebeyond").hexdigest()[:16])
        self.assertEqual(by_family["godzilla"]["value"], hashlib.md5(b"key").hexdigest()[:16])
        self.assertIsNone(by_family["weevely3"]["value"])
        self.assertFalse(by_family["weevely3"]["official_default"])


if __name__ == "__main__":
    unittest.main()
