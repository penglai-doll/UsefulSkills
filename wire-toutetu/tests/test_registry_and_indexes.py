from __future__ import annotations

import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))


class RegistryTests(unittest.TestCase):
    def test_registry_has_required_fields_and_verified_fixtures(self) -> None:
        from wiretoutetu_core.registry import load_registry

        registry = load_registry(SKILL_ROOT / "scripts" / "registry.yaml")
        required = {
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
        self.assertGreaterEqual(len(registry), 12)
        for plugin in registry:
            self.assertEqual(required, set(plugin))
            if plugin["support_status"].startswith("verified-"):
                self.assertTrue(plugin["fixture_ids"], plugin["plugin_id"])

    def test_signal_routing_is_deterministic(self) -> None:
        from wiretoutetu_core.registry import load_registry, select_plugins

        registry = load_registry(SKILL_ROOT / "scripts" / "registry.yaml")
        selected = select_plugins(registry, {"http", "post", "aes"})
        ids = [item["plugin_id"] for item in selected]

        self.assertEqual(ids, sorted(ids))
        self.assertIn("proto.http1", ids)
        self.assertIn("webshell.behinder", ids)

    def test_scripts_index_is_rendered_from_registry(self) -> None:
        from build_indexes import render_scripts_index
        from wiretoutetu_core.registry import load_registry

        registry = load_registry(SKILL_ROOT / "scripts" / "registry.yaml")
        rendered = render_scripts_index(registry)

        self.assertTrue(rendered.startswith("# WireToutetu Script Index\n"))
        self.assertIn("`webshell.behinder`", rendered)
        self.assertIn("verified-decode", rendered)


if __name__ == "__main__":
    unittest.main()
