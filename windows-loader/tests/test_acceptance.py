"""Black-box acceptance contract for Windows Loader v1.

Production behavior is deliberately absent when this suite lands. Each
behavioral test first checks for its public script, producing a meaningful RED
failure instead of an import error. All bounded result collections use a single
observable envelope: items, total_count, shown_count, truncated, details_path.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from urllib.parse import urlparse

from fixture_factory import (
    copy_structured_fixtures,
    make_long_path,
    make_reparse_link,
    make_windows_root,
    sha256,
    write_evidence_set,
)


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"
REPOSITORY_ROOT = SKILL_ROOT.parents[0]
SCHEMA = "windows-loader.v1"
ENVELOPE_FIELDS = {"items", "total_count", "shown_count", "truncated", "details_path"}


class LoaderAcceptanceCase(unittest.TestCase):
    maxDiff = None

    def require_script(self, name: str) -> Path:
        script = SCRIPTS / name
        self.assertTrue(script.is_file(), f"missing public script: {script}")
        return script

    def require_reference(self, name: str) -> Path:
        reference = SKILL_ROOT / "references" / name
        self.assertTrue(reference.is_file(), f"missing required reference: {reference}")
        return reference

    def run_json(self, script_name: str, *arguments: object, expected_code: int = 0) -> dict:
        script = self.require_script(script_name)
        completed = subprocess.run(
            [sys.executable, str(script), *(str(argument) for argument in arguments)],
            cwd=SKILL_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            expected_code,
            completed.returncode,
            f"{script_name} stderr:\n{completed.stderr}\nstdout:\n{completed.stdout}",
        )
        if expected_code:
            return {"stderr": completed.stderr, "stdout": completed.stdout}
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"{script_name} did not emit JSON: {error}\n{completed.stdout}")
        self.assertEqual(SCHEMA, document.get("schema"))
        return document

    def assert_envelope(self, container: dict, key: str, limit: int = 50) -> list:
        envelope = container.get(key)
        self.assertIsInstance(envelope, dict, f"{key} must be a bounded-list envelope")
        self.assertTrue(ENVELOPE_FIELDS.issubset(envelope), f"{key} envelope fields")
        items = envelope["items"]
        self.assertIsInstance(items, list, f"{key}.items must be a list")
        self.assertEqual(len(items), envelope["shown_count"], f"{key}.shown_count")
        self.assertGreaterEqual(envelope["total_count"], envelope["shown_count"], key)
        self.assertEqual(envelope["total_count"] > envelope["shown_count"], envelope["truncated"], key)
        self.assertLessEqual(envelope["shown_count"], limit, f"{key} exceeds result limit")
        self.assertTrue(
            envelope["details_path"] is None or isinstance(envelope["details_path"], str),
            f"{key}.details_path must be optional None or a string",
        )
        return items

    def guest_path(self, root: Path, local_path: Path) -> str:
        return root.name.upper() + ":\\" + "\\".join(local_path.relative_to(root).parts)

    def dotted_call_name(self, node: ast.AST, aliases: dict[str, str] | None = None) -> str:
        if isinstance(node, ast.Name):
            name = node.id
            return (aliases or {}).get(name, name)
        if isinstance(node, ast.Attribute):
            prefix = self.dotted_call_name(node.value, aliases)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    def literal_mode(self, call: ast.Call, resolved_call: str) -> str | None:
        is_function_open = resolved_call in {"open", "builtins.open", "io.open"}
        position = 1 if is_function_open else 0
        mode_node = call.args[position] if len(call.args) > position else None
        for keyword in call.keywords:
            if keyword.arg == "mode":
                mode_node = keyword.value
        return mode_node.value if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str) else None

    def supplied_mode_node(self, call: ast.Call, resolved_call: str) -> ast.AST | None:
        is_function_open = resolved_call in {"open", "builtins.open", "io.open"}
        position = 1 if is_function_open else 0
        mode_node = call.args[position] if len(call.args) > position else None
        for keyword in call.keywords:
            if keyword.arg == "mode":
                mode_node = keyword.value
        return mode_node

    def static_target_text(self, call: ast.Call, resolved_call: str) -> str:
        if resolved_call not in {"open", "builtins.open", "io.open"} and isinstance(call.func, ast.Attribute):
            return ast.unparse(call.func.value).lower()
        return ast.unparse(call.args[0]).lower() if call.args else ""

    def import_aliases(self, tree: ast.AST) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    aliases[imported.asname or imported.name.split(".")[0]] = imported.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for imported in node.names:
                    if imported.name != "*":
                        aliases[imported.asname or imported.name] = f"{node.module}.{imported.name}"
        return aliases

    def assert_no_unsafe_process_or_mount_routes(self, script: Path) -> None:
        source = script.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(script))
        aliases = self.import_aliases(tree)
        forbidden_import_prefixes = ("subprocess", "ctypes", "win32", "pythoncom", "comtypes")
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    module = imported.name.lower()
                    local_name = imported.asname or imported.name.split(".")[0]
                    self.assertFalse(
                        module.startswith(forbidden_import_prefixes),
                        f"unsafe process/mount bridge import in {script.name}: {imported.name}",
                    )
                    self.assertFalse(
                        module.startswith("multiprocessing"),
                        f"unsafe process module import in {script.name}: {imported.name}",
                    )
                    self.assertFalse(
                        module.startswith("asyncio.subprocess"),
                        f"unsafe asyncio subprocess import in {script.name}: {imported.name}",
                    )
                    if module in {"os", "asyncio"}:
                        aliases[local_name] = module
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").lower()
                self.assertFalse(
                    module.startswith(forbidden_import_prefixes),
                    f"unsafe process/mount bridge import in {script.name}: {node.module}",
                )
                self.assertFalse(
                    module.startswith("multiprocessing"),
                    f"unsafe process import in {script.name}: {node.module}",
                )
                self.assertFalse(
                    module.startswith("asyncio.subprocess"),
                    f"unsafe asyncio subprocess import in {script.name}: {node.module}",
                )
                for imported in node.names:
                    local_name = imported.asname or imported.name
                    if module == "asyncio" and imported.name.startswith("create_subprocess"):
                        self.fail(f"unsafe asyncio subprocess import in {script.name}: {imported.name}")
                    if module == "os" and imported.name in {
                        "system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
                        "spawnv", "spawnve", "spawnvp", "spawnvpe", "execl", "execle",
                        "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
                    }:
                        aliases[local_name] = f"os.{imported.name}"

        prohibited_calls = {
            "os.system", "os.popen", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
            "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe", "os.execl", "os.execle",
            "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp", "os.execvpe",
            "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
            "multiprocessing.Process",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call = self.dotted_call_name(node.func, aliases)
                self.assertNotIn(call, prohibited_calls, f"process execution is prohibited in {script.name}: {call}")

        normalized_source = re.sub(r"[^a-z0-9]", "", source.lower())
        mount_tokens = (
            "mountdiskimage", "dismountdiskimage", "mountvol", "diskpart", "attachvirtualdisk",
            "detachvirtualdisk", "virtdisk", "losetup", "ewfmount", "qemunbd", "wslmount",
            "umount", "libewf", "pyewf", "imdisk", "osfmount", "arsenalimage",
        )
        for token in mount_tokens:
            self.assertNotIn(token, normalized_source, f"mount API/command is prohibited in {script.name}: {token}")

    def test_inspect_evidence_recognizes_supported_images_and_hash_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence = write_evidence_set(Path(temporary))
            expected_formats = {
                "raw": "raw",
                "dd": "raw",
                "img": "raw",
                "vhd": "vhd",
                "vhdx": "vhdx",
                "single_e01": "e01",
            }
            for name, expected_format in expected_formats.items():
                document = self.run_json(
                    "inspect_evidence.py", "--image", evidence[name], "--hash", "now"
                )
                self.assertEqual(expected_format, document["evidence"]["format"])
                self.assertEqual(sha256(evidence[name]), document["evidence"]["sha256"])

            standalone = self.run_json(
                "inspect_evidence.py", "--image", evidence["single_e01"], "--hash", "later"
            )
            self.assertEqual(
                ["standalone.E01"], self.assert_envelope(standalone["evidence"], "segments")
            )
            self.assertEqual("later", standalone["evidence"]["hash"]["policy"])
            self.assertNotIn("sha256", standalone["evidence"])

            split = self.run_json(
                "inspect_evidence.py", "--image", evidence["split_e01"], "--hash", "skip"
            )
            self.assertEqual(
                ["evidence.E01", "evidence.E02"], self.assert_envelope(split["evidence"], "segments")
            )
            self.assertEqual("skip", split["evidence"]["hash"]["policy"])
            self.assertNotIn("sha256", split["evidence"])

            split_now = self.run_json(
                "inspect_evidence.py", "--image", evidence["split_e02"], "--hash", "now"
            )
            self.assertEqual("evidence.E01", Path(split_now["evidence"]["path"]).name)
            self.assertEqual(
                ["evidence.E01", "evidence.E02"],
                self.assert_envelope(split_now["evidence"], "segments"),
            )
            self.assertEqual(
                sum(path.stat().st_size for path in (evidence["split_e01"], evidence["split_e02"])),
                split_now["evidence"]["size"],
            )
            self.assertIn("set_sha256", split_now["evidence"]["hash"])
            segment_hashes = self.assert_envelope(split_now["evidence"]["hash"], "segment_hashes")
            self.assertEqual(["evidence.E01", "evidence.E02"], [item["name"] for item in segment_hashes])
            self.assertEqual(
                [sha256(evidence["split_e01"]), sha256(evidence["split_e02"])],
                [item["sha256"] for item in segment_hashes],
            )
            aggregate = hashlib.sha256()
            for item in segment_hashes:
                aggregate.update(item["name"].encode("utf-8"))
                aggregate.update(b"\x00")
                aggregate.update(item["sha256"].encode("ascii"))
                aggregate.update(b"\n")
            self.assertEqual(aggregate.hexdigest(), split_now["evidence"]["hash"]["set_sha256"])

            invalid = self.run_json(
                "inspect_evidence.py", "--image", evidence["invalid"], "--hash", "skip",
                expected_code=2,
            )
            self.assertIn("unsupported", invalid["stderr"].lower())

    def test_relative_e01_inputs_are_recorded_as_absolute_canonical_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary)
            evidence = write_evidence_set(cwd / "evidence")
            relative_e02 = Path("evidence") / evidence["split_e02"].name
            inspect = subprocess.run(
                [
                    sys.executable,
                    str(self.require_script("inspect_evidence.py")),
                    "--image",
                    str(relative_e02),
                ],
                cwd=cwd,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, inspect.returncode, inspect.stderr)
            inspected = json.loads(inspect.stdout)
            inspected_path = Path(inspected["evidence"]["path"])
            self.assertTrue(inspected_path.is_absolute())
            self.assertEqual(evidence["split_e01"].resolve(), inspected_path)

            initialized = subprocess.run(
                [
                    sys.executable,
                    str(self.require_script("case_state.py")),
                    "init",
                    "--case-dir",
                    "case",
                    "--image",
                    str(relative_e02),
                ],
                cwd=cwd,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, initialized.returncode, initialized.stderr)
            session = json.loads((cwd / "case" / "session.json").read_text(encoding="utf-8"))
            session_path = Path(session["evidence"]["path"])
            self.assertTrue(session_path.is_absolute())
            self.assertEqual(evidence["split_e01"].resolve(), session_path)

    def test_tree_inspection_normalizes_guest_paths_reports_long_path_and_bounds_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture_root = Path(temporary)
            first = make_windows_root(fixture_root, "C")
            second = make_windows_root(fixture_root, "D")
            long_path = make_long_path(first)
            long_guest_path = self.guest_path(first, long_path)
            for index in range(75):
                hit = first / "Users" / "Alice" / "AppData" / "Roaming" / "Many" / str(index)
                hit.mkdir(parents=True, exist_ok=True)
                (hit / "config.json").write_text("{}", encoding="utf-8")
            document = self.run_json(
                "inspect_windows_tree.py",
                "--root", first,
                "--root", second,
                "--guest-path", long_guest_path.upper(),
                "--limit", "50",
            )
            installations = self.assert_envelope(document, "windows_installations")
            self.assertEqual(2, len(installations))
            path_hits = self.assert_envelope(document, "hits")
            self.assertIn(long_guest_path, path_hits, "long case-insensitive guest path must be reported")
            self.assertGreater(len(long_guest_path), 260)
            self.assertTrue(any("ServiceProfiles" in path for path in path_hits))
            self.assertTrue(any("Packages" in path for path in path_hits))
            self.assert_envelope(document, "errors")

    def test_tree_inspection_never_follows_reparse_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as external:
            root = make_windows_root(Path(temporary))
            link = make_reparse_link(root, Path(external))
            if link is None:
                self.skipTest("this host cannot create a synthetic directory reparse link")
            document = self.run_json("inspect_windows_tree.py", "--root", root)
            serialized = json.dumps(document)
            self.assertNotIn("MUST-NOT-BE-INDEXED", serialized)
            skipped = self.assert_envelope(document, "skipped")
            self.assertTrue(any("reparse" in item.lower() for item in skipped))

    def test_catalog_search_refuses_intermediate_reparse_and_reports_probe_failures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryDirectory() as external:
            root = Path(temporary) / "C"
            (root / "Windows").mkdir(parents=True)
            outside = Path(external)
            marker = outside / "FooChat" / "MUST-NOT-BE-INDEXED.ini"
            marker.parent.mkdir(parents=True)
            marker.write_text("secret", encoding="utf-8")
            link = root / "ProgramData"
            try:
                os.symlink(outside, link, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("this host cannot create a synthetic directory reparse link")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "FooChat",
                "--kind", "config",
            )
            self.assertNotIn("MUST-NOT-BE-INDEXED", json.dumps(document))
            self.assertTrue(
                any("reparse" in error.casefold() for error in self.assert_envelope(document, "errors"))
            )

        sys.path.insert(0, str(SCRIPTS))
        try:
            import common as loader_common

            summary = loader_common.ScanSummary(depth_limit=1, entry_budget=10)
            fake_entry = mock.Mock()
            fake_entry.is_symlink.side_effect = PermissionError("probe denied")
            self.assertTrue(loader_common.is_reparse(Path("denied"), fake_entry, summary))
            self.assertTrue(any("probe" in error.casefold() for error in summary.errors))
        finally:
            sys.path.pop(0)

    def test_path_search_returns_actual_high_value_foochat_and_registry_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = make_windows_root(Path(temporary))
            additional_high_value = (
                root / "PortableApps" / "FooChat" / "portable.ini",
                root / "Users" / "Public" / "Tools" / "FooChat" / "public.json",
                root / "ProgramData" / "Foo" / "FooChat" / "publisher.ini",
                root / "Users" / "Alice" / "AppData" / "Local" / "Packages"
                / "FooChat_123abc" / "RoamingState" / "roaming.json",
                root / "Users" / "Alice" / "AppData" / "Local" / "Packages"
                / "FooChat_123abc" / "Settings" / "settings.dat",
            )
            for path in additional_high_value:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")
            software_hive = root / "Windows" / "System32" / "config" / "SOFTWARE"
            software_hive.write_bytes(
                b"binary-prefix\x00FooChat\\Config\\Server\x00"
                + "Foo Publisher FooChat".encode("utf-16le")
            )
            generic = root / "Misc" / "FooChat" / "fallback.json"
            generic.parent.mkdir(parents=True)
            generic.write_text("{}", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "FooChat",
                "--publisher", "Foo",
                "--user", "Alice",
                "--kind", "all",
            )
            hits = self.assert_envelope(document, "hits")
            expected_hits = {
                r"C:\Users\Alice\AppData\Roaming\FooChat\config.json",
                r"C:\ProgramData\FooChat\config.ini",
                r"C:\Program Files\FooChat\FooChat.exe",
                r"C:\Tools\Portable\FooChat\settings.xml",
                r"C:\PortableApps\FooChat\portable.ini",
                r"C:\Users\Public\Tools\FooChat\public.json",
                r"C:\ProgramData\Foo\FooChat\publisher.ini",
                r"C:\Users\Alice\AppData\Local\Packages\FooChat_123abc\LocalState\settings.json",
                r"C:\Users\Alice\AppData\Local\Packages\FooChat_123abc\RoamingState\roaming.json",
                r"C:\Users\Alice\AppData\Local\Packages\FooChat_123abc\Settings\settings.dat",
            }
            self.assertTrue(expected_hits.issubset(set(hits)), "actual FooChat high-value paths")
            registry_hints = self.assert_envelope(document, "registry_hints")
            self.assertIn(r"C:\Windows\System32\config\SOFTWARE", registry_hints)
            registry_matches = self.assert_envelope(document, "registry_matches")
            self.assertTrue(
                any(
                    match["hive"] == r"C:\Windows\System32\config\SOFTWARE"
                    and "foochat" in match["value"].casefold()
                    for match in registry_matches
                ),
                "Stage 1 must return a concrete bounded offline-registry match",
            )
            self.assertLessEqual(document["search"]["depth"], 4)
            self.assertFalse(document["search"]["expanded"])
            self.assertFalse(document["search"]["stage2"]["executed"])
            self.assertNotIn(self.guest_path(root, generic), hits, "a Stage 1 hit must prevent generic root scanning")

    def test_path_search_stage2_requires_explicit_authorization_after_stage1_miss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            fallback = root / "Users" / "Alice" / "Documents" / "RareChat" / "settings.json"
            fallback.parent.mkdir(parents=True)
            fallback.write_text("{}", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "RareChat",
                "--publisher", "Rare",
                "--user", "Alice",
                "--kind", "config",
                "--depth", "4",
                "--limit", "5",
                "--entry-budget", "40",
            )
            self.assertEqual([], self.assert_envelope(document, "hits"))
            stage2 = document["search"]["stage2"]
            self.assertFalse(stage2["authorized"])
            self.assertFalse(stage2["executed"])
            self.assertTrue(stage2["authorization_required"])
            self.assertEqual(self.guest_path(root, root), stage2["proposed_scope"])
            self.assertEqual(4, stage2["estimated_cost"]["depth_limit"])
            self.assertEqual(40, stage2["estimated_cost"]["maximum_entries"])
            self.assertEqual(5, stage2["estimated_cost"]["result_limit"])

    def test_path_search_entry_budget_is_one_honest_total_across_all_phases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            target = root / "Users" / "Alice" / "Documents" / "RareChat" / "settings.json"
            target.parent.mkdir(parents=True)
            target.write_text("{}", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "RareChat",
                "--kind", "config",
                "--expand",
                "--depth", "4",
                "--limit", "5",
                "--entry-budget", "1",
            )
            budget = document["search"]["budget"]
            self.assertEqual(1, budget["authorized_total_entries"])
            self.assertLessEqual(budget["total_entries_seen"], 1)
            self.assertEqual(
                budget["total_entries_seen"],
                budget["routing_entries"] + budget["stage1_entries"] + budget["stage2_entries"],
            )
            self.assertEqual("routing+stage1+stage2-total", budget["scope"])
            self.assertEqual(1, document["search"]["stage2"]["estimated_cost"]["maximum_entries"])
            self.assertLessEqual(document["scan"]["entries_seen"], 1)
            self.assertTrue(document["scan"]["truncated"])
            self.assertTrue(
                any("budget" in error.casefold() for error in self.assert_envelope(document, "errors"))
            )

    def test_path_search_runs_only_bounded_stage2_after_explicit_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            for index in range(12):
                fallback = root / "Users" / "Alice" / "Documents" / f"RareChat-{index}" / "settings.json"
                fallback.parent.mkdir(parents=True)
                fallback.write_text("{}", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "RareChat",
                "--publisher", "Rare",
                "--user", "Alice",
                "--kind", "config",
                "--expand",
                "--depth", "4",
                "--limit", "2",
                "--entry-budget", "2000",
            )
            hits = self.assert_envelope(document, "hits", limit=2)
            self.assertEqual(2, len(hits))
            stage2 = document["search"]["stage2"]
            self.assertTrue(stage2["authorized"])
            self.assertTrue(stage2["executed"])
            self.assertEqual(4, document["scan"]["depth_limit"])
            self.assertEqual(2000, document["scan"]["entry_budget"])
            self.assertLessEqual(document["scan"]["entries_seen"], 2000)

    def test_explicit_expand_runs_catalog_scoped_stage2_and_keeps_partial_stage1_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            stage1 = root / "ProgramData" / "FooChat" / "config.ini"
            stage1.parent.mkdir(parents=True)
            stage1.write_text("{}", encoding="utf-8")
            stage2 = root / "Users" / "Alice" / "Documents" / "FooChat" / "settings.json"
            stage2.parent.mkdir(parents=True)
            stage2.write_text("{}", encoding="utf-8")
            outside_catalog = root / "Misc" / "FooChat" / "must-not-scan.json"
            outside_catalog.parent.mkdir(parents=True)
            outside_catalog.write_text("{}", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "FooChat",
                "--kind", "config",
                "--expand",
                "--depth", "4",
                "--limit", "10",
                "--entry-budget", "1000",
            )
            self.assertTrue(document["search"]["stage2"]["executed"])
            hits = set(self.assert_envelope(document, "hits", limit=10))
            self.assertIn(self.guest_path(root, stage1), hits)
            self.assertIn(self.guest_path(root, stage2), hits)
            self.assertNotIn(self.guest_path(root, outside_catalog), hits)

    def test_stage1_catalog_outputs_structured_path_hits_for_high_value_locations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            files = (
                root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx",
                root / "Windows" / "AppCompat" / "Programs" / "Amcache.hve",
                root / "Windows" / "System32" / "sru" / "SRUDB.dat",
                root / "Windows" / "ServiceProfiles" / "LocalService" / "AppData" / "Local" / "svc.ini",
                root / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "boot.cmd",
                root / "Users" / "Alice" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "History",
                root / "Users" / "Alice" / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt",
            )
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py", "--root", root, "--kind", "all", "--limit", "50"
            )
            aliases = set(self.assert_envelope(document, "hits"))
            self.assertTrue({self.guest_path(root, path) for path in files}.issubset(aliases))
            structured = self.assert_envelope(document, "path_hits")
            required = {
                "guest_path_segments", "scope", "category", "priority",
                "common_files", "cautions",
            }
            self.assertTrue(structured)
            self.assertTrue(all(required.issubset(hit) for hit in structured))

    def test_registry_budget_is_fair_across_sorted_system_and_user_hives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            software = root / "Windows" / "System32" / "config" / "SOFTWARE"
            software.parent.mkdir(parents=True)
            software.write_bytes(b"X" * 4096)
            for name in ("Zed", "Alice"):
                hive = root / "Users" / name / "NTUSER.DAT"
                hive.parent.mkdir(parents=True)
                hive.write_bytes(
                    ("FooChat user config" if name == "Zed" else "unrelated").encode("utf-16le")
                )
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "FooChat",
                "--kind", "config",
                "--registry-byte-budget", "192",
                "--limit", "10",
            )
            matches = self.assert_envelope(document, "registry_matches", limit=10)
            self.assertTrue(any(match["hive"].endswith(r"Users\Zed\NTUSER.DAT") for match in matches))
            hints = self.assert_envelope(document, "registry_hints", limit=10)
            self.assertEqual(sorted(hints, key=str.casefold), hints)
            self.assertLessEqual(document["search"]["stage1"]["registry_scan"]["bytes_read"], 192)

    def test_path_search_matches_non_ascii_utf16_registry_terms_within_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            hive = root / "Windows" / "System32" / "config" / "SOFTWARE"
            hive.parent.mkdir(parents=True)
            hive.write_bytes(
                b"\x00\x01prefix"
                + "腾讯\\微信\\配置".encode("utf-16le")
                + b"\x00\x00suffix"
            )
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "微信",
                "--publisher", "腾讯",
                "--kind", "config",
                "--registry-byte-budget", "128",
                "--limit", "5",
            )
            matches = self.assert_envelope(document, "registry_matches", limit=5)
            self.assertTrue(matches)
            self.assertTrue(any("微信" in match["value"] for match in matches))
            self.assertTrue(any("腾讯" in match["value"] for match in matches))
            self.assertLessEqual(document["search"]["stage1"]["registry_scan"]["bytes_read"], 128)
            self.assertFalse(document["search"]["stage2"]["executed"])

    def test_registry_software_match_does_not_suppress_explicit_logs_stage2(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "C"
            hive = root / "Windows" / "System32" / "config" / "SOFTWARE"
            hive.parent.mkdir(parents=True)
            hive.write_bytes(b"FooChat\\Configuration")
            log = root / "Users" / "Alice" / "Documents" / "FooChat" / "events.log"
            log.parent.mkdir(parents=True)
            log.write_text("event", encoding="utf-8")
            document = self.run_json(
                "find_windows_paths.py",
                "--root", root,
                "--software", "FooChat",
                "--kind", "logs",
                "--expand",
                "--depth", "3",
                "--limit", "5",
                "--entry-budget", "2000",
            )
            self.assertTrue(self.assert_envelope(document, "registry_matches"))
            self.assertTrue(document["search"]["stage2"]["executed"])
            self.assertIn(self.guest_path(root, log), self.assert_envelope(document, "hits"))

    def test_artifact_cli_parses_registry_evtx_and_browser_like_structured_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixtures = copy_structured_fixtures(Path(temporary))
            registry = self.run_json(
                "analyze_artifact.py", "registry", "--input", fixtures["sample_registry.dat"]
            )
            self.assertEqual("software", registry["artifact"]["hive_role"])
            self.assertIn("FooChat", json.dumps(self.assert_envelope(registry, "records")))
            self.assertEqual(
                registry["artifact"],
                self.assert_envelope(registry, "artifacts")[0],
                "required artifacts must carry the analyzed artifact, not remain empty",
            )

            evtx = self.run_json(
                "analyze_artifact.py", "evtx", "--input", fixtures["sample.evtx.json"],
                "--log", "Security", "--event-id", "4624",
                "--from", "2025-01-02T03:00:00Z", "--to", "2025-01-02T03:04:30Z",
                "--keyword", "Alice",
            )
            events = self.assert_envelope(evtx, "events")
            self.assertEqual([4624], [event["event_id"] for event in events])
            self.assertEqual(["Security"], [event["log"] for event in events])

            for kind, fixture_key in (("sqlite", "sqlite"), ("json", "sample.json"),
                                      ("ini", "sample.ini"), ("xml", "sample.xml")):
                parsed = self.run_json(
                    "analyze_artifact.py", "structured", "--kind", kind,
                    "--input", fixtures[fixture_key], "--limit", "50",
                )
                self.assertEqual(kind, parsed["artifact"]["kind"])
                records = self.assert_envelope(parsed, "records")
                self.assertIn("chat.example.test", json.dumps(records))
                if kind == "sqlite":
                    self.assertIn("urls", json.dumps(parsed))
                    self.assertIn("visit_count", json.dumps(parsed))

    def test_artifact_evtx_filters_limits_and_never_claims_binary_support_without_a_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fixtures = copy_structured_fixtures(temporary_path)
            limited = self.run_json(
                "analyze_artifact.py", "evtx", "--input", fixtures["sample.evtx.json"],
                "--event-id", "4624", "--event-id", "4625", "--limit", "1",
            )
            events = limited["events"]
            self.assertEqual(2, events["total_count"])
            self.assertEqual(1, events["shown_count"])
            self.assertTrue(events["truncated"])

            binary_evtx = temporary_path / "Security.evtx"
            binary_evtx.write_bytes(b"ElfFile\x00not-a-real-event-log")
            binary = self.run_json(
                "analyze_artifact.py", "evtx", "--input", binary_evtx, "--limit", "10",
            )
            self.assertEqual([], self.assert_envelope(binary, "events", 10))
            self.assertIn(binary["artifact"]["parser"], {"python-evtx", "unavailable"})
            if binary["artifact"]["parser"] == "unavailable":
                self.assertIn("python-evtx", json.dumps(self.assert_envelope(binary, "errors", 10)).lower())

    def test_artifact_evtx_namespaced_xml_preserves_system_fields_and_rejects_invalid_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "Security.xml"
            source.write_text(
                """<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <Event><System><Provider Name="Microsoft-Windows-Security-Auditing"/>
                <EventID>4624</EventID><TimeCreated SystemTime="2025-01-02T03:04:05Z"/>
                <Channel>Security</Channel></System><EventData><Data>Alice logged on</Data></EventData></Event>
                </Events>""",
                encoding="utf-8",
            )
            result = self.run_json(
                "analyze_artifact.py", "evtx", "--input", source, "--log", "Security",
                "--event-id", "4624", "--from", "2025-01-02T03:00:00Z",
                "--to", "2025-01-02T03:05:00Z", "--keyword", "Alice",
            )
            events = self.assert_envelope(result, "events")
            self.assertEqual(1, len(events))
            self.assertEqual("Microsoft-Windows-Security-Auditing", events[0]["provider"])
            self.assertEqual("2025-01-02T03:04:05Z", events[0]["timestamp"])
            invalid = self.run_json(
                "analyze_artifact.py", "evtx", "--input", source, "--from", "not-a-time",
            )
            self.assertEqual([], self.assert_envelope(invalid, "events"))
            self.assertIn("invalid --from", json.dumps(self.assert_envelope(invalid, "errors")).lower())

    def test_artifact_evtx_xml_event_budget_stops_before_building_all_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "many-events.xml"
            event = "<Event><EventData><Data>not-the-keyword</Data></EventData></Event>"
            source.write_text("<Events>" + event * 5001 + "</Events>", encoding="utf-8")
            result = self.run_json(
                "analyze_artifact.py", "evtx", "--input", source, "--keyword", "never-matches",
            )
            self.assertEqual([], self.assert_envelope(result, "events"))
            self.assertIn("event parser budget reached", json.dumps(self.assert_envelope(result, "errors")).lower())

    def test_artifact_structured_input_is_read_only_and_malformed_content_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            fixtures = copy_structured_fixtures(temporary_path)
            database = fixtures["sqlite"]
            before = database.stat()
            structured = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "sqlite", "--input", database,
                "--limit", "1",
            )
            after = database.stat()
            self.assertEqual((before.st_size, before.st_mtime_ns), (after.st_size, after.st_mtime_ns))
            self.assertEqual(1, structured["records"]["shown_count"])

            malformed = temporary_path / "broken.json"
            malformed.write_text('{"unterminated": ', encoding="utf-8")
            rejected = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "json", "--input", malformed,
            )
            self.assertEqual([], self.assert_envelope(rejected, "records"))
            self.assertTrue(self.assert_envelope(rejected, "errors"))

    def test_artifact_sqlite_uses_immutable_read_only_access_and_detects_dpapi_blobs_globally_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            database = temporary_path / "Login Data"
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE a_logins (origin_url TEXT, encrypted_value BLOB, note TEXT)")
                connection.execute(
                    "INSERT INTO a_logins (origin_url, encrypted_value) VALUES (?, ?)",
                    ("https://chat.example.test", b"\x01\x00\x00\x00\xd0\x8c\x9d\xdfDPAPI-BLOB"),
                )
                for index in range(3):
                    connection.execute(f"CREATE TABLE extra_{index} (value TEXT)")
                    connection.execute(f"INSERT INTO extra_{index} VALUES ('row-{index}')")
                connection.commit()
            finally:
                connection.close()
            before = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in temporary_path.iterdir()}
            result = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "sqlite", "--input", database,
                "--limit", "2",
            )
            after = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in temporary_path.iterdir()}
            self.assertEqual(before, after, "read-only analysis must not create SQLite sidecars or mutate evidence")
            self.assertLessEqual(result["tables"]["shown_count"], 2)
            self.assertLessEqual(result["columns"]["shown_count"], 2)
            self.assertLessEqual(result["records"]["shown_count"], 2)
            table = self.assert_envelope(result, "tables", 2)[0]
            self.assertNotIn("column_count", table)
            self.assertEqual(2, table["columns_shown"])
            self.assertTrue(table["columns_truncated"])
            self.assertTrue(any(
                item["record"].get("protection") == "likely-dpapi"
                for item in self.assert_envelope(result, "records", 2)
                if isinstance(item.get("record"), dict)
            ))

    def test_artifact_sqlite_blob_preview_is_bounded_and_deep_json_returns_unified_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            database = temporary_path / "Login Data"
            raw_blob = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf" + b"x" * 20000
            connection = sqlite3.connect(database)
            try:
                connection.execute("CREATE TABLE a_logins (encrypted_value BLOB)")
                connection.execute("INSERT INTO a_logins VALUES (?)", (raw_blob,))
                connection.execute("CREATE TABLE a_text (encrypted_value TEXT)")
                connection.execute("INSERT INTO a_text VALUES (?)", ("AQAAANCMnd8BFdERtext-marker",))
                connection.commit()
            finally:
                connection.close()
            before = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in temporary_path.iterdir()}
            result = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "sqlite", "--input", database,
            )
            after = {path.name: (path.stat().st_size, path.stat().st_mtime_ns) for path in temporary_path.iterdir()}
            self.assertEqual(before, after)
            record = self.assert_envelope(result, "records")[0]["record"]
            value = record["encrypted_value"]
            self.assertIsInstance(value, dict)
            self.assertEqual(len(raw_blob), value["length"])
            self.assertLess(len(value["preview"]), len(raw_blob))
            self.assertEqual("likely-dpapi", record["protection"])
            self.assertLess(len(json.dumps(result)), 5000, "oversized blobs must never be materialized into output")
            self.assertTrue(any(
                item["record"].get("protection") == "likely-dpapi"
                for item in self.assert_envelope(result, "records")
                if item["table"] == "a_text" and isinstance(item.get("record"), dict)
            ), "bounded text previews retain DPAPI marker detection")

            deep_json = temporary_path / "deep.json"
            deep_json.write_text("[" * 3000 + "0" + "]" * 3000, encoding="utf-8")
            rejected = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "json", "--input", deep_json,
            )
            self.assertEqual([], self.assert_envelope(rejected, "records"))
            self.assertIn("recursion", json.dumps(self.assert_envelope(rejected, "errors")).lower())

    def test_artifact_registry_default_and_usrclass_roles_and_limit_cap_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            for name, role in (("DEFAULT", "default"), ("UsrClass.dat", "user-class")):
                source = temporary_path / name
                source.write_bytes(b"registry fixture")
                result = self.run_json(
                    "analyze_artifact.py", "registry", "--input", source, "--limit", "100000",
                )
                self.assertEqual(role, result["artifact"]["hive_role"])
                self.assertEqual(200, result["limits"]["maximum"])
                self.assertLessEqual(result["records"]["shown_count"], result["limits"]["maximum"])

    def test_artifact_dpapi_decrypt_requires_an_exact_second_confirmation_and_stays_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "dpapi.json"
            source.write_text('{"blob": "DPAPI\\u0001\\u0000\\u0000protected"}', encoding="utf-8")
            refused = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "json", "--input", source,
                "--decrypt", expected_code=2,
            )
            self.assertIn("confirmation", refused["stderr"].lower())
            result = self.run_json(
                "analyze_artifact.py", "structured", "--kind", "json", "--input", source,
                "--decrypt", "--decrypt-confirmation", "I_CONFIRM_NO_BUNDLED_DPAPI_DECRYPT",
            )
            self.assertIn("dpapi", json.dumps(self.assert_envelope(result, "records")).lower())
            self.assertEqual("unsupported", result["decrypt"]["status"])
            self.assertNotIn("decrypted", json.dumps(result).lower())

    def test_case_state_requires_secret_acknowledgement_and_uses_approved_plaintext_layout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            self.run_json("case_state.py", "init", "--case-dir", case_dir)
            expected_layout = (
                "session.json", "notes.md", "commands.jsonl", "findings.jsonl", "secrets.jsonl",
                "inspect.json", "mounts.json", "raw",
            )
            self.assertEqual(set(expected_layout), {path.name for path in case_dir.iterdir()})
            for relative in expected_layout[:-1]:
                self.assertTrue((case_dir / relative).is_file(), f"approved case file: {relative}")
            self.assertTrue((case_dir / "raw").is_dir(), "approved case raw directory")
            refused = self.run_json(
                "case_state.py", "record-secret", "--case-dir", case_dir,
                "--name", "api-token", "--stdin", expected_code=2,
            )
            self.assertIn("acknowledge", refused["stderr"].lower())
            self.run_json("case_state.py", "acknowledge-plaintext-risk", "--case-dir", case_dir)
            recorded = subprocess.run(
                [
                    sys.executable, str(self.require_script("case_state.py")),
                    "record-secret", "--case-dir", str(case_dir),
                    "--name", "api-token", "--stdin",
                ],
                cwd=SKILL_ROOT, text=True, input="plain-text-secret",
                capture_output=True, check=False,
            )
            self.assertEqual(0, recorded.returncode, recorded.stderr)
            secrets = case_dir / "secrets.jsonl"
            self.assertIn("plain-text-secret", secrets.read_text(encoding="utf-8"))
            self.assertFalse((case_dir / "case-state.json").exists())
            for relative in expected_layout:
                path = case_dir / relative
                if path.is_file() and path != secrets:
                    self.assertNotIn("plain-text-secret", path.read_text(encoding="utf-8"))
            self.assertFalse(list(case_dir.rglob("*.tmp")), "atomic writes must not leave temporary state")

    def test_case_state_session_uses_complete_v1_schema_and_explicit_hash_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            evidence = write_evidence_set(temporary_path / "evidence")
            required = {
                "case_id", "evidence", "hash_policy", "environment", "format", "mounts",
                "windows_installations", "users", "path_hits", "artifacts", "routes", "cleanup", "errors",
            }
            scenarios = (
                ("raw", "raw", "now"),
                ("single_e01", "e01", "later"),
                ("split_e02", "e01", "skip"),
                ("vhd", "vhd", "later"),
                ("vhdx", "vhdx", "later"),
            )
            for key, expected_format, policy in scenarios:
                with self.subTest(key=key, policy=policy):
                    case_dir = temporary_path / f"case-{key}"
                    initialized = self.run_json(
                        "case_state.py", "init", "--case-dir", case_dir,
                        "--image", evidence[key], "--hash", policy,
                        "--mode", "fast-path",
                    )
                    session = json.loads((case_dir / "session.json").read_text(encoding="utf-8"))
                    self.assertTrue(required.issubset(session), required - set(session))
                    self.assertEqual(SCHEMA, session["schema"])
                    self.assertIsInstance(session["case_id"], str)
                    self.assertIsInstance(session["environment"], dict)
                    self.assertEqual(expected_format, session["format"])
                    self.assertEqual(policy, session["hash_policy"])
                    self.assertEqual("fast-path", session["mode"])
                    self.assertIsInstance(session["evidence"], dict)
                    self.assertEqual(session["evidence"], initialized["evidence"])
                    self.assertEqual(session["case_id"], initialized["case_id"])
                    segment_envelope = session["evidence"]["segments"]
                    segments = self.assert_envelope(session["evidence"], "segments")
                    self.assertTrue(Path(segment_envelope["details_path"]).is_absolute())
                    self.assertTrue(
                        Path(segment_envelope["details_path"]).is_relative_to(case_dir.resolve())
                    )
                    self.assertEqual(session["evidence"]["segment_count"], len(segments))
                    self.assertEqual(
                        session["evidence"]["total_size"],
                        sum(segment["size"] for segment in segments),
                    )
                    for segment in segments:
                        self.assertEqual({"name", "size", "mtime", "mtime_ns"}, set(segment))
                    for field in (
                        "mounts", "windows_installations", "users", "path_hits",
                        "artifacts", "routes", "cleanup", "errors",
                    ):
                        self.assertEqual([], self.assert_envelope(session, field))
                    if policy == "now":
                        self.assertRegex(session["evidence"].get("sha256", ""), r"^[0-9a-f]{64}$")
                        hashes = session["evidence"]["hash"]["segment_hashes"]
                        self.assertTrue(Path(hashes["details_path"]).is_absolute())
                        self.assertTrue(
                            Path(hashes["details_path"]).is_relative_to(case_dir.resolve())
                        )
                    else:
                        self.assertNotIn("sha256", session["evidence"], "later/skip must not hash automatically")
                        self.assertNotIn("hash", session["evidence"], "later/skip must not hash segment contents")

                    if key == "split_e02":
                        self.assertEqual(str(evidence["split_e01"]), session["evidence"]["path"])
                        self.assertEqual(
                            ["evidence.E01", "evidence.E02"],
                            [segment["name"] for segment in segments],
                        )

            unsupported_case = temporary_path / "case-unsupported"
            refused = self.run_json(
                "case_state.py", "init", "--case-dir", unsupported_case,
                "--image", evidence["invalid"], expected_code=2,
            )
            self.assertIn("unsupported", refused["stderr"].lower())

    def test_case_state_mode_is_optional_for_compatibility_and_resume_returns_real_top_level_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            initialized = self.run_json("case_state.py", "init", "--case-dir", case_dir)
            self.assertIsNone(initialized["mode"])
            resumed = self.run_json("case_state.py", "resume", "--case-dir", case_dir)
            for field in (
                "case_id", "evidence", "hash_policy", "environment", "format",
                "windows_installations", "users", "path_hits", "artifacts", "routes",
                "cleanup", "errors",
            ):
                self.assertEqual(initialized[field], resumed[field], field)
            self.assertEqual([], self.assert_envelope(resumed, "mounts"))
            self.assertEqual((case_dir / "mounts.json").resolve(), Path(resumed["mounts"]["details_path"]))
            self.assertIsNone(resumed["mode"])

    def test_case_state_e01_now_hashes_every_segment_and_resume_detects_content_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            evidence = write_evidence_set(temporary_path / "evidence")
            case_dir = temporary_path / "case"
            self.run_json(
                "case_state.py", "init", "--case-dir", case_dir,
                "--image", evidence["split_e02"], "--hash", "now",
            )
            session = json.loads((case_dir / "session.json").read_text(encoding="utf-8"))
            hashes = self.assert_envelope(session["evidence"]["hash"], "segment_hashes")
            self.assertEqual(["evidence.E01", "evidence.E02"], [item["name"] for item in hashes])
            self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) for item in hashes))
            self.assertRegex(session["evidence"]["hash"]["set_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("sha256", session["evidence"], "multi-segment evidence uses the deterministic set hash")
            self.assertTrue(
                self.run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"]
            )

            changed = evidence["split_e02"]
            original = changed.read_bytes()
            stat = changed.stat()
            changed.write_bytes(bytes([original[0] ^ 0xFF]) + original[1:])
            os.utime(changed, ns=(stat.st_atime_ns, stat.st_mtime_ns))
            self.assertTrue(changed.stat().st_size == stat.st_size)
            self.assertFalse(
                self.run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"],
                "now policy must detect content changes even when size and mtime are preserved",
            )

    def test_case_state_e01_resume_detects_changed_or_missing_later_segment_without_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            evidence = write_evidence_set(temporary_path / "evidence")
            case_dir = temporary_path / "case"
            self.run_json(
                "case_state.py", "init", "--case-dir", case_dir,
                "--image", evidence["split_e02"], "--hash", "later",
            )
            session = json.loads((case_dir / "session.json").read_text(encoding="utf-8"))
            self.assertNotIn("hash", session["evidence"])
            self.assertTrue(
                self.run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"]
            )
            evidence["split_e02"].write_bytes(evidence["split_e02"].read_bytes() + b"changed")
            self.assertFalse(
                self.run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"]
            )
            evidence["split_e02"].unlink()
            self.assertFalse(
                self.run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"],
                "a missing E01 segment must invalidate resume",
            )

    def test_case_state_persists_atomically_without_acl_changes(self) -> None:
        source = self.require_script("case_state.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        aliases = self.import_aliases(tree)
        helpers = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "atomic_write_text"]
        self.assertEqual(1, len(helpers), "case-state requires one atomic_write_text helper")
        helper = helpers[0]
        helper_node_ids = {id(node) for node in ast.walk(helper)}
        helper_calls = [
            self.dotted_call_name(node.func, aliases)
            for node in ast.walk(helper)
            if isinstance(node, ast.Call)
        ]
        self.assertIn("os.replace", helper_calls, "atomic_write_text itself must perform os.replace")
        helper_has_temp_write = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            call = self.dotted_call_name(node.func, aliases)
            in_helper = id(node) in helper_node_ids
            self.assertFalse(
                call.endswith(".write_text") or call.endswith(".write_bytes"),
                "case-state paths must not use direct Path.write_text/write_bytes",
            )
            if call in {"io.open", "os.open", "os.write", "os.fdopen"}:
                self.fail(f"case-state must not use {call}; atomic writes use a temporary text path")
            if call in {
                "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copyfileobj",
                "shutil.copytree", "shutil.move",
            }:
                self.fail(f"case-state must not use write-capable {call}")
            if call not in {"open", "builtins.open", "Path.open"} and not call.endswith(".open"):
                continue
            supplied_mode = self.supplied_mode_node(node, call)
            if supplied_mode is not None and not (
                isinstance(supplied_mode, ast.Constant) and isinstance(supplied_mode.value, str)
            ):
                self.fail("case-state must not use a non-literal explicitly supplied open mode")
            mode = self.literal_mode(node, call)
            if mode is None:
                continue
            self.assertNotIn("a", mode, "case-state must not append directly to a destination")
            if any(flag in mode for flag in ("w", "x", "+")):
                self.assertTrue(in_helper, "write-capable opens are allowed only inside atomic_write_text")
                target = self.static_target_text(node, call)
                self.assertRegex(target, r"temp|tmp", "atomic_write_text must write to a temp/tmp path")
                helper_has_temp_write = True
        for node in ast.walk(tree):
            if not isinstance(node, ast.ImportFrom) or node.module != "builtins":
                continue
            self.assertNotIn("open", [imported.name for imported in node.names], "builtins.open aliases are prohibited")
        self.assertTrue(helper_has_temp_write, "atomic_write_text must write a temp/tmp target before replace")
        lower_source = source.lower()
        for acl_mutator in ("icacls", "set-acl", "chmod", "chown", "takeown"):
            self.assertNotIn(acl_mutator, lower_source, "plaintext persistence must not tighten ACLs")

    def test_case_state_resume_revalidates_evidence_mount_existence_and_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary)
            image = write_evidence_set(temporary_path)["raw"]
            case_dir = temporary_path / "case"
            mount_root = temporary_path / "mounted-root"
            mount_root.mkdir()
            self.run_json("case_state.py", "init", "--case-dir", case_dir, "--image", image)
            self.run_json(
                "case_state.py", "record-mount", "--case-dir", case_dir,
                "--path", mount_root, "--read-only",
            )
            initial = self.run_json("case_state.py", "resume", "--case-dir", case_dir)
            self.assertTrue(initial["revalidation"]["evidence_matches"])
            initial_mounts = self.assert_envelope(initial["revalidation"], "mounts")
            self.assertEqual(True, initial_mounts[0]["exists"])
            self.assertEqual(True, initial_mounts[0]["claimed_read_only"])
            self.assertEqual(False, initial_mounts[0]["read_only"])
            self.assertEqual("os.access(W_OK)", initial_mounts[0]["probe_method"])
            image.write_bytes(image.read_bytes() + b"changed")
            mount_root.rmdir()
            resumed = self.run_json("case_state.py", "resume", "--case-dir", case_dir)
            self.assertFalse(resumed["revalidation"]["evidence_matches"])
            resumed_mounts = self.assert_envelope(resumed["revalidation"], "mounts")
            self.assertEqual(False, resumed_mounts[0]["exists"])
            self.assertEqual(False, resumed_mounts[0]["read_only"])

    def test_case_state_record_mount_freezes_absolute_path_across_working_directories(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            tempfile.TemporaryDirectory() as other_directory,
        ):
            base = Path(temporary)
            case_dir = base / "case"
            mount_root = base / "mounted"
            mount_root.mkdir()
            self.run_json("case_state.py", "init", "--case-dir", case_dir)
            record = subprocess.run(
                [
                    sys.executable,
                    str(self.require_script("case_state.py")),
                    "record-mount",
                    "--case-dir",
                    str(case_dir),
                    "--path",
                    "mounted",
                    "--read-only",
                ],
                cwd=base,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, record.returncode, record.stderr)
            recorded = [
                json.loads(line)
                for line in (case_dir / "mounts.json").read_text(encoding="utf-8").splitlines()
                if line
            ]
            self.assertEqual(str(mount_root.resolve()), recorded[0]["path"])
            resumed = subprocess.run(
                [
                    sys.executable,
                    str(self.require_script("case_state.py")),
                    "resume",
                    "--case-dir",
                    str(case_dir),
                ],
                cwd=other_directory,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, resumed.returncode, resumed.stderr)
            document = json.loads(resumed.stdout)
            mounts = self.assert_envelope(document, "mounts")
            self.assertEqual(str(mount_root.resolve()), mounts[0]["path"])
            self.assertTrue(mounts[0]["exists"])

    def test_case_state_concurrent_jsonl_records_are_not_lost(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            self.run_json("case_state.py", "init", "--case-dir", case_dir)
            self.run_json("case_state.py", "acknowledge-plaintext-risk", "--case-dir", case_dir)
            script = self.require_script("case_state.py")
            requests = []
            for index in range(8):
                requests.extend([
                    ("record-command", "--text", f"command-{index}"),
                    ("record-finding", "--text", f"finding-{index}"),
                    ("record-secret", "--name", f"secret-{index}", "--stdin", f"value-{index}"),
                    ("record-cleanup", "--text", f"cleanup-{index}"),
                ])
            from concurrent.futures import ThreadPoolExecutor

            def invoke(request: tuple[str, ...]) -> tuple[tuple[str, ...], int, str]:
                command = request
                input_text = None
                if request[0] == "record-secret":
                    command = request[:-1]
                    input_text = request[-1]
                completed = subprocess.run(
                    [sys.executable, str(script), command[0], "--case-dir", str(case_dir), *command[1:]],
                    cwd=SKILL_ROOT, text=True, input=input_text,
                    capture_output=True, check=False,
                )
                return request, completed.returncode, completed.stderr

            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(invoke, requests))
            failures = [result for result in results if result[1] != 0]
            self.assertEqual([], failures, "concurrent mutation stderr must remain visible")
            for name, expected in (("commands.jsonl", 16), ("findings.jsonl", 8), ("secrets.jsonl", 8)):
                records = [line for line in (case_dir / name).read_text(encoding="utf-8").splitlines() if line]
                self.assertEqual(expected, len(records), name)
            cleanup = json.loads((case_dir / "session.json").read_text(encoding="utf-8"))["cleanup"]
            self.assertEqual(8, cleanup["total_count"])
            self.assertEqual((case_dir / "commands.jsonl").resolve(), Path(cleanup["details_path"]))
            self.assertFalse((case_dir / ".case-state-lock").exists(), "case mutex is removed after mutation")

    def test_runtime_case_artifacts_are_not_part_of_the_skill_release(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("./tmp/windows-loader/<case-id>/", skill)
        release_files = [
            path.relative_to(SKILL_ROOT)
            for path in SKILL_ROOT.rglob("*")
            if path.is_file()
        ]
        runtime_names = {
            "session.json",
            "commands.jsonl",
            "findings.jsonl",
            "secrets.jsonl",
            "inspect.json",
            "mounts.json",
        }
        leaked = [
            str(path)
            for path in release_files
            if "tmp" in path.parts or path.name in runtime_names
        ]
        self.assertEqual([], leaked, "runtime case artifacts stay outside the skill release")

    def test_static_safety_contract_and_mount_references(self) -> None:
        for name in ("mount-windows.md", "mount-linux.md", "mount-wsl.md"):
            text = self.require_reference(name).read_text(encoding="utf-8").lower()
            for required in ("read-only", "verify", "cleanup"):
                self.assertIn(required, text, f"{name}: {required}")
            for forbidden_default in (
                "default action: remove_hiberfile", "default action: ntfsfix",
                "default action: repair", "default action: initialize",
            ):
                self.assertNotIn(forbidden_default, text, f"{name}: {forbidden_default}")

        authorization = self.require_reference("install-authorization.md").read_text(encoding="utf-8")
        for required_line in (
            "INSTALL_PLAN_APPROVAL: IMMUTABLE_EXACT_PLAN_ID_REQUIRED",
            "PLAN_CHANGE: NEW_PLAN_ID_REQUIRED",
            "TRANSPORT_ONLY_FALLBACK: APPROVED_PLAN_REQUIRED",
        ):
            self.assertIn(required_line, authorization)
        gates = self.require_reference("safety-gates.md").read_text(encoding="utf-8")
        for required_line in (
            "BITLOCKER: CONFIRMATION_REQUIRED",
            "VSS: CONFIRMATION_REQUIRED",
            "DPAPI: CONFIRMATION_REQUIRED",
            "FOUR_ROUTE_FALLBACK: PRESENT_ALL_ROUTES; AGENT_CHOICE: PROHIBITED",
            "GENERIC_CONFIRMATION_ACCEPTED: NO",
            "ORIGINAL_WRITE_FIRST_CONFIRMATION: PREFIX I_CONFIRM_ORIGINAL_WRITE + EXACT_ABSOLUTE_PATH",
            "ORIGINAL_WRITE_SECOND_CONFIRMATION: PREFIX I_CONFIRM_COMMAND + EXACT_ABSOLUTE_PATH + FULL_COMMAND",
        ):
            self.assertIn(required_line, gates)

    def test_task4_documentation_contract_is_complete_and_cross_linked(self) -> None:
        """Keep the operator-facing v1 safety contract independently reviewable."""
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        frontmatter = re.match(r"\A---\n(?P<body>.*?)\n---\n", skill, re.DOTALL)
        self.assertIsNotNone(frontmatter, "SKILL.md requires YAML frontmatter")
        fields = [line.split(":", 1)[0] for line in frontmatter.group("body").splitlines() if ":" in line]
        self.assertEqual(["name", "description"], fields, "only name and description belong in frontmatter")
        self.assertRegex(frontmatter.group("body"), r"(?m)^description: Use when\b")
        self.assertNotIn("[TODO", skill)

        references = {
            "mount-windows.md": (
                "WINDOWS_VHD_ROUTE: Mount-DiskImage -Access ReadOnly",
                "WINDOWS_RAW_E01_PRIMARY: Arsenal Image Mounter",
                "WINDOWS_RAW_E01_FALLBACK: OSFMount",
                "VERSION_HELP_PROBE_REQUIRED",
                "Get-Command", "Get-Help Mount-DiskImage -Full", "$disks[0].IsReadOnly",
                "Dismount-DiskImage", "Get-DiskImage -ImagePath $image",
                "## 常见失败与清理",
                "PARTIAL_FAILURE: IMMEDIATE_CLEANUP",
                "SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP",
            ),
            "mount-linux.md": (
                "LINUX_RAW_ROUTE: losetup --read-only --partscan",
                "LINUX_OFFSET_ROUTE: mount -o ro,offset=",
                "LINUX_E01_ROUTE: libewf",
                "LINUX_E01_EXPORT: SIZE_TIME_SPACE_APPROVAL_REQUIRED",
                "LINUX_VHD_ROUTE: qemu-nbd --read-only",
                "ntfs-3g -o ro,norecover",
                "command -v", "RO=1", "findmnt", "sudo umount", "## 常见失败与清理",
                "PARTIAL_FAILURE: IMMEDIATE_CLEANUP",
                "SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP",
            ),
            "mount-wsl.md": (
                "WSL_WINDOWS_PATH_CONVERSION: wslpath",
                "WSL_PREFLIGHT: sudo + loop + nbd + FUSE + kernel",
                "WSL_INCAPABLE: ASK_USER_TO_RESTART_IN_WINDOWS_ONLY",
                "WSL_AUTO_SWITCH: PROHIBITED",
                "wslpath", "RO=1", "findmnt", "sudo umount", "## 无能力、常见失败与 cleanup",
                "PARTIAL_FAILURE: IMMEDIATE_CLEANUP",
                "SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP",
            ),
            "install-authorization.md": (
                "PLAN_FIELDS: tool, source, version_or_channel, commands, scope, privileges, uac_driver_service_reboot_effects",
                "APPROVAL: EXACT_INSTALL_PLAN_ID_ONLY",
                "PLAN_CHANGE: NEW_PLAN_ID_REQUIRED",
                "TRANSPORT_ONLY_FALLBACK: curl|wget|Invoke-WebRequest|BITS",
                "TRANSPORT_ONLY_FALLBACK: APPROVED_PLAN_REQUIRED",
                "PREAPPROVED_TRANSPORT_ALTERNATIVES_ONLY",
                "LINUX_PACKAGE_MANAGER_ROUTING: REQUIRED",
            ),
            "safety-gates.md": (
                "FOUR_ROUTE_FALLBACK: PRESENT_ALL_ROUTES; AGENT_CHOICE: PROHIBITED",
                "ORIGINAL_WRITE: TWO_CONFIRMATIONS_REQUIRED",
                "ORIGINAL_WRITE_FIRST_CONFIRMATION: PREFIX I_CONFIRM_ORIGINAL_WRITE + EXACT_ABSOLUTE_PATH",
                "ORIGINAL_WRITE_SECOND_CONFIRMATION: PREFIX I_CONFIRM_COMMAND + EXACT_ABSOLUTE_PATH + FULL_COMMAND",
                "PRE_POST_EVIDENCE: SIZE + MTIME + AVAILABLE_HASHES",
                "LOSS_OF_PRISTINE_WARNING: REQUIRED",
                "BITLOCKER: CONFIRMATION_REQUIRED",
                "VSS: CONFIRMATION_REQUIRED",
                "DPAPI_KEYS: CONFIRMATION_REQUIRED",
                "DPAPI_TOOLS: CONFIRMATION_REQUIRED",
                "DPAPI_DECRYPT: CONFIRMATION_REQUIRED",
                "PLAINTEXT_SECRET_FIRST_WRITE_WARNING: REQUIRED",
                "ACL_TIGHTENING: PROHIBITED",
                "PERSISTENT_CASE_STATE: REQUIRED",
                "END_TURN_SUMMARY: ABSOLUTE_PATH + PLAINTEXT + MOUNT + CLEANUP",
            ),
            "windows-path-catalog.md": (
                "CATALOG_FIELDS: guest_path_segments, scope, category, priority, common_files, cautions",
                "BROWSER_HISTORY", "POWERSHELL_HISTORY", "REGISTRY_HIVES", "SERVICE_PROFILES",
                "STARTUP", "SERVICES", "SCHEDULED_TASKS", "JUMP_LISTS", "NETWORK",
            ),
            "schema.md": (
                "REQUIRED_CASE_SCHEMA_FIELDS: case_id, evidence, hash_policy, environment, format, mounts, windows_installations, users, path_hits, artifacts, routes, cleanup, errors",
                "BOUNDED_ENVELOPE: items, total_count, shown_count, truncated, details_path",
                "SEARCH_DEFAULTS: depth=4, limit=50, follow_reparse=false",
                "ACL_ERROR: NOT_EVIDENCE_OF_ABSENCE",
            ),
        }
        for name, required_lines in references.items():
            reference = self.require_reference(name)
            text = reference.read_text(encoding="utf-8")
            for required_line in required_lines:
                self.assertIn(required_line, text, f"{name}: {required_line}")
            self.assertRegex(text, r"https?://", f"{name}: cite an official/project source")
            if len(text.splitlines()) > 100:
                self.assertRegex(text, r"(?im)^##\s+(目录|table of contents)\b", f"{name}: long references need a TOC")
            self.assertIn(f"./references/{name}", skill, f"SKILL.md must directly link {name}")

        for required_line in (
            "SUPPORTED_FORMATS: raw, dd, img, E01, split E01, VHD, VHDX",
            "MODES: mount-only, fast-path, mount-and-analyze",
            "HASH_POLICY: now, later, skip",
            "CURRENT_TERMINAL_REFERENCE: SELECT_EXACTLY_ONE_OF_WINDOWS_LINUX_WSL",
            "REFERENCE_ADAPTERS: PROHIBITED",
            "TERMINAL_AUTO_SWITCH: PROHIBITED",
            "SEARCH: TWO_STAGE_BOUNDED",
            "NO_FORMAL_REPORT",
        ):
            self.assertIn(required_line, skill)

        config = (SKILL_ROOT / "agents" / "openai.yaml").read_text(encoding="utf-8")
        self.assertEqual(
            [
                "interface:",
                '  display_name: "Windows Loader"',
                '  short_description: "Read-only Windows guest image mounting and focused forensic triage."',
                '  default_prompt: "Use $windows-loader to mount this Windows guest image read-only and perform focused evidence triage."',
            ],
            [line for line in config.splitlines() if line],
            "openai.yaml exposes only quoted interface fields",
        )
        self.assertRegex(config, r'(?m)^interface:$')
        self.assertRegex(config, r'(?m)^  display_name: "[^"]+"$')
        self.assertRegex(config, r'(?m)^  short_description: "[^"]+"$')
        self.assertIn('default_prompt: "Use $windows-loader', config)
        self.assertNotIn("Use -loader", config)
        self.assertIn("# Windows Loader v1", skill)

    def test_task4_reviewed_contract_has_reproducible_state_routes_and_sources(self) -> None:
        """Exercise the reviewed document contract as structured operator data."""
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        schema = self.require_reference("schema.md").read_text(encoding="utf-8")
        authorization = self.require_reference("install-authorization.md").read_text(encoding="utf-8")
        windows = self.require_reference("mount-windows.md").read_text(encoding="utf-8")
        wsl = self.require_reference("mount-wsl.md").read_text(encoding="utf-8")
        catalog = self.require_reference("windows-path-catalog.md").read_text(encoding="utf-8")
        gates = self.require_reference("safety-gates.md").read_text(encoding="utf-8")

        required_schema = [
            "case_id", "evidence", "hash_policy", "environment", "format", "mounts",
            "windows_installations", "users", "path_hits", "artifacts", "routes", "cleanup", "errors",
        ]
        schema_match = re.search(r"```json CASE_SCHEMA_REQUIRED_FIELDS\n(?P<fields>\[.*?\])\n```", schema, re.DOTALL)
        self.assertIsNotNone(schema_match, "schema must publish its exact required field vector")
        self.assertEqual(required_schema, json.loads(schema_match.group("fields")))
        self.assertIn("OPTIONAL_CLI_FIELDS: EXTENSIONS_NOT_SUBSTITUTIONS", schema)

        required_case_files = [
            "session.json", "notes.md", "commands.jsonl", "findings.jsonl", "secrets.jsonl",
            "inspect.json", "mounts.json", "raw/",
        ]
        for text in (skill, schema):
            self.assertIn("./tmp/windows-loader/<case-id>/", text)
            for name in required_case_files:
                self.assertIn(name, text)
        for trigger in ("mount", "install", "long scan", "multi-turn", "large artifact", "imminent context compression"):
            self.assertIn(trigger, skill.lower(), f"automatic case-state trigger: {trigger}")

        plan_match = re.search(r"```json canonical-plan\.json\n(?P<plan>\{.*?\})\n```", authorization, re.DOTALL)
        self.assertIsNotNone(plan_match, "authorization must provide a reproducible canonical plan example")
        plan = json.loads(plan_match.group("plan"))
        self.assertEqual(
            ["commands", "privileges", "scope", "source", "tool", "uac_driver_service_reboot_effects", "version_or_channel"],
            sorted(plan),
        )
        self.assertIsInstance(plan["commands"], list)
        canonical = json.dumps(plan, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        digest = hashlib.sha256(canonical).hexdigest()
        self.assertIn(f"INSTALL_PLAN_ID_EXAMPLE_SHA256: {digest}", authorization)
        changed = dict(plan)
        changed["scope"] = "machine"
        changed_canonical = json.dumps(changed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
        self.assertNotEqual(digest, hashlib.sha256(changed_canonical).hexdigest(), "field changes invalidate approval")
        self.assertIn("CANONICAL_UTF8_JSON: SORTED_KEYS + STABLE_COMMAND_ARRAY_ORDER + COMPACT_SEPARATORS + LF", authorization)
        alternatives_match = re.search(
            r"```json TRANSPORT_ALTERNATIVES_OBJECT\n(?P<object>\{.*?\})\n```",
            authorization,
            re.DOTALL,
        )
        self.assertIsNotNone(alternatives_match)
        alternatives = json.loads(alternatives_match.group("object"))
        self.assertEqual("one_of", alternatives["type"])
        self.assertIsInstance(alternatives["alternatives"], list)
        self.assertGreaterEqual(len(alternatives["alternatives"]), 2)
        self.assertTrue(all(isinstance(command, str) and command for command in alternatives["alternatives"]))
        self.assertIn("SEQUENTIAL_COMMANDS_REMAIN_DISTINCT", authorization)

        lower_wsl = wsl.lower()
        for forbidden in ("wsl.exe", "powershell.exe", "cmd.exe"):
            self.assertNotIn(forbidden, lower_wsl, f"WSL reference must not invoke Windows executable: {forbidden}")
        for required in ("uname -a", "/proc/version", "/proc/sys/kernel/osrelease"):
            self.assertIn(required, lower_wsl)

        self.assertIn("$diskImage = Mount-DiskImage -ImagePath $image -Access ReadOnly -PassThru", windows)
        self.assertIn("$disks = @($diskImage | Get-Disk)", windows)
        self.assertIn("$disks[0].IsReadOnly", windows)
        self.assertIn("Dismount-DiskImage -ImagePath $image", windows)
        self.assertIn("aim_cli.exe", windows)
        self.assertIn("OSFMount.com", windows)
        self.assertNotIn("ArsenalImageMounter --help", windows)
        self.assertNotIn("OSFMount --help", windows)
        self.assertNotIn("四路线失败阶梯", windows)

        table_rows = [line for line in catalog.splitlines() if line.startswith("| `")]
        self.assertGreaterEqual(len(table_rows), 20, "catalog must enumerate plan paths rather than compressing them")
        for row in table_rows:
            cells = [cell.strip() for cell in row.split("|")[1:-1]]
            self.assertEqual(6, len(cells), row)
            self.assertTrue(all(cells), row)
        self.assertNotIn("...", catalog)
        for segment in (
            "Windows/System32", "Windows/SysWOW64", "Windows/System32/config/DEFAULT",
            "Windows/System32/winevt/Logs", "Windows/System32/Tasks", "Windows/Prefetch",
            "Windows/AppCompat/Programs/Amcache.hve", "Program Files (x86)", "ProgramData",
            "Users/<user>/AppData/Roaming", "Users/<user>/AppData/Local", "Users/<user>/AppData/LocalLow",
            "LocalState", "RoamingState", "Settings", "Users/<user>/Documents", "Users/<user>/Downloads",
            "Users/<user>/Saved Games", "Users/<user>/Desktop", "Google/Chrome", "Microsoft/Edge",
            "Mozilla/Firefox", "PSReadLine", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve", "SRUDB.dat",
            "systemprofile", "LocalService", "NetworkService", "Start Menu/Programs/Startup", "TaskCache",
            "AutomaticDestinations", "CustomDestinations", "Wlansvc", "NetworkList", "Windows/System32/drivers/etc/hosts",
            "Local Settings",
        ):
            self.assertIn(segment, catalog, segment)

        expected_routes = (
            "readonly diagnose/retry",
            "direct readonly extraction (TSK/libewf)",
            "estimate then working copy repair/write",
            "original-evidence repair/write",
        )
        for index, route in enumerate(expected_routes, start=1):
            self.assertIn(f"{index}. {route}", gates)
        for heading in ("availability", "risk", "user choice"):
            self.assertIn(heading, gates.lower())
        self.assertIn("确认写入原镜像: <absolute-path>", gates)
        self.assertIn("完整命令", gates)

        required_sources = {
            "mount-windows.md": {
                "https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage",
                "https://arsenalrecon.com/products/arsenal-image-mounter",
                "https://www.osforensics.com/tools/mount-disk-images.html",
            },
            "mount-linux.md": {"https://github.com/libyal/libewf", "https://qemu.readthedocs.io/en/latest/tools/qemu-nbd.html"},
            "mount-wsl.md": {"https://learn.microsoft.com/en-us/windows/wsl/wsl2-mount-disk"},
            "safety-gates.md": {"https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-portal"},
        }
        allowed_hosts = {
            "learn.microsoft.com", "docs.python.org", "qemu.readthedocs.io", "github.com",
            "arsenalrecon.com", "www.osforensics.com",
        }
        for name, required_urls in required_sources.items():
            text = self.require_reference(name).read_text(encoding="utf-8")
            for url in required_urls:
                self.assertIn(url, text, f"primary source missing from {name}: {url}")
            urls = re.findall(r"https?://[^>\s)]+", text)
            self.assertTrue(urls, f"{name}: primary source URLs required")
            self.assertTrue(all(urlparse(url).hostname in allowed_hosts for url in urls), name)

    def test_bundled_scripts_do_not_spawn_processes_or_mount(self) -> None:
        for required in (
            "inspect_evidence.py", "inspect_windows_tree.py", "find_windows_paths.py",
            "case_state.py", "analyze_artifact.py",
        ):
            self.require_script(required)
        script_files = list(SCRIPTS.rglob("*.py"))
        self.assertTrue(script_files, "bundled public scripts must exist before safety can be validated")
        for script in script_files:
            self.assert_no_unsafe_process_or_mount_routes(script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
