"""Regression tests for the final whole-branch review findings."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL_ROOT / "scripts"


def run_json(script: str, *arguments: object, input_text: str | None = None,
             env: dict[str, str] | None = None, expected_code: int = 0) -> dict:
    completed = subprocess.run(
        [sys.executable, str(SCRIPTS / script), *(str(value) for value in arguments)],
        cwd=SKILL_ROOT,
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
        env=env,
    )
    if completed.returncode != expected_code:
        raise AssertionError(
            f"{script}: expected {expected_code}, got {completed.returncode}\n"
            f"stderr:\n{completed.stderr}\nstdout:\n{completed.stdout}"
        )
    if expected_code:
        return {"stdout": completed.stdout, "stderr": completed.stderr}
    return json.loads(completed.stdout)


def load_script_module(name: str):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
        if spec is None or spec.loader is None:
            raise AssertionError(f"cannot load {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class FinalReviewRegressionCase(unittest.TestCase):
    def test_ewf_sequence_crosses_e99_to_eaa_for_inspect_hash_and_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number in range(1, 100):
                (root / f"disk.E{number:02d}").write_bytes(f"segment-{number}".encode())
            eaa = root / "disk.EAA"
            eaa.write_bytes(b"segment-100")

            inspected = run_json(
                "inspect_evidence.py", "--image", eaa, "--hash", "now", "--limit", "101",
            )
            evidence = inspected["evidence"]
            self.assertEqual("disk.E01", Path(evidence["path"]).name)
            self.assertEqual(100, evidence["segment_count"])
            names = [item["name"] for item in evidence["hash"]["segment_hashes"]["items"]]
            self.assertEqual("disk.E99", names[-2])
            self.assertEqual("disk.EAA", names[-1])

            case_dir = root / "case"
            run_json(
                "case_state.py", "init", "--case-dir", case_dir,
                "--image", eaa, "--hash", "later",
            )
            self.assertTrue(
                run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"]
            )
            eaa.unlink()
            self.assertFalse(
                run_json("case_state.py", "resume", "--case-dir", case_dir)
                ["revalidation"]["evidence_matches"]
            )

    def test_ewf_sequence_rejects_missing_lettered_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for number in range(1, 100):
                (root / f"disk.E{number:02d}").write_bytes(b"x")
            (root / "disk.EAB").write_bytes(b"gap")
            refused = run_json(
                "inspect_evidence.py", "--image", root / "disk.EAB",
                expected_code=2,
            )
            self.assertIn("contiguous", refused["stderr"].lower())

    def test_ewf_e01_entry_rejects_distant_unambiguous_faa_segment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "disk.E01"
            first.write_bytes(b"first")
            (root / "disk.FAA").write_bytes(b"distant-segment")
            refused = run_json(
                "inspect_evidence.py", "--image", first, expected_code=2,
            )
            self.assertIn("contiguous", refused["stderr"].lower())

    def test_ewf_unambiguous_nonregular_or_reparse_candidate_fails_closed(self) -> None:
        module = load_script_module("common")
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "disk.E01"
            first.write_bytes(b"first")

            class Candidate:
                stem = "disk"
                suffix = ".FAA"
                name = "disk.FAA"

                @staticmethod
                def is_file() -> bool:
                    return False

            candidate = Candidate()
            for reparsed, message in ((True, "reparse"), (False, "regular")):
                with self.subTest(reparsed=reparsed):
                    with mock.patch.object(
                        Path,
                        "iterdir",
                        return_value=iter((first, candidate)),
                    ), mock.patch.object(
                        module,
                        "is_reparse",
                        side_effect=lambda path, target=candidate, value=reparsed: (
                            value if path is target else False
                        ),
                    ):
                        with self.assertRaisesRegex(ValueError, message):
                            module.evidence_segments(first)

    def test_ewf_nonregular_or_reparse_fixed_format_collision_fails_closed(self) -> None:
        module = load_script_module("common")
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "disk.E01"
            first.write_bytes(b"first")

            class Collision:
                stem = "disk"
                suffix = ".raw"
                name = "disk.raw"

                @staticmethod
                def is_file() -> bool:
                    return False

            collision = Collision()
            for reparsed, message in ((True, "reparse"), (False, "regular")):
                with self.subTest(reparsed=reparsed):
                    with mock.patch.object(
                        Path,
                        "iterdir",
                        return_value=iter((first, collision)),
                    ), mock.patch.object(
                        module,
                        "is_reparse",
                        side_effect=lambda path, target=collision, value=reparsed: (
                            value if path is target else False
                        ),
                    ):
                        with self.assertRaisesRegex(ValueError, message):
                            module.evidence_segments(first)

    def test_ewf_index_covers_all_letter_blocks_and_disambiguates_fixed_suffixes(self) -> None:
        module = load_script_module("common")
        expected = {
            "disk.E01": 1,
            "disk.E99": 99,
            "disk.EAA": 100,
            "disk.EZZ": 775,
            "disk.FAA": 776,
            "disk.ZZZ": 14971,
        }
        for name, index in expected.items():
            self.assertEqual(index, module.ewf_segment_index(Path(name)), name)
            self.assertEqual(
                Path(name).suffix.removeprefix("."),
                module.ewf_segment_extension(index),
                name,
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("disk.E01", "disk.VHC", "disk.VHD"):
                (root / name).write_bytes(b"x")
            self.assertEqual("e01", module.infer_evidence_format(root / "disk.VHD"))

    def test_sqlite_sidecars_are_detected_and_never_silently_reported_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "History"
            connection = sqlite3.connect(database)
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute("CREATE TABLE visits (url TEXT)")
                connection.commit()
                connection.execute("INSERT INTO visits VALUES ('wal-only.example')")
                connection.commit()
                self.assertTrue(Path(str(database) + "-wal").is_file())

                result = run_json(
                    "analyze_artifact.py", "structured", "--kind", "sqlite",
                    "--input", database,
                )
            finally:
                connection.close()

            artifact = result["artifact"]
            self.assertEqual("incomplete-sidecars-not-applied", artifact["completeness"])
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertGreaterEqual(result["sidecars"]["total_count"], 1)
            self.assertIn("-wal", json.dumps(result["sidecars"]).lower())
            self.assertIn("sidecar", json.dumps(result["errors"]).lower())
            self.assertNotIn("wal-only.example", json.dumps(result))

    def test_binary_evtx_parser_exception_is_failed_and_not_high_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "Evtx"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "Evtx.py").write_text(
                "class Evtx:\n"
                "    def __init__(self, path): raise RuntimeError('forced-parser-failure')\n",
                encoding="utf-8",
            )
            binary = root / "Security.evtx"
            binary.write_bytes(b"ElfFile\x00synthetic-binary")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", binary, env=env,
            )
            artifact = result["artifact"]
            self.assertIn(artifact["parser_status"], {"failed", "unavailable"})
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertNotEqual("complete", artifact["completeness"])
            self.assertIn("python-evtx", json.dumps(artifact["attempts"]).lower())
            self.assertIn("forced-parser-failure", json.dumps(result["errors"]).lower())

    def test_binary_evtx_malformed_record_xml_downgrades_parser_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "Evtx"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "Evtx.py").write_text(
                "class Record:\n"
                "    def xml(self): return '<Event>'\n"
                "class Evtx:\n"
                "    def __init__(self, path): self.path = path\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *args): return False\n"
                "    def records(self): return [Record()]\n",
                encoding="utf-8",
            )
            binary = root / "Security.evtx"
            binary.write_bytes(b"ElfFile\x00synthetic-binary")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", binary, env=env,
            )
            artifact = result["artifact"]
            self.assertNotEqual("succeeded", artifact["parser_status"])
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertTrue(artifact["completeness"].startswith("incomplete"))
            attempt = artifact["attempts"][0]
            self.assertNotEqual("succeeded", attempt["status"])
            self.assertEqual(1, attempt["records_attempted"])
            self.assertEqual(0, attempt["records_parsed"])
            self.assertEqual(1, attempt["records_failed"])
            self.assertIn("xml", json.dumps(result["errors"]).lower())

    def test_binary_evtx_mixed_records_report_attempted_parsed_and_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "Evtx"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "Evtx.py").write_text(
                "class Record:\n"
                "    def __init__(self, xml): self._xml = xml\n"
                "    def xml(self): return self._xml\n"
                "class Evtx:\n"
                "    def __init__(self, path): self.path = path\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *args): return False\n"
                "    def records(self):\n"
                "        return [\n"
                "            Record('<Event><System><EventID>1</EventID></System></Event>'),\n"
                "            Record('<Event>'),\n"
                "        ]\n",
                encoding="utf-8",
            )
            binary = root / "Security.evtx"
            binary.write_bytes(b"ElfFile\x00synthetic-binary")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", binary, env=env,
            )
            artifact = result["artifact"]
            self.assertEqual("partial-failed", artifact["parser_status"])
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertEqual("incomplete-record-errors", artifact["completeness"])
            attempt = artifact["attempts"][0]
            self.assertEqual(2, attempt["records_attempted"])
            self.assertEqual(1, attempt["records_parsed"])
            self.assertEqual(1, attempt["records_failed"])

    def test_binary_evtx_valid_record_keeps_success_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "Evtx"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "Evtx.py").write_text(
                "class Record:\n"
                "    def xml(self):\n"
                "        return '<Event><System><EventID>1</EventID></System></Event>'\n"
                "class Evtx:\n"
                "    def __init__(self, path): self.path = path\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *args): return False\n"
                "    def records(self): return [Record()]\n",
                encoding="utf-8",
            )
            binary = root / "Security.evtx"
            binary.write_bytes(b"ElfFile\x00synthetic-binary")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", binary, env=env,
            )
            artifact = result["artifact"]
            self.assertEqual("succeeded", artifact["parser_status"])
            self.assertEqual("parser-high", artifact["confidence"])
            self.assertEqual("complete-with-python-evtx", artifact["completeness"])
            self.assertEqual([], result["errors"]["items"])
            attempt = artifact["attempts"][0]
            self.assertEqual(1, attempt["records_attempted"])
            self.assertEqual(1, attempt["records_parsed"])
            self.assertEqual(0, attempt["records_failed"])

    def test_large_binary_evtx_probe_truncation_does_not_downgrade_valid_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "Evtx"
            package.mkdir()
            (package / "__init__.py").write_text("", encoding="utf-8")
            (package / "Evtx.py").write_text(
                "class Record:\n"
                "    def xml(self):\n"
                "        return '<Event><System><EventID>1</EventID></System></Event>'\n"
                "class Evtx:\n"
                "    def __init__(self, path): self.path = path\n"
                "    def __enter__(self): return self\n"
                "    def __exit__(self, *args): return False\n"
                "    def records(self): return [Record()]\n",
                encoding="utf-8",
            )
            binary = root / "Security.evtx"
            binary.write_bytes(
                b"ElfFile\x00" + b"x" * (1024 * 1024 + 100)
            )
            env = os.environ.copy()
            env["PYTHONPATH"] = str(root)
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", binary, env=env,
            )
            artifact = result["artifact"]
            self.assertEqual("succeeded", artifact["parser_status"])
            self.assertEqual("parser-high", artifact["confidence"])
            self.assertEqual("complete-with-python-evtx", artifact["completeness"])
            attempt = artifact["attempts"][0]
            self.assertEqual(1, attempt["records_attempted"])
            self.assertEqual(1, attempt["records_parsed"])
            self.assertEqual(0, attempt["records_failed"])
            self.assertNotIn("prefix", json.dumps(result["errors"]).lower())

    def test_large_synthetic_evtx_probe_truncation_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "events.evtx.json"
            source.write_text(
                '{"events":[{"event_id":1,"message":"'
                + ("x" * (1024 * 1024 + 100))
                + '"}]}',
                encoding="utf-8",
            )
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", source,
            )
            artifact = result["artifact"]
            self.assertNotEqual("succeeded", artifact["parser_status"])
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertTrue(artifact["completeness"].startswith("incomplete"))
            self.assertIn("prefix", json.dumps(result["errors"]).lower())

    def test_evtx_filter_boundary_error_does_not_rewrite_parser_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "events.evtx.json"
            source.write_text(
                '{"events":[{"event_id":1,"timestamp":"2026-01-01T00:00:00Z"}]}',
                encoding="utf-8",
            )
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", source,
                "--from", "not-a-time",
            )
            artifact = result["artifact"]
            self.assertEqual("succeeded", artifact["parser_status"])
            self.assertEqual("fixture-only", artifact["confidence"])
            self.assertEqual("synthetic-fixture-complete", artifact["completeness"])
            self.assertIn("invalid --from", json.dumps(result["errors"]).lower())

    def test_synthetic_evtx_parse_errors_downgrade_fixture_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "events.evtx.json"
            source.write_text('{"events": [', encoding="utf-8")
            result = run_json(
                "analyze_artifact.py", "evtx", "--input", source,
            )
            artifact = result["artifact"]
            self.assertNotEqual("succeeded", artifact["parser_status"])
            self.assertNotEqual("parser-high", artifact["confidence"])
            self.assertTrue(artifact["completeness"].startswith("incomplete"))
            self.assertNotEqual("succeeded", artifact["attempts"][0]["status"])
            self.assertTrue(result["errors"]["items"])

    def test_structured_parse_errors_and_prefix_truncation_are_never_complete_or_high(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malformed = {
                "json": ("broken.json", '{"unterminated": '),
                "xml": ("broken.xml", "<root>"),
                "ini": ("broken.ini", "value-without-section"),
            }
            for kind, (name, contents) in malformed.items():
                with self.subTest(kind=kind):
                    source = root / name
                    source.write_text(contents, encoding="utf-8")
                    result = run_json(
                        "analyze_artifact.py", "structured", "--kind", kind,
                        "--input", source,
                    )
                    self.assertNotEqual("parser-high", result["artifact"]["confidence"])
                    self.assertIn(
                        result["artifact"]["parser_status"],
                        {"failed", "partial-failed"},
                    )
                    self.assertTrue(
                        result["artifact"]["completeness"].startswith("incomplete")
                    )
                    self.assertTrue(result["errors"]["items"])

            oversized = root / "oversized.json"
            oversized.write_text(
                '{"value":"' + ("x" * (1024 * 1024 + 100)) + '"}',
                encoding="utf-8",
            )
            result = run_json(
                "analyze_artifact.py", "structured", "--kind", "json",
                "--input", oversized,
            )
            self.assertNotEqual("parser-high", result["artifact"]["confidence"])
            self.assertIn(
                result["artifact"]["parser_status"],
                {"failed", "partial-failed"},
            )
            self.assertTrue(result["artifact"]["completeness"].startswith("incomplete"))
            self.assertIn("prefix", json.dumps(result["errors"]).lower())

            valid = root / "valid.json"
            valid.write_text('{"ok": true}', encoding="utf-8")
            succeeded = run_json(
                "analyze_artifact.py", "structured", "--kind", "json",
                "--input", valid,
            )
            self.assertEqual("succeeded", succeeded["artifact"]["parser_status"])

    def test_registry_dpapi_detection_uses_original_binary_and_base64_values(self) -> None:
        module = load_script_module("analyze_artifact")
        binary = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdfprotected"
        binary_record = module.registry_value_record("HKCU\\Software\\Demo", "blob", binary)
        base64_record = module.registry_value_record(
            "HKCU\\Software\\Demo", "encoded", "AQAAANCMnd8BFdERAAAAAA",
        )
        self.assertEqual("likely-dpapi", binary_record["protection"])
        self.assertEqual("likely-dpapi", base64_record["protection"])
        self.assertNotIn("decrypted", json.dumps([binary_record, base64_record]).lower())
        self.assertLess(len(binary_record["value"]), 1024)

        with tempfile.TemporaryDirectory() as temporary:
            hive = Path(temporary) / "NTUSER.DAT"
            hive.write_bytes(b"prefix:" + binary + b":AQAAANCMnd8BFdERAAAAAA")
            result = run_json(
                "analyze_artifact.py", "registry", "--input", hive, "--limit", "10",
            )
            protected = [
                record for record in result["records"]["items"]
                if record.get("protection") == "likely-dpapi"
            ]
            self.assertGreaterEqual(len(protected), 2)

    def test_registry_dpapi_signatures_are_prioritized_inside_the_result_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            hive = Path(temporary) / "NTUSER.DAT"
            decoys = b":".join(f"ordinary-value-{index}".encode() for index in range(100))
            hive.write_bytes(
                decoys
                + b"\x01\x00\x00\x00\xd0\x8c\x9d\xdfbinary"
                + b"AQAAANCMnd8BFdERAAAAAA"
            )
            result = run_json(
                "analyze_artifact.py", "registry", "--input", hive, "--limit", "2",
            )
            records = result["records"]["items"]
            self.assertEqual(2, len(records))
            self.assertTrue(all(
                record.get("protection") == "likely-dpapi"
                for record in records
            ))

    def test_windows_vhd_recipe_detaches_exact_image_on_every_unsuccessful_path(self) -> None:
        reference = (SKILL_ROOT / "references" / "mount-windows.md").read_text(encoding="utf-8")
        compact = " ".join(reference.split())
        for token in (
            "try {", "catch {", "finally {", "$diskImage.Attached",
            "@($diskImage | Get-Disk)", "$disks.Count -eq 1",
            "$disks[0].IsReadOnly", "Dismount-DiskImage -ImagePath $image",
        ):
            self.assertIn(token, compact)
        self.assertIn("$verified = $true", compact)
        self.assertRegex(
            compact,
            r"finally \{.*if \(-not \$verified\).*Dismount-DiskImage -ImagePath \$image",
        )
        self.assertNotIn("Dismount-DiskImage -ImagePath $diskImage.ImagePath", compact)
        self.assertGreater(
            compact.index("$verified = $true"),
            compact.index("$disks[0] | Select-Object"),
            "the success flag must be the last operation before finally",
        )

    def test_record_secret_has_no_command_line_value_and_persists_stdin_after_ack(self) -> None:
        help_text = subprocess.run(
            [sys.executable, str(SCRIPTS / "case_state.py"), "record-secret", "--help"],
            cwd=SKILL_ROOT, text=True, capture_output=True, check=False,
        ).stdout
        self.assertNotIn("--value", help_text)
        self.assertIn("--stdin", help_text)
        self.assertNotIn("--prompt", help_text)

        with tempfile.TemporaryDirectory() as temporary:
            case_dir = Path(temporary) / "case"
            run_json("case_state.py", "init", "--case-dir", case_dir)
            refused = run_json(
                "case_state.py", "record-secret", "--case-dir", case_dir,
                "--name", "token", "--stdin", input_text="complete-secret",
                expected_code=2,
            )
            self.assertIn("acknowledge", refused["stderr"].lower())
            run_json("case_state.py", "acknowledge-plaintext-risk", "--case-dir", case_dir)
            completed = run_json(
                "case_state.py", "record-secret", "--case-dir", case_dir,
                "--name", "token", "--stdin", input_text="complete-secret",
            )
            self.assertNotIn("complete-secret", json.dumps(completed))
            self.assertIn(
                '"value": "complete-secret"',
                (case_dir / "secrets.jsonl").read_text(encoding="utf-8"),
            )

    def test_public_path_kind_contract_and_scan_order_limit_are_explicit(self) -> None:
        help_text = subprocess.run(
            [sys.executable, str(SCRIPTS / "find_windows_paths.py"), "--help"],
            cwd=SKILL_ROOT, text=True, capture_output=True, check=False,
        ).stdout
        self.assertIn("{all,config,data,logs,secret}", help_text)
        self.assertNotIn("executable", help_text)
        self.assertNotIn("{any,", help_text)
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("HOST_ENUMERATION_ORDER_LIMITATION", skill)
        module = load_script_module("common")
        scan = module.ScanSummary(depth_limit=4, entry_budget=50).document()
        self.assertEqual("host-filesystem-order", scan["enumeration_order"])
        self.assertFalse(scan["deterministic_order_guaranteed"])

    def test_available_hash_algorithms_are_recorded_without_hashing_later_or_skip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "disk.raw"
            image.write_bytes(b"evidence")
            for policy in ("later", "skip"):
                inspected = run_json(
                    "inspect_evidence.py", "--image", image, "--hash", policy,
                )
                self.assertEqual(["sha256"], inspected["available_hash_algorithms"])
                self.assertEqual(["sha256"], inspected["evidence"]["available_hash_algorithms"])
                self.assertNotIn("sha256", inspected["evidence"])

                case_dir = root / f"case-{policy}"
                run_json(
                    "case_state.py", "init", "--case-dir", case_dir,
                    "--image", image, "--hash", policy,
                )
                session = json.loads((case_dir / "session.json").read_text(encoding="utf-8"))
                self.assertEqual(["sha256"], session["available_hash_algorithms"])
                self.assertEqual(["sha256"], session["evidence"]["available_hash_algorithms"])
                self.assertNotIn("hash", session["evidence"])
                self.assertNotIn("sha256", session["evidence"])


if __name__ == "__main__":
    unittest.main()
