import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    path = ROOT / "scripts" / name
    if not path.exists():
        raise AssertionError(f"missing script: {path}")
    spec = importlib.util.spec_from_file_location(name.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class InspectEvidenceContractTests(unittest.TestCase):
    def test_hash_policy_supports_skip_later_and_selected_algorithms(self):
        inspect = load_script("inspect_evidence.py")

        self.assertEqual(inspect.parse_hash_policy("none"), {"mode": "skip", "algorithms": []})
        self.assertEqual(inspect.parse_hash_policy("later"), {"mode": "later", "algorithms": []})
        self.assertEqual(
            inspect.parse_hash_policy("md5,sha256"),
            {"mode": "now", "algorithms": ["md5", "sha256"]},
        )

    def test_bounded_summary_reports_counts_and_truncation(self):
        inspect = load_script("inspect_evidence.py")

        summary = inspect.bounded_items(["a", "b", "c"], limit=2, details_path="/tmp/details.json")

        self.assertEqual(summary["items"], ["a", "b"])
        self.assertEqual(summary["total_count"], 3)
        self.assertEqual(summary["shown_count"], 2)
        self.assertTrue(summary["truncated"])
        self.assertEqual(summary["details_path"], "/tmp/details.json")

    def test_non_system_data_disk_is_classified_without_os_anchors(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "var/www/site").mkdir(parents=True)
            (root / "var/lib/mysql").mkdir(parents=True)

            result = inspect.classify_image_role(root)

        self.assertEqual(result["role"], "data")
        self.assertGreaterEqual(result["confidence"], 0.5)
        self.assertIn("/var/www", result["evidence"])

    def test_reference_routing_is_minimal_and_reasoned(self):
        inspect = load_script("inspect_evidence.py")
        triage = {
            "panels": {"bt": {"detected": False}, "onepanel": {"detected": True}},
            "docker": {"detected": True},
            "services": {"web": {"detected": False}, "database": {"detected": False}},
            "goals": [],
        }

        refs = inspect.recommend_references(triage)
        names = [ref["file"] for ref in refs]

        self.assertIn("panel-1panel.md", names)
        self.assertIn("docker-linux.md", names)
        self.assertNotIn("panel-bt.md", names)
        self.assertTrue(all("priority" in ref and "reason" in ref for ref in refs))

    def test_ewf_export_estimate_reports_size_time_and_space(self):
        inspect = load_script("inspect_evidence.py")

        estimate = inspect.estimate_ewf_export(media_size=500 * 1024**3, free_space=600 * 1024**3, throughput_mib_s=100)

        self.assertEqual(estimate["estimated_export_size"], 500 * 1024**3)
        self.assertTrue(estimate["space_available"])
        self.assertGreater(estimate["estimated_export_seconds"], 0)

    def test_docker_mount_mappings_include_business_data_tags(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            data_root = Path(td)
            container_dir = data_root / "containers" / "abc"
            container_dir.mkdir(parents=True)
            (container_dir / "config.v2.json").write_text(
                json.dumps({"Name": "/web", "Config": {"Image": "nginx:latest"}, "MountPoints": {}}),
                encoding="utf-8",
            )
            (container_dir / "hostconfig.json").write_text(
                json.dumps({"Binds": ["/srv/site:/usr/share/nginx/html:ro"]}),
                encoding="utf-8",
            )

            mappings = inspect.extract_docker_mount_mappings(data_root)

        self.assertEqual(mappings[0]["container_id"], "abc")
        self.assertEqual(mappings[0]["container_path"], "/usr/share/nginx/html")
        self.assertEqual(mappings[0]["source"], "/srv/site")
        self.assertIn("web", mappings[0]["likely_business_data"])

    def test_docker_mount_mappings_resolve_sources_inside_evidence_root(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "srv/site").mkdir(parents=True)
            data_root = root / "var/lib/docker"
            container_dir = data_root / "containers" / "abc"
            container_dir.mkdir(parents=True)
            (container_dir / "config.v2.json").write_text(
                json.dumps({"Name": "/web", "Config": {"Image": "nginx:latest"}, "MountPoints": {}}),
                encoding="utf-8",
            )
            (container_dir / "hostconfig.json").write_text(
                json.dumps({"Binds": ["/srv/site:/usr/share/nginx/html:ro"]}),
                encoding="utf-8",
            )

            mappings = inspect.extract_docker_mount_mappings(data_root, evidence_root=root)

        self.assertTrue(mappings[0]["source_exists"])

    def test_mounted_tree_inspection_has_required_compact_contract_fields(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "etc").mkdir()
            (root / "var/www/site").mkdir(parents=True)
            (root / "etc/os-release").write_text('PRETTY_NAME="Fixture Linux"\n', encoding="utf-8")

            result = inspect.inspect_path(
                root,
                inspect.parse_hash_policy("none"),
                case_id="fixture",
                output_dir=Path(td) / "out",
            )

        for field in [
            "schema_version",
            "case_id",
            "evidence_file",
            "case_paths",
            "tools",
            "preflight",
            "format",
            "services",
            "paths",
            "routes",
            "errors",
        ]:
            self.assertIn(field, result)
        self.assertEqual(result["image_role"], "mixed")
        self.assertIn("web-recovery.md", [ref["file"] for ref in result["routes"]["recommended_references"]])

    def test_find_named_files_accepts_relative_base_without_crash(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "relbase" / "sub").mkdir(parents=True)
            (Path(td) / "relbase" / "sub" / "docker-compose.yml").write_text("x: 1\n", encoding="utf-8")
            previous_cwd = os.getcwd()
            os.chdir(td)
            try:
                found = inspect.find_named_files(Path("relbase"), {"docker-compose.yml"})
            finally:
                os.chdir(previous_cwd)
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].endswith("docker-compose.yml"))

    def test_triage_level_fast_skips_deep_probes(self):
        inspect = load_script("inspect_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "etc").mkdir()
            (root / "etc/os-release").write_text('PRETTY_NAME="Fixture Linux"\n', encoding="utf-8")
            (root / "www/server/panel").mkdir(parents=True)
            outdir = Path(td) / "out"

            fast = inspect.inspect_path(
                root,
                inspect.parse_hash_policy("none"),
                case_id="fast-case",
                output_dir=outdir,
                triage_level="fast",
            )
            full = inspect.inspect_path(
                root,
                inspect.parse_hash_policy("none"),
                case_id="full-case",
                output_dir=outdir,
                triage_level="full",
            )

        self.assertEqual(fast.get("triage_level"), "fast")
        self.assertTrue(fast["os_profile"].get("skipped"))
        self.assertTrue(fast["panels"].get("skipped"))
        self.assertTrue(fast["docker"].get("skipped"))
        self.assertEqual(fast["image_role"], "mixed")
        self.assertEqual(full["os_profile"].get("distribution"), "Fixture Linux")
        self.assertTrue(full["panels"]["bt"]["detected"])
        self.assertNotIn("skipped", full["panels"])


class MountEvidenceContractTests(unittest.TestCase):
    def test_mount_options_are_filesystem_specific(self):
        mount = load_script("mount_evidence.py")

        self.assertEqual(mount.mount_options_for_fs("ext4"), ["ro", "noload"])
        self.assertEqual(mount.mount_options_for_fs("xfs"), ["ro", "norecovery"])
        self.assertEqual(mount.mount_options_for_fs("btrfs"), ["ro", "norecovery", "skip_balance"])
        self.assertEqual(mount.mount_options_for_fs("unknown"), ["ro"])

    def test_resume_validation_allows_mtime_warning_but_blocks_size_mismatch(self):
        mount = load_script("mount_evidence.py")
        run_meta = {
            "evidence": {"path": "/evidence/disk.dd", "size": 100, "mtime": 1},
            "mounts": [{"mount_path": "/mnt/ev", "active": True}],
        }

        ok = mount.validate_resume(run_meta, current={"path": "/evidence/disk.dd", "size": 100, "mtime": 2}, active_mounts=["/mnt/ev"])
        bad = mount.validate_resume(run_meta, current={"path": "/evidence/disk.dd", "size": 101, "mtime": 1}, active_mounts=["/mnt/ev"])

        self.assertTrue(ok["can_resume"])
        self.assertIn("mtime", ok["warnings"][0])
        self.assertFalse(bad["can_resume"])
        self.assertIn("size", bad["blockers"][0])

    def test_mount_root_conflict_uses_case_specific_alternate(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            requested = Path(td) / "evidence_mount"
            requested.mkdir()
            (requested / "occupied").write_text("busy", encoding="utf-8")

            selected = mount.select_mount_root(requested, "case-001")

        self.assertNotEqual(selected["selected"], str(requested))
        self.assertTrue(selected["conflict"])
        self.assertIn("case-001", selected["selected"])

    def test_mount_plan_uses_partition_offsets_and_filesystem_options(self):
        mount = load_script("mount_evidence.py")
        inspect_result = {
            "evidence_file": {"path": "/evidence/disk.dd", "detected_format": "raw-style"},
            "format": {"kind": "raw-style"},
            "partitions": {
                "items": [
                    {
                        "number": 1,
                        "start_offset": 1048576,
                        "filesystem": "xfs",
                        "mount_candidate": True,
                    }
                ]
            },
        }

        commands, mounts = mount.plan_mounts(inspect_result, "/mnt/evidence_mount/case")

        self.assertIn("offset=1048576", mounts[0]["options"])
        self.assertIn("norecovery", mounts[0]["options"])
        self.assertEqual(commands[0]["stage"], "mount-read-only")


class ResumeContractTests(unittest.TestCase):
    def _make_evidence(self, td: Path) -> Path:
        evidence = td / "disk.dd"
        evidence.write_bytes(b"\0" * 4096)
        return evidence

    def _write_saved_inspection(self, td: Path, evidence: Path, size: int, mtime: float) -> Path:
        saved = {
            "schema_version": "linux-loader.v1",
            "case_id": "resume-case",
            "evidence_file": {
                "path": str(evidence.resolve()),
                "basename": evidence.name,
                "size": size,
                "mtime": mtime,
                "readable": True,
                "detected_format": "raw-style",
            },
            "format": {"kind": "raw-style", "confidence": 0.55, "evidence": ["default raw/dd/img handling"]},
            "ewf": {"detected": False},
            "partitions": {"items": [], "source": None, "errors": []},
            "tools": {},
            "preflight": {},
            "errors": [],
        }
        inspect_file = td / "inspect.json"
        inspect_file.write_text(json.dumps(saved), encoding="utf-8")
        return inspect_file

    def _run_mount(self, mount, argv: list[str]) -> tuple[int, dict]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = mount.main(argv)
        return code, json.loads(buffer.getvalue())

    def test_resume_with_matching_size_proceeds(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = self._make_evidence(root)
            stat = evidence.stat()
            inspect_file = self._write_saved_inspection(root, evidence, size=stat.st_size, mtime=stat.st_mtime)

            code, result = self._run_mount(
                mount,
                ["--resume", "--inspect-json", str(inspect_file), "--dry-run", "--output-dir", str(root / "out")],
            )

        self.assertEqual(code, 0)
        self.assertTrue(result["resume"]["can_resume"])
        self.assertEqual(result["resume"]["blockers"], [])
        self.assertEqual(result["resume"]["warnings"], [])
        self.assertEqual(result["resume"]["resumed_from"], str(inspect_file))
        self.assertEqual(result["evidence_file"]["size"], stat.st_size)
        self.assertFalse(any(error.get("fatal") for error in result.get("errors") or []))

    def test_resume_blocks_on_size_mismatch(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = self._make_evidence(root)
            stat = evidence.stat()
            inspect_file = self._write_saved_inspection(root, evidence, size=stat.st_size + 1, mtime=stat.st_mtime)

            code, result = self._run_mount(
                mount,
                ["--resume", "--inspect-json", str(inspect_file), "--dry-run", "--output-dir", str(root / "out")],
            )

        self.assertEqual(code, 1)
        self.assertFalse(result["resume"]["can_resume"])
        self.assertTrue(any("size" in blocker for blocker in result["resume"]["blockers"]))
        self.assertTrue(
            any(error.get("fatal") and "size" in str(error.get("message", "")) for error in result.get("errors") or [])
        )

    def test_resume_warns_on_mtime_drift(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = self._make_evidence(root)
            stat = evidence.stat()
            inspect_file = self._write_saved_inspection(root, evidence, size=stat.st_size, mtime=stat.st_mtime - 5.0)

            code, result = self._run_mount(
                mount,
                ["--resume", "--inspect-json", str(inspect_file), "--dry-run", "--output-dir", str(root / "out")],
            )

        self.assertEqual(code, 0)
        self.assertTrue(result["resume"]["can_resume"])
        self.assertTrue(any("mtime" in warning for warning in result["resume"]["warnings"]))

    def test_resume_without_prior_inspection_fails_clearly(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = self._make_evidence(root)

            code, result = self._run_mount(
                mount,
                ["--resume", str(evidence), "--case-id", "missing", "--output-dir", str(root / "out"), "--dry-run"],
            )

        self.assertEqual(code, 1)
        self.assertTrue(
            any(
                error.get("fatal") and "cannot read prior inspection" in str(error.get("message", ""))
                for error in result.get("errors") or []
            )
        )

    def test_dry_run_reports_loop_support_as_not_probed(self):
        mount = load_script("mount_evidence.py")
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evidence = self._make_evidence(root)

            code, result = self._run_mount(
                mount,
                [str(evidence), "--dry-run", "--case-id", "dryrun", "--output-dir", str(root / "out")],
            )

        self.assertEqual(code, 0)
        self.assertEqual(result["preflight"]["loop_attach"], "unknown")
        self.assertIn("not probed in dry-run", str(result["preflight"].get("reason")))


if __name__ == "__main__":
    unittest.main()
