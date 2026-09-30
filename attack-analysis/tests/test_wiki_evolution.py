from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from common import evolution  # noqa: E402
from common.evolution import EvolutionError  # noqa: E402

PY = sys.executable


def make_skill(tmp: Path) -> Path:
    """Minimal skills-layer tree with a copy of the seeded wiki."""
    skill = tmp / "skill"
    (skill / "wiki").mkdir(parents=True)
    shutil.copytree(ROOT / "wiki" / "patterns", skill / "wiki" / "patterns")
    for name in ("index.md", "logs.md", "skill-impact.md", "state.json"):
        shutil.copy2(ROOT / "wiki" / name, skill / "wiki" / name)
    (skill / "SKILL.md").write_text(
        "---\nname: attack-analysis\ndescription: test\n---\n\n# Attack Analysis\n", encoding="utf-8"
    )
    (skill / "agents").mkdir()
    (skill / "agents" / "openai.yaml").write_text('default_prompt: "Use $attack-analysis"\n', encoding="utf-8")
    (skill / "references").mkdir()
    (skill / "references" / "reporting.md").write_text("- No threat score, ever.\n", encoding="utf-8")
    return skill


def make_trace(tmp: Path, case_id: str, outcome: str) -> Path:
    case = tmp / f"case-{case_id}"
    case.mkdir(exist_ok=True)
    (case / "analysis-manifest.json").write_text(
        json.dumps({"case_id": case_id, "mode": "quick-report", "files": [
            {"detected_type": "web_access", "bad_line_count": 2}
        ]}),
        encoding="utf-8",
    )
    trace = evolution.build_case_trace(case, outcome=outcome, notes=f"notes for {case_id}")
    path = tmp / f"trace-{case_id}.json"
    path.write_text(json.dumps(trace, ensure_ascii=False), encoding="utf-8")
    return path


class TraceCaptureTests(unittest.TestCase):
    def test_capture_trace_and_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            case = tmp_path / "case-big"
            case.mkdir()
            report_dir = tmp_path / "report" / "case-big"
            report_dir.mkdir(parents=True)
            (report_dir / "log-analysis-report.md").write_text("x" * 40000, encoding="utf-8")
            trace = evolution.build_case_trace(
                case, outcome="fail", notes="n" * 20000, report_dir=report_dir
            )
            self.assertEqual(trace["outcome"], "fail")
            self.assertTrue(trace["report_present"])
            # the 40000-char report is excerpt-capped to 6000 inside the view
            self.assertLessEqual(trace["wiki_view"].count("x"), 6100)
            self.assertLessEqual(len(trace["wiki_view"]), evolution.TRACE_WIKI_VIEW_CAP + 30)
            self.assertIn("analyst_notes: " + "n" * 100, trace["wiki_view"])
            self.assertIn("truncated at wiki cap", trace["wiki_view"])

    def test_capture_trace_requires_valid_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EvolutionError):
                evolution.build_case_trace(Path(tmp) / "missing", outcome="maybe")

    def test_wiki_view_cap_constant_matches_paper(self):
        self.assertEqual(evolution.TRACE_WIKI_VIEW_CAP, 15000)


class BatchCompositionTests(unittest.TestCase):
    def _traces(self, tmp: Path, fails: int, passes: int):
        paths = []
        for i in range(fails):
            paths.append(make_trace(tmp, f"f{i}", "fail"))
        for i in range(passes):
            paths.append(make_trace(tmp, f"p{i}", "pass"))
        return [evolution.load_trace(p) for p in paths]

    def test_batch_caps_match_paper(self):
        self.assertEqual(evolution.MAX_BATCH_TRACES, 8)
        self.assertEqual(evolution.MAX_FAILING_TRACES, 5)
        self.assertEqual(evolution.MAX_PASSING_TRACES, 3)

    def test_too_many_traces_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            traces = self._traces(Path(tmp), 5, 4)
            with self.assertRaises(EvolutionError):
                evolution.validate_batch(traces)

    def test_too_many_failing_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            traces = self._traces(Path(tmp), 6, 2)
            with self.assertRaises(EvolutionError):
                evolution.validate_batch(traces)

    def test_too_many_passing_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            traces = self._traces(Path(tmp), 0, 4)
            with self.assertRaises(EvolutionError):
                evolution.validate_batch(traces)

    def test_legal_batch_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            traces = self._traces(Path(tmp), 5, 3)
            evolution.validate_batch(traces)


class ConsolidateTests(unittest.TestCase):
    def test_create_pattern_updates_index_and_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            traces = [evolution.load_trace(make_trace(Path(tmp), "c1", "fail"))]
            ops = [{
                "op": "create_pattern",
                "target": "wiki/patterns/P-900-test-pattern.md",
                "title": "P-900: test",
                "meta": {"type": "failure-mode", "source": "c1"},
                "index_line": "PROBLEM: t -> ROOT CAUSE: t -> FIX: t",
                "content": "## PROBLEM\n\nt\n",
            }]
            result = evolution.consolidate(skill, traces, ops, summary="unit")
            self.assertEqual(result["applied_ops"], 1)
            index_text = (skill / "wiki" / "index.md").read_text(encoding="utf-8")
            self.assertIn("P-900-test-pattern", index_text)
            self.assertTrue((skill / "wiki" / "patterns" / "P-900-test-pattern.md").is_file())
            logs = (skill / "wiki" / "logs.md").read_text(encoding="utf-8")
            self.assertIn("consolidate", logs)
            self.assertEqual(evolution.validate_wiki(skill), [])

    def test_set_index_line_replaces_catalog_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            traces = [evolution.load_trace(make_trace(Path(tmp), "c1", "pass"))]
            slug = "wiki/patterns/P-001-windows-tzdata-naive-timestamps.md"
            ops = [{"op": "set_index_line", "target": slug, "index_line": "PROBLEM: x -> ROOT CAUSE: y -> FIX: z"}]
            evolution.consolidate(skill, traces, ops)
            index_text = (skill / "wiki" / "index.md").read_text(encoding="utf-8")
            self.assertIn("PROBLEM: x -> ROOT CAUSE: y -> FIX: z", index_text)

    def test_skill_layer_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            traces = [evolution.load_trace(make_trace(Path(tmp), "c1", "fail"))]
            ops = [{"op": "append", "target": "SKILL.md", "content": "x"}]
            with self.assertRaises(EvolutionError):
                evolution.consolidate(skill, traces, ops)

    def test_harness_owned_wiki_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            traces = [evolution.load_trace(make_trace(Path(tmp), "c1", "fail"))]
            ops = [{"op": "append", "target": "wiki/skill-impact.md", "content": "x"}]
            with self.assertRaises(EvolutionError):
                evolution.consolidate(skill, traces, ops)

    def test_anchor_must_be_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            traces = [evolution.load_trace(make_trace(Path(tmp), "c1", "fail"))]
            ops = [{"op": "replace", "target": "wiki/logs.md", "anchor": "not-there", "content": "x"}]
            with self.assertRaises(EvolutionError):
                evolution.consolidate(skill, traces, ops)


class ProposeTests(unittest.TestCase):
    def _proposal(self, tmp: Path, **overrides):
        proposal = {
            "kind": "skill-edit",
            "target": "SKILL.md",
            "rationale": "test",
            "traces_read": ["a", "b", "c", "d"],
            "ops": [{"op": "append", "target": "SKILL.md", "content": "\n## New\n"}],
        }
        proposal.update(overrides)
        return proposal

    def test_stage_proposal_writes_pending_with_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            path = evolution.stage_proposal(skill, self._proposal(Path(tmp)))
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["status"], "pending")
            self.assertIn("b/SKILL.md", data["diff"])

    def test_wiki_target_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EvolutionError):
                evolution.stage_proposal(
                    make_skill(Path(tmp)),
                    self._proposal(Path(tmp), target="wiki/index.md",
                                   ops=[{"op": "append", "target": "wiki/index.md", "content": "x"}]),
                )

    def test_non_atomic_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EvolutionError):
                evolution.stage_proposal(
                    make_skill(Path(tmp)),
                    self._proposal(
                        Path(tmp),
                        ops=[
                            {"op": "append", "target": "SKILL.md", "content": "x"},
                            {"op": "append", "target": "references/reporting.md", "content": "y"},
                        ],
                    ),
                )

    def test_fewer_than_four_traces_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(EvolutionError):
                evolution.stage_proposal(
                    make_skill(Path(tmp)), self._proposal(Path(tmp), traces_read=["a"])
                )

    def test_no_action_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            with self.assertRaises(EvolutionError):
                evolution.stage_proposal(
                    skill,
                    self._proposal(
                        Path(tmp),
                        kind="no_action",
                        target=None,
                        ops=[{"op": "append", "target": "SKILL.md", "content": "x"}],
                    ),
                )
            path = evolution.stage_proposal(skill, {
                "kind": "no_action", "target": None, "rationale": "nothing",
                "traces_read": [], "ops": [],
            })
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["kind"], "no_action")


class EvaluateTests(unittest.TestCase):
    def _stage_edit(self, skill: Path, content: str = "\n## Evolution\n") -> Path:
        proposal = {
            "kind": "skill-edit",
            "target": "SKILL.md",
            "rationale": "test change",
            "traces_read": ["a", "b", "c", "d"],
            "ops": [{"op": "append", "target": "SKILL.md", "content": content}],
        }
        return evolution.stage_proposal(skill, proposal)

    def test_rejected_change_is_rolled_back_but_ledger_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            # baseline on a green tree -> R_best = 1.0, so a gate-only edit
            # (R = 1.0) is NOT a strict improvement and must be rejected.
            evolution.evaluate_proposal(skill, None, gate_mode="lite", baseline=True)
            result = evolution.evaluate_proposal(skill, self._stage_edit(skill), gate_mode="lite")
            self.assertEqual(result["outcome"], "rejected")
            self.assertNotIn("## Evolution", (skill / "SKILL.md").read_text(encoding="utf-8"))
            impact = (skill / "wiki" / "skill-impact.md").read_text(encoding="utf-8")
            self.assertIn("— rejected", impact)
            self.assertIn("b/SKILL.md", impact)  # unified diff recorded
            state = evolution.load_state(skill)
            self.assertEqual(state["rejected"], 1)
            self.assertEqual(state["r_best"], 1.0)  # wiki/state untouched by rollback

    def test_accepted_change_is_kept_when_it_improves_r(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            state = evolution.load_state(skill)
            state["r_best"] = 0.5
            state["baseline_set"] = True
            evolution.save_state(skill, state)
            result = evolution.evaluate_proposal(skill, self._stage_edit(skill), gate_mode="lite")
            self.assertEqual(result["outcome"], "accepted")
            self.assertIn("## Evolution", (skill / "SKILL.md").read_text(encoding="utf-8"))
            impact = (skill / "wiki" / "skill-impact.md").read_text(encoding="utf-8")
            self.assertIn("— accepted", impact)
            state = evolution.load_state(skill)
            self.assertEqual(state["accepted"], 1)
            self.assertEqual(state["r_best"], 1.0)
            self.assertTrue(state["early_stop"])

    def test_baseline_sets_r_best(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            result = evolution.evaluate_proposal(skill, None, gate_mode="lite", baseline=True)
            self.assertEqual(result["outcome"], "baseline")
            state = evolution.load_state(skill)
            self.assertTrue(state["baseline_set"])
            self.assertEqual(state["r_best"], result["r_best"])

    def test_expects_rubric_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            proposal = {
                "kind": "skill-edit",
                "target": "SKILL.md",
                "rationale": "behavior change",
                "expects_rubric": True,
                "traces_read": ["a", "b", "c", "d"],
                "ops": [{"op": "append", "target": "SKILL.md", "content": "x"}],
            }
            path = evolution.stage_proposal(skill, proposal)
            with self.assertRaises(EvolutionError):
                evolution.evaluate_proposal(skill, path, gate_mode="lite")
            # with the reviewed score it proceeds
            result = evolution.evaluate_proposal(
                skill, path, gate_mode="lite", rubric_score=0.8, baseline=False
            )
            self.assertIn(result["outcome"], ("accepted", "rejected"))

    def test_gate_lite_detects_contract_breakage(self):
        with tempfile.TemporaryDirectory() as tmp:
            skill = make_skill(Path(tmp))
            (skill / "SKILL.md").write_text("broken", encoding="utf-8")
            gate = evolution.run_gate(skill, mode="lite")
            self.assertFalse(gate["ok"])
            self.assertEqual(gate["r_det"], 0.0)
            self.assertTrue(gate["components"]["contract"])

    @unittest.skipIf(os.environ.get("WIKI_EVOLUTION_GATE"), "nested inside a gate run")
    def test_full_gate_green_on_real_repo(self):
        gate = evolution.run_gate(ROOT, mode="full")
        self.assertTrue(gate["ok"], gate["components"])


class CliTests(unittest.TestCase):
    def run_cli(self, args, expect_rc=0):
        proc = subprocess.run(
            [PY, str(ROOT / "scripts" / "wiki_cli.py")] + args,
            encoding="utf-8", capture_output=True,
        )
        self.assertEqual(
            proc.returncode, expect_rc,
            f"rc={proc.returncode} args={args}\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
        return proc

    def test_validate_wiki_on_real_repo(self):
        proc = self.run_cli(["validate-wiki"])
        self.assertIn("wiki ok", proc.stdout)

    def test_status_json(self):
        proc = self.run_cli(["status", "--json"])
        state = json.loads(proc.stdout)
        self.assertIn("r_best", state)

    def test_consolidate_rejects_oversized_batch_via_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            skill = make_skill(tmp_path)
            traces = [str(make_trace(tmp_path, f"p{i}", "pass")) for i in range(4)]
            ops_path = tmp_path / "ops.json"
            ops_path.write_text(json.dumps({"ops": []}), encoding="utf-8")
            proc = subprocess.run(
                [PY, str(ROOT / "scripts" / "wiki_cli.py"), "--skill-root", str(skill),
                 "consolidate", "--traces", *traces, "--ops", str(ops_path), "--check"],
                encoding="utf-8", capture_output=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("cap is 3", proc.stderr)


if __name__ == "__main__":
    unittest.main()
