#!/usr/bin/env python3
"""Evolution harness CLI for attack-analysis (WikiSkill three-layer loop).

Subcommands map to the four components of the evolutionary loop:

- ``capture-trace``  (harness)  freeze one closed case into the raw layer
- ``consolidate``    (Wiki Maintainer) compile sampled traces into the wiki
- ``propose``        (Skill Proposer) stage one atomic skill-change proposal
- ``evaluate``       (Gating) apply, gate, accept-or-rollback, ledger update
- ``validate-wiki`` / ``status``  consistency and loop-state inspection

See references/evolution.md for the full role protocol.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

from common import evolution
from common.evolution import EvolutionError
from common.cli_utils import configure_stdio


def default_skill_root() -> Path:
    return SCRIPT_DIR.parent


def print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def cmd_capture_trace(args: argparse.Namespace) -> int:
    trace = evolution.build_case_trace(
        case_dir=Path(args.case_dir),
        outcome=args.outcome,
        notes=args.notes or "",
        analyst_score=args.analyst_score,
        report_dir=Path(args.report_dir) if args.report_dir else None,
    )
    output = Path(args.output) if args.output else Path(args.case_dir) / "case-trace.json"
    if output.exists() and not args.overwrite:
        raise EvolutionError(f"trace already exists (use --overwrite): {output}")
    evolution.write_text(output.resolve(), json.dumps(trace, ensure_ascii=False, indent=2) + "\n")
    if args.json:
        print_json(trace)
    else:
        summary = {
            "trace_path": str(output.resolve()),
            "case_id": trace["case_id"],
            "outcome": trace["outcome"],
            "wiki_view_chars": len(trace["wiki_view"]),
            "wiki_view_cap": evolution.TRACE_WIKI_VIEW_CAP,
        }
        print_json(summary)
    return 0


def cmd_consolidate(args: argparse.Namespace) -> int:
    skill_root = Path(args.skill_root).resolve() if args.skill_root else default_skill_root()
    traces = [evolution.load_trace(Path(p)) for p in args.traces]
    ops_doc = json.loads(Path(args.ops).read_text(encoding="utf-8"))
    ops = ops_doc.get("ops", []) if isinstance(ops_doc, dict) else ops_doc
    if args.check:
        evolution.validate_batch(traces)
        evolution.validate_wiki_ops(skill_root, ops)
        images = evolution.plan_post_images(skill_root, ops)
        print_json({"checked": True, "batch_size": len(traces), "touched_files": sorted(images)})
        return 0
    result = evolution.consolidate(skill_root, traces, ops, summary=args.summary or "")
    result["mode"] = "consolidate"
    print_json(result)
    return 0


def cmd_propose(args: argparse.Namespace) -> int:
    skill_root = Path(args.skill_root).resolve() if args.skill_root else default_skill_root()
    proposal = json.loads(Path(args.proposal).read_text(encoding="utf-8"))
    path = evolution.stage_proposal(skill_root, proposal)
    if args.json:
        print_json({"staged": str(path), "proposal_id": proposal["proposal_id"], "diff": proposal.get("diff", "")})
    else:
        print_json({"staged": str(path), "proposal_id": proposal["proposal_id"]})
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    skill_root = Path(args.skill_root).resolve() if args.skill_root else default_skill_root()
    if not args.baseline and not args.proposal:
        raise EvolutionError("evaluate requires --proposal unless --baseline is set")
    result = evolution.evaluate_proposal(
        skill_root,
        Path(args.proposal) if args.proposal else None,
        gate_mode=args.gate,
        rubric_score=args.rubric_score,
        baseline=args.baseline,
    )
    if args.json:
        print_json(result)
    else:
        gate = result.get("gate", {})
        print(
            f"outcome={result['outcome']} R={result.get('r')} "
            f"R_best={result.get('r_best')} gate_ok={gate.get('ok')}"
        )
        for name, problems in (gate.get("components") or {}).items():
            for problem in problems:
                print(f"  [{name}] {problem}")
        state = evolution.load_state(skill_root)
        print(f"early_stop={state.get('early_stop')} iterations={state.get('iterations')}")
    return 0


def cmd_validate_wiki(args: argparse.Namespace) -> int:
    skill_root = Path(args.skill_root).resolve() if args.skill_root else default_skill_root()
    problems = evolution.validate_wiki(skill_root)
    if args.json:
        print_json({"ok": not problems, "problems": problems})
    else:
        for problem in problems:
            print(f"PROBLEM: {problem}")
        print("wiki ok" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


def cmd_status(args: argparse.Namespace) -> int:
    skill_root = Path(args.skill_root).resolve() if args.skill_root else default_skill_root()
    state = evolution.load_state(skill_root)
    state["problems"] = evolution.validate_wiki(skill_root)
    print_json(state) if args.json else print(json.dumps(state, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="attack-analysis experience evolution harness.")
    parser.add_argument("--skill-root", help="Skill root (defaults to the directory containing scripts/)")
    sub = parser.add_subparsers(dest="command", required=True)

    capture = sub.add_parser("capture-trace", help="Freeze one closed case into a raw-layer trace")
    capture.add_argument("--case-dir", required=True, help="Case cache dir containing analysis-manifest.json")
    capture.add_argument("--outcome", required=True, choices=["pass", "fail"])
    capture.add_argument("--notes", help="Analyst notes: what worked, what failed, workarounds found")
    capture.add_argument("--analyst-score", type=float, help="Optional reviewed case score in [0, 1]")
    capture.add_argument("--report-dir", help="Report dir override (default: sibling report/<case-id>)")
    capture.add_argument("--output", help="Trace output path (default: <case-dir>/case-trace.json)")
    capture.add_argument("--overwrite", action="store_true")
    capture.add_argument("--json", action="store_true")
    capture.set_defaults(func=cmd_capture_trace)

    consolidate = sub.add_parser("consolidate", help="Apply Wiki-Maintainer ops for a sampled trace batch")
    consolidate.add_argument("--traces", nargs="+", required=True, help="case-trace.json paths (<=8, <=5 fail, <=3 pass)")
    consolidate.add_argument("--ops", required=True, help="Ops JSON file (create_pattern/append/replace/insert_after/set_index_line)")
    consolidate.add_argument("--summary", help="One-line consolidation summary for logs.md")
    consolidate.add_argument("--check", action="store_true", help="Validate batch and ops without writing")
    consolidate.add_argument("--json", action="store_true")
    consolidate.set_defaults(func=cmd_consolidate)

    propose = sub.add_parser("propose", help="Stage one atomic skill-change proposal")
    propose.add_argument("--proposal", required=True, help="Proposal JSON file (kind/target/ops/traces_read/rationale)")
    propose.add_argument("--json", action="store_true")
    propose.set_defaults(func=cmd_propose)

    evaluate = sub.add_parser("evaluate", help="Gate a staged proposal: apply, validate, accept or rollback")
    evaluate.add_argument("--proposal", help="Staged proposal path (required unless --baseline)")
    evaluate.add_argument("--gate", choices=["full", "lite"], default="full")
    evaluate.add_argument("--rubric-score", type=float, help="Reviewer case score in [0, 1] blended into R")
    evaluate.add_argument("--baseline", action="store_true", help="Measure current tree and set initial R_best")
    evaluate.add_argument("--json", action="store_true")
    evaluate.set_defaults(func=cmd_evaluate)

    validate = sub.add_parser("validate-wiki", help="Check wiki layer consistency")
    validate.add_argument("--json", action="store_true")
    validate.set_defaults(func=cmd_validate_wiki)

    status = sub.add_parser("status", help="Show evolution loop state")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)
    return parser


def main() -> int:
    configure_stdio()
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except EvolutionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
