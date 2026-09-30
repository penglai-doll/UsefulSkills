"""WikiSkill-style evolution harness core for attack-analysis.

Implements the mechanics of the three-layer experience architecture:

- raw layer: per-case ``case-trace.json`` files (built from case outputs)
- wiki layer: ``wiki/patterns/`` + ``index.md`` + ``logs.md`` +
  ``skill-impact.md`` (+ harness-owned ``state.json``/proposals/backups)
- skills layer: everything else in the skill root (SKILL.md, references/,
  scripts/, tests/, PURPOSE.md)

The AI roles (Wiki Maintainer, Skill Proposer) produce op lists; this module
validates and applies them, runs the validation gate, and enforces the
paper's invariants: sampled batch composition (<=8 traces, <=5 failing,
<=3 passing), 15000-char wiki view cap, atomic single-target proposals,
at-least-4-traces reading requirement, accept-iff-improvement gating with
skill rollback, and a wiki that is never rolled back.
"""

from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRACE_WIKI_VIEW_CAP = 15000
MAX_BATCH_TRACES = 8
MAX_FAILING_TRACES = 5
MAX_PASSING_TRACES = 3
MIN_TRACES_READ = 4

WIKI_DIR = "wiki"
INDEX_TARGET = "wiki/index.md"
EDITABLE_SUFFIXES = {".md", ".py", ".yaml", ".yml", ".json", ".txt", ".cfg", ".ini"}
# Harness-owned wiki files: neither role may ever target these.
WIKI_FORBIDDEN_TARGETS = ("wiki/skill-impact.md", "wiki/state.json")
WIKI_FORBIDDEN_PREFIXES = ("wiki/proposals/", "wiki/backups/")

GOLD_IP = "198.51.100.23"
GOLD_EVENT_TYPES = {"web_probe", "login_signal", "sql_suspicious", "login_record", "operation_record"}


class EvolutionError(ValueError):
    """Raised when a role-produced artifact violates the protocol."""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _ensure_trailing_newline(text: str) -> str:
    return text if text.endswith("\n") else text + "\n"


def target_parts(target: str) -> list[str]:
    return [part for part in target.split("/") if part and part != "."]


# ---------------------------------------------------------------------------
# Raw layer: trace capture
# ---------------------------------------------------------------------------


def _counts(items) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(item)
        counts[key] = counts.get(key, 0) + 1
    return counts


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def build_case_trace(
    case_dir: Path,
    outcome: str,
    notes: str = "",
    analyst_score: float | None = None,
    report_dir: Path | None = None,
) -> dict[str, Any]:
    """Assemble the raw-layer trace for one closed case.

    Reads the case's own artifacts (manifest, events, correlations, report)
    and emits an immutable ``case-trace.json`` record whose ``wiki_view`` is
    pre-truncated to the 15000-char wiki cap.
    """
    if outcome not in ("pass", "fail"):
        raise EvolutionError("outcome must be 'pass' or 'fail'")
    case_dir = case_dir.expanduser().resolve()
    if not case_dir.is_dir():
        raise EvolutionError(f"case dir not found: {case_dir}")

    manifest = _load_json(case_dir / "analysis-manifest.json") or {}
    events_doc = _load_json(case_dir / "event-candidates.json") or {}
    corr_doc = _load_json(case_dir / "correlation-candidates.json") or {}

    if report_dir is None:
        report_dir = case_dir.parent.parent / "report" / case_dir.name
    report_path: Path | None = report_dir / "log-analysis-report.md"
    report_text = None
    try:
        report_text = read_text(report_path)
    except OSError:
        report_path = None

    events = events_doc.get("events", [])
    correlations = corr_doc.get("correlations", [])
    files = manifest.get("files", [])
    detected_types = [f.get("detected_type", "unknown") for f in files]
    bad_lines = sum(int(f.get("bad_line_count") or 0) for f in files)

    trace: dict[str, Any] = {
        "schema": 1,
        "case_id": manifest.get("case_id") or case_dir.name,
        "created_at": utc_now_iso(),
        "outcome": outcome,
        "mode": manifest.get("mode"),
        "source_dir": str(case_dir),
        "report_path": str(report_path) if report_path else None,
        "inventory": {
            "file_count": len(files),
            "detected_types": _counts(detected_types),
            "bad_line_total": bad_lines,
            "default_timezone": manifest.get("default_timezone"),
            "network_status": manifest.get("network_status"),
        },
        "extraction": {
            "event_count": len(events),
            "event_types": _counts(e.get("event_type") for e in events),
            "timezone_notes": list(events_doc.get("timezone_notes", [])),
            "parser_errors": [s for s in events_doc.get("parser_stats", []) if s.get("error")],
        },
        "correlation": {
            "count": len(correlations),
            "strength": _counts(c.get("strength") for c in correlations),
        },
        "report_present": bool(report_text),
        "analyst": {
            "notes": notes.strip(),
            "score": analyst_score,
        },
        "artifact_files": sorted(p.name for p in case_dir.iterdir() if p.is_file()),
    }
    trace["wiki_view"] = compact_trace_view(trace, report_text)
    return trace


def compact_trace_view(trace: dict[str, Any], report_text: str | None) -> str:
    """Serialize a trace into the capped string fed to the wiki layer."""
    inv = trace.get("inventory", {})
    ext = trace.get("extraction", {})
    cor = trace.get("correlation", {})
    lines = [
        f"case: {trace.get('case_id')}",
        f"outcome: {trace.get('outcome')}",
        f"mode: {trace.get('mode')}",
        f"files: {inv.get('file_count')} detected: {json.dumps(inv.get('detected_types', {}), ensure_ascii=False)}",
        f"events: {ext.get('event_count')} types: {json.dumps(ext.get('event_types', {}), ensure_ascii=False)}",
        f"correlations: {cor.get('count')} strength: {json.dumps(cor.get('strength', {}), ensure_ascii=False)}",
        f"report_present: {trace.get('report_present')}",
    ]
    if ext.get("timezone_notes"):
        lines.append("timezone_notes: " + "; ".join(ext["timezone_notes"]))
    for stat in ext.get("parser_errors", [])[:5]:
        lines.append(f"parser_error: {stat.get('path')} {stat.get('module')}: {stat.get('error')}")
    notes = (trace.get("analyst", {}) or {}).get("notes", "")
    if notes:
        lines.append(f"analyst_notes: {notes}")
    if report_text:
        lines.append("report_excerpt:")
        lines.append(report_text[:6000])
    view = "\n".join(lines)
    if len(view) > TRACE_WIKI_VIEW_CAP:
        view = view[:TRACE_WIKI_VIEW_CAP] + "\n...[truncated at wiki cap]"
    return view


def load_trace(path: Path) -> dict[str, Any]:
    try:
        trace = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvolutionError(f"cannot read trace {path}: {exc}") from exc
    if not isinstance(trace, dict) or trace.get("schema") != 1:
        raise EvolutionError(f"trace {path} is not a schema-1 case trace")
    if trace.get("outcome") not in ("pass", "fail"):
        raise EvolutionError(f"trace {path} has invalid outcome")
    return trace


def validate_batch(traces: list[dict[str, Any]]) -> None:
    """Enforce the paper's sampled batch composition (<=8, <=5 fail, <=3 pass)."""
    if not traces:
        raise EvolutionError("batch is empty; provide at least one trace")
    if len(traces) > MAX_BATCH_TRACES:
        raise EvolutionError(f"batch has {len(traces)} traces; cap is {MAX_BATCH_TRACES}")
    failing = sum(1 for t in traces if t["outcome"] == "fail")
    passing = sum(1 for t in traces if t["outcome"] == "pass")
    if failing > MAX_FAILING_TRACES:
        raise EvolutionError(f"batch has {failing} failing traces; cap is {MAX_FAILING_TRACES}")
    if passing > MAX_PASSING_TRACES:
        raise EvolutionError(f"batch has {passing} passing traces; cap is {MAX_PASSING_TRACES}")
    ids = [t.get("case_id") for t in traces]
    if len(set(ids)) != len(ids):
        raise EvolutionError("batch contains duplicate case ids")


# ---------------------------------------------------------------------------
# Patch ops: validation, planning, apply, rollback
# ---------------------------------------------------------------------------


def _check_target_path(target: str) -> None:
    if not target or "\\" in target or ":" in target or Path(target).is_absolute():
        raise EvolutionError(f"invalid target path: {target!r} (use '/' separators)")
    parts = target_parts(target)
    if not parts or ".." in parts or target != "/".join(parts):
        raise EvolutionError(f"target path escapes the skill root: {target!r}")
    if parts[0] == "wiki":
        if target in WIKI_FORBIDDEN_TARGETS or any(target.startswith(p) for p in WIKI_FORBIDDEN_PREFIXES):
            raise EvolutionError(f"target is harness-owned and may not be edited: {target!r}")
    if Path(target).suffix.lower() not in EDITABLE_SUFFIXES:
        raise EvolutionError(f"target suffix not editable: {target!r}")


def _contained_path(skill_root: Path, target: str) -> Path:
    path = skill_root / target
    if not path.resolve().is_relative_to(skill_root.resolve()):
        raise EvolutionError(f"target resolves outside the skill root: {target!r}")
    current = skill_root
    for part in Path(target).parts:
        current = current / part
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise EvolutionError(f"target traverses a linked path: {target!r}")
    if path.is_file() and path.stat().st_nlink > 1:
        raise EvolutionError(f"target is a hard link: {target!r}")
    return path


def _op_fields(op: Any, index: int) -> tuple[str, str]:
    if not isinstance(op, dict):
        raise EvolutionError(f"ops[{index}] is not an object")
    kind = op.get("op")
    target = op.get("target")
    if kind not in ("create", "append", "replace", "insert_after", "create_pattern", "set_index_line"):
        raise EvolutionError(f"ops[{index}] has unknown op kind: {kind!r}")
    if not isinstance(target, str) or not target:
        raise EvolutionError(f"ops[{index}] target must be a non-empty string")
    content = op.get("content")
    if kind in ("create", "append", "replace", "insert_after", "create_pattern") and not isinstance(content, str):
        raise EvolutionError(f"ops[{index}] ({kind}) requires string content")
    if kind in ("replace", "insert_after") and not isinstance(op.get("anchor"), str):
        raise EvolutionError(f"ops[{index}] ({kind}) requires a string anchor")
    if kind in ("create_pattern", "set_index_line"):
        line = op.get("index_line")
        if not isinstance(line, str) or not line.strip() or "\n" in line:
            raise EvolutionError(f"ops[{index}] ({kind}) requires a single-line index_line")
    return kind, target  # type: ignore[return-value]


def _check_anchor(path: Path, target: str, op: dict[str, Any], index: int) -> None:
    anchor = op["anchor"]
    text = read_text(path)
    occurrences = text.count(anchor)
    if occurrences != 1:
        raise EvolutionError(
            f"ops[{index}]: anchor must occur exactly once in {target} (found {occurrences})"
        )


def validate_wiki_ops(skill_root: Path, ops: list[dict[str, Any]]) -> None:
    """Validate Wiki-Maintainer ops: targets stay inside wiki/, anchors resolve."""
    for i, op in enumerate(ops):
        kind, target = _op_fields(op, i)
        _check_target_path(target)
        if target_parts(target)[0] != "wiki":
            raise EvolutionError(f"maintainer op target must stay under wiki/: {target!r}")
        path = _contained_path(skill_root, target)
        exists = path.is_file()
        if kind in ("create", "create_pattern"):
            if exists:
                raise EvolutionError(f"ops[{i}]: target already exists: {target}")
            if kind == "create_pattern" and target_parts(target)[:2] != ["wiki", "patterns"]:
                raise EvolutionError(
                    f"ops[{i}]: create_pattern target must be wiki/patterns/<file>.md: {target}"
                )
        elif not exists:
            raise EvolutionError(f"ops[{i}]: target does not exist: {target}")
        if kind in ("replace", "insert_after"):
            _check_anchor(path, target, op, i)


def validate_skill_ops(skill_root: Path, proposal: dict[str, Any]) -> None:
    """Validate a Skill-Proposer proposal: atomic, non-wiki, reading requirements."""
    kind = proposal.get("kind")
    if kind not in ("skill-edit", "skill-create", "no_action"):
        raise EvolutionError(f"proposal kind must be skill-edit|skill-create|no_action, got {kind!r}")
    ops = proposal.get("ops", [])
    if not isinstance(ops, list):
        raise EvolutionError("proposal ops must be a list")
    if kind == "no_action":
        if ops:
            raise EvolutionError("no_action proposal must have empty ops")
        return
    traces_read = proposal.get("traces_read", [])
    if (not isinstance(traces_read, list) or not all(isinstance(item, str) and item.strip() for item in traces_read)
            or len(set(traces_read)) < MIN_TRACES_READ):
        raise EvolutionError(
            f"proposal must list at least {MIN_TRACES_READ} distinct traces_read entries "
            f"(paper reading requirement); got {traces_read!r}"
        )
    target = proposal.get("target")
    if not isinstance(target, str) or not target:
        raise EvolutionError("proposal requires a single string target")
    _check_target_path(target)
    _contained_path(skill_root, target)
    if target_parts(target)[0] == "wiki":
        raise EvolutionError("proposer may not edit the wiki layer; wiki writes go through consolidate")
    if kind == "skill-create":
        if len(ops) != 1 or ops[0].get("op") != "create" or ops[0].get("target") != target:
            raise EvolutionError("skill-create requires exactly one create op on the proposal target")
        if (skill_root / target).exists():
            raise EvolutionError(f"skill-create target already exists: {target}")
    else:
        if not ops:
            raise EvolutionError("skill-edit requires at least one op")
        if not (skill_root / target).is_file():
            raise EvolutionError(f"skill-edit target does not exist: {target}")
    for i, op in enumerate(ops):
        _op_fields(op, i)
        if op.get("target") != target:
            raise EvolutionError(
                f"proposal is not atomic: ops[{i}] targets {op.get('target')!r}, expected {target!r}"
            )
        if kind == "skill-edit" and op.get("op") == "create":
            raise EvolutionError("skill-edit ops may not use create")
        if op.get("op") in ("replace", "insert_after"):
            _check_anchor(skill_root / target, target, op, i)


def render_pattern_page(op: dict[str, Any]) -> str:
    title = op.get("title") or target_parts(op["target"])[-1].rsplit(".", 1)[0]
    meta = op.get("meta") or {}
    meta_lines = [
        f"- Type: {meta.get('type', 'failure-mode')}",
        f"- Status: {meta.get('status', 'active')}",
    ]
    if meta.get("source"):
        meta_lines.append(f"- Source: {meta['source']}")
    return f"# {title}\n\n" + "\n".join(meta_lines) + "\n\n" + _ensure_trailing_newline(op["content"])


def _index_line_for(target: str, index_line: str) -> str:
    slug = target_parts(target)[-1]
    return f"- [{slug}]({target}) — {index_line}"


def _set_index_line(index_text: str, target: str, index_line: str) -> str:
    slug = target_parts(target)[-1]
    pattern = re.compile(r"^.*\([^)]*" + re.escape(slug) + r"\).*$", re.MULTILINE)
    found = pattern.findall(index_text)
    if len(found) != 1:
        raise EvolutionError(f"index line for {slug} must exist exactly once (found {len(found)})")
    start = pattern.search(index_text).start()
    end = pattern.search(index_text).end()
    return index_text[:start] + _index_line_for(target, index_line) + index_text[end:]


def plan_post_images(skill_root: Path, ops: list[dict[str, Any]]) -> dict[str, str]:
    """Compute post-apply file contents in memory without touching disk.

    Handles the maintainer sugar ops (``create_pattern``, ``set_index_line``)
    by deriving the matching wiki/index.md updates, so sequential ops on the
    same file compose correctly.
    """
    images: dict[str, str] = {}
    for op in ops:
        kind = op["op"]
        target = op["target"]
        if kind == "create":
            images[target] = _ensure_trailing_newline(op["content"])
            continue
        if kind == "create_pattern":
            images[target] = render_pattern_page(op)
            line = _index_line_for(target, op["index_line"])
            index_current = images.get(INDEX_TARGET)
            if index_current is None:
                index_current = read_text(skill_root / INDEX_TARGET)
            if line in index_current:
                raise EvolutionError(f"index line already present for {target}")
            images[INDEX_TARGET] = _ensure_trailing_newline(index_current) + line + "\n"
            continue
        if kind == "set_index_line":
            index_current = images.get(INDEX_TARGET)
            if index_current is None:
                index_current = read_text(skill_root / INDEX_TARGET)
            images[INDEX_TARGET] = _set_index_line(index_current, target, op["index_line"])
            continue
        current = images.get(target)
        if current is None:
            current = read_text(skill_root / target)
        if kind == "append":
            images[target] = _ensure_trailing_newline(current) + _ensure_trailing_newline(op["content"])
        elif kind == "insert_after":
            images[target] = _insert_after(current, op["anchor"], op["content"])
        elif kind == "replace":
            images[target] = _replace_once(current, op["anchor"], op["content"])
        else:  # pragma: no cover - validated earlier
            raise EvolutionError(f"unsupported op in planning: {kind}")
    return images


def _insert_after(text: str, anchor: str, content: str) -> str:
    pos = text.find(anchor)
    line_end = text.find("\n", pos + len(anchor))
    block = _ensure_trailing_newline(content)
    if line_end == -1:
        return _ensure_trailing_newline(text) + block
    insert_at = line_end + 1
    return text[:insert_at] + block + text[insert_at:]


def _replace_once(text: str, anchor: str, content: str) -> str:
    pos = text.find(anchor)
    replacement = content
    if not replacement.endswith("\n") and text[pos + len(anchor) : pos + len(anchor) + 1] == "\n":
        replacement += "\n"
    return text[:pos] + replacement + text[pos + len(anchor) :]


def unified_diff(target: str, before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{target}",
            tofile=f"b/{target}",
        )
    )


def proposal_diff(skill_root: Path, proposal: dict[str, Any], images: dict[str, str] | None = None) -> str:
    ops = proposal.get("ops", [])
    if not ops:
        return ""
    images = images or plan_post_images(skill_root, ops)
    chunks = []
    for target in dict.fromkeys(op["target"] for op in ops):
        path = skill_root / target
        before = read_text(path) if path.is_file() else ""
        chunks.append(unified_diff(target, before, images[target]))
    return "\n".join(chunk for chunk in chunks if chunk)


def backup_targets(skill_root: Path, backup_dir: Path, targets: list[str]) -> None:
    """Snapshot pre-apply state of skill files for rollback (skills only)."""
    manifest: dict[str, dict[str, Any]] = {}
    for target in targets:
        path = skill_root / target
        if path.is_file():
            manifest[target] = {"existed": True, "content": read_text(path)}
        else:
            manifest[target] = {"existed": False, "content": ""}
    backup_dir.mkdir(parents=True, exist_ok=True)
    write_text(backup_dir / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))


def apply_images(skill_root: Path, images: dict[str, str]) -> None:
    for target, content in images.items():
        write_text(_contained_path(skill_root, target), content)


def rollback_targets(skill_root: Path, backup_dir: Path, targets: list[str]) -> None:
    manifest = json.loads((backup_dir / "manifest.json").read_text(encoding="utf-8"))
    for target in targets:
        record = manifest[target]
        path = skill_root / target
        if record["existed"]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(record["content"], encoding="utf-8")
        elif path.exists():
            path.unlink()


# ---------------------------------------------------------------------------
# Wiki maintenance (consolidate)
# ---------------------------------------------------------------------------


def consolidate(
    skill_root: Path,
    traces: list[dict[str, Any]],
    ops: list[dict[str, Any]],
    summary: str = "",
) -> dict[str, Any]:
    """Apply Wiki-Maintainer ops after batch-composition and op validation.

    Nothing here touches the skills layer: the wiki is compile-time memory,
    and it is never rolled back.
    """
    validate_batch(traces)
    validate_wiki_ops(skill_root, ops)
    images = plan_post_images(skill_root, ops)
    apply_images(skill_root, images)

    stamp = utc_now_iso()
    case_ids = ", ".join(str(t.get("case_id")) for t in traces)
    failing = sum(1 for t in traces if t["outcome"] == "fail")
    op_lines = "\n".join(f"  - {op['op']} {op['target']}" for op in ops) or "  - (no ops)"
    entry = (
        f"\n## {stamp} — consolidate\n\n"
        f"- Batch: {len(traces)} traces ({failing} failing, {len(traces) - failing} passing): {case_ids}\n"
        f"- Ops applied:\n{op_lines}\n"
        + (f"- Summary: {summary}\n" if summary else "")
    )
    append_wiki_log(skill_root, entry)
    return {"applied_ops": len(ops), "batch_size": len(traces), "failing": failing}


# ---------------------------------------------------------------------------
# Validation gate
# ---------------------------------------------------------------------------


def validate_wiki(skill_root: Path) -> list[str]:
    """Consistency checks over the wiki layer."""
    problems: list[str] = []
    wiki = skill_root / "wiki"
    for name in ("index.md", "logs.md", "skill-impact.md", "state.json"):
        if not (wiki / name).is_file():
            problems.append(f"wiki/{name} missing")
    patterns_dir = wiki / "patterns"
    if not patterns_dir.is_dir():
        problems.append("wiki/patterns/ missing")
        return problems
    try:
        state = json.loads((wiki / "state.json").read_text(encoding="utf-8"))
        for key in ("r_best", "iterations", "accepted", "rejected", "early_stop"):
            if key not in state:
                problems.append(f"wiki/state.json missing key {key}")
    except (OSError, json.JSONDecodeError):
        problems.append("wiki/state.json is not valid JSON")
    try:
        index_text = read_text(wiki / "index.md")
    except OSError:
        return problems
    for pattern_file in sorted(patterns_dir.glob("*.md")):
        linked = f"({pattern_file.name})" in index_text or f"/{pattern_file.name})" in index_text
        if not linked:
            problems.append(f"wiki/index.md has no line linking {pattern_file.name}")
    for match in re.finditer(r"\((patterns/[^)]+\.md)\)", index_text):
        if not (wiki / match.group(1)).is_file():
            problems.append(f"wiki/index.md links to missing pattern {match.group(1)}")
    return problems


def _contract_checks(skill_root: Path) -> list[str]:
    problems: list[str] = []
    skill_path = skill_root / "SKILL.md"
    try:
        skill = read_text(skill_path)
    except OSError:
        return ["SKILL.md missing"]
    if "name: attack-analysis" not in skill:
        problems.append("SKILL.md frontmatter missing name: attack-analysis")
    if "description:" not in skill:
        problems.append("SKILL.md frontmatter missing description")
    try:
        agent = read_text(skill_root / "agents" / "openai.yaml")
        if "$attack-analysis" not in agent:
            problems.append("agents/openai.yaml does not reference $attack-analysis")
    except OSError:
        problems.append("agents/openai.yaml missing")
    try:
        reporting = read_text(skill_root / "references" / "reporting.md")
        if "No threat score" not in reporting:
            problems.append("references/reporting.md lost the 'No threat score' red line")
    except OSError:
        problems.append("references/reporting.md missing")
    problems.extend(validate_wiki(skill_root))
    return problems


def _gate_py_compile(skill_root: Path) -> list[str]:
    problems: list[str] = []
    for sub in ("scripts", "scripts/parsers", "scripts/common"):
        for py in sorted((skill_root / sub).glob("*.py")):
            try:
                compile(py.read_bytes(), str(py), "exec")
            except (SyntaxError, OSError) as exc:
                problems.append(f"py_compile failed: {py.name}: {exc}")
    return problems


def _gate_unittest(skill_root: Path) -> list[str]:
    env = dict(os.environ, WIKI_EVOLUTION_GATE="1", PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
            cwd=skill_root, encoding="utf-8", errors="replace", capture_output=True,
            check=False, env=env, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return ["unittest suite timed out after 180 seconds"]
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-15:]
        return ["unittest suite failed: " + " | ".join(tail)]
    return []


def _gate_gold_pipeline(skill_root: Path) -> list[str]:
    fixture = skill_root / "tests" / "fixtures" / "gold_attack_case"
    if not fixture.is_dir():
        return ["gold fixture missing"]
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp) / "work"
        steps = [
            [sys.executable, "scripts/inventory_logs.py", str(fixture), "--mode", "quick-report",
             "--case-id", "gate", "--workdir", str(workdir)],
            [sys.executable, "scripts/extract_log_events.py", "--manifest",
             str(workdir / "cache" / "gate" / "analysis-manifest.json"), "--output-dir",
             str(workdir / "cache" / "gate"), "--json"],
            [sys.executable, "scripts/correlate_events.py", "--events",
             str(workdir / "cache" / "gate" / "event-candidates.json"), "--output-dir",
             str(workdir / "cache" / "gate"), "--json"],
        ]
        outputs: list[dict[str, Any]] = []
        for cmd in steps:
            try:
                proc = subprocess.run(
                    cmd, cwd=skill_root, encoding="utf-8", errors="replace",
                    capture_output=True, check=False, timeout=60,
                    env=dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1"),
                )
            except subprocess.TimeoutExpired:
                return [f"gold pipeline step timed out: {Path(cmd[1]).name}"]
            if proc.returncode != 0:
                return [f"gold pipeline step failed: {Path(cmd[1]).name}: {proc.stderr.strip()[:300]}"]
            try:
                outputs.append(json.loads(proc.stdout))
            except json.JSONDecodeError:
                return [f"gold pipeline step emitted non-JSON output: {Path(cmd[1]).name}"]
    events = outputs[1].get("events", [])
    ips = {e.get("actor_ip_normalized") for e in events if e.get("actor_ip_normalized")}
    types = {e.get("event_type") for e in events}
    correlations = outputs[2].get("correlations", [])
    problems: list[str] = []
    if GOLD_IP not in ips:
        problems.append(f"gold pipeline lost source IP {GOLD_IP}")
    missing = GOLD_EVENT_TYPES - types
    if missing:
        problems.append(f"gold pipeline lost event types: {sorted(missing)}")
    if not correlations or not any("same_ip" in c.get("basis", []) for c in correlations):
        problems.append("gold pipeline lost same-ip correlations")
    return problems


def run_gate(skill_root: Path, mode: str = "full") -> dict[str, Any]:
    """Run the deterministic validation gate.

    mode='full': contract + py_compile + unittest + gold-case pipeline.
    mode='lite': contract + py_compile only (used inside tests / quick loops).

    ``r_det`` is 1.0 only when every required component passes.
    """
    if mode not in ("full", "lite"):
        raise EvolutionError("gate mode must be 'full' or 'lite'")
    components: dict[str, list[str]] = {}
    components["contract"] = _contract_checks(skill_root)
    components["py_compile"] = _gate_py_compile(skill_root)
    if mode == "full":
        components["unittest"] = _gate_unittest(skill_root)
        components["gold_pipeline"] = _gate_gold_pipeline(skill_root)
    ok = all(not problems for problems in components.values())
    return {
        "mode": mode,
        "ok": ok,
        "r_det": 1.0 if ok else 0.0,
        "components": components,
        "checked_at": utc_now_iso(),
    }


def combine_scores(r_det: float, rubric_score: float | None) -> float:
    """R = deterministic gate score, optionally blended with the case rubric."""
    if rubric_score is None:
        return r_det
    if not 0.0 <= rubric_score <= 1.0:
        raise EvolutionError("rubric score must be within [0, 1]")
    return round(0.5 * r_det + 0.5 * rubric_score, 4)


def check_rubric_expectation(proposal: dict[str, Any], rubric_score: float | None) -> None:
    """Behavior-changing proposals must carry a reviewed validation-case score.

    ``expects_rubric: true`` in the proposal means the change affects analysis
    behavior; the gate alone (docs passing does not prove analysis quality)
    cannot score it, so evaluate refuses to run without ``--rubric-score``.
    """
    if proposal.get("expects_rubric") and rubric_score is None:
        raise EvolutionError(
            "proposal declares expects_rubric: true; rerun evaluate with --rubric-score "
            "from a held-out validation-case review"
        )


# ---------------------------------------------------------------------------
# State, skill-impact ledger, logs
# ---------------------------------------------------------------------------


def load_state(skill_root: Path) -> dict[str, Any]:
    path = skill_root / "wiki" / "state.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "schema": 1,
            "r_best": 0.0,
            "baseline_set": False,
            "iterations": 0,
            "accepted": 0,
            "rejected": 0,
            "no_action": 0,
            "early_stop": False,
            "last_updated": utc_now_iso(),
            "history": [],
        }


def save_state(skill_root: Path, state: dict[str, Any]) -> None:
    state["schema"] = 1
    state["last_updated"] = utc_now_iso()
    write_text(
        skill_root / "wiki" / "state.json",
        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
    )


def append_wiki_log(skill_root: Path, entry: str) -> None:
    with (skill_root / "wiki" / "logs.md").open("a", encoding="utf-8") as handle:
        handle.write(entry.rstrip("\n") + "\n")


def append_skill_impact(
    skill_root: Path,
    proposal: dict[str, Any],
    outcome: str,
    r_det: float | None,
    rubric: float | None,
    r: float | None,
    r_best_before: float | None,
) -> None:
    diff = proposal.get("diff", "")
    validation = (
        f"gate={r_det if r_det is not None else '-'} "
        f"rubric={rubric if rubric is not None else '-'} "
        f"R={r if r is not None else '-'}"
    )
    before = f" (R_best before: {r_best_before})" if r_best_before is not None else ""
    traces = ", ".join(proposal.get("traces_read", [])) or "-"
    entry = (
        f"\n## {proposal.get('proposal_id')} — {proposal.get('kind')} — "
        f"{proposal.get('target') or '-'} — {outcome}\n\n"
        f"- Date: {utc_now_iso()}\n"
        f"- Validation: {validation}{before}\n"
        f"- Traces read: {traces}\n"
        f"- Rationale: {proposal.get('rationale', '')}\n"
        f"````diff\n{diff}\n````\n"
    )
    with (skill_root / "wiki" / "skill-impact.md").open("a", encoding="utf-8") as handle:
        handle.write(entry)


# ---------------------------------------------------------------------------
# Proposals (Skill Proposer staging + Gating)
# ---------------------------------------------------------------------------


def proposals_dir(skill_root: Path) -> Path:
    path = _contained_path(skill_root, "wiki/proposals")
    path.mkdir(parents=True, exist_ok=True)
    return path


def next_proposal_id(skill_root: Path) -> str:
    max_seq = 0
    for path in proposals_dir(skill_root).glob("prop-*.json"):
        match = re.match(r"prop-(\d+)\.json", path.name)
        if match:
            max_seq = max(max_seq, int(match.group(1)))
    return f"prop-{max_seq + 1:04d}"


def validate_proposal_id(proposal_id: Any) -> str:
    if not isinstance(proposal_id, str) or not re.fullmatch(r"prop-\d{4,}", proposal_id):
        raise EvolutionError("proposal_id must be prop- followed by at least four digits")
    return proposal_id


def stage_proposal(skill_root: Path, proposal: dict[str, Any]) -> Path:
    validate_skill_ops(skill_root, proposal)
    if not proposal.get("proposal_id"):
        proposal["proposal_id"] = next_proposal_id(skill_root)
    validate_proposal_id(proposal["proposal_id"])
    if not proposal.get("diff"):
        proposal["diff"] = proposal_diff(skill_root, proposal)
    proposal["status"] = "pending"
    proposal["staged_at"] = utc_now_iso()
    path = _contained_path(skill_root, f"wiki/proposals/{proposal['proposal_id']}.json")
    if path.exists():
        raise EvolutionError(f"proposal id already staged: {proposal['proposal_id']}")
    write_text(path, json.dumps(proposal, ensure_ascii=False, indent=2) + "\n")
    return path


def load_proposal(path: Path) -> dict[str, Any]:
    try:
        proposal = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvolutionError(f"cannot read proposal {path}: {exc}") from exc
    if not isinstance(proposal, dict) or not proposal.get("proposal_id"):
        raise EvolutionError(f"invalid proposal file: {path}")
    validate_proposal_id(proposal["proposal_id"])
    return proposal


def save_proposal(skill_root: Path, proposal: dict[str, Any]) -> Path:
    validate_proposal_id(proposal["proposal_id"])
    proposals_dir(skill_root)
    path = _contained_path(skill_root, f"wiki/proposals/{proposal['proposal_id']}.json")
    write_text(path, json.dumps(proposal, ensure_ascii=False, indent=2) + "\n")
    return path


def _mark_proposal(skill_root: Path, proposal: dict[str, Any], status: str, extra: dict[str, Any] | None = None) -> None:
    proposal["status"] = status
    proposal["decided_at"] = utc_now_iso()
    if extra:
        proposal.update(extra)
    save_proposal(skill_root, proposal)


def evaluate_proposal(
    skill_root: Path,
    proposal_path: Path | None,
    gate_mode: str = "full",
    rubric_score: float | None = None,
    baseline: bool = False,
) -> dict[str, Any]:
    """Apply-or-rollback decision point of the evolution loop.

    ``baseline=True`` measures the current tree and stores the result as the
    initial ``R_best`` (paper: R_best initialized to the baseline validation
    score). Otherwise the staged proposal is applied, the gate runs on the
    modified tree, and the change is kept iff the gate is green AND
    ``R > R_best``; otherwise every touched skill file is rolled back. The
    wiki layer (including the skill-impact ledger) is updated in both cases
    and never rolled back.
    """
    skill_root = skill_root.expanduser().resolve()
    # Reject malformed scores before applying a proposal or touching loop state.
    combine_scores(0.0, rubric_score)
    state = load_state(skill_root)
    r_best_before = float(state.get("r_best", 0.0))

    if baseline:
        gate = run_gate(skill_root, gate_mode)
        r = combine_scores(gate["r_det"], rubric_score)
        state["r_best"] = r
        state["baseline_set"] = True
        state["early_stop"] = float(r) >= 1.0
        save_state(skill_root, state)
        append_wiki_log(
            skill_root,
            f"\n## {utc_now_iso()} — baseline\n\n"
            f"- Gate mode: {gate_mode}; gate={gate['r_det']} "
            f"rubric={rubric_score if rubric_score is not None else '-'}\n"
            f"- R_best initialized to {r}\n",
        )
        if proposal_path is not None:
            _mark_proposal(skill_root, load_proposal(proposal_path), "baseline-measured", {"r": r, "r_det": gate["r_det"]})
        return {"outcome": "baseline", "r_best": r, "gate": gate}

    if proposal_path is None:
        raise EvolutionError("evaluate requires --proposal unless --baseline is set")
    proposal = load_proposal(proposal_path)
    check_rubric_expectation(proposal, rubric_score)
    kind = proposal.get("kind")

    if kind == "no_action":
        state["no_action"] = int(state.get("no_action", 0)) + 1
        state["iterations"] = int(state.get("iterations", 0)) + 1
        save_state(skill_root, state)
        append_skill_impact(skill_root, proposal, "no_action", None, rubric_score, None, None)
        append_wiki_log(
            skill_root,
            f"\n## {utc_now_iso()} — evaluate {proposal['proposal_id']}\n\n"
            f"- Outcome: no_action — proposer found nothing worth changing this iteration.\n",
        )
        _mark_proposal(skill_root, proposal, "no_action")
        return {"outcome": "no_action", "r_best": r_best_before}

    validate_skill_ops(skill_root, proposal)
    ops = proposal["ops"]
    targets = sorted({op["target"] for op in ops})
    images = plan_post_images(skill_root, ops)
    proposal.setdefault("diff", proposal_diff(skill_root, proposal, images))

    backup_dir = _contained_path(skill_root, "wiki/backups/" + proposal["proposal_id"])
    backup_targets(skill_root, backup_dir, targets)
    try:
        apply_images(skill_root, images)
        gate = run_gate(skill_root, gate_mode)
    except Exception:
        rollback_targets(skill_root, backup_dir, targets)
        raise

    r = combine_scores(gate["r_det"], rubric_score)
    accept = gate["ok"] and r > r_best_before

    if accept:
        state["r_best"] = r
        state["accepted"] = int(state.get("accepted", 0)) + 1
        state["early_stop"] = float(r) >= 1.0
        outcome = "accepted"
    else:
        rollback_targets(skill_root, backup_dir, targets)
        state["rejected"] = int(state.get("rejected", 0)) + 1
        outcome = "rejected"
    state["iterations"] = int(state.get("iterations", 0)) + 1
    state.setdefault("history", []).append(
        {
            "proposal_id": proposal["proposal_id"],
            "kind": kind,
            "target": proposal.get("target"),
            "outcome": outcome,
            "r": r,
            "r_det": gate["r_det"],
            "r_best_before": r_best_before,
            "at": utc_now_iso(),
        }
    )
    save_state(skill_root, state)
    append_skill_impact(skill_root, proposal, outcome, gate["r_det"], rubric_score, r, r_best_before)
    append_wiki_log(
        skill_root,
        f"\n## {utc_now_iso()} — evaluate {proposal['proposal_id']}\n\n"
        f"- Outcome: {outcome} (gate={gate['r_det']}, "
        f"rubric={rubric_score if rubric_score is not None else '-'}, "
        f"R={r}, R_best before={r_best_before})\n"
        f"- Target: {proposal.get('target')}\n"
        f"- Early stop: {bool(state.get('early_stop'))}\n",
    )
    _mark_proposal(skill_root, proposal, outcome, {"r": r, "r_det": gate["r_det"]})
    return {"outcome": outcome, "r": r, "r_best": float(state["r_best"]), "gate": gate}
