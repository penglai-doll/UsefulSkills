# Evolution Protocol (WikiSkill)

This skill compiles case experience into persistent knowledge and evolves the
skill itself, following the WikiSkill theory (arXiv:2608.27454): a
**three-layer knowledge architecture** plus an **evolutionary loop with four
components**. The harness (`scripts/wiki_cli.py`, library
`scripts/common/evolution.py`) enforces the mechanics; the AI roles produce
the content.

## Three-Layer Architecture

```text
attack-analysis/
  wiki/                     # WIKI LAYER: persistent knowledge (never rolled back)
    patterns/*.md           #   one page per failure mode / successful strategy
    index.md                #   one line per pattern: PROBLEM -> ROOT CAUSE -> FIX
    logs.md                 #   chronological evolution log
    skill-impact.md         #   proposal ledger: diff + score + outcome (harness-only)
    state.json              #   R_best / iteration counters (harness-only)
    proposals/              #   staged + decided proposals (harness-only)
    backups/                #   pre-apply snapshots for skill rollback (harness-only)
  SKILL.md references/ scripts/ tests/ PURPOSE.md   # SKILLS LAYER (evolving)

$PWD/cache/<case-id>/case-trace.json   # RAW LAYER: one immutable trace per closed case
$PWD/cache/<case-id>/ ...              #   plus the case's own artifacts (manifest,
$PWD/report/<case-id>/ ...             #   events, correlations, report = full evidence)
```

Layer rules:

1. **Raw layer** is append-only per case: after a case closes, capture a
   trace (`capture-trace`) and do not rewrite case artifacts.
2. **Wiki layer** is the compile-time memory. It is updated only by the Wiki
   Maintainer through `consolidate`, plus harness bookkeeping. It is **never
   rolled back**, even when a skill change is rejected.
3. **Skills layer** is what a case analysis runs on. It changes only through
   the gate (`evaluate`) — never by direct edits during an evolution session.

## Role Separation (hard rules)

- **Inference Agent (case analysis)**: executes the normal workflow using
  SKILL.md + references only. It must **not read `wiki/`** during case work.
  The paper's ablation shows wiki access during task execution degrades skill
  development (60.9% vs 63.7%): the skills must stay self-sufficient.
- **Wiki Maintainer**: consolidates sampled traces into the wiki via
  `consolidate`. It may **only** write under `wiki/` (and never
  `skill-impact.md`, `state.json`, `proposals/`, `backups/` — harness-owned).
  It never edits the skills layer.
- **Skill Proposer**: reads the wiki index, `skill-impact.md`, and raw
  traces, then stages **one atomic proposal** via `propose`. It may target
  only the skills layer, never `wiki/`, and its proposal must list **at least
  4** `traces_read` entries (paper requirement). If nothing is worth
  changing, it stages a `no_action` proposal.
- **Harness/Gating**: `evaluate` is the only component that applies
  skill changes, runs validation, accepts or rolls back, and updates
  `skill-impact.md` + `logs.md` + `state.json`.

## Loop

```text
run cases (Inference Agent, no wiki access)
  -> capture-trace per closed case            (raw layer grows)
  -> every batch: consolidate                 (Wiki Maintainer, <=8 traces)
  -> propose one atomic skill change          (Skill Proposer)
  -> evaluate: apply -> gate -> accept/rollback (Gating)
  -> stop when R_best >= 1.0 (early termination)
```

### 1. Capture traces (raw layer)

After closing a case (report written), record the outcome and what was
learned:

```bash
python3 <skill-root>/scripts/wiki_cli.py capture-trace \
  --case-dir "$PWD/cache/<case-id>" --outcome fail \
  --notes "xlsx login header variant fell back to xlsx_table; manual mapping recovered" \
  --analyst-score 0.6
```

- `--outcome` is the reviewed verdict of the run: `pass` or `fail`.
- `--notes` is the experience payload: what failed, what worked, workarounds.
- The harness assembles `case-trace.json` from the case's own artifacts and
  pre-truncates `wiki_view` to **15,000 chars** (paper cap). Downstream
  consumers must use `wiki_view`, never the full report.

### 2. Consolidate (Wiki Maintainer)

Sample up to **8** traces per batch — at most **5 failing** and **3 passing**
(paper composition; the harness rejects anything else). Read the traces'
`wiki_view`, then write ops:

```json
{
  "summary": "one-line summary",
  "ops": [
    {"op": "create_pattern", "target": "wiki/patterns/P-009-slug.md",
     "title": "P-009: title", "meta": {"type": "failure-mode", "source": "case-x"},
     "index_line": "PROBLEM: ... -> ROOT CAUSE: ... -> FIX: ...",
     "content": "## PROBLEM\n...\n## ROOT CAUSE\n...\n## FIX / Workaround\n..."},
    {"op": "set_index_line", "target": "wiki/patterns/P-001-....md",
     "index_line": "PROBLEM: ... -> ROOT CAUSE: ... -> FIX: ..."},
    {"op": "append", "target": "wiki/patterns/P-003-p6spy-embedded-in-spring.md",
     "content": "- 2026-09: confirmed on case-y; see notes"},
    {"op": "replace", "target": "wiki/index.md", "anchor": "<exact current line>",
     "content": "<replacement line>"},
    {"op": "insert_after", "target": "wiki/logs.md", "anchor": "<exact line>",
     "content": "observation"}
  ]
}
```

Op semantics: `create`/`append`/`replace`/`insert_after` are patch-based
incremental edits (paper style); anchors must match exactly once.
`create_pattern` and `set_index_line` are harness sugar that keep
`index.md` in sync automatically. `logs.md` entries are appended by the
harness — do not edit it by hand.

```bash
# validate without writing:
python3 <skill-root>/scripts/wiki_cli.py --check consolidate \
  --traces "$PWD/cache/a/case-trace.json" "$PWD/cache/b/case-trace.json" \
  --ops ops.json
# apply:
python3 <skill-root>/scripts/wiki_cli.py consolidate \
  --traces ... --ops ops.json --summary "..."
```

Pattern pages must be **standalone**: PROBLEM / ROOT CAUSE / FIX with an
actionable workaround, written so a reader who never saw the trace can apply
the fix.

### 3. Propose (Skill Proposer)

Read `wiki/index.md`, `wiki/skill-impact.md`, the batch outcome summary, the
raw traces, and the motivating pattern pages. Then produce **at most one**
proposal targeting **one file** (the atomic unit here; the paper's "single
skill" maps to one file so patches stay reviewable and rollback precise):

```json
{
  "kind": "skill-edit",
  "target": "SKILL.md",
  "rationale": "one line: which wiki patterns motivate this",
  "traces_read": ["case-a", "case-b", "case-c", "case-d"],
  "patterns_read": ["wiki/patterns/P-004-xlsx-header-variants.md"],
  "ops": [
    {"op": "insert_after", "target": "SKILL.md", "anchor": "7. Use AI to review",
     "content": "8. When xlsx header detection is low-confidence, ..."}
  ]
}
```

- `kind`: `skill-edit` (append/replace/insert_after on an existing file),
  `skill-create` (exactly one `create` op on a new file), or `no_action`
  (empty ops) — matching the paper's atomic create-or-patch-or-nothing.
- `traces_read` must list **>= 4** case ids actually read (harness-enforced).
- `expects_rubric: true` for proposals that change analysis behavior; such
  proposals are evaluated only with a reviewed validation-case score (see
  below). Docs-only or mechanical proposals may omit the rubric.

```bash
python3 <skill-root>/scripts/wiki_cli.py propose --proposal proposal.json
# stages to wiki/proposals/prop-NNNN.json with a unified diff attached
```

### 4. Evaluate (Gating and Rollback)

```bash
# once per campaign: set the baseline (paper: R_best = baseline score)
python3 <skill-root>/scripts/wiki_cli.py evaluate --baseline --gate full

# per proposal:
python3 <skill-root>/scripts/wiki_cli.py evaluate \
  --proposal wiki/proposals/prop-0001.json --gate full --rubric-score 0.8
```

Semantics:

1. The harness applies the proposal's ops to the skills layer.
2. It runs the validation gate (`--gate full`):
   contract checks + `py_compile` + unittest suite + gold-case pipeline
   (inventory -> extract -> correlate must still find the gold attack chain).
   `--gate lite` runs contract + py_compile only.
3. Score: gate is binary (`r_det` 0/1); with a reviewer's validation-case
   score, `R = 0.5*r_det + 0.5*rubric`.
4. **Accept iff the gate is green AND `R > R_best`** (strict improvement,
   paper rule). Otherwise every touched skill file is rolled back from the
   harness snapshot.
5. In both cases the harness appends the proposal's metadata, target, unified
   diff, score, and outcome to `wiki/skill-impact.md`, appends `wiki/logs.md`,
   and updates `wiki/state.json`. The wiki is never rolled back.
6. When `R_best >= 1.0`, `state.early_stop` becomes true: stop proposing
   (paper early termination). `wiki_cli.py status` shows the state.

## Validation-Case Reviews (R rubric)

`--rubric-score` comes from re-running the evolved skill on a held-out case
and scoring the report 0..1: timeline correctness with explicit time-zone
handling; evidence chain resolvable to file+line; source-IP analysis without
identity overreach; uncertainty stated; no threat scores. Record the review
in the case trace notes.

- Proposals with `expects_rubric: true` are rejected by `evaluate` unless
  `--rubric-score` is supplied; the score blends into
  `R = 0.5*gate + 0.5*rubric`.
- Proposals without the flag are scored by the gate alone — use that only
  for docs-only or mechanical changes.
- Baselines for real campaigns should also carry a rubric score:
  `evaluate --baseline --rubric-score <x>`. A gate-only baseline on an
  already-green tree sets `R_best = 1.0`, which immediately early-stops the
  loop (nothing left to prove at the gate level) — that is the paper's
  early-termination rule applied to the checkable surface.

## Campaign Checklist

1. `evaluate --baseline --gate full` (initialize R_best).
2. Run cases; `capture-trace` each closed case.
3. Batch 5-8 traces; `consolidate`.
4. Read index + skill-impact + >= 4 traces; `propose` (or `no_action`).
5. `evaluate --proposal ... --gate full`; read `status`.
6. Repeat 2-5 until `early_stop` or the campaign budget ends.

## Non-Goals

The harness never pushes, never edits reports or caches, and never
auto-proposes: the maintainer/proposer roles are always an AI (or human)
reading real traces. It only enforces composition caps, atomicity, reading
requirements, gating, rollback, and the ledgers.
