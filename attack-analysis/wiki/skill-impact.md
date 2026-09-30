# Skill Impact

Record of skill-change proposals and their gate outcomes. Appended by the
harness only (`wiki_cli.py evaluate`); never edited by hand and never rolled
back. One `## ` entry per evaluated proposal.

Entry format:

```
## <proposal-id> — <kind> — <target> — <accepted|rejected|no_action>
- Date: <ISO timestamp>
- Validation: gate=<0..1> rubric=<score or -> R=<score> (R_best before: <x>)
- Traces read: <comma-separated case ids>
- Rationale: <one line>
```diff
<unified diff of the proposed change; empty for no_action>
```
```

No proposals evaluated yet.
