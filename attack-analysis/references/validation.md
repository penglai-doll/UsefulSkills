# Validation

Run before publishing changes:

```bash
python3 -m unittest discover -s attack-analysis/tests -v
python3 -m py_compile attack-analysis/scripts/*.py attack-analysis/scripts/parsers/*.py attack-analysis/scripts/common/*.py
python3 attack-analysis/scripts/inventory_logs.py attack-analysis/tests/fixtures/gold_attack_case --mode quick-report --json >/tmp/attack_inventory.json
python3 attack-analysis/scripts/extract_log_events.py --manifest /tmp/attack_inventory.json --output-dir /tmp/attack-analysis-cache --json >/tmp/attack_events.json
python3 attack-analysis/scripts/correlate_events.py --events /tmp/attack-analysis-cache/event-candidates.json --output-dir /tmp/attack-analysis-cache --json >/tmp/attack_corr.json
```

Evolution harness checks (see [evolution.md](./evolution.md)):

```bash
python3 attack-analysis/scripts/wiki_cli.py validate-wiki
python3 attack-analysis/scripts/wiki_cli.py status
```

`wiki_cli.py evaluate` re-runs this whole checklist (contract + py_compile +
unittest + gold pipeline) as part of its gate; `evaluate --baseline` is a
campaign-start action that initializes `R_best`, not a routine check.

Also validate:

- `SKILL.md` frontmatter name and description exist.
- `agents/openai.yaml` references `$attack-analysis` in `default_prompt`.
- Unknown logs are not forced into verified types.
- Network fallback is recorded when enrichment is unavailable.
- Reports and examples do not include threat scores or risk totals.
- `wiki/index.md` links every pattern page in `wiki/patterns/` and vice versa.
- Proposals stay atomic (one target), list >= 4 distinct traces read, and never target `wiki/`.
- Invalid dates do not stop later records; mixed naive/aware times do not crash or create unsupported time joins. Extraction/correlation caps are visible.
- JSON stdout is UTF-8 under a legacy Windows console encoding; subprocess validation uses explicit UTF-8.
- Proposal IDs cannot escape storage paths, reserved wiki paths cannot be bypassed with `./`, linked targets cannot redirect writes, and an apply exception restores the original skill.
