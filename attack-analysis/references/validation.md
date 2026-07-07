# Validation

Run before publishing changes:

```bash
python3 -m unittest discover -s attack-analysis/tests -v
python3 -m py_compile attack-analysis/scripts/*.py attack-analysis/scripts/parsers/*.py attack-analysis/scripts/common/*.py
python3 attack-analysis/scripts/inventory_logs.py attack-analysis/tests/fixtures/gold_attack_case --mode quick-report --json >/tmp/attack_inventory.json
python3 attack-analysis/scripts/extract_log_events.py --manifest /tmp/attack_inventory.json --output-dir /tmp/attack-analysis-cache --json >/tmp/attack_events.json
python3 attack-analysis/scripts/correlate_events.py --events /tmp/attack-analysis-cache/event-candidates.json --output-dir /tmp/attack-analysis-cache --json >/tmp/attack_corr.json
```

Also validate:

- `SKILL.md` frontmatter name and description exist.
- `agents/openai.yaml` references `$attack-analysis` in `default_prompt`.
- Unknown logs are not forced into verified types.
- Network fallback is recorded when enrichment is unavailable.
- Reports and examples do not include threat scores or risk totals.
