# Purpose

This file maps the attack-analysis skill back to the wiki patterns that
motivate its current shape (WikiSkill skills layer contract). When the gate
accepts a proposal, the Skill Proposer updates the matching row here and
cites the pattern pages it relied on.

## Why this skill exists

Reconstruct server attacks from mixed logs into an evidence-backed Markdown
incident report — without loading raw logs into model context, without
asserting unproven causality, and without pseudo-quantitative scoring.

## Component-to-pattern map

| Skill component | Motivating wiki patterns |
| --- | --- |
| `SKILL.md` Environment notes + tzdata requirement | [P-001](wiki/patterns/P-001-windows-tzdata-naive-timestamps.md) |
| `scripts/common/ip_normalize.py`, evidence rules on IP attribution | [P-002](wiki/patterns/P-002-xff-port-ipchain-normalization.md), [P-008](wiki/patterns/P-008-evidence-wording-discipline.md) |
| `scripts/extract_log_events.py` parser chains (`PARSER_MAP`) | [P-003](wiki/patterns/P-003-p6spy-embedded-in-spring.md) |
| `scripts/inventory_logs.py` xlsx header detection | [P-004](wiki/patterns/P-004-xlsx-header-variants.md) |
| `scripts/inventory_logs.py` syslog filename fallback, `references/log-types.md` | [P-005](wiki/patterns/P-005-rotated-syslog-no-extension.md) |
| `scripts/correlate_events.py` same-IP windows, `references/correlation.md` | [P-006](wiki/patterns/P-006-gold-attack-chain-strategy.md) |
| `references/workflow.md` large-log handling | [P-007](wiki/patterns/P-007-large-log-windowing.md) |
| `references/reporting.md` wording rules, gate contract check | [P-008](wiki/patterns/P-008-evidence-wording-discipline.md) |
| Evolution loop (`references/evolution.md`, `scripts/wiki_cli.py`) | the loop that compiles and applies all of the above |

## Change discipline

Skill changes enter only through the gated loop: traces -> wiki patterns ->
atomic proposal -> validation gate -> accept-or-rollback. `PURPOSE.md` rows
are part of the skills layer, so updating this map is itself a proposable
`skill-edit` on this file.
