# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repository is a collection of custom-designed AI skills (for Claude Code, OpenAI Codex, etc.). Each skill lives in its own subdirectory with a standardized structure.

## Skill Structure Convention

Each skill directory follows this layout:

```
<skill-name>/
  SKILL.md          # Main skill definition (frontmatter: name, description, type)
  scripts/          # Python helper scripts invoked by the skill
  references/       # Supporting documents referenced by SKILL.md (workflow, heuristics, etc.)
  agents/           # Agent platform configs (e.g., openai.yaml for Codex)
```

- `SKILL.md` is the entry point — it uses YAML frontmatter (`name`, `description`) and defines the skill's operating rules, fixed workflow, resources, guardrails, and example requests.
- Reference docs are written in Chinese (Simplified) when the skill targets Chinese-language output.
- Scripts are Python 3, self-contained with minimal external dependencies.

## Current Skills

- **android-malware-analysis** — Static analysis of suspicious Android packages (APK/XAPK/APKS/ZIP/DEX). Generates Chinese Markdown + DOCX investigation reports with two-phase callback extraction and SDK key recovery.

## Working With Skills

When creating or modifying a skill:

1. Keep `SKILL.md` as the single source of truth for the skill's behavior contract.
2. Reference docs go in `references/` — `SKILL.md` links to them rather than inlining large content.
3. Scripts should be runnable standalone (`python scripts/<script>.py --help`).
4. Agent configs in `agents/` adapt the skill for specific platforms (Codex, etc.) — they reference the same `SKILL.md` content.

## Commands (android-malware-analysis)

```bash
# Check environment readiness
python android-malware-analysis/scripts/check_android_tools.py

# Run full investigation pipeline
python android-malware-analysis/scripts/investigate_android_app.py <sample> --output-dir <dir> --mode auto

# Raw IOC pre-check only
python android-malware-analysis/scripts/analyze_package.py <path>
```
