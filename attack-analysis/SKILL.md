---
name: attack-analysis
description: Use when analyzing server attack logs and producing a Markdown incident timeline/report from web access logs, application logs, SQL/P6Spy logs, login/operation exports, firewall/WAF/auth/system text logs, or mixed log directories; focuses on attack reconstruction, source IP enrichment, evidence chains, problems found, and remediation, not real-time SIEM alerting or active exploitation.
---

# Attack Analysis

Skill release: `1.0.1`

AI-led, script-assisted server attack log reconstruction. Use scripts for deterministic inventory, parsing, normalization, and candidate correlations; use AI judgment to confirm scope, link events, explain attack flow, and write the final report.

## Start

Before running inventory, parsing, enrichment, or report generation, use exactly one mode: `quick-report` or `interactive`. Reuse the user's explicit choice for the same case across turns; ask only if no choice exists or the case/scope changed. Do not infer a mode from urgency or provided paths.

- `quick-report`: emergency-first. Accept paths, inventory all recognizable logs, use defaults, run extraction/correlation, and produce a first Markdown report with uncertainties called out.
- `interactive`: investigation-first. Confirm included files, declared log types, per-file time zones, target time range, and focus questions before extraction.

If the user only invokes `/attack-analysis` or asks to analyze logs without naming a mode, ask a short mode-selection question and wait for the answer before running tools.

Default network assist is enabled for public enrichment. If networking fails, record the failure and continue offline. Do not install tools or download databases without separate user approval.

## Workflow

1. Record the user's mode choice: `quick-report` or `interactive`; reuse it while continuing the same case.
2. Run inventory on user-provided files or directories.
3. Build or update `analysis-manifest.json` with mode, default time zone, per-file type/time-zone fields, include decisions, and network status.
4. In `interactive`, ask the user to confirm file inclusion, type, time range, and per-file time zone when detection is ambiguous.
5. Extract compact event candidates with parser modules. Never load full GB-scale logs into model context.
6. Generate basic correlation candidates by IP/account/request/session/path and time window.
7. Use AI to review candidate events/correlations, reject noise, and promote only evidence-backed attack-chain steps.
8. Enrich attacker IP/domain/ASN/public vulnerability context when useful; keep external enrichment separate from log evidence.
9. Write `$PWD/report/<case-id>/log-analysis-report.md` with timeline, source IPs, attack process, evidence, current problems, remediation, and limitations.
10. Close the case: capture an execution trace for the experience loop (`capture-trace`, outcome `pass`/`fail` plus analyst notes).

Detailed workflow: [workflow.md](./references/workflow.md)

## Scripts

Treat `<skill-root>` as the installed `attack-analysis/` directory that contains `scripts/`. Run scripts from there; keep `--workdir "$PWD"` pointed at the directory where you want case outputs written. Do not assume the analyzed log directory itself contains a `scripts/` folder.

```bash
python3 <skill-root>/scripts/inventory_logs.py <paths...> --mode quick-report --case-id "<case-id>" --workdir "$PWD" --json
python3 <skill-root>/scripts/extract_log_events.py --manifest "$PWD/cache/<case-id>/analysis-manifest.json" --output-dir "$PWD/cache/<case-id>/" --json
python3 <skill-root>/scripts/correlate_events.py --events "$PWD/cache/<case-id>/event-candidates.json" --output-dir "$PWD/cache/<case-id>/" --json
```

Environment: Python 3.10+ standard library only, plus the `tzdata` package on Windows (`pip install -r <skill-root>/requirements.txt`). Linux uses the system tz database and needs nothing extra. Without `tzdata` on Windows, named time zones such as `Asia/Shanghai` cannot resolve: timestamps stay naive and are marked `unknown`, and the manifest and event output record a `timezone_notes` warning — treat any such warning as a setup problem to fix before trusting the timeline.

Script roles:

- `inventory_logs.py`: file discovery, type detection, size strategy, time-range hints, and manifest seed.
- `extract_log_events.py`: dispatcher only; calls parsers under `scripts/parsers/`.
- `correlate_events.py`: conservative candidate grouping only; does not assert causality.
- `wiki_cli.py`: experience-evolution harness (`capture-trace`, `consolidate`, `propose`, `evaluate`, `validate-wiki`, `status`); reserved for evolution sessions, see [evolution.md](./references/evolution.md).

## Log Coverage

Read [log-types.md](./references/log-types.md) before claiming support.

- v1 verified: common/combined Apache-nginx style access logs, Spring Boot app logs, P6Spy SQL logs, xlsx login/operation exports.
- v1 best-effort: auth logs, firewall/WAF text logs, system/service logs, generic text logs, mysqlbinlog text exports.
- future interface only: binary MySQL binlog deep reconstruction, Windows Event Log, cloud audit logs, Kubernetes/container forensics.

## Evidence Rules

- Every report claim needs log evidence, external enrichment, or explicit analyst inference.
- Preserve raw references as file path plus line number or row number where possible.
- Treat extraction `partial`/`truncated`, parser limits and correlation `unresolved_time_event_ids` as coverage gaps. Invalid dates remain record-level candidates; unknown time zones are excluded from temporal joins. Report the last scanned reference and narrow the range or increase the cap before claiming full coverage.
- Normalize IPs and ports, but preserve original values.
- Distinguish confirmed log facts, candidate correlations, external enrichment, and AI inference.
- Do not output threat scores, risk totals, numeric severity ratings, or “battle power” style labels.

Correlation rules: [correlation.md](./references/correlation.md)

## Network and Privacy

Default online enrichment may query public IP/ASN/location, domain reputation context, CVE/product documentation, scanner/User-Agent signatures, and public attack patterns.

Allowed to send externally by default: IPs, domains, ASN targets, public keywords, and short User-Agent fragments.

Do not send externally by default: full logs, tokens, cookies, request bodies, passwords, private account identifiers, internal business parameters, database query results, or complete sensitive URLs.

Network rules: [ip-enrichment.md](./references/ip-enrichment.md)

## Boundaries

v1 is a log-sourced attack reconstruction report skill. It is not a real-time SIEM, active defense system, vulnerability verifier, judicial evidence preservation platform, full packet/disk/memory forensics tool, or all-format parser.

Do not actively scan attacker infrastructure, visit suspected callback URLs, exploit vulnerabilities, block IPs, change firewalls, delete files, or modify production systems unless the user explicitly starts a separate remediation task.

## Experience and Evolution

The skill carries a WikiSkill-style three-layer experience architecture (theory: arXiv:2608.27454), implemented by `scripts/wiki_cli.py`:

- **Raw layer**: one immutable `case-trace.json` per closed case under `$PWD/cache/<case-id>/` (plus the case artifacts themselves). Captured with `capture-trace` at workflow step 10.
- **Wiki layer**: `<skill-root>/wiki/` — `patterns/` pages (PROBLEM → ROOT CAUSE → FIX), `index.md` catalog, `logs.md` evolution log, and the harness-owned `skill-impact.md`/`state.json`. Updated only by the Wiki Maintainer role via `consolidate`; never rolled back.
- **Skills layer**: `SKILL.md`, `references/`, `scripts/`, `tests/`, `PURPOSE.md`. Changed only through gated atomic proposals (`propose` + `evaluate`): accept iff the validation gate is green and the score strictly improves `R_best`; otherwise roll back.

Role separation is mandatory: during a case analysis (this workflow) do **not** read or edit `wiki/` — case work runs on the skills layer alone. The wiki is only read and written in dedicated evolution sessions (maintainer consolidates trace batches; proposer stages one atomic skill change; the gate decides). Full protocol: [evolution.md](./references/evolution.md).

## Resources

- [workflow.md](./references/workflow.md): modes, state machine, large-log handling.
- [log-types.md](./references/log-types.md): verified/best-effort/future log coverage.
- [correlation.md](./references/correlation.md): candidate grouping and AI promotion rules.
- [ip-enrichment.md](./references/ip-enrichment.md): default online assist and privacy boundaries.
- [reporting.md](./references/reporting.md): Markdown report contract.
- [error-handling.md](./references/error-handling.md): malformed logs and mismatch handling.
- [validation.md](./references/validation.md): required checks before publishing changes.
- [evolution.md](./references/evolution.md): three-layer experience architecture and the four-component evolution loop.
- [PURPOSE.md](./PURPOSE.md): skill-to-pattern motivation map (skills layer contract).
