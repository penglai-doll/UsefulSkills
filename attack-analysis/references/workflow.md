# Workflow

## Modes

Mode selection is a hard preflight gate. Reuse the user's explicit `quick-report` or `interactive` choice for the same case. Ask before running tools only when no choice exists or the case/scope changed; continuing a case does not require repeated mode confirmation.

### quick-report
Use for emergency response. Defaults:

- Include all recognized logs under provided paths.
- Use `Asia/Shanghai` unless timestamps prove another time zone or the user supplies one.
- Enable public network enrichment.
- Continue on parser failures and report limitations.
- Produce a first-pass report quickly; mark ambiguous findings as unresolved.

### interactive
Use for deep investigation. Confirm before extraction:

- Included files and excluded files.
- Declared type for ambiguous logs.
- Default and per-file time zone.
- Target time window.
- High-priority questions, such as suspected IP, account, URL, or compromise time.

## State Machine

```text
mode-confirmation -> paths -> inventory -> manifest -> optional-confirmation -> extraction -> correlation -> AI review -> enrichment -> report -> case-trace
```

## Command Resolution

Use `<skill-root>` for script locations and `$PWD` for analyst-owned outputs. The scripts live under the installed `attack-analysis/` skill directory, not under the directory being analyzed.

```bash
python3 <skill-root>/scripts/inventory_logs.py <paths...> --mode quick-report --case-id "<case-id>" --workdir "$PWD" --json
python3 <skill-root>/scripts/extract_log_events.py --manifest "$PWD/cache/<case-id>/analysis-manifest.json" --output-dir "$PWD/cache/<case-id>/" --json
python3 <skill-root>/scripts/correlate_events.py --events "$PWD/cache/<case-id>/event-candidates.json" --output-dir "$PWD/cache/<case-id>/" --json
```

- `mode-confirmation`: record the explicit choice of `quick-report` or `interactive` and retain it across turns for this case.
- `inventory`: discover files, estimate size/line counts, detect compression, sample safely, infer log type and time range.
- `manifest`: record mode, default time zone, per-file overrides, include flags, network status, and analysis notes.
- `extraction`: stream logs through parser modules and emit compact events.
- `correlation`: group candidates conservatively. Scripts do not assert attacker intent.
- Coverage gaps: inspect `parser_stats`, `partial`, `truncated` and `unresolved_time_event_ids`. At a cap, `total_count=null` means the remaining candidates were not counted; `last_ref` is the last emitted line/row, not proof that the full file was scanned. Invalid dates remain in the evidence and do not abort following records. Time joins require a resolved offset and normalize to UTC.
- `AI review`: compare events against logs, reject noise, build attack chain, call out missing evidence.
- `report`: write Markdown with evidence references and uncertainty.
- `case-trace`: close the case by freezing a raw-layer experience trace:

```bash
python3 <skill-root>/scripts/wiki_cli.py capture-trace \
  --case-dir "$PWD/cache/<case-id>" --outcome pass \
  --notes "what worked, what failed, workarounds found"
```

The trace (`case-trace.json`) is immutable once written. During case analysis
do not read `<skill-root>/wiki/` — wiki access is reserved for evolution
sessions ([evolution.md](./evolution.md)).

## Large Logs

Never paste full large logs into model context.

- `<100MB`: full streaming scan is acceptable.
- `100MB-2GB`: use streaming extraction, keyword/time/IP filters, and capped output.
- `>2GB`: run inventory first, then narrow by time range, keywords, status codes, IPs, or chunks.

Recommended extraction order:

1. File boundaries: first and last timestamp-bearing records.
2. User-provided time window.
3. Security keywords: `login`, `auth`, `error`, `exception`, `union`, `select`, `sleep`, `upload`, `shell`, `cmd`, `admin`, `token`, `passwd`, `\.git`, `backup`, `zip`, `sql`.
4. High-signal HTTP statuses: 4xx/5xx, repeated 2xx on sensitive paths, unusual methods.
5. Top talker IPs and rare paths.

## Outputs

Default outputs under the invocation working directory:

```text
$PWD/cache/<case-id>/
  log-inventory.json
  analysis-manifest.json
  event-candidates.json
  correlation-candidates.json
  ip-enrichment.json
  case-trace.json
$PWD/report/<case-id>/log-analysis-report.md
```
