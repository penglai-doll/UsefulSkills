# Workflow

## Modes

Mode selection is a hard preflight gate. Before running any tool, ask the user to choose `quick-report` or `interactive` unless the current user request already names one of them. Do not reuse a previous turn's mode silently.

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
mode-confirmation -> paths -> inventory -> manifest -> optional-confirmation -> extraction -> correlation -> AI review -> enrichment -> report
```

- `mode-confirmation`: require an explicit current-turn choice of `quick-report` or `interactive`.
- `inventory`: discover files, estimate size/line counts, detect compression, sample safely, infer log type and time range.
- `manifest`: record mode, default time zone, per-file overrides, include flags, network status, and analysis notes.
- `extraction`: stream logs through parser modules and emit compact events.
- `correlation`: group candidates conservatively. Scripts do not assert attacker intent.
- `AI review`: compare events against logs, reject noise, build attack chain, call out missing evidence.
- `report`: write Markdown with evidence references and uncertainty.

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

Default output root:

```text
output/attack-analysis/<case-id>/
  report/log-analysis-report.md
  cache/log-inventory.json
  cache/analysis-manifest.json
  cache/event-candidates.json
  cache/correlation-candidates.json
  cache/ip-enrichment.json
```
