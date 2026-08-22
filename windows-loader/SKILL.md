---
name: windows-loader
description: Use when mounting, inspecting, triaging, or extracting targeted forensic evidence from a Windows guest disk image (raw/dd/img, single or split E01, VHD, or VHDX) from the current Windows, Linux, or WSL terminal without writing to original evidence.
---

# Windows Loader v1

Handle Windows **guest** evidence only. Keep original evidence read-only; do not execute guest binaries, services, scripts, installers, or document macros. Produce an interactive case summary, not a formal report.

## Declare the task

1. Record the absolute evidence path, detected format, segment set, current terminal, case-state path, and requested mode.
2. Require one hash policy: `now`, `later`, or `skip`. Record available hash algorithms and preserve the policy in case state; never silently hash or skip.
3. Accept only `raw`, `dd`, `img`, `E01`, split `E01`, `VHD`, and `VHDX`.
4. Set exactly one mode: `mount-only`, `fast-path`, or `mount-and-analyze`.

SUPPORTED_FORMATS: raw, dd, img, E01, split E01, VHD, VHDX
EWF_SEGMENT_SEQUENCE: E01-E99, EAA-EZZ, FAA-FZZ, ... , ZAA-ZZZ
EWF_SEGMENT_INPUT: CANONICALIZE_TO_E01; REJECT_MISSING_OR_AMBIGUOUS_CONTINUATIONS
MODES: mount-only, fast-path, mount-and-analyze
HASH_POLICY: now, later, skip
AVAILABLE_HASH_ALGORITHMS: RECORD_IN_INSPECT_AND_CASE_STATE_WITHOUT_IMPLICIT_HASHING
NO_FORMAL_REPORT

## Route the current terminal

Inspect the current terminal once, then select exactly one independent reference. Do not adapt, blend, emulate, auto-switch, or invoke a different environment.

CURRENT_TERMINAL_REFERENCE: SELECT_EXACTLY_ONE_OF_WINDOWS_LINUX_WSL
REFERENCE_ADAPTERS: PROHIBITED
TERMINAL_AUTO_SWITCH: PROHIBITED

- Native Windows terminal: read [mount-windows.md](./references/mount-windows.md).
- Native Linux terminal: read [mount-linux.md](./references/mount-linux.md).
- WSL terminal: read [mount-wsl.md](./references/mount-wsl.md).

If the selected environment cannot safely meet a prerequisite, stop and ask the user for the stated next action. In WSL, only ask the user to restart in Windows; never restart, invoke, or switch it yourself.

## Work in the selected mode

- `mount-only`: perform preflight, mount read-only, verify the mount, inventory only the Windows guest layout, retain a successful mount, and give cleanup commands.
- `fast-path`: perform the same safe preflight and mount, then run the two-stage bounded search for the user-named artifact or product.
- `mount-and-analyze`: perform `mount-only`, then request a narrowly scoped analysis target before reading artifacts.

Use bundled scripts only for deterministic local inspection and bounded output:

```text
python scripts/inspect_evidence.py --help
python scripts/inspect_windows_tree.py --help
python scripts/find_windows_paths.py --help
python scripts/analyze_artifact.py --help
python scripts/case_state.py --help
python scripts/case_state.py init --case-dir ./tmp/windows-loader/<case-id> --image <evidence> --hash <now|later|skip> --mode <mount-only|fast-path|mount-and-analyze>
```

SEARCH: TWO_STAGE_BOUNDED

Stage 1 searches the high-value catalogued paths before expanded discovery. Stage 2 runs only after explicit `--expand` authorization and remains inside the catalog's enumerated roots; it never scans the unrestricted mounted root. Default to depth 4 and limit 50; do not follow reparse points. Record ACL-denied paths as errors, never as absence. Read [windows-path-catalog.md](./references/windows-path-catalog.md) and [schema.md](./references/schema.md) before presenting results.

HOST_ENUMERATION_ORDER_LIMITATION: bounded scans consume the host filesystem's enumeration order. Results are not guaranteed to be deterministic when the entry budget truncates a directory; deterministic sorting would first require unbounded enumeration. Report this limitation in scan metadata and never describe a truncated scan as exhaustive.

## Create case state automatically

Create case state before the first mount or installation proposal, before a long scan, when a task becomes multi-turn, before handling a large artifact, or when imminent context compression could lose operational facts. Use `./tmp/windows-loader/<case-id>/` by default and keep it outside original evidence. Do not wait for a user reminder.

The case directory contains exactly these persistent case artifacts: `session.json`, `notes.md`, `commands.jsonl`, `findings.jsonl`, `secrets.jsonl`, `inspect.json`, `mounts.json`, and `raw/`. Treat optional CLI output fields as extensions; never use them to replace required case-schema fields.

## Gate every state-changing or sensitive step

Read [install-authorization.md](./references/install-authorization.md) before proposing any installation, package action, driver, service, reboot, or download. An approval authorizes only its immutable exact plan ID.

Read [safety-gates.md](./references/safety-gates.md) before presenting route fallbacks, writing anything to original evidence, accessing BitLocker/VSS/DPAPI material, or recording plaintext secrets. Do not change ACLs or add encryption as a side effect.

Never put a secret value on the command line. After the plaintext-risk acknowledgement, use bounded `record-secret --stdin`; do not echo the value or include it in operational command logs.

SECRET_INPUT: BOUNDED_STDIN
COMMAND_LINE_SECRET_VALUE: PROHIBITED

## Finish each turn

Persist case state outside original evidence. End every turn with absolute paths, whether plaintext secrets were written, mount state, exact cleanup status/commands, current hash status, and any confirmation still required. Keep successful mounts until the user asks for cleanup; clean partial failures immediately.
