---
name: wire-toutetu
description: Analyze offline PCAP/PCAPNG/CAP and gzip packet captures for CTF traffic, protocol reconstruction, object recovery, layered decoding, WebShell traffic, and HTTP tunnels. Use when the user supplies a capture or case directory, asks for a packet timeline, wants files/flags recovered, or needs Behinder, Godzilla, AntSword, China Chopper, Weevely3, suo5, reGeorg, or Neo-reGeorg traffic explained. Optimized for compact local models through signal-routed references and paginated evidence queries.
---

# WireToutetu

## Operating contract

- Treat captures and sidecars as offline evidence. Do not start live capture.
- Run `scripts/wiretoutetu.py preflight --json` before the first analysis on a machine.
- TShark is required. Detect Windows, Linux, or WSL explicitly. Ask before installing or upgrading tools or drivers.
- Runtime is Python 3.10+ with `requirements.txt`; Scapy in `requirements-test.txt` is fixture-generation-only.
- Default to `--network offline`. Before `--network on`, show the smallest proposed query/material and obtain confirmation.
- Only statically inspect extracted scripts, binaries, and documents.
- Preserve the original capture and sidecar hashes. Write generated state under `./tmp/WireToutetu/<case-id>/` unless the user names a case directory.
- Report `verified-decode`, `verified-extract`, `best-effort`, `metadata-only`, or `unavailable` exactly as returned by the catalog. Do not promote a capability from documentation alone.
- Do not invent confidence or a risk total. Separate observed `EVT-*` facts from `FIND-*` model judgments; every finding cites evidence IDs.

## Default workflow

1. Run preflight and inspect the selected platform route, TShark version, field count, optional tools, and upgrade note.
2. Hash the capture and sidecars. Let the CLI choose the size route:
   - below 100 MiB: full pipeline;
   - 100 MiB through 2 GiB: stream index, payloads on demand;
   - above 2 GiB: inventory first, then slice by time, IP, port, or stream.
3. Analyze:

   ```text
   python scripts/wiretoutetu.py analyze <capture> --case-dir <dir> --sidecar <path>
   ```

   Add `--question <text>` when the user has a specific question. Without one, reconstruct the complete event chain: time, endpoint, protocol, operation, target, result, evidence, and gaps.
4. Read the returned `routes`. Load `references/index.md`, then only the recommended domain index and leaf documents. Never load the full knowledge tree into a small model.
5. Query small views first. Default to 50 rows; follow the cursor instead of requesting oversized output:

   ```text
   python scripts/wiretoutetu.py query --case-dir <dir> --view summary
   python scripts/wiretoutetu.py query --case-dir <dir> --view timeline --limit 50
   python scripts/wiretoutetu.py query --case-dir <dir> --view evidence --id <EVIDENCE-ID>
   ```

6. Answer the user's question first. Cite `FLOW-*`, `TXN-*`, `OBJ-*`, `DEC-*`, and `EVT-*`; list unresolved keys, missing segments, unsupported fields, and partial objects.
7. Export only when requested. `markdown` is a Chinese result document; `bundle` is reopened and hash-verified after creation.

## WebShell routing

- Use `references/webshell/index.md` when HTTP/WebSocket payloads show encryption, delimiters, stable POST paths, tunnel headers, or supplied family/key material.
- Read family keys from `references/webshell/default-keys.json`. Treat them as sourced candidates, not universal defaults.
- Prefer explicit sidecar profiles and keys. Missing key material is `not-attempted`; wrong keys and strict padding/tag failures are `failed`.
- Preserve request and response direction. Record every unwrap/decode layer with input/output hashes, lengths, parameter source, status, and next action.
- For suo5, parse the random-XOR frame and KLV map before routing `dt` as an inner protocol. For reGeorg/Neo-reGeorg, reconstruct connect/read/write/forward/disconnect control events and target fields.

## Evidence and completeness

- `FLOW-*`: endpoints, direction, packet/time range, byte count, retransmission/out-of-order/missing/truncated state.
- `TXN-*`: protocol transaction; HTTP/2 stores TCP stream and substream.
- `OBJ-*`: source transaction, filename, magic, size, SHA-256, extraction path.
- `DEC-*`: algorithm, non-secret parameter description, source, hashes, lengths, fixed decode status, error.
- `EVT-*`: timeline observation.
- `FIND-*`: model conclusion referencing one or more evidence IDs.
- Completeness is only `complete`, `partial`, `truncated`, or `unknown`.
- Decode status is only `text`, `binary`, `partial`, `failed`, or `not-attempted`.

## Knowledge and experience

- `scripts/registry.yaml` is the plugin routing source. `references/registry.yaml` plus leaf frontmatter are the knowledge routing source.
- Run `python scripts/build_indexes.py --check` and `python scripts/validate_catalog.py --check` after changing plugins, references, fixtures, or support levels.
- Review at most five relevant lessons before analysis:

  ```text
  python scripts/wiretoutetu.py experience review --signal <signal>
  ```

- `经验.md` stores at most 12 stable lessons and 4 recent summaries under 12 KiB. Never place flags, IOCs, account values, raw keys, full payloads, or challenge answers there.
- Analysis-specific material remains in the case. Merge only a short, reusable, fixture-validated lesson. When the Skill directory is read-only, save the candidate as `experience-pending.json` in the case.

## Output discipline

- Every command returns the fixed JSON envelope documented in `references/schemas/data-contracts.md`.
- Default to interactive evidence, not a formal report.
- When a stage fails, keep parser, filter, tool, and input errors separate; resume from the last valid checkpoint.
- Use `cleanup --case-dir <dir>` only for generated case files. Verify original capture and sidecar hashes remain unchanged.
