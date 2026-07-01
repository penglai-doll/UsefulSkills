---
name: linux-loader
description: Use when Codex needs to mount, inspect, triage, or perform focused forensic recovery from Linux server disk evidence images in WSL2 or Linux, including raw/dd/img and E01 evidence, BT/aaPanel or 1Panel recovery, website/database/log recovery, Docker volume and bind-mount analysis, or read-only baseline evidence reconnaissance.
---

# Linux Loader v1.0.0

AI-led, script-assisted Linux evidence mounting and triage. Use local tools first, keep evidence read-only, keep context small for local models, and load detailed references only when routing or the user goal requires them.

## Start

Ask these questions before running tools:

1. Evidence path: require a WSL-accessible path. If the user provides a Windows path, suggest `wslpath`.
2. Hash policy: ask `now`, `later`, or `skip`; if `now` or `later`, ask for `md5`, `sha1`, `sha256`, or a comma-separated set.
3. Task mode:
   - `mount-only`: mount read-only and produce compact baseline reconnaissance.
   - `fast-path`: use when the user already states a target such as Docker, BT/aaPanel, 1Panel, website, database, or logs.
   - `mount-and-analyze`: mount read-only, then ask for the focused analysis goal before loading detailed references.

Never execute binaries, scripts, services, containers, or application code from mounted evidence.

## State Machine

Use this order unless `fast-path` explicitly skips deep triage after safe mounting:

```text
preflight -> identify -> hash-decision -> optional-pre-mount-hash -> expose-image ->
enumerate-partitions -> mount-read-only -> os-triage -> service-triage ->
route-references -> optional-focused-analysis -> optional-deferred-hash ->
cleanup-guidance
```

- `preflight`: validate path/readability, WSL2 context, automatic sudo probe, absolute output path, mount-root conflict, loop probe, `losetup -P` probe, FUSE permission probe, and resume state.
- `hash-decision`: record `now`, `later`, or `skip`; never compute hashes without user choice.
- `expose-image`: use raw/dd/img directly; for E01 prefer `ewfmount` only when FUSE works, otherwise offer `ewfexport` with size/time/free-space estimates.
- `mount-read-only`: select filesystem-specific read-only options; do not repair filesystems.
- `os-triage`: classify `system`, `data`, `mixed`, or `unknown`; skip deep OS checks for data-only images.
- `service-triage`: detect web, database, Docker, panels, common data roots, and logs with bounded scans.
- `route-references`: load only required references. Mention optional references without reading them unless needed.

## Scripts

Use scripts for deterministic facts and compact JSON only:

```bash
python3 scripts/inspect_evidence.py <path> --hash none --json
python3 scripts/mount_evidence.py <path> --dry-run --case-id <case-id> --json
```

Required script behavior:

- Support `--json`, `--output-dir`, `--case-id`, `--summary-limit`, and `--hash none|later|md5|sha1|sha256|md5,sha1,sha256`.
- `mount_evidence.py` also supports `--dry-run`, `--inspect-json`, `--resume`, and `--triage-level full|fast`.
- Write outputs outside mounted evidence under an absolute `output/linux-loader/<case-id>/` path by default.
- Use `/mnt/evidence_mount/<case-id>/` only for read-only mount targets unless preflight detects a conflict, then choose a case-specific alternate.
- Privilege handling is automatic: try root, then `sudo -n true`. If unavailable, emit `blocked=true`, `manual_command`, and `user_choices` (`manual_sudo`, `interactive_sudo`); do not add a user-facing sudo mode or try a bare privileged `mount`.
- For E01, if `ewfmount` is missing, ask before planning `apt-get install -y ewf-tools`; if apt/sudo is unavailable, offer `download_portable_ewftools` using wget/curl into a temporary cache directory, never a system path or mounted evidence.
- If FUSE is unavailable, do not plan `ewfmount`; ask whether to elevate/repair FUSE or use `ewfexport` raw fallback when available.
- Keep model-facing JSON compact. Do not include full logs, full recursive listings, full Docker metadata, complete histories, secrets, or large file contents.
- Capped lists must include `total_count`, `shown_count`, `truncated`, and optional `details_path`.

## Minimum Reference Loading

Read [reference-routing.md](./references/reference-routing.md) after inspection output is available. Then read only the matching detailed reference:

- BT/aaPanel: [panel-bt.md](./references/panel-bt.md)
- 1Panel: [panel-1panel.md](./references/panel-1panel.md)
- Other panels: [panel-common.md](./references/panel-common.md)
- Docker: [docker-linux.md](./references/docker-linux.md)
- Website recovery: [web-recovery.md](./references/web-recovery.md)
- Database recovery: [database-recovery.md](./references/database-recovery.md)
- Log/timeline analysis: [log-analysis.md](./references/log-analysis.md)

Read [mounting-workflow.md](./references/mounting-workflow.md) for mount failures, WSL2 loop/FUSE issues, E01 fallback, LVM/LUKS recognition, known-good loop fixture commands, and filesystem-specific mount options.

Read [triage-checklist.md](./references/triage-checklist.md) for the compact baseline report shape.

Read [validation.md](./references/validation.md) before changing scripts or public behavior.

## Safety

- Prefer local built-in tools: `file`, `stat`, `fdisk`, `parted`, `blkid`, `mount`, `findmnt`, `lsblk`, `losetup`, `md5sum`, `sha1sum`, and `sha256sum`.
- Ask before installing third-party tools. E01 normally needs `ewf-tools`; FUSE may be required for `ewfmount`.
- Treat FUSE as usable only when `/dev/fuse` exists, is readable/writable by the current user, and `fusermount` or `fusermount3` exists; otherwise prefer user-approved `ewfexport`.
- Recognize LVM/LUKS and provide manual read-only continuation guidance, but do not auto-activate LVM, unlock LUKS, assemble RAID, run `fsck`, or write to evidence.
- Separate confirmed evidence facts, path-based inferences, and next-step suggestions.
