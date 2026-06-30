# Linux Loader Skill Design

## Summary

Create a new `linux-loader` skill for WSL2-first Linux server evidence mounting and targeted forensic analysis. The v1 scope supports `raw`, `dd`, `img`, and `E01` evidence images. The skill is AI-led and script-assisted: scripts collect deterministic facts and perform read-only mounting, while the model asks for intent, routes to the minimum required reference material, interprets findings, and reports next steps.

The skill must start by asking for the evidence file path. Before mounting, it must confirm whether the user wants hash calculation now, later, or not at all, then confirm whether the user wants only mounting and baseline triage, a fast-path focused analysis, or a full mount-and-analyze workflow such as recovering a web site, restoring panel data, extracting Docker-mounted business data, or reviewing logs.

## Current Implementation Status

The initial `linux-loader` package has been implemented in this repository.

- `SKILL.md` defines the public workflow contract, initial questions, read-only safety rules, hash decision policy, and minimum reference loading rules.
- `agents/openai.yaml` exposes the Codex-facing interface and default `$linux-loader` prompt.
- `references/` contains one-level, demand-loaded domain notes for mounting, baseline triage, routing, BT/aaPanel, 1Panel, other panels, Docker, website recovery, database recovery, log analysis, and validation.
- `scripts/inspect_evidence.py` emits compact JSON for evidence metadata, hash policy, tool/preflight state, format/E01 estimates, partition metadata, mounted-tree triage, panel/service/Docker indicators, Docker mount mappings, and reference routing.
- `scripts/mount_evidence.py` prepares read-only mount plans, filesystem-specific mount options, output paths, dry-run execution, `run-meta.json`, resume metadata, and a real known-good `losetup -P` probe when Linux plus non-interactive sudo/root support it.
- `tests/test_linux_loader_contract.py` covers hash policy, bounded summaries, non-system data disks, reference routing, E01 export estimates, Docker bind/source mapping, required compact JSON fields, filesystem mount options, mount-root conflicts, partition offset mount planning, and resume validation.

Fresh validation commands:

```bash
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py linux-loader
python3 -m unittest discover -s linux-loader/tests -v
python3 -m py_compile linux-loader/scripts/inspect_evidence.py linux-loader/scripts/mount_evidence.py
python3 linux-loader/scripts/inspect_evidence.py --help
python3 linux-loader/scripts/mount_evidence.py --help
git diff --check
```

## Interaction And Workflow

- Ask for a WSL-accessible evidence path first. If the user provides a Windows path, instruct converting it with `wslpath`.
- Ask whether to calculate hashes before long-running processing, defer hashing until after mounting, or skip hashing. If hashing is requested, ask which algorithms to calculate.
- Confirm task mode before mounting:
  - `mount-only`: mount read-only, collect baseline evidence metadata, and summarize likely analysis directions.
  - `fast-path`: mount read-only, perform only the minimum checks needed for the user's known goal, then route to the requested analysis reference.
  - `mount-and-analyze`: mount read-only, then ask for the specific analysis goal before reading detailed references.
- Treat `mount-only` as a baseline forensic reconnaissance report, not just a mount confirmation.
- Allow `fast-path` only when the user explicitly states the target direction, such as Docker, BT/aaPanel, 1Panel, web recovery, database extraction, or log review. Fast-path may skip deep `os-triage` and `service-triage`, but must not skip preflight, format identification, safe mounting, mount status recording, or minimum evidence-driven reference routing.
- For `mount-and-analyze`, ask only the details needed for the requested direction, then load the minimum matching reference files.
- Never execute binaries, scripts, containers, services, or application code from the mounted evidence.

Use this fixed state machine for implementation:

```text
preflight -> identify -> hash-decision -> optional-pre-mount-hash -> expose-image ->
enumerate-partitions -> mount-read-only -> os-triage -> service-triage -> route-references ->
optional-focused-analysis -> optional-deferred-hash -> cleanup-guidance
```

- `preflight`: validate path, readability, WSL context, sudo needs, output paths, and required local tools.
- `identify`: detect raw-style image versus E01 and record tool availability.
- `hash-decision`: record whether the user wants hashing `now`, `later`, or `skip`, and which algorithms they requested.
- `optional-pre-mount-hash`: compute only the requested hashes when the user chooses `now`.
- `expose-image`: use the original raw-style image directly, or expose E01 through `ewfmount`.
- `enumerate-partitions`: collect partition offsets, sizes, filesystem guesses, and mount candidates.
- `mount-read-only`: mount each viable partition read-only and record success or failure per partition.
- `os-triage`: inspect mounted filesystems for OS, users, timezone, SSH, cron, systemd, persistence, shell history, and account clues.
- `service-triage`: inspect mounted filesystems for web, databases, Docker, panels, runtime services, common data directories, and log entry points.
- `route-references`: emit recommended reference files from evidence-driven routing.
- `optional-focused-analysis`: read only the routed references needed for the user's stated goal.
- `optional-deferred-hash`: offer to compute requested hashes after mounting/analysis when the user chose `later`, and persist pending hash state if they defer again.
- `cleanup-guidance`: print unmount commands and loop/EWF cleanup commands, but do not unmount automatically unless the user asks.

## Skill Package

Create this package:

```text
linux-loader/
  SKILL.md
  agents/openai.yaml
  scripts/
    inspect_evidence.py
    mount_evidence.py
  references/
    mounting-workflow.md
    triage-checklist.md
    reference-routing.md
    panel-bt.md
    panel-1panel.md
    panel-common.md
    web-recovery.md
    docker-linux.md
    database-recovery.md
    log-analysis.md
    validation.md
```

`SKILL.md` should stay concise and define the contract: WSL2 priority, supported formats, initial questions, read-only mounting, dependency policy, minimum reference loading, and AI/script responsibility split.

`inspect_evidence.py` should output structured JSON for file metadata, requested hashes, format guesses, E01 metadata when available, partition tables, Linux system indicators, common service indicators, common data directories, and Docker/panel/web/database clues.

`mount_evidence.py` should generate and run read-only mount operations under `/mnt/evidence_mount/<case-id>/` unless preflight finds that path occupied, in which case it should use an alternate path such as `/mnt/ev-mount-<case-id>/`. For raw-style images, use built-in Linux tools where possible. For E01, require `ewf-tools`/`ewfmount` to expose a raw view before partition handling.

Both scripts must support `--json`, `--output-dir`, `--case-id`, `--summary-limit`, and `--hash none|later|md5|sha1|sha256|md5,sha1,sha256`. Hashing must default to the user's explicit choice from the skill workflow, not to an automatic all-hash policy. `mount_evidence.py` must also support `--dry-run` to print planned commands without mounting, `--inspect-json` to reuse a prior inspection result, `--resume` to continue from `run-meta.json`, and `--triage-level full|fast` to support the fast-path interaction.

Store script outputs outside mounted evidence partitions, under `output/linux-loader/<case-id>/` by default. Preflight must resolve this to an absolute path and record it in JSON:

```text
output/linux-loader/<case-id>/
  inspect.json
  mount.json
  commands.log
  run-meta.json
```

Use `/mnt/evidence_mount/<case-id>/` only for read-only mount targets and EWF/raw exposed views.

`run-meta.json` is a resumable state file, not only a log. It must include `last_completed_stage`, `stage_status`, `resume_supported`, `cleanup_commands`, active loop devices, EWF mount paths, mounted partition paths, selected hash policy, pending hash policy, evidence path/size/mtime, output directory absolute path, mount root absolute path, and the output files written so far. `--resume` must hard-block on evidence size mismatch, missing evidence, or active mount/loop state mismatch. Evidence path or mtime changes should become `resume_warnings` when the user explicitly supplies the current path and the size still matches.

## Script Output Contract

`inspect_evidence.py` and `mount_evidence.py` must write predictable JSON so the model can summarize results without rereading large directory trees.

Required top-level fields:

- `schema_version`: start with `linux-loader.v1`.
- `case_id`: stable case identifier derived from user input or generated timestamp.
- `evidence_file`: path, basename, size, mtime, readability, and detected format.
- `hashes`: requested algorithms, skipped/user-declined status, computed values, elapsed seconds, and per-algorithm errors.
- `case_paths`: output directory absolute path, requested mount root, selected mount root, mount-root conflict status, and alternate path reason.
- `tools`: available/missing tools and whether each is built-in, optional, or required for the current format.
- `preflight`: WSL/kernel details, sudo status, loop device functional probe, `losetup -P` probe result, FUSE availability, and resume state.
- `format`: raw-style/E01 classification, confidence, and detection evidence.
- `ewf`: E01 metadata, exposed raw path, dependency/errors, estimated export size, estimated export time, export free-space check, and export fallback choice when relevant.
- `partitions`: partition number, start offset, length, filesystem guess, role guess, LVM/LUKS indicators, and mount candidate status.
- `mounts`: partition id, mount path, filesystem, options, readonly flag, success/error, and cleanup command.
- `image_role`: `system`, `data`, `mixed`, or `unknown`, with evidence and confidence.
- `os_profile`: distribution, hostname, timezone, kernel clues, users, sudo/admin clues, SSH clues, shell history clues, cron/systemd clues.
- `services`: detected web, database, cache, runtime, panel, Docker, and other service indicators.
- `paths`: common data paths with existence, type, size/count when cheap, and related service/panel tags.
- `panels`: detected BT/aaPanel, 1Panel, and other panel indicators with confidence and evidence paths.
- `docker`: data-root, daemon config, container count, volume count, compose candidates, and mount mappings.
- `routes`: `recommended_references`, `suggested_next_steps`, and reasons for each recommendation.
- `errors`: structured nonfatal and fatal errors with command, stderr excerpt, and suggested next action.

Keep JSON compact. Do not include large file listings, full logs, file contents, secrets, or recursive directory dumps.

## Local Model Token Budget

The skill must optimize for weak or local models with limited context.

- Default loaded context after `SKILL.md` should be only `inspect.json`/`mount.json` summaries plus `reference-routing.md`. Do not read detailed references until routes or the user goal require them.
- Keep `SKILL.md` as the contract and keep detailed domain knowledge in one-level reference files. Each reference should start with a short "read when" section and a compact path checklist.
- Scripts must emit bounded summaries by default. Use `--summary-limit` to cap per-category findings, with a default target of 50 rows per category unless the user asks for more.
- Every capped list must include `total_count`, `shown_count`, `truncated`, and, when useful, `details_path` pointing to a local artifact outside the mounted evidence.
- Do not place full logs, full `find` output, complete Docker metadata, complete user histories, or large config contents in model-facing JSON. Store larger raw outputs in sidecar files and summarize them.
- Directory scanning must be bounded by depth, candidate path allowlists, and per-category result caps. Prefer known forensic pivots over recursive full-disk enumeration.
- `routes.recommended_references` must include priority and reason. Load `required` references first; mention `optional` references without reading them unless the user confirms or the focused task needs them.
- User-facing output should lead with a short summary and next actions. Do not paste full JSON unless the user explicitly asks.
- Fast-path mode should be the preferred route when the user already states a goal, because it reduces unnecessary OS/service triage and reference loading.

## WSL2 Preflight

WSL2 support must be capability-driven, not command-existence-driven.

- Record `uname -a`, `/proc/version`, and whether the environment appears to be WSL2.
- Probe `losetup` by creating a small temporary file, attaching it read-only if permitted, checking that the loop device appears, and detaching it. If sudo is unavailable, record the probe as `unknown` rather than `passed`.
- Probe `losetup -P` with a known-good tiny partitioned image, not an arbitrary user image. `mounting-workflow.md` must include a reproducible fixture recipe using `dd` to create a 50 MiB file, `sfdisk` or `fdisk` to create one Linux partition, optional `mkfs.ext4` after loop attach, then `losetup --read-only -P`. Treat a loop device with no generated partition node for this known-good fixture as `losetup_partition_scan=failed`; this distinguishes `-P` failure from user images that simply lack a partition table.
- For E01, check `ewfinfo`, `ewfmount`, `/dev/fuse`, and `fusermount`/`fusermount3`. If FUSE is unavailable, do not attempt `ewfmount`.
- Resolve output and mount roots to absolute paths. Check whether the requested mount root already exists, is mounted, or conflicts with another run; choose a case-specific alternate mount root when needed.
- Store probe results in `preflight` and use them to choose the mount path.

## Mounting Strategy

Use this priority order for raw/dd/img images:

1. Prefer `losetup --read-only -P` only when preflight confirms loop attach and partition scanning work.
2. Fall back to partition offset mounting with `mount -o ro,noload,loop,offset=<bytes>` when loop partition scanning is unavailable or fails.
3. Fall back to reporting partition metadata only when neither mount strategy succeeds.

For E01:

1. Require `ewfinfo`/`ewfmount` from `ewf-tools`.
2. Require FUSE support for the `ewfmount` path. If `/dev/fuse` or `fusermount` support is unavailable, explain the WSL2 limitation.
3. Mount E01 segments read-only through `ewfmount` into the case mount workspace when FUSE works.
4. If FUSE is unavailable but `ewfexport` exists, offer an explicit user-approved fallback to export E01 to raw under the output workspace, warning about required disk space and time.
5. Before offering raw export, estimate export size from EWF media size when available, estimate time from a measured or configured throughput range when possible, and compare required space to free space in the output directory.
6. Treat the exposed or exported raw image as the partition source for the raw/dd/img strategy.
7. Record E01 metadata, fallback choice, estimated export size/time, free-space result, output raw path when applicable, and cleanup commands in JSON.

Never run write-mode mount commands. Choose read-only mount options by detected filesystem type:

- `ext2/ext3/ext4`: prefer `ro,noload`.
- `xfs`: prefer `ro,norecovery`.
- `btrfs`: prefer `ro,norecovery,skip_balance` when supported; if rejected, try documented read-only Btrfs alternatives such as `ro,nologreplay,skip_balance`; do not use deprecated `recovery` as a default.
- unknown filesystems: use plain `ro` first, then stop and report if the filesystem requires a specialized safe option.

Record the selected option set and any fallback in `mounts`.

## LVM And LUKS Recognition

v1 must recognize LVM and LUKS instead of treating them as generic mount failures.

- Detect LVM signatures from partition type, `blkid`, `file`, and available `pvs`, `vgs`, `lvs` output.
- Detect LUKS signatures from partition type, `blkid`, `file`, and `cryptsetup isLuks` when available.
- Report LVM physical volumes, volume groups, logical volumes, UUIDs, and device paths when tools are available.
- Do not auto-activate volume groups or unlock encrypted devices in v1.
- When LVM blocks direct mounting, provide manual read-only continuation commands such as `vgchange -ay --readonly` where supported, plus a warning to confirm the evidence-safe workflow before running them.
- When LUKS is detected, report that a passphrase/key is required and stop before any unlock attempt unless a future version explicitly supports that workflow.

## OS And Data Disk Triage

`os-triage` must first classify the mounted content instead of assuming every image is a bootable Linux system.

- Mark `image_role=system` when standard OS anchors exist, such as `/etc/os-release`, `/etc/passwd`, `/etc/shadow`, `/boot`, or systemd directories.
- Mark `image_role=data` when OS anchors are absent but business data, logs, web roots, database directories, Docker volumes, backups, or panel/application directories exist.
- Mark `image_role=mixed` when both system anchors and separate data-disk style roots exist.
- For `data` images, skip deep OS/user/persistence checks and focus `service-triage` on directory layout, web/database/application data, Docker volumes, backups, and logs.
- For `unknown` images, report that no Linux system or common service roots were found and provide next-step manual inspection pivots.

## Baseline Output

In `mount-only`, report all easy-to-collect baseline facts that help the next analyst continue:

- Evidence path, file name, size, modification time, readability, detected format, and collection timestamp.
- Hash calculation status. If the user requested hashes now, report selected algorithms, values, and elapsed time; if the user deferred, state that hashing is pending and can be resumed later; if the user declined, state that hashing was skipped by user choice.
- E01 metadata from `ewfinfo` when available, such as case fields, evidence identifiers, acquisition tool, acquisition time, and segment details.
- E01 export fallback estimate when applicable: estimated raw size, estimated time, output free space, and user decision.
- Partition table type, partition numbers, offsets, sizes, filesystem candidates, and likely roles such as root, boot, home, swap, or data.
- LVM/LUKS recognition status, including detected PV/VG/LV information or encrypted-volume indicators.
- Mounted partition paths, mount options, filesystem type, and failure reason for any partition that cannot be mounted.
- Image role: system, data, mixed, or unknown. For non-system data disks, explain that OS checks were skipped and data-focused triage was used.
- Linux system clues such as distribution, hostname, timezone, kernel traces, users, sudo/admin clues, SSH clues, cron/systemd indicators, and shell history locations.
- Common service and data clues for Nginx, Apache, MySQL/MariaDB, PostgreSQL, Redis, Docker, BT/aaPanel, 1Panel, cPanel, Plesk, DirectAdmin, PHP, Node, Python, and Java services.
- Common data entry points including `/www/wwwroot`, `/www/server`, `/opt/1panel`, `/var/lib/1panel`, `/var/www`, `/srv`, `/opt`, `/home`, `/var/lib/docker`, `/var/lib/mysql`, `/var/lib/postgresql`, and `/var/log`.
- Three to five next-step suggestions based on actual findings, without expanding analysis that the user did not request.

## Minimum Reference Loading

Use `reference-routing.md` as a compact routing table after `os-triage` and `service-triage`. Do not read detailed references unless evidence or the user's goal makes them relevant.

- Read `panel-bt.md` only when BT/aaPanel indicators exist, such as `/www/server/panel`, `/www/wwwroot`, `/www/backup`, or matching panel services.
- Read `panel-1panel.md` only when 1Panel indicators exist, such as `/opt/1panel`, `/var/lib/1panel`, `1panel.service`, or 1Panel application layout clues.
- Read `panel-common.md` only for other panel clues such as Webmin, CyberPanel, Plesk, cPanel, DirectAdmin, or Nginx Proxy Manager.
- Read `docker-linux.md` when Docker data, services, compose files, or the user's goal points to containers.
- Read `web-recovery.md` for site recovery goals or web-root/web-server configuration clues.
- Read `database-recovery.md` for database extraction or recovery goals, or database data directory clues.
- Read `log-analysis.md` for login, intrusion, operation timeline, WebShell, or incident reconstruction goals.

If a tool, panel, or service is absent and the user did not ask for that direction, mention it briefly at most and do not load its detailed reference.

`inspect_evidence.py` should also emit `routes.recommended_references` using the same rules, so weak local models can follow explicit routing without reconstructing all conditions from prose.

## Domain References

- `mounting-workflow.md`: WSL2 raw/dd/img/E01 read-only mounting flow, offsets, loop devices, mount options, and failure handling.
- `triage-checklist.md`: baseline reconnaissance checklist and output shape.
- `panel-bt.md`: BT/aaPanel paths for panel database/config, sites, Nginx/Apache/PHP config, backup files, logs, and databases.
- `panel-1panel.md`: 1Panel installation paths, app layout, compose files, volumes, backups, logs, and Docker relationship.
- `panel-common.md`: lightweight indicators and paths for other Linux hosting panels, including Webmin, CyberPanel, cPanel, Plesk, DirectAdmin, and Nginx Proxy Manager.
- `web-recovery.md`: web root, server config, application framework, upload, config, and backup recovery pivots.
- `docker-linux.md`: Docker root discovery, container metadata parsing, volume and bind mount recovery, compose correlation, and read-only analysis rules.
- `database-recovery.md`: common database data directories, config locations, dump/backup locations, and safe extraction guidance.
- `log-analysis.md`: authentication, shell, service, web, panel, cron, and systemd logs for timeline analysis.
- `validation.md`: command checks, sample dry runs, error cases, JSON schema expectations, and skill validation.

## Docker Requirements

Docker is an important first-class analysis path. When Docker is present, baseline triage must include the Docker data-root, container count, volume count, compose file candidates, and a short summary of likely business-data mount paths.

Detailed Docker analysis must prioritize reconstructing container mount relationships:

- Parse Docker data-root, including custom `data-root` from `daemon.json`.
- Inspect container `config.v2.json` and `hostconfig.json`.
- Extract `MountPoints`, `Binds`, named volumes, bind mounts, and compose `volumes:` mappings.
- Output a mapping table from container path to host path or volume path.
- For each mapping, include container name/id, image, compose project when available, container path, source host path or volume name, resolved volume path, source existence, and a `likely_business_data` tag.
- Highlight likely web, database, panel, and configuration paths such as `/app`, `/data`, `/config`, `/var/www`, `/usr/share/nginx/html`, `/www/wwwroot`, `/etc/nginx`, `/var/lib/mysql`, and `/var/lib/postgresql`.
- Do not start containers, execute images, modify metadata, or run mounted application code.

## Dependency Policy And Safety

- Prefer local WSL2/Linux built-in tools: `file`, `stat`, `fdisk`, `parted`, `blkid`, `mount`, `findmnt`, `lsblk`, `losetup`, `md5sum`, `sha1sum`, and `sha256sum`.
- Do not install tools for convenience. Third-party tools are allowed only when the format or filesystem cannot reasonably be handled otherwise.
- For E01, if `ewfmount`/`ewfinfo` is missing, explain why `ewf-tools` is necessary, what can still be done without it, and ask before installing. If FUSE is unavailable, offer `ewfexport` as a user-approved raw-export fallback when installed.
- For LVM and LUKS, identify and report the condition in v1 and provide manual continuation guidance, but do not auto-activate, decrypt, repair, or write to evidence.
- For RAID or uncommon filesystems, identify and report the condition in v1, but do not auto-assemble, repair, or write to evidence.
- Mount read-only. Select filesystem-specific safe options rather than applying one option to every filesystem.
- Do not run `fsck` repair, write to the evidence image, change Docker metadata, or contact services discovered inside the evidence.
- Separate confirmed evidence facts, path-based inferences, and next-step suggestions in user-facing output.

## Test Plan

- Validate `SKILL.md` frontmatter and naming with the skill validation script or a manual frontmatter check if local dependencies are missing.
- Run `python3 scripts/inspect_evidence.py --help` and `python3 scripts/mount_evidence.py --help`.
- Verify missing-path handling returns structured errors without stack traces.
- Verify hash declined mode records skipped hashing and no hash values.
- Verify hash deferred mode records pending hash state and can calculate hashes after mounting without remounting evidence.
- Verify requested hash mode computes only the selected algorithms and records elapsed time.
- Verify a raw/dd/img fixture or small synthetic image produces JSON with file metadata, selected hash status, format guess, and partition information.
- Verify WSL2 preflight records loop attach and `losetup -P` probe results using a known-good single-partition fixture, including graceful `unknown` status when sudo is unavailable.
- Verify E01 handling reports FUSE availability and gives a clear dependency or `ewfexport` fallback message when `ewfmount` cannot work.
- Verify E01 raw-export fallback reports estimated export size/time and output free-space status before user approval.
- Verify E01 handling reports a clear dependency message when `ewfmount` is absent.
- Verify LVM and LUKS fixtures are recognized and reported without auto-activation or unlock attempts.
- Verify `--resume` refuses to continue when evidence file size or active mount state does not match `run-meta.json`, but treats mtime-only changes as warnings.
- Verify fast-path skips deep OS/service triage only after the user states a concrete target and still records safe mounting state and routed references.
- Verify output directory and mount root are absolute in JSON, and mount-root conflicts produce an alternate case-specific mount path.
- Verify non-system data-disk fixtures are classified as `image_role=data` and use data-focused triage.
- Verify ext*, XFS, Btrfs, and unknown filesystem fixtures select the expected read-only mount option family and record fallbacks.
- Verify summary output caps include `total_count`, `shown_count`, `truncated`, and optional `details_path`, and that model-facing JSON does not contain full recursive listings.
- Verify reference routing loads only `required` references by default and leaves `optional` references unread until needed.
- Verify reference routing does not load BT, 1Panel, Docker, web, database, or log references unless corresponding indicators or user goals exist.
- Verify Docker fixture metadata produces data-root, container/volume counts, and container-path to host/volume-path mount mappings.
- Verify mount operations default under `/mnt/evidence_mount/<case-id>/` and never request write mode.

Use this fixture matrix for implementation validation:

- Missing path fixture: nonexistent path returns a fatal JSON error with no stack trace.
- Tiny raw image fixture: produces image metadata and respects the requested hash policy even when no partition table exists.
- Small partitioned raw image fixture: produces partition metadata and dry-run mount commands.
- Known-good loop fixture: generated by documented `dd` plus `sfdisk`/`fdisk` commands, used to distinguish missing partition tables from `losetup -P` silent failure.
- WSL2 loop probe fixture: simulates loop support present, loop support missing, and `losetup -P` silent failure.
- E01 dependency fixture: when `ewfmount` is missing, reports `ewf-tools` as required for E01 and asks before installation.
- E01 FUSE fixture: missing `/dev/fuse` or `fusermount` produces a FUSE-specific error and optional `ewfexport` fallback.
- E01 export estimate fixture: mock EWF metadata and output free space produce export size/time/free-space fields.
- LVM fixture: LVM signatures and mock `pvs/vgs/lvs` output are reported without activation.
- LUKS fixture: encrypted-volume signatures are reported without unlock attempts.
- Resume fixture: interrupted `run-meta.json` can resume when size and active mount state match, while mtime-only drift is reported as a warning.
- Output-path fixture: relative output paths become absolute JSON paths and occupied mount roots are replaced with an alternate case-specific path.
- Non-system data disk fixture: no `/etc/os-release` or `/etc/passwd`, but web/database/app data exists, producing `image_role=data`.
- Filesystem option fixture: ext*, XFS, Btrfs, and unknown filesystems choose separate read-only option sets.
- Token-budget fixture: oversized path, Docker, and log candidate sets are truncated in JSON with sidecar details and do not force detailed reference loading.
- Mounted Linux tree fixture: fake `/etc/os-release`, `/etc/passwd`, SSH config, cron, systemd units, web roots, database directories, and logs exercise `os-triage` and `service-triage`.
- BT/aaPanel fixture: `/www/server/panel`, `/www/wwwroot`, `/www/backup` triggers only `panel-bt.md` plus any user-requested analysis reference.
- 1Panel fixture: `/opt/1panel`, `/var/lib/1panel`, compose/app layout triggers `panel-1panel.md` and Docker routing when applicable.
- Docker metadata fixture: `daemon.json`, `containers/*/{config.v2.json,hostconfig.json}`, `volumes/`, and compose files produce mount mappings with business-data tags.
- Negative routing fixture: a Linux tree without panels or Docker does not recommend panel or Docker references.

## Assumptions

- v1 targets WSL2 first. Generic Linux can be documented as compatible where the same tools and mount semantics apply.
- v1 officially supports `raw`, `dd`, `img`, and `E01`; VHD/VHDX, LVM activation, RAID assembly, and encrypted-volume unlocking are deferred.
- The skill lives in this repository as `linux-loader/`, following the existing skill-package convention.
- The design favors low token use for local models by loading only concise routing information first and detailed references only after evidence-driven routing.
