# Linux Loader Skill Design

## Summary

Create a new `linux-loader` skill for WSL2-first Linux server evidence mounting and targeted forensic analysis. The v1 scope supports `raw`, `dd`, `img`, and `E01` evidence images. The skill is AI-led and script-assisted: scripts collect deterministic facts and perform read-only mounting, while the model asks for intent, routes to the minimum required reference material, interprets findings, and reports next steps.

The skill must start by asking for the evidence file path. Before mounting, it must confirm whether the user wants only mounting and baseline triage, or mounting followed by a focused analysis goal such as recovering a web site, restoring panel data, extracting Docker-mounted business data, or reviewing logs.

## Interaction And Workflow

- Ask for a WSL-accessible evidence path first. If the user provides a Windows path, instruct converting it with `wslpath`.
- Confirm task mode before mounting:
  - `mount-only`: mount read-only, collect baseline evidence metadata, and summarize likely analysis directions.
  - `mount-and-analyze`: mount read-only, then ask for the specific analysis goal before reading detailed references.
- Treat `mount-only` as a baseline forensic reconnaissance report, not just a mount confirmation.
- For `mount-and-analyze`, ask only the details needed for the requested direction, then load the minimum matching reference files.
- Never execute binaries, scripts, containers, services, or application code from the mounted evidence.

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

`inspect_evidence.py` should output structured JSON for file metadata, hashes, format guesses, E01 metadata when available, partition tables, Linux system indicators, common service indicators, common data directories, and Docker/panel/web/database clues.

`mount_evidence.py` should generate and run read-only mount operations under `/mnt/evidence_mount/<case-id>/`. For raw-style images, use built-in Linux tools where possible. For E01, require `ewf-tools`/`ewfmount` to expose a raw view before partition handling.

## Baseline Output

In `mount-only`, report all easy-to-collect baseline facts that help the next analyst continue:

- Evidence path, file name, size, modification time, readability, detected format, and collection timestamp.
- `md5`, `sha1`, and `sha256` hashes, with elapsed time or a note if the user explicitly skips hashing for a very large image.
- E01 metadata from `ewfinfo` when available, such as case fields, evidence identifiers, acquisition tool, acquisition time, and segment details.
- Partition table type, partition numbers, offsets, sizes, filesystem candidates, and likely roles such as root, boot, home, swap, or data.
- Mounted partition paths, mount options, filesystem type, and failure reason for any partition that cannot be mounted.
- Linux system clues such as distribution, hostname, timezone, kernel traces, users, sudo/admin clues, cron/systemd indicators, and shell history locations.
- Common service and data clues for Nginx, Apache, MySQL/MariaDB, PostgreSQL, Redis, Docker, BT/aaPanel, 1Panel, PHP, Node, Python, and Java services.
- Common data entry points including `/www/wwwroot`, `/www/server`, `/opt/1panel`, `/var/lib/1panel`, `/var/www`, `/srv`, `/opt`, `/home`, `/var/lib/docker`, `/var/lib/mysql`, `/var/lib/postgresql`, and `/var/log`.
- Three to five next-step suggestions based on actual findings, without expanding analysis that the user did not request.

## Minimum Reference Loading

Use `reference-routing.md` as a compact routing table after baseline triage. Do not read detailed references unless evidence or the user's goal makes them relevant.

- Read `panel-bt.md` only when BT/aaPanel indicators exist, such as `/www/server/panel`, `/www/wwwroot`, `/www/backup`, or matching panel services.
- Read `panel-1panel.md` only when 1Panel indicators exist, such as `/opt/1panel`, `/var/lib/1panel`, `1panel.service`, or 1Panel application layout clues.
- Read `panel-common.md` only for other panel clues such as Webmin, CyberPanel, Plesk, cPanel, or Nginx Proxy Manager.
- Read `docker-linux.md` when Docker data, services, compose files, or the user's goal points to containers.
- Read `web-recovery.md` for site recovery goals or web-root/web-server configuration clues.
- Read `database-recovery.md` for database extraction or recovery goals, or database data directory clues.
- Read `log-analysis.md` for login, intrusion, operation timeline, WebShell, or incident reconstruction goals.

If a tool, panel, or service is absent and the user did not ask for that direction, mention it briefly at most and do not load its detailed reference.

## Domain References

- `mounting-workflow.md`: WSL2 raw/dd/img/E01 read-only mounting flow, offsets, loop devices, mount options, and failure handling.
- `triage-checklist.md`: baseline reconnaissance checklist and output shape.
- `panel-bt.md`: BT/aaPanel paths for panel database/config, sites, Nginx/Apache/PHP config, backup files, logs, and databases.
- `panel-1panel.md`: 1Panel installation paths, app layout, compose files, volumes, backups, logs, and Docker relationship.
- `panel-common.md`: lightweight indicators and paths for other Linux hosting panels.
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
- Highlight likely web, database, panel, and configuration paths such as `/app`, `/data`, `/config`, `/var/www`, `/usr/share/nginx/html`, `/www/wwwroot`, `/etc/nginx`, `/var/lib/mysql`, and `/var/lib/postgresql`.
- Do not start containers, execute images, modify metadata, or run mounted application code.

## Dependency Policy And Safety

- Prefer local WSL2/Linux built-in tools: `file`, `stat`, `fdisk`, `parted`, `blkid`, `mount`, `findmnt`, `lsblk`, `md5sum`, `sha1sum`, and `sha256sum`.
- Do not install tools for convenience. Third-party tools are allowed only when the format or filesystem cannot reasonably be handled otherwise.
- For E01, if `ewfmount`/`ewfinfo` is missing, explain why `ewf-tools` is necessary, what can still be done without it, and ask before installing.
- For LVM, RAID, encrypted volumes, or uncommon filesystems, identify and report the condition in v1, but do not auto-activate, decrypt, repair, or write to evidence.
- Mount read-only. Use `ro` and, for journaled Linux filesystems where appropriate, `noload`.
- Do not run `fsck` repair, write to the evidence image, change Docker metadata, or contact services discovered inside the evidence.
- Separate confirmed evidence facts, path-based inferences, and next-step suggestions in user-facing output.

## Test Plan

- Validate `SKILL.md` frontmatter and naming with the skill validation script or a manual frontmatter check if local dependencies are missing.
- Run `python3 scripts/inspect_evidence.py --help` and `python3 scripts/mount_evidence.py --help`.
- Verify missing-path handling returns structured errors without stack traces.
- Verify a raw/dd/img fixture or small synthetic image produces JSON with file metadata, hashes, format guess, and partition information.
- Verify E01 handling reports a clear dependency message when `ewfmount` is absent.
- Verify reference routing does not load BT, 1Panel, Docker, web, database, or log references unless corresponding indicators or user goals exist.
- Verify Docker fixture metadata produces data-root, container/volume counts, and container-path to host/volume-path mount mappings.
- Verify mount operations default under `/mnt/evidence_mount/<case-id>/` and never request write mode.

## Assumptions

- v1 targets WSL2 first. Generic Linux can be documented as compatible where the same tools and mount semantics apply.
- v1 officially supports `raw`, `dd`, `img`, and `E01`; VHD/VHDX, LVM activation, RAID assembly, and encrypted-volume unlocking are deferred.
- The skill lives in this repository as `linux-loader/`, following the existing skill-package convention.
- The design favors low token use for local models by loading only concise routing information first and detailed references only after evidence-driven routing.
