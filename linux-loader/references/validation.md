# Validation

读取时机: 修改 `linux-loader` 脚本、SKILL.md、reference 路由或公开行为前读取。

## 基础验证

```bash
python3 -m unittest discover -s linux-loader/tests -v
python3 linux-loader/scripts/inspect_evidence.py --help
python3 linux-loader/scripts/mount_evidence.py --help
python3 tools/check_skills.py
```

最后一条命令从仓库根目录运行，使用仓库自带的标准库校验器，不依赖外部 skill-creator 路径或 PyYAML。

## 必测契约

- hash: `none`, `later`, 单算法，多算法。
- summary cap: `total_count`, `shown_count`, `truncated`, `details_path`。
- non-system data disk: 无 OS anchors 但有业务数据。
- Docker mount mapping: bind mount 和 named volume。
- resume: `--resume` 复用上次 inspect JSON（`--inspect-json` 或 `<output-dir>/<case-id>/inspect.json`），不重复 inspect；size mismatch 必须 fatal 阻断；mtime drift / path 变化仅 warning；恢复后基于保存的 inspection 重新规划挂载。
- triage-level: `fast` 跳过 os_profile、panel、Docker 深度扫描与 loop probe（结果标记 skipped/unknown），`full` 全量执行；`--dry-run` 不做 loop probe。
- sudo: CLI help 不暴露 `--sudo-mode`；无 root/非交互 sudo 时 privileged command 必须 `blocked=true`，输出 `user_choices` (`manual_sudo`, `interactive_sudo`)；挂载要求重新提权运行 helper，其他前置命令可输出 `manual_command`；`--dry-run` 不应按执行失败退出。
- E01 dependency: `ewfmount` 缺失时只输出需用户确认的 `apt-get install -y ewf-tools` 计划；apt/sudo 不可用时附带 `download_portable_ewftools`，下载/解压路径必须在系统临时缓存目录，不能进入系统路径、工作区根或检材挂载点。
- E01 FUSE: FUSE 缺失或 `/dev/fuse` 不可读写时不计划 `ewfmount`，改为提示提权/修复 FUSE 或用户确认后的 `ewfexport` 估算。
- filesystem options: ext*, XFS, Btrfs, unknown。
- 整盘 ext4 image 必须保留 `noload`；未知文件系统禁止自动挂载。
- attach 使用 `--read-only`，`blockdev --getro` 失败时绝不 mount；mount 返回 0 但 findmnt 验证失败时不可报告成功，并清理本次 mount/loop。
- reference routing: 未命中不读取详细 reference。
