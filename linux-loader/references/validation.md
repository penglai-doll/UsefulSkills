# Validation

读取时机: 修改 `linux-loader` 脚本、SKILL.md、reference 路由或公开行为前读取。

## 基础验证

```bash
python3 -m unittest discover -s linux-loader/tests -v
python3 linux-loader/scripts/inspect_evidence.py --help
python3 linux-loader/scripts/mount_evidence.py --help
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py linux-loader
```

如果 `quick_validate.py` 因缺少 PyYAML 失败，先按本地依赖问题处理，再用手动 frontmatter 检查兜底。

## 必测契约

- hash: `none`, `later`, 单算法，多算法。
- summary cap: `total_count`, `shown_count`, `truncated`, `details_path`。
- non-system data disk: 无 OS anchors 但有业务数据。
- Docker mount mapping: bind mount 和 named volume。
- resume: size mismatch 阻断，mtime drift warning。
- E01: FUSE 缺失、`ewfexport` 估算。
- filesystem options: ext*, XFS, Btrfs, unknown。
- reference routing: 未命中不读取详细 reference。
