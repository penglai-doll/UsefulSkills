# Triage Checklist

读取时机: 生成 mount-only 基线报告或调整 JSON 摘要字段时读取。

## 输出顺序

1. 检材: 路径、文件名、大小、mtime、格式、读取状态。
2. Hash: `now/later/skip`，算法、结果、耗时或 pending 状态。
3. E01: 元数据、FUSE 状态、导出估算和用户选择。
4. 分区: 表类型、编号、offset、大小、文件系统、角色猜测。
5. LVM/LUKS: 命中证据、PV/VG/LV 或加密提示。
6. 挂载: 分区、挂载点、选项、成功/失败原因。
7. 镜像角色: `system`, `data`, `mixed`, `unknown`。
8. OS 线索: 发行版、主机名、时区、用户、sudo、SSH、cron、systemd、shell history。
9. 服务/数据: Web、DB、Docker、面板、运行时、日志入口。
10. 下一步: 3 到 5 条，基于实际命中，不展开未请求方向。

## Token 预算

- 每类默认最多 50 条。
- 截断列表必须有 `total_count`, `shown_count`, `truncated`, `details_path`。
- 不把完整日志、完整递归目录、完整 Docker metadata 放进模型上下文。
