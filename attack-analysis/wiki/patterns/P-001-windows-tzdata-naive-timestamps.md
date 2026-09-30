# P-001: Windows 缺少 tzdata 导致时间戳退化为 unknown

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: SKILL.md environment notes)

## PROBLEM

在 Windows 上运行提取流水线时，命名时区（如 `Asia/Shanghai`）无法解析，
事件时间戳保持 naive 并被标记 `timestamp_status=unknown`，
清单与事件输出出现 `timezone_notes` 警告，时间线排序不可信。

## ROOT CAUSE

Python `zoneinfo` 在 Windows 上没有系统时区数据库；未安装 `tzdata`
包时，任何 IANA 时区名都会抛出异常，脚本降级为 naive 时间。

## FIX / Workaround

1. 分析前运行 `pip install -r <skill-root>/requirements.txt` 安装 `tzdata`。
2. 把任何 `timezone_notes` 警告当作环境故障处理：先修复环境，再信任时间线。
3. Linux/macOS 使用系统 tz 数据库，无需安装。

## Evidence

- SKILL.md “Environment” 段。
- scripts/common/time_normalize.py 的降级路径。
