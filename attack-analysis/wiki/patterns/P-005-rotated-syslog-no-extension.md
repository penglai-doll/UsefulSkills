# P-005: 无扩展名轮转 syslog 文件被当作未知文本

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: references/log-types.md)

## PROBLEM

取证打包中的 `secure`、`messages`、`secure.1`、`messages.gz` 等无扩展名
（或仅轮转后缀）的系统日志，内容检测落在 generic 时会被判为
`generic_text`，报告把它当“未知文本”降权，auth 线索被埋没。

## ROOT CAUSE

内容检测只看正文模式；syslog 正文样式随发行版变化，文件名这一强信号
没有被利用。

## FIX / Workaround

1. 内容检测为 generic 且文件名命中已知 syslog 名单
   （secure/messages/syslog/auth/kern/daemon/cron/maillog/debug 及轮转变体）时，
   类型改为 `system_text` 并加 note `well_known_system_log:no_extension`。
2. 二进制记账文件（`wtmp/btmp/lastlog/faillog`）仍然排除，不强行解析。
3. 报告中保持 best-effort 声明。

## Evidence

- references/log-types.md “v1 Best-Effort”。
- scripts/inventory_logs.py detect_text 尾部分支。
