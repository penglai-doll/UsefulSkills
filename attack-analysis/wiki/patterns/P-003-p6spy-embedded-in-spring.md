# P-003: P6Spy SQL 行内嵌在 Spring 应用日志中被漏提取

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: extract_log_events.py PARSER_MAP)

## PROBLEM

P6Spy 常以 `WARN ... SQL 语句：...` 形式打印在 Spring Boot 应用日志里。
若只按单一 parser 处理，要么丢 SQL 行，要么丢应用日志行，
SQL 注入探测与同请求的应用报错无法关联。

## ROOT CAUSE

检测器按“文件主类型”二选一，而真实文件是混合格式。

## FIX / Workaround

1. `p6spy_sql` 类型映射到 parser 链 `[p6spy_sql, spring_app]`，两遍解析取并集。
2. 文本检测优先匹配 `p6spy` 或 `SQL 语句`（中英文都要）。
3. 提取后检查 `parser_stats`，确认两个 parser 都有产出。

## Evidence

- scripts/extract_log_events.py PARSER_MAP。
- tests/fixtures/gold_attack_case（p6spy.log 与 app.log 同链）。
