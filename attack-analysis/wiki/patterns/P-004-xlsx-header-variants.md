# P-004: 登录/操作 xlsx 导出表头变体导致误判为 xlsx_table

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: inventory_logs.detect_xlsx)

## PROBLEM

登录导出表头出现变体（`USERNAME` vs `USER_NAME`、时间列改名）时，
被低置信度判为 `xlsx_table`，整张表走通用解析，登录爆破序列丢失。

## ROOT CAUSE

检测规则用固定表头集合精确匹配，业务方导出模板经常改名或增删列。

## FIX / Workaround

1. 表头匹配一律大写化后取交集（`{LOGIN_TIME, IP} ∩ {USER_NAME, LOGIN_NAME, USERNAME}`）。
2. 时间列按优先级扫描多个候选（`LOGIN_TIME/CREATE_TIME/OPER_TIME/CHECK_DATE/...`）。
3. 低置信度 `xlsx_table` 在 interactive 模式必须请用户确认 declared_type；
   quick-report 模式在报告中明确标注限制。

## Evidence

- scripts/inventory_logs.py detect_xlsx。
- references/error-handling.md “Type Mismatch”。
