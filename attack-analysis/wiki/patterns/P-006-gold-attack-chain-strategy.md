# P-006: 黄金攻击链的关联抓法（探测→爆破登录→SQLi→上传）

- Type: successful-strategy
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: tests/fixtures/gold_attack_case)

## PROBLEM

单日志看每条事件都像噪声：探测 404、一次登录失败、一两条可疑 SQL、
一个上传请求，单独都构不成结论。

## ROOT CAUSE

攻击链的证据分布在四类日志（access、app、p6spy、xlsx 登录/操作）里，
必须靠同 IP + 时间窗把链串起来。

## FIX / Workaround

1. 关联主键用归一化 IP，强窗口 ±5 分钟（弱窗口 ±30 分钟）。
2. 关注序列：同 IP 探测（404/敏感路径）→ 登录失败→成功 →
   `sql_suspicious`（union/select/sleep）→ 上传/管理操作。
3. xlsx 登录/操作记录与 access 日志按账号+时间互证。
4. AI 晋升时使用 `consistent with / suggests / confirmed by`
   分级措辞，引用原始文件+行号。

## Evidence

- tests/fixtures/gold_attack_case/expected_findings.md。
- references/correlation.md。
