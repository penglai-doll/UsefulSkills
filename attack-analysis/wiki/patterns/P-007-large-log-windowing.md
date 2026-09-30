# P-007: 超大日志的窗口化提取顺序

- Type: successful-strategy
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: references/workflow.md)

## PROBLEM

GB 级日志直接塞进模型上下文必然失败或截断，要么超时要么丢关键窗口。

## ROOT CAUSE

上下文有限；全量扫描不可行，而无序抽样又会错过攻击窗口。

## FIX / Workaround

按信息密度递减的固定顺序窗口化：
1. 文件边界（首尾含时间戳记录）。
2. 用户给定的目标时间窗。
3. 安全关键词（login/auth/error/union/select/sleep/upload/shell/...）。
4. 高信号 HTTP 状态（4xx/5xx、敏感路径上的 2xx、异常 method）。
5. Top talker IP 与稀有路径。

`<100MB` 可全量流式；`100MB-2GB` 流式+过滤+封顶输出；`>2GB`
先 inventory 再按窗口切块。

## Evidence

- references/workflow.md “Large Logs”。
