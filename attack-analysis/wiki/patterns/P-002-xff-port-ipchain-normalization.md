# P-002: 访问日志来源 IP 带端口 / X-Forwarded-For 代理链导致关联漏配

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: references/error-handling.md)

## PROBLEM

`1.2.3.4:54321`、括号包裹的 IPv6、逗号分隔的 X-Forwarded-For 代理链
如果按原样做关联键，同一攻击者会被拆成多个“IP”，跨日志关联大量漏配，
来源 IP 统计失真。

## ROOT CAUSE

访问日志中的 remote host 字段经常包含端口或代理链；未经归一化就分组，
键空间被端口/代理噪声放大。

## FIX / Workaround

1. 统一归一化为 `actor_ip_normalized` + `actor_port`，代理链保留在可选
   `ip_chain` 字段（首元素视为疑似真实来源，标注为推断而非事实）。
2. 关联只使用 `actor_ip_normalized`；报告引用原始值。
3. 不依据 IP 归属单独做身份归因。

## Evidence

- references/error-handling.md “IP Variants”。
- scripts/common/ip_normalize.py。
