---
knowledge_id: ctf-patterns.dns-icmp-tunnels
title: DNS/ICMP 隧道拼接
signals: [dns-tunnel, icmp-tunnel]
read_when: 标签或 Echo data 呈分片序列时。
support_status: best-effort
---

# DNS/ICMP 隧道拼接

## 读取时机

标签或 Echo data 呈分片序列时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

序号、会话 ID、方向、重传、块长、根域或 ICMP id。

## 反例

DNS 重试与 ping 丢包会重复。

## 提取方法

按序号去重恢复有序块，缺块插入缺口后再解码。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

未知 framing 不跨会话拼接。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
