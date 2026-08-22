---
knowledge_id: protocols.dns
title: DNS 与隧道
signals: [dns, dns.qry.name, txt]
read_when: 出现 DNS、长子域、TXT 或高频 NXDOMAIN 时。
support_status: verified-extract
---

# DNS 与隧道

## 读取时机

出现 DNS、长子域、TXT 或高频 NXDOMAIN 时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

QNAME/QTYPE/rcode/TTL/事务 ID、标签长度熵和时序。

## 反例

CDN、遥测、DKIM 也会产生长域名或 TXT。

## 提取方法

按根域/客户端聚合，只对重复结构标签尝试 Base32/Base64/Hex。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

只有请求、缓存缺响应或 DoH/DoT 未解密时标 partial。

## 夹具

`pcap.dns-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
