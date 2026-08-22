---
knowledge_id: protocols.icmp
title: ICMP/ICMPv6 与隧道
signals: [icmp, icmpv6, echo]
read_when: 出现 Echo、自定义 data 或异常长度时。
support_status: verified-extract
---

# ICMP/ICMPv6 与隧道

## 读取时机

出现 Echo、自定义 data 或异常长度时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

type/code/id/seq、请求响应、data 长度熵、固定头和间隔。

## 反例

系统探活和路径 MTU 会稳定产生 ICMP。

## 提取方法

按 id/端点/序号聚合 data，处理缺号与重复后再解码。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

NAT 可重写 id；单向抓包不宣称完整会话。

## 夹具

`pcap.icmp-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
