---
knowledge_id: protocols.http2
title: HTTP/2 子流
signals: [http2, h2, streamid]
read_when: 出现 ALPN h2 或 http2.streamid 时。
support_status: best-effort
---

# HTTP/2 子流

## 读取时机

出现 ALPN h2 或 http2.streamid 时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

以 (tcp.stream,http2.streamid) 聚合 HEADERS/DATA/END_STREAM/RST_STREAM。

## 反例

一个 TCP 流出现多个 URI 是并发子流的正常行为。

## 提取方法

保存 :method/:path/:status，按子流重组 DATA。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

TLS 未解密、缺 SETTINGS 或 HPACK 动态表时保持 best-effort。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
