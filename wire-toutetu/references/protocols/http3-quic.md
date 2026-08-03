---
knowledge_id: protocols.http3-quic
title: HTTP/3 与 QUIC 元数据
signals: [quic, http3, dcid, scid]
read_when: 出现 QUIC、HTTP/3 或 UDP/443 时。
support_status: metadata-only
---

# HTTP/3 与 QUIC 元数据

## 读取时机

出现 QUIC、HTTP/3 或 UDP/443 时。

## 版本矩阵

- 当前等级：`metadata-only`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

记录 DCID/SCID、版本、握手、SNI/ALPN、stream ID 和端点迁移。

## 反例

UDP/443 也可能是 DoQ、VPN 或自定义 QUIC。

## 提取方法

无 secrets 输出连接元数据；有 secrets 才路由 HTTP/3 字段。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺密钥时维持 metadata-only，不推测应用载荷。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
