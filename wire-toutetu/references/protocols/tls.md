---
knowledge_id: protocols.tls
title: TLS 解密材料
signals: [tls, ssl, keylog, rsa]
read_when: 出现 TLS、SSLKEYLOGFILE、RSA 私钥或应用层不可见时。
support_status: best-effort
---

# TLS 解密材料

## 读取时机

出现 TLS、SSLKEYLOGFILE、RSA 私钥或应用层不可见时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

版本、SNI、ALPN、证书、cipher suite 和会话复用；key log 优先。

## 反例

自签名或证书异常不单独证明恶意。

## 提取方法

识别 CLIENT_* secrets 后设置 tls.keylog_file；记录解密后的协议。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

TLS 1.3 不用 RSA 私钥解密；缺握手或 secrets 错误明确 failed。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
