---
knowledge_id: decoding.encoding
title: URL/Base64/Hex/ROT13
signals: [url, base64, base64url, hex, rot13]
read_when: 字段满足编码约束时。
support_status: verified-decode
---

# URL/Base64/Hex/ROT13

## 读取时机

字段满足编码约束时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

区分标准/URL-safe Base64、padding、percent、Hex 分隔与 ROT13。

## 反例

token、UUID 和哈希不自动可解码。

## 提取方法

只在字段边界操作，记录算法长度并做文本/魔数验证。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

非法字符、奇数 Hex、无效 UTF-8 保留失败状态。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
