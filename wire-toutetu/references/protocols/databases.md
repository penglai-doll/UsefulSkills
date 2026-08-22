---
knowledge_id: protocols.databases
title: MySQL/Redis/MongoDB
signals: [mysql, redis, mongodb]
read_when: 出现数据库端口或解码字段时。
support_status: best-effort
---

# MySQL/Redis/MongoDB

## 读取时机

出现数据库端口或解码字段时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

MySQL command/query、Redis RESP、Mongo opcode/namespace/requestId。

## 反例

端口只是提示，代理和 TLS 需协议佐证。

## 提取方法

按 requestId 或顺序配对，只输出查询摘要与证据 ID。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

压缩、TLS 或版本未知时标 best-effort。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
