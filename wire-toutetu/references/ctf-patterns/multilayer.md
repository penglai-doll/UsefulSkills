---
knowledge_id: ctf-patterns.multilayer
title: 多层编码链搜索
signals: [base64, hex, gzip, xor, rot13]
read_when: 载荷呈嵌套编码、压缩或魔数时。
support_status: verified-decode
---

# 多层编码链搜索

## 读取时机

载荷呈嵌套编码、压缩或魔数时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

每层校验字符集、长度、padding、压缩头、熵和输出魔数。

## 反例

短串可能同时像 Hex/Base64。

## 提取方法

有界深度、状态去重、输出上限，每层生成 DEC。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

爆炸解压、循环状态、错误 key 或截断立即停止。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
