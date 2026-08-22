---
knowledge_id: webshell.behinder
title: 冰蝎 v2/v3/v4
signals: [behinder, aes, xor, post]
read_when: POST 高熵、固定路径、AES/XOR 或提供冰蝎 key 时。
support_status: verified-decode
---

# 冰蝎 v2/v3/v4

## 读取时机

POST 高熵、固定路径、AES/XOR 或提供冰蝎 key 时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

v2 协商；v3/v4 预共享；Java/PHP/.NET 常见 AES/XOR 与 raw/Base64/JSON/image/magic 包装。

## 反例

加密 API、上传和图片 POST 也会高熵。

## 提取方法

先拆包装，再以 sidecar/协商 key 解 AES 或循环 XOR；请求响应分别写 DEC。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

错误、缺 key、截断块分别为 failed/not-attempted/partial。

## 夹具

`txn.behinder-v3-aes`、`txn.behinder-v4-xor`

## 来源

- [https://github.com/rebeyond/Behinder](https://github.com/rebeyond/Behinder)
- [https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0](https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0)
