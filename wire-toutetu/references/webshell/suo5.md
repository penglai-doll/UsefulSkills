---
knowledge_id: webshell.suo5
title: suo5 帧与 KLV
signals: [suo5, klv, xor, websocket]
read_when: 出现 URL-safe Base64 分帧、2 字节 XOR 或 KLV 键时。
support_status: verified-decode
---

# suo5 帧与 KLV

## 读取时机

出现 URL-safe Base64 分帧、2 字节 XOR 或 KLV 键时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

8 字节 header 解 obs+长度；data 再 Base64+XOR；KLV 为 klen/key/vlen/value。

## 反例

普通 Base64 长连接不等于 suo5。

## 提取方法

解析 ac、id、h、p、dt、sid、r、m；dt 继续路由内层协议。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

超限长度、截断或未知 action 逐层记录。

## 夹具

`txn.suo5-klv`

## 来源

- [https://github.com/zema1/suo5](https://github.com/zema1/suo5)
