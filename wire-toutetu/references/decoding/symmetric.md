---
knowledge_id: decoding.symmetric
title: AES 对称解密
signals: [aes, cbc, ecb, gcm]
read_when: sidecar/profile 指定 AES key/mode/IV/nonce/tag 时。
support_status: best-effort
---

# AES 对称解密

## 读取时机

sidecar/profile 指定 AES key/mode/IV/nonce/tag 时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

严格验证 key 长、块对齐、PKCS7、CBC IV 与 GCM nonce/tag/AAD。

## 反例

块长二进制不证明 AES。

## 提取方法

严格 padding/tag 校验，错误 key 不降级成文本。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺 key not-attempted；截断或 tag 错误 failed。

## 夹具

ECB/CBC ? WebShell ?????GCM ???? tag?GCM ???????????

## 来源

- [https://github.com/rebeyond/Behinder](https://github.com/rebeyond/Behinder)
- [https://github.com/BeichenDream/Godzilla](https://github.com/BeichenDream/Godzilla)
