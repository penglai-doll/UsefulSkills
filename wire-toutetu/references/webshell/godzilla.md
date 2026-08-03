---
knowledge_id: webshell.godzilla
title: 哥斯拉
signals: [godzilla, aes, xor, post]
read_when: 出现 pass+key、MD5 定界或哥斯拉 profile 时。
support_status: verified-decode
---

# 哥斯拉

## 读取时机

出现 pass+key、MD5 定界或哥斯拉 profile 时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

Java/C# AES raw/Base64，PHP XOR raw/Base64，key 常由 MD5[:16] 派生。

## 反例

表单字段名和 Base64 都可能正常。

## 提取方法

拆定界与 Base64，按语言 profile 解密，并验证方法/参数结构。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

ASP 和旧变体只按夹具晋级；模式不明时受控枚举。

## 夹具

`txn.godzilla-java-aes`、`txn.godzilla-csharp-aes`、`txn.godzilla-php-xor`

## 来源

- [https://github.com/BeichenDream/Godzilla](https://github.com/BeichenDream/Godzilla)
- [https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0](https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0)
