---
knowledge_id: webshell.weevely
title: Weevely3 ObfPost
signals: [weevely, obfpost, password]
read_when: 提供候选密码或发现密码派生定界时。
support_status: verified-decode
---

# Weevely3 ObfPost

## 读取时机

提供候选密码或发现密码派生定界时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

MD5(password)：key 前8、header 8:20、trailer 20:32；Base64→XOR→zlib。

## 反例

偶然定界仍需 zlib 成功和语义验证。

## 提取方法

搜索派生定界，补 padding，循环 XOR 后 zlib 解压。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无通用官方默认密码；缺候选为 not-attempted。

## 夹具

`txn.weevely3-session`

## 来源

- [https://github.com/epinna/weevely3](https://github.com/epinna/weevely3)
