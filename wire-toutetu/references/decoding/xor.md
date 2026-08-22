---
knowledge_id: decoding.xor
title: 循环 XOR
signals: [xor, key, known-plaintext]
read_when: 提供 key、随机 XOR 协议或已知明文时。
support_status: verified-decode
---

# 循环 XOR

## 读取时机

提供 key、随机 XOR 协议或已知明文时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

记录 key 长、offset、方向差异，用魔数或结构验证。

## 反例

单字节 XOR 可偶然产生可打印短串。

## 提取方法

key 原值只留 case/sidecar；受控枚举 offset。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无语义或魔数不符保持 failed/best-effort。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://github.com/zema1/suo5](https://github.com/zema1/suo5)
