---
knowledge_id: tooling.tshark
title: TShark 4.4/4.6 适配
signals: [tshark, capinfos, fields]
read_when: 运行解析、字段缺失或对象导出时。
support_status: verified-extract
---

# TShark 4.4/4.6 适配

## 读取时机

运行解析、字段缺失或对象导出时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

以 -G fields 和 --export-objects help 探测本机能力，记录 --version。

## 反例

文档字段不保证本机 build 启用。

## 提取方法

动态求交字段集，follow/export 使用受控参数。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

字段缺失降级，不把空字段当无流量。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
