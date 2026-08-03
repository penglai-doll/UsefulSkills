---
knowledge_id: decoding.file-container
title: 文件魔数与容器
signals: [magic, zip, pdf, pe, elf]
read_when: 输出可能是文件或归档时。
support_status: verified-extract
---

# 文件魔数与容器

## 读取时机

输出可能是文件或归档时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

检查 PNG/ZIP/GZIP/PDF/MZ/ELF/RAR/SQLite 头与容器目录。

## 反例

扩展名和嵌入魔数可伪造。

## 提取方法

只读落盘、SHA-256、列目录；可执行内容仅静态检查。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

损坏容器保留原字节与解析错误。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
