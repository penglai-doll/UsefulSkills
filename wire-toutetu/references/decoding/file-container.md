---
knowledge_id: decoding.file-container
title: 文件魔数与容器
signals: [magic, zip, pdf, pe, elf]
read_when: 输出可能是文件或归档时。
support_status: best-effort
---

# 文件魔数与容器

## 读取时机

输出可能是文件或归档时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

命中 PNG/ZIP/GZIP/PDF/MZ/ELF/RAR/SQLite 头部魔数即判定容器类型；魔数只校验输出起始字节，流中部命中需再结合长度与结构确认。

## 反例

扩展名和嵌入魔数可伪造。

## 提取方法

识别后写入 OBJ：保留文件名、前 16 字节魔数、大小、SHA-256 与提取路径；无法识别的输出按原字节保存并标记 best-effort。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

损坏容器保留原字节与解析错误。

## 夹具

无独立夹具；魔数识别由 `pcap.http1-basic`、`pcap.ftp-basic`、`pcap.smtp-basic` 的对象提取夹具间接覆盖，维持 best-effort 分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
