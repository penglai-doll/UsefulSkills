---
knowledge_id: decoding.compression
title: Gzip/Zlib 与 HTTP 压缩
signals: [gzip, zlib, deflate]
read_when: 出现压缩魔数或 Content-Encoding 时。
support_status: verified-decode
---

# Gzip/Zlib 与 HTTP 压缩

## 读取时机

出现压缩魔数或 Content-Encoding 时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

gzip 1f8b；zlib CMF/FLG；deflate 可能带 zlib 头或 raw。

## 反例

高熵不等于压缩。

## 提取方法

按协议头选算法，设置输出大小与膨胀倍率上限。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

截断标 partial；zip bomb 阈值停止。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
