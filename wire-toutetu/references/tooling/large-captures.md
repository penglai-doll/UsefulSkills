---
knowledge_id: tooling.large-captures
title: 大抓包切分与内存
signals: [large-capture, memory-limit, slice]
read_when: 抓包≥100MiB 或内存限制触发时。
support_status: best-effort
---

# 大抓包切分与内存

## 读取时机

抓包≥100MiB 或内存限制触发时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

<100MiB 完整；100MiB–2GiB 流索引；>2GiB 先清点再切片。

## 反例

压缩体积小但展开可能很大。

## 提取方法

TShark 以 stdout 增量流式读取，只聚合 FLOW/协议计数，不物化 payload；按 flow 的包范围或时间/IP/端口/流过滤，用 editcap/TShark 切出小片段后再做完整分析。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

切片保留过滤器和包范围；跨片事务 partial。

## 夹具

`test_stream_index_reads_tshark_incrementally_without_payload_materialization` 以真实 TShark 验证流索引增量读取且不物化 payload；大文件内存路径维持 best-effort 分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
