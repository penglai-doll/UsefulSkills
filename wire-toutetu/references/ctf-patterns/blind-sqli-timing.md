---
knowledge_id: ctf-patterns.blind-sqli-timing
title: 盲注与时序
signals: [sqli, sleep, timing]
read_when: 参数呈布尔/时间盲注序列时。
support_status: best-effort
---

# 盲注与时序

## 读取时机

参数呈布尔/时间盲注序列时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

归一化模板、字符位置、比较式、状态/长度差、RTT 中位数与 MAD。

## 反例

慢后端、重传和限流会制造延迟。

## 提取方法

使用对照组与稳健统计重建位/字符并引用 TXN。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

样本少或抖动大只输出候选。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
