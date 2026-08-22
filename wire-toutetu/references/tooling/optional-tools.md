---
knowledge_id: tooling.optional-tools
title: 可选工具适配器
signals: [aircrack, ffmpeg, zeek, scapy]
read_when: 题型需要 Wi-Fi、媒体、日志或夹具时。
support_status: best-effort
---

# 可选工具适配器

## 读取时机

题型需要 Wi-Fi、媒体、日志或夹具时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

aircrack 用于 Wi-Fi，ffmpeg 用于已知 codec，Scapy 只生成测试夹具。

## 反例

可选工具缺失不影响 TShark 基础分析。

## 提取方法

先展示用途与命令，确认后安装，记录版本与派生哈希。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

适配器失败单独写 failures。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
