---
knowledge_id: protocols.rtp
title: RTP/RTCP 媒体
signals: [rtp, rtcp, ssrc]
read_when: 出现 RTP/RTCP 或连续 UDP 媒体时。
support_status: best-effort
---

# RTP/RTCP 媒体

## 读取时机

出现 RTP/RTCP 或连续 UDP 媒体时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

SSRC、sequence、timestamp、payload type、jitter、丢包与 SDP 映射。

## 反例

连续 UDP 不必然是 RTP。

## 提取方法

优先从 SDP 取 codec，导出 payload 后可交 ffmpeg 封装。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无 SDP 的动态类型与丢包媒体标 best-effort/partial。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
