---
knowledge_id: protocols.websocket
title: WebSocket 帧
signals: [websocket, upgrade, opcode]
read_when: 出现 HTTP Upgrade、opcode 或长连接双向帧时。
support_status: best-effort
---

# WebSocket 帧

## 读取时机

出现 HTTP Upgrade、opcode 或长连接双向帧时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

握手、方向、FIN/opcode、mask、分片、压缩和控制帧。

## 反例

长轮询与 SSE 不是 WebSocket。

## 提取方法

关联 Upgrade 事务，按方向拼 continuation，最后解压消息。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺握手时端口强制解码易误判，标 best-effort。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
