---
knowledge_id: ctf-patterns.side-channels
title: 包长/时序/方向侧信道
signals: [side-channel, packet-length, timing]
read_when: 明文不可见但题目暗示侧信道时。
support_status: best-effort
---

# 包长/时序/方向侧信道

## 读取时机

明文不可见但题目暗示侧信道时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

方向、去基线长度、量化间隔、端口低位、TTL/IPID 和重传排除。

## 反例

MTU、压缩、拥塞和 ACK 会改变观测。

## 提取方法

建立控制序列，列候选映射与误差，以可逆结果验证。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无独立验证时保持候选。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
