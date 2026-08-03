---
knowledge_id: protocols.rdp
title: RDP 控制与元数据
signals: [rdp, tpkt, x224]
read_when: 出现 TPKT/X.224、CredSSP 或 RDPUDP 时。
support_status: best-effort
---

# RDP 控制与元数据

## 读取时机

出现 TPKT/X.224、CredSSP 或 RDPUDP 时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

协商协议、TLS/CredSSP、虚拟通道与会话时序。

## 反例

3389 可承载其他协议。

## 提取方法

保存连接和协商事件；字段可见时再导出通道对象。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

加密桌面内容不从包大小推断具体操作。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
