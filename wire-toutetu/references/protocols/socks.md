---
knowledge_id: protocols.socks
title: SOCKS4/5 控制面
signals: [socks, socks5, proxy]
read_when: 出现 SOCKS 握手或代理链时。
support_status: best-effort
---

# SOCKS4/5 控制面

## 读取时机

出现 SOCKS 握手或代理链时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

版本、认证方法、CONNECT/BIND/UDP ASSOCIATE、ATYP、目标和响应码。

## 反例

代理端口不证明 SOCKS。

## 提取方法

由控制事务映射外层流和目标，载荷继续按内层协议路由。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

中途抓包缺握手时只记录组合特征。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
