---
knowledge_id: webshell.regeorg
title: reGeorg/Neo-reGeorg 控制面
signals: [regeorg, neoreg, x-cmd, proxy]
read_when: 出现 CONNECT/FORWARD/READ/DISCONNECT 头时。
support_status: verified-extract
---

# reGeorg/Neo-reGeorg 控制面

## 读取时机

出现 CONNECT/FORWARD/READ/DISCONNECT 头时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

经典 X-CMD/X-TARGET/X-PORT；Neo 可能随机字段和 cookie。

## 反例

反向代理健康检查可能有相似动词。

## 提取方法

标准化 header，输出连接、读写、转发、断开与目标事件。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

随机映射缺 sidecar 时不猜目标。

## 夹具

`txn.regeorg-control` 覆盖 CONNECT/FORWARD/READ/DISCONNECT 控制序列与普通 POST 反例；`pcap.tunnels-suo5-regeorg` 以真实 TShark 验证 HTTP 控制头提取与目标字段重建。

## 来源

- [https://github.com/sensepost/reGeorg](https://github.com/sensepost/reGeorg)
- [https://github.com/L-codes/Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg)
