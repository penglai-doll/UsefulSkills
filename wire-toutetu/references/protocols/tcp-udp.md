---
knowledge_id: protocols.tcp-udp
title: TCP/UDP 流与重组
signals: [tcp, udp, retransmission, out_of_order]
read_when: 出现 TCP/UDP 或需判断缺段、乱序、重传时。
support_status: verified-extract
---

# TCP/UDP 流与重组

## 读取时机

出现 TCP/UDP 或需判断缺段、乱序、重传时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

五元组与 tcp.stream/udp.stream 双索引；记录 SYN/FIN/RST、重传、乱序、lost_segment、cap_len/len。

## 反例

重传或单向流可能只是抓包点差异。

## 提取方法

先索引流，再按 stream 重组；大载荷落盘；缺段标 partial。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

端口复用、NAT 和中途抓包会缺握手，不按序号空隙臆补字节。

## 夹具

`pcap.tcp-basic`、`pcap.udp-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
