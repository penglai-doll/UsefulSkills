---
knowledge_id: protocols.ftp
title: FTP/FTP-DATA 对象
signals: [ftp, ftp-data, pasv, retr, stor]
read_when: 出现 FTP 控制或数据连接时。
support_status: verified-extract
---

# FTP/FTP-DATA 对象

## 读取时机

出现 FTP 控制或数据连接时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

USER/PASS、PORT/PASV/EPSV、RETR/STOR、150/226 与数据五元组。

## 反例

高端口连接不自动属于 FTP。

## 提取方法

由控制事务映射数据流，按命令方向恢复对象并计算哈希。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

缺控制流时对象来源 unknown；FTPS 需 TLS secrets。

## 夹具

`pcap.ftp-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
