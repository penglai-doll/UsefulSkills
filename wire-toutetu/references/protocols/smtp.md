---
knowledge_id: protocols.smtp
title: SMTP/MIME 对象
signals: [smtp, mime, mail]
read_when: 出现 SMTP、MIME boundary 或附件时。
support_status: verified-extract
---

# SMTP/MIME 对象

## 读取时机

出现 SMTP、MIME boundary 或附件时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

EHLO/MAIL FROM/RCPT TO/DATA、状态码、Transfer-Encoding、multipart 和文件名。

## 反例

邮件正文和附件使用 Base64 很正常。

## 提取方法

重组 DATA，按 MIME 分段，解传输编码并哈希附件。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

STARTTLS 后无 secrets 只保留握手前元数据。

## 夹具

`pcap.smtp-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
