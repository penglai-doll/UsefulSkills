---
knowledge_id: protocols.http1
title: HTTP/1.x 深度事务
signals: [http, get, post, chunked, multipart]
read_when: 出现 HTTP/1.x、表单、上传下载或 WebShell 候选时。
support_status: verified-extract
---

# HTTP/1.x 深度事务

## 读取时机

出现 HTTP/1.x、表单、上传下载或 WebShell 候选时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

方法/URI/Host、响应码、chunked、Content-Encoding、multipart boundary 和同流顺序。

## 反例

大 POST、压缩响应和固定 URI 可能是正常 API。

## 提取方法

启用 TCP/HTTP 重组与解压，配对请求响应，http.file_data 按 OBJ 落盘哈希。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无响应或流水线错配标 partial；解压失败保留原始实体。

## 夹具

`pcap.http1-basic`

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
