---
knowledge_id: protocols.smb
title: SMB/SMB3 文件与会话
signals: [smb, smb2, smb3]
read_when: 出现 SMB 协商、树连接或文件读写时。
support_status: best-effort
---

# SMB/SMB3 文件与会话

## 读取时机

出现 SMB 协商、树连接或文件读写时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

dialect、session/tree/file ID、CREATE/READ/WRITE/CLOSE、路径、签名和加密。

## 反例

IPC$ 与命名管道可能是正常管理。

## 提取方法

按 session/tree/file 恢复对象；SMB3 仅在有会话密钥时解密。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

复合请求与版本字段差异保持 best-effort。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
