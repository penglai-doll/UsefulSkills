---
knowledge_id: webshell.detection-matrix
title: WebShell 反例与检测矩阵
signals: [webshell, post, high-entropy]
read_when: 命中多个家族或需排除正常 POST 时。
support_status: best-effort
---

# WebShell 反例与检测矩阵

## 读取时机

命中多个家族或需排除正常 POST 时。

## 版本矩阵

- 当前等级：`best-effort`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

比较 URI、大小熵、定界、方向对称、可验证解码、操作语义和目标字段。

## 反例

备份上传、图床、SSO、GraphQL 与遥测都可能高熵。

## 提取方法

先建同 URI 正常对照；只有验证事实写 EVT，判断写 FIND 并引证。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

无 key/无响应/样本少时输出缺口，不给风险总分。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0](https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0)
- [https://hello-ctf.com/hc-misc/pcap/](https://hello-ctf.com/hc-misc/pcap/)
