---
knowledge_id: webshell.chopper
title: 中国菜刀
signals: [chopper, eval, post]
read_when: 出现单参数 POST、脚本关键字或响应定界时。
support_status: verified-decode
---

# 中国菜刀

## 读取时机

出现单参数 POST、脚本关键字或响应定界时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

PHP/ASP/ASPX/JSP 参数、URL/Base64、eval/Execute 和前后标记。

## 反例

管理后台和调试接口可能提交脚本片段。

## 提取方法

保留重复 form 值，按语言解码并用定界提取响应。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

不使用固定密码假设；截断响应标 partial。

## 夹具

`txn.chopper-php`、`txn.chopper-asp`、`txn.chopper-aspx`、`txn.chopper-jsp`

## 来源

- [https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0](https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0)
