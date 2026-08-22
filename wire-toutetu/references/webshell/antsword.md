---
knowledge_id: webshell.antsword
title: 蚁剑
signals: [antsword, base64, rot13, post]
read_when: 出现蚁剑 PHP 编码链、随机前缀或 eval 参数时。
support_status: verified-decode
---

# 蚁剑

## 读取时机

出现蚁剑 PHP 编码链、随机前缀或 eval 参数时。

## 版本矩阵

- 当前等级：`verified-decode`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

PHP default/Base64/ROT13/随机前缀，自定义 encoder 可组合。

## 反例

CMS 插件也可能含 eval/base64。

## 提取方法

在参数边界执行 strip-prefix→Base64→ROT13，每层保存哈希。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

未知插件只给候选链，不无限递归。

## 夹具

`txn.antsword-php-default`、`txn.antsword-php-base64`、`txn.antsword-php-rot13`

## 来源

- [https://github.com/AntSwordProject/antSword](https://github.com/AntSwordProject/antSword)
- [https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0](https://github.com/Leeyuxun/Webshell_traffic_analysis_tool/releases/tag/v3.0)
