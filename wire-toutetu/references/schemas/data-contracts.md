---
knowledge_id: schemas.data-contracts
title: Case 与证据数据契约
signals: [schema, flow, txn, obj, dec, evt, find]
read_when: 编写插件、查询、导出或解释完整性时。
support_status: verified-extract
---

# Case 与证据数据契约

## 读取时机

编写插件、查询、导出或解释完整性时。

## 版本矩阵

- 当前等级：`verified-extract`；只有实际夹具通过才晋级。
- 先读取 `preflight` 的平台、TShark 版本和字段能力；4.4/4.6 差异走动态探测。

## 观察特征

FLOW/TXN/OBJ/DEC/EVT/FIND 分域；HTTP/2 双索引；固定完整性和解码状态。

## 反例

FIND 判断不等于 EVT 观察事实。

## 提取方法

先证据后判断；FIND 必须引用证据；分页最大 500 条/4MiB。

## 解码状态机

`not-attempted → text|binary|partial|failed`。每步保存输入/输出 SHA-256、长度、参数来源和错误；提取能力使用 `verified-extract/best-effort/metadata-only/unavailable`。

## 失败路径

字段缺失用 null/unknown 与 errors，不发明默认值。

## 夹具

无独立夹具；维持当前分级。

## 来源

- [https://www.wireshark.org/docs/man-pages/tshark.html](https://www.wireshark.org/docs/man-pages/tshark.html)
