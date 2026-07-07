# Reporting

Write `report/log-analysis-report.md` in Chinese unless the user requests another language.

## Required Sections

1. `# 日志攻击分析报告`
2. `## 摘要结论`
3. `## 分析范围与日志清单`
4. `## 时间线与时区说明`
5. `## 攻击来源 IP、运营商、定位与查询来源`
6. `## 攻击方式与实现过程`
7. `## 跨日志关联证据链`
8. `## 关键证据表`
9. `## 当前存在的问题`
10. `## 补救与加固建议`
11. `## 不确定性、缺失日志与分析限制`

## Evidence Table

Include columns:

- `证据ID`
- `时间`
- `来源文件`
- `位置`
- `事件/请求/操作`
- `关联对象`
- `结论用途`

## Wording Rules

- No threat score, risk total, severity number, or rating scale.
- Separate log facts from external enrichment and AI inference.
- If logs are missing or damaged, say exactly what cannot be concluded.
- Do not claim attacker identity from IP geolocation, ASN, or ISP alone.
