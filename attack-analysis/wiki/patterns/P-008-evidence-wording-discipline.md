# P-008: 证据措辞分级与禁评分红线

- Type: failure-mode
- Status: active
- First compiled: 2026-09-03 (v1.1 wiki seeding, source: references/reporting.md)

## PROBLEM

报告把候选关联写成确定事实（“攻击者于 X 时入侵”），或输出威胁评分/
风险总分/战斗力式标签，读者据此做了过度处置。

## ROOT CAUSE

把脚本产出的 candidate 与 AI 推断混同；评分数字看起来客观，
实际是未经校准的伪量化。

## FIX / Workaround

1. 措辞与证据强度对齐：`confirmed by`（日志原文直接支持）、
   `suggests`（候选关联）、`consistent with`（时区不确定等弱证据）。
2. IP 归属（geo/ASN/ISP）不得单独用于身份归因。
3. 红线：不输出威胁评分、风险总分、数字严重度或评级。
4. 每条结论标注类型：日志事实 / 候选关联 / 外部富集 / AI 推断。

## Evidence

- references/reporting.md “Wording Rules”。
- references/correlation.md “Evidence Promotion”。
