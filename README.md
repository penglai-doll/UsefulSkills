# 个人自用Skills合集

## 简介

一个以网络安全为主的Skills合集，工作流主要参考本人平时干活和接触到各种奇奇怪怪的案例。

### 目前已经完成/计划

- [x] 恶意APK分析器5.0.0
  - 默认面向案件固证，按需升级为 Java/Native 深度逆向
  - apktool 优先建立可复用工作区，盘点 Manifest、资源、assets、隐藏载荷与 SO
  - 以 `evidence_id`、来源、提取方法和状态替代冗杂总风险评分
  - 默认支持 AI+被动网络搜索辅助 SDK、域名和调证字段归属，并通过 `review-queue` / `review-decisions` 回写审阅结论
  - 报告与中间产物统一输出到 `output/<sample>/report` 和 `output/<sample>/cache`
  - 已支持 SDK/平台调证值、回连候选、签名证书、渠道标识、打包环境、嵌套载荷和关键哈希提取
  - ZIP fallback、符号链接、超大文本和 Native strings 均采用有界扫描；专用 provider 仅提交命中规则的 `styles.xml/info` 密文
  - Native 深挖仅对证据选中的 SO 调用 Ghidra/Rizin、Capstone、Unicorn 和 YARA
  - 报告拆分为固证报告和逆向技术附录；动态测试在 v5.0 仅保留接口契约
- [ ] 舆情分析

尽可能以更优（各种奇怪渠道？）的方式不断完善实现

## 参考文献

- [好SKill的五个共性](https://mp.weixin.qq.com/s/BDPTsJy1GZL4PgSx9L4ykw)
- 安恒“恒脑”（思维链参考）
- 很多很碎的东西，会慢慢补充
