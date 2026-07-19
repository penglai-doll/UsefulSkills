# 个人自用Skills合集

## 简介

一个以网络安全为主的Skills合集，工作流主要参考本人平时干活和接触到各种奇奇怪怪的案例。

### 目前已经完成/计划

- [x] 恶意APK分析器6.1.0
  - 入口改为先选择固证/逆向双模式，不再默认任务类别
  - apktool 优先建立可复用工作区，盘点 Manifest、资源、assets、隐藏载荷与 SO；apktool 成功时直接复用 smali，JADX 主要用于隐藏载荷深挖
  - 以 `evidence_id`、来源、提取方法和状态替代冗杂总风险评分
  - 默认支持 AI+联网辅助 SDK、域名、调证字段、框架案例、分析案例和架构案例研判
  - 报告与中间产物统一输出到 `output/<sample>/report` 和 `output/<sample>/cache`
  - 已支持 SDK/平台调证值、SDK 使用痕迹、回连候选、签名证书、渠道标识、打包环境、嵌套载荷和关键哈希提取
  - 两阶段端点提取重建：一方/第三方分流 + 代码推理（变量赋值跟踪、拼接 URL 还原），端点证据原地标注回连候选/仅服务地址/低上下文三分类与建议处置，分类不改动证据 status
  - SDK 调证值新增 `confidence` 置信标注（high/medium），仅作审阅优先级提示
  - 固证报告端点章节重构为“回连候选研判”：回连候选突出展示、服务地址明确标注非回连 IOC、低上下文只做计数与理由分桶，节首固定“AI 研判为准”声明
  - 6.1 明确脚本/AI 分工：脚本只做确定性候选与分类标注、工作区和静态深挖，AI 负责业务理解、路径追踪、联网辅助分析、结论定性和报告取舍
  - 全部外部工具 subprocess 调用带超时防护，畸形样本不再挂死管线；Ghidra/Rizin 等工具状态诚实标注 not_available/prepared_not_executed
  - Windows 工具链建议优先 7z/JADX 本机安装，apktool 缺失时可 `--allow-unpack-fallback` 降级
  - ZIP fallback、符号链接、超大文本和 Native strings 均采用有界扫描；专用 provider 仅提交命中规则的 `styles.xml/info` 密文
  - Native 深挖仅对证据选中的 SO 调用 Ghidra/Rizin、Capstone、Unicorn 和 YARA
  - 报告拆分为固证报告、逆向报告和技术附录；动态测试在 6.1.x 仅保留接口契约
- [x] Linux Loader v1.0.0
  - 面向 WSL2/Linux 的 Linux 检材只读挂载、基础盘点和按需分析
  - 支持 raw/dd/img 与 E01；E01 缺 `ewf-tools` 时可提示 apt 安装或 wget/curl 下载到临时缓存，FUSE 不可用时提示提权或 `ewfexport` 降级
  - 自动试探 sudo；无可用 sudo 时输出 `manual_command` 和用户选择，不增加额外模式
  - 本地模型友好：摘要 JSON、最小 reference 读取，重点覆盖 Docker 挂载映射、常见面板、网站、数据库和日志
  - 已覆盖 WSL2 权限/FUSE、哈希策略、非系统数据盘、LVM/LUKS、文件系统只读参数和路由契约测试
- [x] Attack Analysis 0.1.0
  - 面向服务器被攻击后的日志溯源分析，覆盖 Web access、Spring Boot/P6Spy、登录/操作表格等 v1 已验证输入
  - 工作前必须先确认 `quick-report` 或 `interactive`，避免应急场景下误跑、漏跑或过度分析
  - 默认联网辅助 IP/ASN/运营商/定位等公开情报，联网失败自动降级离线；不默认上传完整日志或敏感字段
  - 采用 AI 主导、脚本辅助：脚本负责日志清单、解析、候选事件与基础关联，AI 负责证据取舍和攻击链还原
  - 明确区分 v1 verified、best-effort 与 future interface，不把 Windows/cloud/K8s/binlog 深解析伪装成已支持能力
  - 已提供 parser 插件架构、跨日志关联候选、金标准攻击样本和契约测试
  - 已通过 skill frontmatter 校验、脚本编译、真实样本 quick-report 流程测试与 5 项单元测试
- [ ] 舆情分析

尽可能以更优（各种奇怪渠道？）的方式不断完善实现

## 参考文献

- [好SKill的五个共性](https://mp.weixin.qq.com/s/BDPTsJy1GZL4PgSx9L4ykw)
- 安恒“恒脑”（思维链参考）
- 很多很碎的东西，会慢慢补充
