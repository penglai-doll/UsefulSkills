# 个人自用Skills合集

## 简介

一个以网络安全为主的Skills合集，工作流主要参考本人平时干活和接触到各种奇奇怪怪的案例。

### 目前已经完成/计划

- [x] 恶意APK分析器6.1.0
  - 入口改为先选择固证/逆向双模式，不再默认任务类别
  - 以 `evidence_id`、来源、提取方法和状态替代冗杂总风险评分
  - 默认支持 AI+联网辅助 SDK、域名、调证字段、框架案例、分析案例和架构案例研判
  - 报告与中间产物统一输出到 `output/<sample>/report` 和 `output/<sample>/cache`
  - 已支持 SDK/平台调证值、SDK 使用痕迹、回连候选、签名证书、渠道标识、打包环境、嵌套载荷和关键哈希提取

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

- [x] WireToutetu v1
  - 面向 Qwen 35B-A3B 等本地小模型的离线 PCAP/PCAPNG/CAP、CTF 与 WebShell 流量分析
  - Python 3.10+ 与 TShark 4.4/4.6 共用内核，显式区分 Windows、Linux 与 WSL；当前实测环境为 Windows、Python 3.11.9、TShark 4.6.4
  - 以插件注册表、41 个知识叶子和双层索引按信号加载，避免一次灌入完整知识库
  - 已验证 HTTP/1.x 对象恢复、TCP/UDP/DNS/ICMP、FTP/SMTP/USB 提取器，以及冰蝎、哥斯拉、蚁剑、菜刀、Weevely3 核心离线解码夹具；suo5 WebSocket 载荷与 reGeorg 自定义头另有真实 TShark 端到端夹具
  - 默认交互与分页证据查询；Markdown/校验分析包按需导出；`经验.md` 保持 12 KiB 硬上限
  - TLS、HTTP/2、SMB、RDP、Wi-Fi、HTTP/3 等按真实能力维持 best-effort 或 metadata-only，不冒充已验证

- [ ] 舆情分析

尽可能以更优（各种奇怪渠道？）的方式不断完善实现

## 参考文献

- [好SKill的五个共性](https://mp.weixin.qq.com/s/BDPTsJy1GZL4PgSx9L4ykw)
- 安恒“恒脑”（思维链参考）
- 很多很碎的东西，会慢慢补充
