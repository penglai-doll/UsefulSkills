# 更新记录

## 2026-10-01：android-malware-analysis 9.0.0

依据 WikiSkill 的 Algorithm 1 新增独立实验入口：空 Skill/Wiki 基线、完整训练轨迹、真实
Maintainer 与 ReAct Proposer、单 Skill 原子变更、严格验证提分、拒绝后保留 Wiki、独立测试、
三次运行及 1000 次配对 Bootstrap。当前 Codex 可通过绑定文件协议由独立 Agent 执行三个
角色；也支持命令桥和模型服务。实验输出与安装目录隔离，恢复和只读复验重建真实调用及
评分链。保留原有案件工作流、人工提案接口和正式源码发布检查。

补齐 PURPOSE.md，并将其纳入受控副本；支持 Wiki 索引和 PURPOSE 的相对路径；发布检查
的完整日志保留全部失败证据，避免被大量缓存提示遮住。新增四份实验 Schema 与方法说明。

完整发布检查：563 个测试，559 通过、4 个递归检查按设计跳过；案件烟测、契约、Schema、
Wiki 和发布文件检查通过。仓库入口与语法检查覆盖 7 个 Skill、132 个脚本并通过。
三轮真实 Codex 小型验证的无 Skill 基线与最终测试均为 100%，按论文规则提前停止，
未显示提升。独立角色演练及复现边界见 [9.0.0 验证记录](./android-malware-analysis/references/9.0.0-validation.md)。
本次实现并验证 Android 领域的方法流程，未重跑论文原始五个基准或复现其成绩表。

## 2026-10-01：全部 Skill 复查与修复

| Skill | 当前版本 | 本次变化 |
| --- | --- | --- |
| android-malware-analysis | 8.1.2 | 连续 resume 保留 reused 结果；JADX 成功退出需有源码产物，无产物不崩溃、不建伪缓存；partial 缓存复用保留状态。 |
| attack-analysis | 1.0.1 | 无效日期保留为记录级缺口；未知时区退出时间关联；输出截断显式标记；Windows JSON 统一 UTF-8；经验演化限制写入路径并覆盖写入失败回滚。 |
| linux-loader | 1.0.1 | 禁止未知文件系统自动挂载；先创建并验证只读 loop，再验证实际 mount；失败时卸载并分离本次设备，保存清理状态。 |
| utm-forensic-cli | 1.1.1 | NBD 基底/差异文件/位图拒绝路径和链接冲突；位图原子落盘；qcow2 不覆盖已有输出；补全 CLI help 和文件系统专用参数。 |
| windows-loader | 1.0.1 | 权限拒绝不再视作设备只读；resume 输出明确的未验证状态；复用已声明的分析目标；元数据测试检查契约而非固定描述文案。 |
| wire-toutetu | 1.0.1 | TLS 密钥与解析配置变化使 inventory 缓存失效；保留 TSV 字段分隔符；HTTP 临时响应不消费请求；多帧 HTTP/2 标记关联缺口。 |
| writing-helper | 1.0.1 | 补充直接引文、代码、路径和链接目标的逐字保留规则；文风修改不自行纠正疑似事实错误。保持纯文档结构。 |

入口统一声明完整版本号，脚本示例解析到安装目录；修复 PURPOSE 引用，调整平台简介长度。仓库新增 `tools/check_skills.py`，只读检查入口元数据、文档链接、版本一致性与 Python 语法。原有未提交的 attack-analysis 经验演化代码经过审查及回归验证后纳入此次更新。

### 验证

环境：Windows、Python 3.12.10。

| 检查 | 数量 | 结果 |
| --- | ---: | --- |
| Android 完整发布检查 | 534 个测试 | 530 通过，4 个递归发布检查按设计跳过；契约、schema、wiki、发布文件检查通过，release_eligible=true。 |
| Attack Analysis | 77 个测试 | 通过，包含 gold 日志流水线、演化回滚及无效分数在写入前拒绝。 |
| Linux Loader | 24 个测试 | 通过，挂载与清理边界使用模拟命令验证。 |
| UTM Forensic CLI | 28 个测试 | 通过，包含本机 NBD 协议自测和证据路径隔离。 |
| Windows Loader | 60 个测试 | 通过。 |
| WireToutetu | 75 个测试 | 66 通过，9 个 TShark 集成检查因本机缺少 TShark 跳过。 |
| 仓库入口与语法检查 | 7 个 Skill、123 个脚本 | 通过。 |
| 独立 CLI help | 21 个入口 | 通过。 |
| WireToutetu 索引与目录检查 | 2 项 | 通过。 |

共 798 个测试，785 通过、13 个有明确原因的跳过，无失败。真实 Linux/WSL 挂载与 macOS UTM 仿真引导未在本次 Windows 环境实测；本记录不将模拟验证或跳过项视作平台集成验证。
