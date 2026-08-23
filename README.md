# UsefulSkills

一组基于我自己日常工作流的实用 Skills，主要用于数字取证、安全分析、OSINT 和写作优化（持续更新）。每个 Skill 都是独立目录，可以按需安装和调用。

## Skills

| 分类 | Skill | 用途 |
| --- | --- | --- |
| APK分析 | [`android-malware-analysis`](./android-malware-analysis/) | Android 样本固证与静态逆向 |
| 服务器日志分析 | [`attack-analysis`](./attack-analysis/) | 服务器攻击日志溯源与事件报告 |
| 磁盘取证(Linux) | [`linux-loader`](./linux-loader/) | Linux/WSL 镜像只读挂载与定向恢复 |
| 磁盘取证(本地AI+Windows) | [`windows-loader`](./windows-loader/) | Windows 客体镜像只读挂载与取证排查 |
| 磁盘取证(基于MacOS，面向Linux) | [`utm-forensic-cli`](./utm-forensic-cli/) | macOS 通过 UTM Linux VM 隔离取证 |
| 流量分析 | [`wire-toutetu`](./wire-toutetu/) | PCAP、CTF 与 WebShell 流量分析 |
| 写作辅助 | [`writing-helper`](./writing-helper/) | 降低 AI 味和表达压力，同时保留原意 |
| OSINT | `osint-skill` | 舆情搜集、信源核验与中文简报（草案） |

## 安装

以Codex为例，克隆仓库后，将需要的 Skill 目录复制到 Codex Skills 目录：

```bash
git clone https://github.com/penglai-doll/UsefulSkills.git
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
cp -R UsefulSkills/<skill-name> "${CODEX_HOME:-$HOME/.codex}/skills/"
```

每个 Skill 可单独安装，不需要复制整个仓库。

(本目录下的Skills如需其他环境，一般AI会提前问你要不要安装，你同意的话就会自动安装)

## 使用

在 Codex / Claude Code / 支持Skills的各类Harness 中使用 `$skill-name` 调用，并提供输入、目标和期望结果：

```text
使用 $attack-analysis 以 quick-report 模式分析 /path/to/logs。
使用 $wire-toutetu 分析 /path/to/capture.pcapng，并还原完整事件链。
使用 $writing-helper 把下面的文字改得自然、克制，同时保留原意。
```

需要外部工具的 Skill 会先执行环境检查，再根据任务进入对应工作流。

## Skill 说明

⚠️**注意：由于很多Skills有工具依赖，在离线使用前，建议先在线测试一遍，安装好需要的环境（所有的Skill均可自动帮你装环境，部分Skill有环境降级功能）**

### android-malware-analysis

- **简介：** 主要用于分析各种APK（包含但不限于zhapian、dubo、luoliao等黑灰产APP），基本能够满足工作要求

- **用法：** 提供 APK、APKS、XAPK、ZIP 或已解包目录，并选择 `evidence`（固证）或 `reverse`（逆向）模式。
- **优点：** 分离固证与逆向目标；覆盖资源、Java/Smali、隐藏载荷和 Native/SO；结论带证据 ID、来源、位置与状态，便于复核。

### attack-analysis

- **简介：** 面向服务器日志的攻击分析Skill，常用于溯源

- **用法：** 提供单个日志、多个日志或日志目录，选择 `quick-report`（快速报告）或 `interactive`（逐步确认）模式。
- **优点：** 支持常见 Web、应用、SQL 和登录操作日志；先提取紧凑事件再由 AI 还原攻击链，适合处理大体量混合日志。

### linux-loader

- **简介：** 目前个人使用的最多的，也是面向在线AI和本地AI都可很好使用（准确地说均测试过多次）的SKill，主要是分析Linux镜像的

- **用法：** 提供 raw/dd/img 或 E01 镜像、Hash 策略，并选择 `mount-only`、`fast-path` 或 `mount-and-analyze`。
- **优点：** 优先保持证据只读；支持 Linux/WSL；可按目标路由到 Docker、面板、网站、数据库和日志恢复。

### windows-loader

- **简介：** 主要面向本地AI使用的Windows取证Skill，有效减少了小模型AI瞎grep的毛病，在线AI也能省省Token

- **用法：** 提供 Windows 客体镜像、当前终端、Hash 策略和工作模式，支持 raw/dd/img、E01、VHD 与 VHDX。
- **优点：** 为 Windows、Linux、WSL 分别选择安全路线；采用两阶段有界搜索；自动保存命令、挂载、发现与清理状态。

### utm-forensic-cli

- **为什么会出现：** 用Mac取证很奇怪对吧，但是就是有的时候，只带了一个Mac出差，半路突然来个任务，做服务器取证，远程家里的Windows还坏了，这种极端情况下，Mac也不是不能用（滑稽）
- **注意：** 需要自带UTM虚拟机环境

- **用法：** 在 macOS 上提供证据路径、案例输出目录和 UTM VM，选择 `preflight`、`quick-report` 或 `interactive`。
- **优点：** 将 Sleuth Kit、libewf 和 YARA 隔离在 UTM Linux VM；分离原始证据、输出与 VM 写层；完整记录命令和工具版本。

### wire-toutetu

- **简介：** 针对本地AI进行优化的流量分析Skill，当然在线API能用，只不过得手动多让他分析一下，默认只会给你最小化分析，比如只看个协议啥的

- **用法：** 提供 PCAP、PCAPNG、CAP 或已有案例目录，可指定分析问题，也可要求还原完整事件链。
- **优点：** 默认离线并保留输入 Hash；支持协议重组、对象恢复、分层解码和多类 WebShell/隧道流量；对本地小模型采用按信号加载与分页证据查询。

### writing-helper

- **用法：** 提供原文和使用场景，可执行起草、降压改写、文风诊断或样本校准。
- **优点：** 删除重复总结、抽象包装和过度修辞，同时保留事实、立场、限定条件、领域术语与作者个性。
- **补充：** 本人平时发癫写二创文的时候偶然诞生的，配合Gemini写日式轻小说形式的有奇效

### osint-skill（测试中）

- **用法：** 提供议题、时间范围、地区、语言和输出形式，用于舆情搜集、信源核验、时间线或中文简报。
- **优点：** 保留来源与采集时间，交叉核验重要说法，并区分事实、主张、情绪信号、传播影响和待确认缺口。

## 参考文献

- [好SKill的五个共性](https://mp.weixin.qq.com/s/BDPTsJy1GZL4PgSx9L4ykw)
- 安恒“恒脑”（思维链参考）
- 很多很碎的东西，会慢慢补充
