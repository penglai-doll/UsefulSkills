---
name: utm-forensic-cli
description: Use when an agent must perform read-only disk-image forensics on macOS by controlling an isolated UTM Linux VM through utmctl, the UTM guest agent, or SSH and using Sleuth Kit/libewf/YARA; not for general VM administration, write mounts, or executing recovered samples.
---

# UTM Forensic CLI v1.0.0

在 macOS 上把 Agent 当作取证编排器：宿主机负责案例目录、证据登记、UTM 生命周期和结果收集；专用 UTM Linux VM 负责 E01/raw 暴露、只读挂载和 Linux 取证工具。默认不用 GUI，也不把整棵证据目录倾倒进上下文。

## Start

首次进入本 skill 时，若用户尚未明确，先让用户选择一个且只能一个模式：

- `preflight`：只检查宿主机、UTM、证据可读性和工具能力；不启动 VM、不挂载证据。
- `quick-report`：启动一次隔离的取证 VM，做有边界的分区、文件系统、关键路径和时间线基线，生成证据可追溯的 Markdown 报告。
- `interactive`：每个分析分支逐步确认，适合不确定目标、超大镜像、定向恢复、YARA 扫描或需要用户决定下一条查询的案件。

同时确认或从用户上下文中解析：

1. 证据路径（E01/Ex01、raw/dd/img 或其他镜像）和是否存在分段文件。
2. 案件输出目录；必须在证据目录之外，优先使用绝对路径。
3. UTM VM 的完整名称或 UUID；不能凭空猜测。用 `utmctl list` 或用户提供的 UUID 解析。
4. 宿主机到 VM 的传输方式：优先可证明只读的共享目录；其次 UTM guest agent；再其次已配置 SSH。不要同时盲试多个传输通道。
5. Hash 策略：默认建议 `sha256`，但在正式读取大镜像前遵循用户选择 `now`、`later` 或 `skip`，并写入 manifest。

若用户已给出这些信息，不重复询问；直接执行 preflight。不要因为缺少工具而自行安装，先列出缺失项并请求安装许可。

## Core contract

- **证据只读**：原始 E01/分段/raw 永不写入；不执行 `fsck`、`ntfsfix`、自动修复、LVM 激活、LUKS 解锁、RAID 组装或任何 `rw` 挂载。
- **证据与输出分离**：所有日志、索引、提取文件和报告写到案例输出目录；不得在证据所在目录创建临时文件。
- **UTM 是执行面**：默认由 Agent 在 macOS 上调用 `utmctl`，不点击 UTM GUI。优先使用 `--disposable` 启动干净 VM，除非用户要求保留 VM 状态。
- **命令可审计**：记录宿主机/VM 命令、UTC 时间、退出码、工具版本、VM 标识、输入路径和输出 artifact 路径；命令输出保存到文件，只把摘要送入上下文。
- **不执行恢复文件**：对提取的脚本、二进制、宏、服务或容器只做静态检查；不要 `bash`、`python`、`chmod +x`、启动服务或访问可疑网络。
- **事实分层**：报告分开 `confirmed`、`derived`、`candidate`、`pending`；文件名、时间戳、字符串或单个 IOC 不能单独升级为入侵结论。
- **最小上下文**：禁止把完整 `fls -r`、完整日志、全盘字符串或大文件内容直接回传模型；先落盘，再使用 `head`、`rg`、字段过滤、哈希和定向 `icat`。
- **停止条件**：遇到缺失工具、无法证明只读、Hash 不一致、VM/guest agent 不可信、挂载需要修复或输出空间不足时停止该分支，报告阻塞原因，不绕过检查。

## Workflow

按以下状态机执行，除非当前模式明确跳过某个状态：

```text
preflight
  -> case-init
  -> hash-and-integrity
  -> choose-transport
  -> start-vm
  -> stage-evidence
  -> expose-ewf
  -> enumerate-partitions
  -> identify-filesystem
  -> bounded-triage
  -> targeted-extraction
  -> review-and-report
  -> unmount-and-teardown
```

详细命令、输出结构和故障路由见：

- [references/workflow.md](references/workflow.md)：端到端流程和 UTM CLI/guest agent/SSH 分支。
- [references/command-matrix.md](references/command-matrix.md)：宿主机与 VM 命令、适用条件和结果保存规则。
- [references/report-schema.md](references/report-schema.md)：manifest、artifact、finding 和报告字段。
- [references/troubleshooting.md](references/troubleshooting.md)：UTM、guest agent、SSH、FUSE、分区和只读挂载故障。

## Preflight

先运行本 skill 自带的确定性检查器；它只读取元数据、工具帮助和可选的镜像摘要，不负责替代取证判断：

```bash
python3 scripts/forensicctl.py preflight <evidence> \
  --hash sha256 \
  --inspect-image \
  --output-dir /absolute/case-output \
  --json
```

检查结果至少应包括：

- 证据绝对路径、大小、权限、`file` 类型和可读性。
- `utmctl`、`img_stat`、`mmls`、`fsstat`、`fls`、`istat`、`icat`、`tsk_recover`、`ewfinfo`、`ewfverify`、`ewfmount`、`ssh`、`scp`、哈希工具的存在性和版本尝试结果。
- `utmctl --help` 中是否具备 `list/status/start/stop/exec/file`；`utmctl list/status` 使用超时，避免 UTM GUI/服务未就绪时卡死 Agent。
- 若开启 `--inspect-image`，保存 `img_stat`、`mmls` 的原始输出到案例目录，模型只读取截断摘要。

`img_stat`/`mmls` 在宿主机能直接读取 E01 时可以作为交叉验证，但 UTM-first 的完整流程仍需在 VM 内执行或验证同一套结果。E01 的 `ewfverify` 完整性检查与 SHA-256 是两件事，不能互相替代。

## UTM control

不要假设 UTM 版本的参数。先查看本机帮助，再执行实际命令：

```bash
utmctl --help
utmctl help start
utmctl help exec
utmctl help file push
utmctl help file pull
```

典型生命周期如下，`<VM>` 必须是完整名称或 UUID：

```bash
utmctl list
utmctl status --hide <VM>
utmctl start --hide --disposable <VM>
# 等待 guest agent 或 SSH 健康检查成功后再继续
utmctl exec --hide <VM> --cmd sh -lc 'id; uname -a'
utmctl stop --hide --request <VM>
```

- guest agent 可用时，优先 `utmctl exec` 执行短命令，`utmctl file push/pull` 传输小型脚本和结果。
- 大型 E01 不要默认通过 `file push` 复制；优先已验证的只读共享目录。若只能复制，复制后在宿主机和 VM 内分别计算 Hash，并把两者写入 manifest。
- guest agent 不可用时才切到已配置的 SSH；使用现有 `known_hosts` 和密钥，不关闭主机密钥校验，不把密码写进命令行。
- `utmctl stop --request` 是正常收尾；只有 VM 卡死且用户允许时才使用 `--force`/`--kill`。永远不要用 `utmctl delete` 清理案件 VM。
- 如果 VM 是用于单次案件的干净模板，优先 `--disposable`；如果需要在 VM 内保留工具缓存或用户明确要保留状态，再使用普通 `start` 并记录原因。

## Evidence access and EWF

### Host staging

1. 创建案例输出目录和 `manifest.json`，不要在证据目录写入任何文件。
2. 对 E01 分段使用 `ewfverify`；对原始镜像先记录用户选择的 Hash。多段 EWF 必须把所有段作为一个证据链处理。
3. 选择一种传输方式并验证只读：
   - 只读共享目录：在 VM 内确认挂载选项和权限，必要时在 guest 侧 `mount -o remount,ro`，不能只相信 UTM UI 标签。
   - guest agent/SSH 复制：复制到 VM 临时 staging，校验 Hash 后设置不可写权限；分析输出写到另一个目录。
4. 在 VM 内生成 guest-side evidence manifest，至少记录 guest path、大小、Hash、`file` 输出和传输方式。

### Guest EWF exposure

在 VM 内保存每一步原始输出：

```bash
mkdir -p /mnt/ewf /mnt/case/raw /mnt/case/extracted
file /evidence/case.E01
ewfinfo /evidence/case.E01 > /mnt/case/raw/ewfinfo.txt
ewfverify /evidence/case.E01 > /mnt/case/raw/ewfverify.txt
ewfmount /evidence/case.E01 /mnt/ewf
find /mnt/ewf -maxdepth 1 -type f -name 'ewf*' -print
```

找到实际 raw 暴露路径后：

```bash
mmls /mnt/ewf/ewf1 > /mnt/case/raw/mmls.txt
```

从 `mmls` 输出读取分区的 `Start` sector 和 `Units are in ... sectors`，不要把 `2048` 或 `512` 当成固定值。没有可靠分区起点时，不得继续 `fsstat` 或 mount。

TSK 能否直接读取 E01 取决于本机编译是否带 libewf；以 `img_stat` 成功和输出内容为准，不要仅凭文件后缀判断。VM 内的 EWF 暴露失败时，按 [troubleshooting.md](references/troubleshooting.md) 选择 FUSE 修复或用户批准的 raw 导出回退，不自动安装或改系统。

## Read-only filesystem analysis

优先使用 TSK 对 raw/E01 做文件系统取证，不必为了 `fls`/`icat` 先 mount：

```bash
fsstat -o <START_SECTOR> /mnt/ewf/ewf1 > /mnt/case/raw/fsstat-<START_SECTOR>.txt
fls -o <START_SECTOR> -p /mnt/ewf/ewf1 > /mnt/case/raw/fls-root.txt
fls -r -o <START_SECTOR> -p /mnt/ewf/ewf1 > /mnt/case/raw/fls-recursive.txt
```

`fls -r` 输出必须落盘；后续只读取定向筛选：

```bash
rg -i -n '(/etc/|\.ssh/|authorized_keys|cron|systemd|bash_history|var/log|Downloads)' \
  /mnt/case/raw/fls-recursive.txt > /mnt/case/raw/fls-interesting.txt
```

针对已确认的 metadata/inode 使用：

```bash
istat -o <START_SECTOR> /mnt/ewf/ewf1 <META_ADDR> > /mnt/case/raw/istat-<META_ADDR>.txt
icat -o <START_SECTOR> /mnt/ewf/ewf1 <META_ADDR> > /mnt/case/extracted/<safe-name>
sha256sum /mnt/case/extracted/<safe-name> >> /mnt/case/raw/extracted-sha256.txt
```

`tsk_recover` 只在用户明确要求恢复、输出空间已估算且目标分区已确认时执行；默认优先用 `icat` 定向提取。若用户提供 YARA 规则，可在 VM 内对提取目录或明确的只读挂载路径运行 `yara -r`，同时记录 YARA 版本、规则文件 Hash、扫描范围和原始结果。不得从网络自动下载规则，不得因命中就执行样本。

只有用户明确需要正常目录树、应用配置或日志内容时才做文件系统 mount。按文件系统选择只读选项；对 ext4/类 Unix 文件系统优先 `ro,noload`，并用 `findmnt` 验证结果。不要把 `mount` 成功当作证据完整性证明。

## Triage and review

`quick-report` 只做边界明确的基线：分区、文件系统、系统标识、用户目录、SSH key、cron/systemd、日志目录、下载目录、最近/异常时间线候选和定向 Hash。不要自动把全盘所有文件内容送进模型。

`interactive` 每次扩大范围前说明：

- 目标路径或 metadata/inode。
- 为什么选择该路径。
- 将生成哪些 artifact。
- 预计读取量和是否需要提取。

对每个可报告结论，保存 `evidence_id`、来源 artifact、路径或 metadata、命令、Hash/时间、状态和局限。疑似恶意文件只做 `file`、`strings`、Hash、格式/元数据和代码/配置静态审查；动态执行另行进入专门沙箱，不在此 skill 内完成。

## Teardown

收尾顺序：

1. 保存并校验 manifest、命令日志、Hash、报告和失败信息。
2. 若有 mount，记录 `findmnt` 后卸载；若有 FUSE，使用对应的 `fusermount -u`，不要强杀仍在读取证据的进程。
3. 关闭 guest 内 staging 访问；不删除原始证据。临时 staging 是否清理要记录路径和动作。
4. `utmctl stop --request`；若使用 disposable VM，记录其丢弃的是 VM 写层而非证据。
5. 最后运行输出目录自检，确认报告引用的 artifact 都存在，且没有把全量日志/秘密复制到模型回复中。

## Resources

- `scripts/forensicctl.py`：宿主机 preflight 与只读执行计划生成器；运行 `python3 scripts/forensicctl.py --help`。
- [references/workflow.md](references/workflow.md)：完整状态机和 guest-agent/SSH/共享目录路径。
- [references/command-matrix.md](references/command-matrix.md)：命令和输出落盘矩阵。
- [references/report-schema.md](references/report-schema.md)：案例 manifest、artifact 和 finding 结构。
- [references/troubleshooting.md](references/troubleshooting.md)：故障分支和停止条件。
