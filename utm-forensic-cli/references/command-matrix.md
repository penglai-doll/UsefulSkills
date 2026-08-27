# 命令矩阵

原则：每条命令都要有执行面、输入、目的、artifact 路径、退出码和超时。下面的 `<...>` 是案件运行时变量，不是可直接复制的证据路径。

## Host preflight

| 目的 | 命令 | 结果 |
|---|---|---|
| 类型/权限 | `file <IMAGE>; stat <IMAGE>` | `raw/preflight.json` |
| EWF 信息 | `ewfinfo <IMAGE>` | `raw/host-ewfinfo.txt` |
| EWF 完整性 | `ewfverify <IMAGE>` | `raw/host-ewfverify.txt` |
| 宿主机 TSK 交叉验证 | `img_stat <IMAGE>; mmls <IMAGE>` | `raw/host-img-stat.txt`, `raw/host-mmls.txt` |
| Hash | `shasum -a 256 <IMAGE>` | `raw/host-sha256.txt` |
| UTM 能力 | `utmctl --help; utmctl help <subcommand>` | `raw/utm-help.txt` |
| TCC 探测 | `utmctl list 2>&1 \| grep -c "OSStatus error -1743"` | 非 0 即 `tcc_blocked` |
| VM 状态 | `utmctl status --hide <VM>`，带超时 | `raw/vm-status.txt` |

不要把 `utmctl list` 或 `status` 作为无超时的阻塞命令；UTM.app/后台服务未就绪时可能无输出或卡住。

## AppleScript transport（utmctl 被 TCC 拒绝时，v1.1.0 实战验证）

前置探测：`osascript -e 'tell application id "com.utmapp.UTM" to get version'`。

| 目的 | 命令形状 | 规则 |
|---|---|---|
| 列出 VM | `osascript -e 'tell application id "com.utmapp.UTM" to get name of every virtual machine'` | 完整名称从这里取 |
| 状态 | `... to get status of virtual machine "<VM>"` | stopped/starting/started |
| 启动 | `osascript -e 'with timeout of 600 seconds
tell ... to start virtual machine "<VM>"
end timeout'` | `-1712` 超时良性，以 status 为准 |
| 停止 | `... to stop virtual machine "<VM>"` | 等价 `--request` |
| 查询 IP | `... to query ip of virtual machine "<VM>"` | 需 guest agent |
| guest 执行 | `... to execute virtual machine "<VM>" at "/bin/sh" with arguments {"-c", "..."}` | 需 guest agent；结果对象用 `get result` 读取 |
| 建配置 | `make new virtual machine with properties {backend:QEMU, configuration:{...}}` | 多词键不加引号 |
| 改配置 | `update configuration of virtual machine "<VM>" with {...}` | VM 必须 stopped |
| 推/拉文件 | `push <file> to ... / pull <guest file>` | 需 guest agent，仅小文件 |

AppleScript 配置记录陷阱：`source` 只注册 `ImageName` 不复制文件（需手工
放进 `<vm>.utm/Data/`）；`drives:{}`/`network interfaces:{}` 清空设备；
`qemu additional arguments` 为逐参数记录列表；驱动器记录无 readOnly 属性。

## Simulation boot（检材仿真引导，v1.1.0）

详见 [simulation-boot.md](simulation-boot.md)。命令骨架：

| 步骤 | 命令 | artifact |
|---|---|---|
| 写阻塞 | `chflags uchg <IMAGE>; touch <IMAGE>`（应 EPERM） | manifest 记录前后 stat |
| 起服务器 | `nohup python3 scripts/nbd_evidence_server.py <IMAGE> <diff> <bitmap> <port> &` | `logs/nbd-server.log` |
| 自测 | `python3 scripts/nbd_selftest.py <port>` | 终端输出存 `logs/nbd-selftest.txt` |
| 建 VM | `make ... configuration:{name, architecture}` 再增量 update | `logs/vm-config-backup.plist` |
| 注入磁盘 | `qemu additional arguments:{{argument string:"-drive"}, {argument string:"if=none,id=evid0,media=disk,file=nbd:127.0.0.1:<port>,format=raw"}, {argument string:"-device"}, {argument string:"ide-hd,drive=evid0"}}` | config.plist |
| 观察 | `tail <case>/logs/nbd-server.log; ps -o %cpu,time -p $(pgrep QEMULauncher \| head -1)` | dirty-block 增长 |
| 终验 | `shasum -a 256 <IMAGE>` 与初始值比对 | `raw/evidence-sha256-verify.txt` |

## Guest agent transport

| 目的 | 命令形状 | 规则 |
|---|---|---|
| 启动 | `utmctl start --hide --disposable <VM>` | 先确认 VM 标识和启动模式 |
| 健康检查 | `utmctl exec --hide <VM> --cmd sh -lc '...'` | 短命令、超时、保存 stdout/stderr |
| 上传小文件 | `cat <LOCAL> \| utmctl file push --hide <VM> <GUEST>` | 只用于小文件，Hash/权限另记 |
| 下载结果 | `utmctl file pull --hide <VM> <GUEST> > <LOCAL>` | 不把大结果直接送上下文 |
| 执行 TSK | `utmctl exec --hide <VM> --cmd sh -lc '...'` | 原始 stdout 写 guest artifact 后 pull |
| 正常停止 | `utmctl stop --hide --request <VM>` | 收尾时记录状态 |

`utmctl exec --cmd` 的参数解析随版本变化；实际运行前用 `utmctl help exec`，必要时先执行 `sh -lc 'printf ...'` 探针。

## SSH transport

| 目的 | 命令形状 | 规则 |
|---|---|---|
| 健康检查 | `ssh -o BatchMode=yes <TARGET> 'id; uname -a'` | 使用已有密钥/known_hosts |
| 小文件上传 | `scp <LOCAL> <TARGET>:<GUEST>` | 复制后在两端校验 Hash |
| 远程命令 | `ssh <TARGET> 'sh -lc ...'` | 不拼接未经检查的用户输入 |
| 结果下载 | `scp <TARGET>:<GUEST_ARTIFACT> <LOCAL>` | 保存原始 artifact，不全文回传 |

不使用 `StrictHostKeyChecking=no`、明文密码或把证据路径直接拼入未转义的 shell 字符串。

## Guest EWF/TSK

| 顺序 | 命令 | 保存 |
|---|---|---|
| EWF 元数据 | `ewfinfo <GUEST_EWF>` | `raw/ewfinfo.txt` |
| EWF 验证 | `ewfverify <GUEST_EWF>` | `raw/ewfverify.txt` |
| 暴露 raw | `ewfmount <GUEST_EWF> <EWF_MOUNT>` | `raw/ewfmount.txt`、实际 raw 路径 |
| 分区 | `mmls <RAW>` | `raw/mmls.txt` |
| 文件系统 | `fsstat -o <START> <RAW>` | `raw/fsstat-<START>.txt` |
| 根目录 | `fls -o <START> -p <RAW>` | `raw/fls-root.txt` |
| 全量索引 | `fls -r -o <START> -p <RAW>` | `raw/fls-recursive.txt` |
| 元数据 | `istat -o <START> <RAW> <META>` | `raw/istat-<META>.txt` |
| 文件提取 | `icat -o <START> <RAW> <META> > <OUT>` | `extracted/<safe-name>` + Hash |
| 恢复 | `tsk_recover -o <START> <RAW> <OUTDIR>` | 仅用户明确需要时执行 |
| 规则扫描（可选） | `yara -r <RULES> <EXTRACTED>` | 记录规则 Hash、版本、范围和原始命中 |

`fls -r`、`tsk_recover` 和大文件 `icat` 必须有空间估计、输出目录和超时/停止策略。

## Read-only mount

仅在普通路径访问确有必要时使用：

```bash
mount -o ro,noload,loop,offset=$((<START> * <SECTOR_SIZE>)) <RAW> <MOUNTPOINT>
findmnt -T <MOUNTPOINT> -o TARGET,SOURCE,FSTYPE,OPTIONS
```

选项按文件系统调整。任何 `rw`、自动修复、journal replay、`fsck` 或不明 driver 行为都是停止条件。
