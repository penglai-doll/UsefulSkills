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
| VM 状态 | `utmctl status --hide <VM>`，带超时 | `raw/vm-status.txt` |

不要把 `utmctl list` 或 `status` 作为无超时的阻塞命令；UTM.app/后台服务未就绪时可能无输出或卡住。

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
