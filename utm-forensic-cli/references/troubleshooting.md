# 故障路由与停止条件

先保存错误输出和环境状态，再选择分支。不要通过无限重试、关闭校验或改成可写挂载来”修复”取证流程。

## utmctl 被 TCC 拒绝（v1.1.0）

症状：`utmctl` 任何子命令输出 `OSStatus error -1743`；`utmctl list` 仍
打印空表头，易误判为”没有 VM”；`utmctl status` 报 “Virtual machine not
found”。

处理：

1. 用 `osascript -e 'tell application id “com.utmapp.UTM” to get version'`
   验证 AppleScript 通道是否可用（同一 shell 内通常仍被允许）；
2. 可用则整体切换到 AppleScript 等价命令（command-matrix 有完整表），
   不再混用两条通道；
3. 两者都不可用且案件必须 GUI 控制时，请求用户在”系统设置 → 隐私与安全
   性 → 自动化/屏幕录制”授权，不要代替用户点击授权对话框。

## UTM 沙盒阻止 QEMU 读取证据（v1.1.0）

症状：VM 启动即退出，QEMU 错误含 `Could not open ... Operation not
permitted`，路径指向 `~/Library/Containers/com.utmapp.UTM` 之外的文件
（直接挂载的证据、qcow2 的 backing file）。

根因：App Store 版 UTM 带 app-sandbox entitlement；安全书签只能由 GUI
打开面板创建。AppleScript `source` 只注册 bundle 内文件名，
`qemu additional arguments` 的 `file urls` 不为 backing file 授权。

处理：改走回环 NBD（`nbd_evidence_server.py`），QEMU 以 TCP 连接取盘，
沙盒不拦截；证据由服务器以 O_RDONLY 供出。见 simulation-boot.md。

## NBD 服务器与 QEMU 互相等待（v1.1.0）

症状：VM 长时间 `starting`，服务器日志停在 `client connected`，QEMU CPU
接近 0。

根因：线格式错误造成双端阻塞。三个高频点：服务器握手标志是 u16 而客户端
标志是 u32（不对称）；客户端 option 帧带 8 字节 IHAVEOPT magic（16 字节
头按 `>QII` 解）；`NBD_REP_INFO` 载荷 `>HQH`、回复头 20 字节 `>QIII`。

处理：停 VM → 修服务器 → `nbd_selftest.py` 通过后再启动 VM。自测不过
绝不起 VM。

## AppleScript 配置记录失败（v1.1.0）

- `-1700 不能转换为 qemu configuration`：多词键（`cpu cores` 等）被加了
  引号，或记录形状不被接受（如部分版本的 serial 记录）。去掉引号；serial
  可跳过。
- update 报”文件不存在”：此前 `source` 注册的 `ImageName` 对应文件不在
  `<vm>.utm/Data/`，手工复制进去即可。
- `start` 报 `-609 连接无效`：UTM.app 自行重启过，重查进程与 VM 列表。
- `start` 报 `-1712 AppleEvent已超时`：良性，用 `get status` 确认真实
  状态。

## 宿主机无法挂载 ext4 镜像（v1.1.0）

症状：`hdiutil attach` 报”无法识别映像”或”无可装载的文件系统”。

根因：macOS 原生不支持 ext4；裸 MBR 镜像还需 `-imagekey
diskimage-class=CRawDiskImage` 才能附加为设备，但依然无可挂载文件系统。

处理：ext4 浏览走 VM/仿真通道或 TSK；确需宿主机挂载时经用户许可安装
FUSE-T + ext4fuse（注意 ext4fuse 已被 Homebrew 标记废弃）。

## guest agent 不可用

症状：`utmctl exec`/`file push` 返回 guest agent 未连接或超时；AppleScript
`query ip` 报”客户机代理没有运行或未安装”。

处理：

- 确认 VM 已完成启动，而不是仅 UTM 显示”running”；TCG（Hypervisor=false）
  下 x86_64 引导需 5-15 分钟，且 VM 可能无故自停（重试一次并记录）；
- 原生 Ubuntu 默认不含 UTM guest agent（utmagent），等待不会使其出现；
  长轮询前先与用户确认该 VM 是否安装过 guest 工具；
- 若用户已配置 SSH，切换到 SSH，并执行 `BatchMode` 健康检查；
- 不在没有授权的情况下开启新的网络接口或暴露 SSH；
- guest agent 和 SSH 都不可用时，停止在 `start-vm`，不要假设命令已经在
  guest 执行；需要 guest 内通道的仿真场景见 simulation-boot.md 的串口/
  网络选项。

## UTM CLI 无输出或超时

症状：`utmctl list/status/version` 没有输出，或长时间不返回。

处理：

1. 给每个 `utmctl` 调用设置有限超时；
2. 检查 `/Applications/UTM.app`、UTM GUI 状态和 VM 标识；
3. 用 `utmctl --help` / `utmctl help <subcommand>` 确认 CLI 版本；
4. 请用户提供完整 VM 名称或 UUID；
5. 若仍无法得到可审计状态，停在 `preflight`，不要启动未知 VM。

## EWF 验证失败

处理：

- 保存 `ewfinfo` 和 `ewfverify` 完整输出；
- 检查段文件是否齐全、名称和顺序是否被改变；
- 与用户确认是否有原始采集记录或已知损坏；
- 不改写 E01，不重建索引，不用“忽略校验”继续输出确定性结论。

## `ewfmount`/FUSE 失败

常见原因：FUSE 未安装、权限不足、挂载点非空、EWF 路径错误或 guest 没有完整 libewf。

处理：

1. 记录 `ewfmount` 版本、错误和 `mount`/FUSE 状态；
2. 确认挂载点为空且不在证据目录；
3. 检查是否存在 `/dev/fuse`、`fusermount`/`fusermount3` 和当前用户权限；
4. 若需要安装工具或修改系统，先请求许可；
5. 用户批准后才考虑 `ewfexport` raw 回退，并先估计空间和时间；
6. FUSE 和 raw 回退都不可用时停止，不用字节偏移猜测文件系统。

## `mmls` 有输出但 `fsstat` 失败

检查：

- 使用的是 `mmls` 的 `Start` sector，不是 byte offset；
- `-o` 的单位与 TSK 期望一致；
- raw 路径确实是 `ewfmount` 暴露的设备文件；
- 是否误选了 unallocated、EFI、swap 或恢复分区；
- 是否需要对 LVM/LUKS 进行人工分析。

不要自动激活 LVM、解密 LUKS 或组装 RAID；这些是单独的用户授权分支。

## 只读 mount 失败或出现写入迹象

- 优先回到不需要 mount 的 `fsstat/fls/istat/icat` 路径；
- 不把 `rw` 作为回退；
- 对 ext4 类文件系统尝试支持的 `ro,noload`，并用 `findmnt` 验证；
- driver 会 journal replay、自动恢复或改变状态时停止；
- 记录失败，不把“无法 mount”写成“证据损坏”。

## Hash 不一致

立即停止分析该副本。保存：

- host 原始 Hash；
- guest copy Hash；
- 文件大小和传输命令；
- 段文件列表；
- 时间和错误输出。

不要用压缩、重新拼接或重新导出覆盖原副本来“解决”不一致。

## 输出空间不足或命令过大

- 终止全量恢复/全量字符串/无界递归命令；
- 先计算预计大小，增加案例输出目录或缩小目标；
- 使用 artifact 文件、字段筛选和 `--summary-limit`；
- 不把输出写回证据目录。

## 可疑文件误执行风险

如果发现命令即将运行从证据提取的脚本/二进制：立即停止该命令，改为 `file`、Hash、`strings`、静态反编译或在另一个明确隔离的动态分析流程中处理。`utm-forensic-cli` 只负责静态取证和证据编排。
