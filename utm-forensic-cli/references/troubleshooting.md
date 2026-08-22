# 故障路由与停止条件

先保存错误输出和环境状态，再选择分支。不要通过无限重试、关闭校验或改成可写挂载来“修复”取证流程。

## UTM CLI 无输出或超时

症状：`utmctl list/status/version` 没有输出，或长时间不返回。

处理：

1. 给每个 `utmctl` 调用设置有限超时；
2. 检查 `/Applications/UTM.app`、UTM GUI 状态和 VM 标识；
3. 用 `utmctl --help` / `utmctl help <subcommand>` 确认 CLI 版本；
4. 请用户提供完整 VM 名称或 UUID；
5. 若仍无法得到可审计状态，停在 `preflight`，不要启动未知 VM。

## guest agent 不可用

症状：`utmctl exec`/`file push` 返回 guest agent 未连接或超时。

处理：

- 确认 VM 已完成启动，而不是仅 UTM 显示“running”；
- 用 UTM VM 内已安装的 guest agent/virtio-serial 配置检查；
- 若用户已配置 SSH，切换到 SSH，并执行 `BatchMode` 健康检查；
- 不在没有授权的情况下开启新的网络接口或暴露 SSH；
- guest agent 和 SSH 都不可用时，停止在 `start-vm`，不要假设命令已经在 guest 执行。

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
