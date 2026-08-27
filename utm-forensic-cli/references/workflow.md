# UTM Forensic CLI 工作流

本参考只在 `utm-forensic-cli` 已通过模式选择后读取。默认采用 UTM-first：macOS Agent 编排，Linux VM 执行；宿主机 TSK 仅用于 preflight 或交叉验证。

## 1. 案例初始化

建议目录：

```text
<case-output>/
├── manifest.json
├── logs/
│   ├── host-commands.jsonl
│   └── guest-commands.jsonl
├── raw/
│   ├── host-img-stat.txt
│   ├── host-mmls.txt
│   ├── ewfinfo.txt
│   ├── ewfverify.txt
│   ├── mmls.txt
│   ├── fsstat-<start>.txt
│   └── fls-*.txt
├── extracted/
├── analysis/
│   ├── inventory.jsonl
│   ├── timeline-candidates.jsonl
│   └── review-notes.md
└── report/
    └── forensic-report.md
```

`<case-output>` 必须与原始证据路径分离。案件 ID 只用于输出和日志，不改名、不移动、不重打包证据。

初始化时记录：

- host 时间和 UTC 时间；
- 证据绝对路径、段文件列表、大小、权限；
- 用户选择的 Hash 策略和结果；
- VM 完整名称/UUID、UTM 版本、启动模式；
- 本地和 VM 内工具版本；
- transport、guest path、挂载路径；
- 每个阶段的开始/结束、退出码、超时或人工决定。

## 2. Preflight 路径

执行：

```bash
python3 scripts/forensicctl.py preflight "$IMAGE" \
  --hash sha256 --inspect-image \
  --output-dir "$CASE_OUTPUT" --json
```

如果宿主机没有工具：

- 先报告缺失命令和替代分支；
- 需要安装时请求用户明确许可；
- 不把“可以安装”写成“已经可用”。

如果 `utmctl list/status` 超时：

- 不重复无限重试；
- 检查 UTM.app 是否正在运行、VM 标识是否完整；
- 可以让用户提供 UUID 或从 UTM GUI 复制名称，但执行仍使用 CLI；
- 把 timeout 写入 preflight，不绕过 VM 状态校验。

## 3. VM 启动与健康检查

先读取当前版本帮助：

```bash
utmctl --help
utmctl help start
utmctl help exec
utmctl help file push
utmctl help file pull
```

启动示例：

```bash
utmctl start --hide --disposable "$VM"
utmctl status --hide "$VM"
```

`--disposable` 只丢弃 VM 写层，不会让宿主机上的 E01 自动变成安全证据；证据完整性仍须独立 Hash/verify。

### utmctl 被 TCC 拒绝时的 AppleScript 分支（v1.1.0）

症状：`utmctl` 输出 `OSStatus error -1743`（可能仍打印空表头，不要据此
判断"无 VM"）。验证与切换：

```bash
utmctl list 2>&1 | grep -q "OSStatus error -1743" && echo TCC-BLOCKED
osascript -e 'tell application id "com.utmapp.UTM" to get version'   # 探测通道
osascript -e 'tell application id "com.utmapp.UTM" to get name of every virtual machine'
osascript -e 'tell application id "com.utmapp.UTM" to get status of virtual machine "'"$VM"'"'
osascript -e 'with timeout of 600 seconds
tell application id "com.utmapp.UTM" to start virtual machine "'"$VM"'"
end timeout'
```

完整等价命令见 [command-matrix.md](command-matrix.md)。事件错误语义：
`-1712` 超时通常良性（以 `get status` 为准）；`-609` 表示 UTM.app 自行
重启过，重查 `pgrep` 与 VM 列表后重试。

### Guest agent 分支

健康检查：

```bash
utmctl exec --hide "$VM" --cmd sh -lc 'printf ready; id; command -v ewfmount mmls fsstat fls icat'
```

传输小文件/配置或结果：

```bash
cat host-script.sh | utmctl file push --hide "$VM" "$GUEST_SCRIPT"
utmctl file pull --hide "$VM" "$GUEST_RESULT" > "$CASE_OUTPUT/analysis/guest-result.json"
```

`file push` 从 stdin 上传，`file pull` 输出到 stdout；不要把大型 E01 作为默认 push 路径。

### SSH 分支

只有 SSH 已配置且用户允许时使用：

```bash
ssh -o BatchMode=yes "$SSH_TARGET" 'id; uname -a'
scp "$SMALL_INPUT" "$SSH_TARGET:$GUEST_PATH"
```

保留现有 `known_hosts`；不要 `StrictHostKeyChecking=no`，不要在命令行、日志或 manifest 中写密码。

## 4. 证据传输与一致性

优先级：

1. VM 内能证明为 read-only 的共享目录；
2. guest agent 或 SSH 复制到 VM staging；
3. 只有用户明确授权时才用其他介质映射。

复制路径示例：

```bash
# host
shasum -a 256 "$IMAGE" > "$CASE_OUTPUT/raw/host-sha256.txt"
scp "$IMAGE" "$SSH_TARGET:/evidence/case.E01"

# guest
sha256sum /evidence/case.E01 > /case/raw/guest-sha256.txt
chmod 0444 /evidence/case.E01
```

对 E01 分段：

- 保持原始段文件名和顺序；
- `ewfverify` 指向第一段或完整 EWF 入口；
- 不把单段 SHA-256 当作整个 EWF 链完整性结论；
- guest copy 的 Hash 与 host 计算结果不一致时停止。

## 5. EWF、分区和文件系统

在 VM 内：

```bash
mkdir -p /mnt/ewf /case/raw /case/extracted
file /evidence/case.E01 > /case/raw/file.txt
ewfinfo /evidence/case.E01 > /case/raw/ewfinfo.txt
ewfverify /evidence/case.E01 > /case/raw/ewfverify.txt
```

验证退出码后才继续：

```bash
ewfmount /evidence/case.E01 /mnt/ewf
RAW=$(find /mnt/ewf -maxdepth 1 -type f -name 'ewf*' -print -quit)
test -n "$RAW"
mmls "$RAW" > /case/raw/mmls.txt
```

从 `mmls` 中记录：

- 分区表类型；
- `Units are in ... sectors`；
- 目标分区的 start/end/length；
- 选择目标分区的理由。

不要把启动分区、恢复分区或 unallocated 行误当作目标文件系统。选定 start 后：

```bash
fsstat -o "$START" "$RAW" > "/case/raw/fsstat-$START.txt"
fls -o "$START" -p "$RAW" > /case/raw/fls-root.txt
```

若 `fsstat` 失败，检查 start 是否为 sector、文件系统类型是否受支持、raw 路径是否正确；不要盲目改 offset。

## 6. Mount 与 TSK 的边界

TSK 的 `fls`、`fsstat`、`istat`、`icat` 不要求先 mount。默认不 mount，优先使用 TSK；这样既能看到取证 metadata，也减少 guest 侧写入风险。

只有需要普通路径访问时才 mount：

```bash
mkdir -p /mnt/evidence
mount -o ro,noload,loop,offset=$((START * SECTOR_SIZE)) "$RAW" /mnt/evidence
findmnt -T /mnt/evidence -o TARGET,SOURCE,FSTYPE,OPTIONS
```

- `noload` 只适用于支持该选项的文件系统；按文件系统调整；
- NTFS 使用 VM 中已安装且明确支持只读的驱动，并验证 options；
- mount/driver 不支持只读时停止，不用 `rw` 作为回退；
- 用 `findmnt`、`mountpoint` 和一个不写入的目录读取验证结果。

## 7. 基线取证

`quick-report` 的默认基线是“少量、可解释、可复核”：

```bash
fls -r -o "$START" -p "$RAW" > /case/raw/fls-recursive.txt
rg -i -n '(/etc/|/var/log/|\.ssh/|authorized_keys|cron|systemd|bash_history|Downloads|tmp)' \
  /case/raw/fls-recursive.txt > /case/raw/fls-interesting.txt
```

对选定项继续：

```bash
istat -o "$START" "$RAW" "$META" > "/case/raw/istat-$META.txt"
icat -o "$START" "$RAW" "$META" > "/case/extracted/$SAFE_NAME"
sha256sum "/case/extracted/$SAFE_NAME" >> /case/raw/extracted-sha256.txt
```

时间线候选使用 TSK 导出的时间字段和明确来源；不要只根据 `mtime` 宣称“攻击时间”。

## 8. 检材仿真引导（simulation-boot，v1.1.0）

用户明确要求"以镜像为基础启动仿真环境"时的并行分支。完整架构、安全门、
AppleScript 模板和 NBD 协议要点见 [simulation-boot.md](simulation-boot.md)。
此处只列流程骨架：

1. **写阻塞**：`chflags uchg "$IMAGE"`，用失败的 `touch` 验证，前后 `stat` 记入 manifest。
2. **宿主机 TSK 基线**（兜底）：mmls/fsstat/fls 先落盘。
3. **NBD 服务器**：`nohup python3 scripts/nbd_evidence_server.py <image> <diff> <bitmap> <port> &`，
   随后 `python3 scripts/nbd_selftest.py <port>` 必须通过再继续。
4. **专用 VM**：AppleScript `make` 最小 VM → 增量 `update configuration`
   （q35/BIOS/VGA/`network interfaces:{}` 清空网卡）→ NBD 磁盘经
   `qemu additional arguments` 注入。
5. **观察**：NBD 日志的 dirty-block 增长、`pgrep QEMULauncher` 的 CPU、
   UTM `get status`；无 Screen Recording 权限时这是唯一的引导活性信号。
6. **交互**：用户在 UTM 窗口操作；Agent 的额外结论一律走 TSK 交叉验证。
7. **收尾**：停 VM → 停服务器 → SHA-256 终验 → （可选）`chflags nouchg`。
   重置仿真 = 清空 diff+bitmap 后重启 VM。

## 9. 收尾

```bash
findmnt -R /mnt/evidence
# 按实际挂载点卸载；FUSE 使用对应 fusermount -u
utmctl stop --hide --request "$VM"
```

如果 guest agent/SSH 命令仍在运行，先等待或记录失败，再停止 VM。停止 VM 前保存结果；不要使用 `utmctl delete`。
