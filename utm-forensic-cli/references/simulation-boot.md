# 检材仿真引导（Evidence Simulation Boot）

以扣押镜像本身为磁盘，在 UTM 中启动被查封的操作系统（"仿真环境取证"）。本流程只在用户明确要求时使用，且必须先通过全部安全门。

适用场景：需要观察系统开机自启行为、登录后的桌面/服务状态、应用数据实时形态。不适用：文件级取证（走 TSK 通道更精确）。

## 安全门（全部满足才允许启动）

1. **内核级写保护**：`chflags uchg <IMAGE>`，并用一次失败的 `touch` 验证 EPERM。记录前后 `stat -f "flags=%Sf"` 到 manifest。该操作只改 inode 标志（ctime 变化），不改内容；可逆（`chflags nouchg`），必须记录。
2. **无网络 VM**：仿真 VM 不得配置任何网卡。被查封系统可能存在开机外联、远程wipe、C2 回连行为。q35/x86_64 下网卡由配置显式添加，默认模板会带 e1000 共享网卡——必须显式清空（见下文）。
3. **差异层隔离**：QEMU 不直接接触证据文件。唯一通道是回环 NBD；所有写入落在案件输出目录的差异文件。
4. **双通道并行**：仿真引导前，宿主机 TSK 通道（mmls/fsstat/fls）应已完成基础鉴定，保证仿真失败时调查不中断。

## 架构

```
UTM「检材仿真」 VM（x86_64 q35 / BIOS / VGA / 无网卡）
     │ 磁盘 = -drive file=nbd:127.0.0.1:10809,format=raw（经 qemu additional arguments 注入）
     ▼
nbd_evidence_server.py（宿主机，非沙盒进程）
   读 → <evidence>（O_RDONLY 打开，无任何写路径）
   写 → <case-output>/extracted/nbd-diff.bin（稀疏差异）+ .bitmap（4KiB 位图）
```

为什么必须走 NBD：App Store 版 UTM 是沙盒应用（entitlements 含
`com.apple.security.app-sandbox`），其 QEMU 子进程打开容器外文件会被拒
（`Operation not permitted`）。安全书签只能由 GUI 打开面板创建；
AppleScript `source` 只注册 bundle 内文件名，`qemu additional arguments`
的 `file urls` 也不给 qcow2 backing file 授权。TCP 回环是 QEMU 在沙盒内
合法可用的通道（`network.client` entitlement）。

## 步骤

### 1. 写保护证据

```bash
stat -f "mode=%Sp flags=%Sf size=%z mtime=%Sm" "$IMAGE"   # 记录前状态
chflags uchg "$IMAGE"
touch "$IMAGE" 2>&1 | head -1                              # 应报 Operation not permitted
```

### 2. 启动 NBD 服务器并自测

```bash
cd "$CASE_OUTPUT"
nohup python3 <skill>/scripts/nbd_evidence_server.py \
  "$IMAGE" extracted/nbd-diff.bin extracted/nbd-diff.bitmap 10809 \
  > logs/nbd-server.log 2>&1 &
sleep 2
python3 <skill>/scripts/nbd_selftest.py 10809    # 必须输出 SELF-TEST PASS
```

**禁止跳过自测**：NBD 线格式错误（见下"协议要点"）会让 QEMU 与服务器
互相等待、VM 卡在 starting，一轮 TCG 引导浪费 5-15 分钟。自测只需几秒。

### 3. 创建专用 VM（不复用分析 VM）

用 AppleScript `make` 建最小 VM，再增量 `update configuration`。**记录键名
不能加引号**（`cpu cores`、`serial ports` 等是字典术语，加引号变成字符串
字面量导致 -1700 强制转换失败）：

```bash
# 最小记录可创建成功；随后增量更新
osascript -e 'tell application id "com.utmapp.UTM" to make new virtual machine \
  with properties {backend:QEMU, configuration:{name:"<案件>-检材仿真", architecture:"x86_64"}}'

# 系统规格 + 移除默认网卡（安全门 2）+ 显示
osascript -e 'tell application id "com.utmapp.UTM" to update configuration of virtual machine "<名>" \
  with {name:"<名>", architecture:"x86_64", machine:"q35", memory:4096, cpu cores:4, \
        hypervisor:false, uefi:false, network interfaces:{}, displays:{{hardware:"VGA"}}}'

# 磁盘走 NBD（清空文件驱动器 + 注入 QEMU 参数，每个参数是独立记录）
osascript -e 'tell application id "com.utmapp.UTM" to update configuration of virtual machine "<名>" \
  with {name:"<名>", architecture:"x86_64", drives:{}, qemu additional arguments: \
    {{argument string:"-drive"}, \
     {argument string:"if=none,id=evid0,media=disk,file=nbd:127.0.0.1:10809,format=raw"}, \
     {argument string:"-device"}, \
     {argument string:"ide-hd,drive=evid0"}}}'
```

要点：

- `uefi:false`（BIOS/SeaBIOS）对 MBR+GRUB 的 Linux 检材兼容性最好；UEFI
  检材才设 true（boot 顺序在 EFI 变量里，脚本不可控，需要 GUI）。
- `drives:{}` 清空文件驱动器；`network interfaces:{}` 清空网卡。
- 2019 年前后的系统用 `VGA` 显示（virtio-gpu 需客户机驱动）。
- 磁盘接口 `ide-hd` 最通用（virtio 需 initramfs 驱动，检材系统未必有）。
- `update configuration` 要求 VM 处于 stopped 状态。

### 4. 启动并观察（无屏幕权限时）

```bash
osascript -e 'with timeout of 600 seconds
tell application id "com.utmapp.UTM" to start virtual machine "<名>"
end timeout'
```

- AppleEvent `-1712` 超时是良性的（启动本身进行中），以 `get status` 为准。
- 观察信号（无 Screen Recording 权限时）：
  - `tail logs/nbd-server.log`：`transmission phase start` 后的连接与 `bitmap saved (N dirty blocks)`；
  - 脏块数持续增长 = 客户机在写（journal 回放/系统写入）= 引导在推进；
  - `ps -o %cpu,time -p $(pgrep QEMULauncher | head -1)`：CPU 活跃 = 模拟运行中；
  - 证据 `stat` 的 mtime/size 不变 + 事后 SHA-256 复验。
- TCG（无 Hypervisor）下 x86_64 引导需 5-15 分钟，VM 无故自停也可能发生
  （尤其旧 Ubuntu），重试一次并记录。

### 5. 交互

用户在 UTM 窗口直接操作仿真系统（需要原系统口令；绕过登录的任何操作
只影响差异层，但必须记录在 manifest 的 decisions 里）。Agent 侧如需
guest 内命令通道：串口 TCP（`serial ports:{{interface:tcp, port:N}}`，
注意该记录在部分版本触发 -1700，失败时改手工编辑 plist 的
`Serial` 数组）、或经用户授权后添加隔离网卡 + SSH。

## 重置与收尾

- **重置仿真**：停 VM → 清空 `nbd-diff.bin` 与 `.bitmap` → 重启 VM 即回到
  扣押时状态（journal 会再次回放到新差异层）。
- **收尾**：`stop` VM → kill NBD 服务器进程 → `chflags nouchg` 前先完成
  最终 SHA-256 复验并落盘。
- 仿真 VM 属于案件工件，不用 `delete` 清理；其 config.plist 与 NBD 脚本
  调用参数写入 manifest。

## 协议要点（NBD 实现者必读）

实战中出现过并已修复的线格式错误：

1. 服务器握手标志是 **u16**，客户端标志是 **u32**（不对称；错成两个 u32
   或两个 u16 都会造成双方互等的死锁）。
2. 客户端每个 option 帧带 **8 字节 IHAVEOPT magic** + u32 option + u32
   长度：16 字节头按 `>QII` 解。
3. `NBD_REP_INFO` 的 export 载荷是 `>HQH`（u16 类型/u64 大小/u16 传输
   标志）；回复头 20 字节按 `>QIII`。
4. QEMU 先探测现代 option（structured reply 等），服务器回 `ERR_UNSUP`
   即可，QEMU 会回退 `EXPORT_NAME`；实现 `OPT_GO` 则更快。
5. 传输阶段请求头 28 字节 `>IHHQQI`；WRITE 的数据紧随请求头之后。

## 失败速查

| 症状 | 原因 | 处置 |
|---|---|---|
| `Could not open backing file ... Operation not permitted` | App Store 沙盒阻止 QEMU 读容器外 backing | 放弃 overlay 方案，走 NBD |
| VM 卡 `starting`，服务器日志停在 `client connected` | NBD 线格式死锁 | 跑 `nbd_selftest.py` 定位，修复后重启服务器与 VM |
| `update configuration` 报 -1700 | 记录键加引号 / 未知的 serial 记录形态 | 键名不加引号；serial 失败可跳过 |
| `start` 报 -609 连接无效 | UTM.app 自行重启过 | 重试前重查 `pgrep UTM` 与 VM 列表 |
| 更新配置报"文件不存在" | 之前 `source` 注册了 `ImageName` 但文件没进 bundle | 把镜像文件复制进 `<vm>.utm/Data/<ImageName>` |
