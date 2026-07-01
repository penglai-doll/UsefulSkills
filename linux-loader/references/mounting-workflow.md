# Mounting Workflow

读取时机: 挂载失败、WSL2 loop/FUSE 诊断、E01 降级、LVM/LUKS、文件系统只读参数或验证夹具需要时读取。

## WSL2 Preflight

- 记录 `uname -a`、`/proc/version`、是否 WSL2。
- 自动检查并记录权限状态：root、`sudo` 是否存在、`sudo -n true` 是否可用。
- 权限探测顺序固定为 root -> `sudo -n true` -> 用户选择；不要暴露额外 sudo 模式。
- 没有 root/非交互 sudo 时，将 privileged command 标记为 `blocked=true`，输出 `manual_command` 和 `user_choices`，不要裸跑 `mount`/`losetup`。
- 检查输出目录和挂载根目录绝对路径；挂载根被占用时换到 `/mnt/ev-mount-<case-id>/`。
- E01 路径检查 `ewfinfo`、`ewfmount`、`ewfexport`、`/dev/fuse` 是否存在且当前用户可读写、`fusermount` 或 `fusermount3`。

## Sudo handling

- 脚本先试 root 和 `sudo -n true`。成功时才可自动执行需要权限的只读挂载命令。
- 失败时不要请求密码、不要重试裸命令；JSON 必须包含 `blocked=true`、`manual_command`、`block_reason`。
- 同时给出两个用户选择:
  - `manual_sudo`: 用户复制 `manual_command` 到可信 WSL 终端手动执行。
  - `interactive_sudo`: 用户在可信 WSL 终端运行同一命令并输入 sudo 密码。
- 缺 `ewf-tools` 时只输出需确认的 `apt-get install -y ewf-tools` 计划；如果 apt 或 sudo 不可用，附带 `download_portable_ewftools`。
- `download_portable_ewftools` 必须使用 `wget` 或 `curl` 下载用户确认的包，路径固定在系统临时缓存下，如 `/tmp/linux-loader-cache/<case-id>/ewf-tools/`；不要写入 `/usr`、`/usr/local`、挂载检材或工作目录根。
- 便携下载命令使用 `LINUX_LOADER_EWFTOOLS_URLS` 接收可信 `.deb` 或 tarball URL，下载到 `downloads/`，解压到 `root/`，再从缓存内查找 `ewfmount`、`ewfexport`、`ewfinfo`。

## Known-good loop fixture

用固定小镜像区分“用户镜像没有分区表”和“WSL2 `losetup -P` 失败”。

```bash
tmpdir="$(mktemp -d)"
img="$tmpdir/linux-loader-loop-probe.img"
dd if=/dev/zero of="$img" bs=1M count=50
printf 'label: dos\n,40M,L,*\n' | sfdisk "$img"
loop="$(sudo losetup --find --show --read-only -P "$img")"
ls "${loop}"p* 2>/dev/null
sudo losetup -d "$loop"
rm -rf "$tmpdir"
```

预期: 已知有分区表的小镜像应生成类似 `/dev/loop0p1`。若只有 loop 设备但无分区节点，记录 `losetup_partition_scan=failed` 并改走 offset mount。

## Raw/dd/img mount priority

1. `losetup --read-only -P`，仅在 loop attach 和 partition scan 都通过时使用。
2. offset mount: `mount -o <safe-options>,loop,offset=<bytes> <image> <mountpoint>`。
3. 只输出分区元数据和失败原因。

## E01 flow

- FUSE 可用定义：`/dev/fuse` 存在、当前用户可读写、存在 `fusermount` 或 `fusermount3`。
- FUSE 可用时优先 `ewfmount`，再把 exposed raw 当作 raw/dd/img 处理。
- FUSE 缺失、不可读写或 fusermount 缺失时，不要计划 `ewfmount`。
- FUSE 不可用时提示用户二选一：提权/修复 FUSE 后重试，或在 `ewfexport` 可用时降级导出 raw。
- FUSE 不可用但 `ewfexport` 可用时，输出需用户确认的导出计划，并先估算:
  - `estimated_export_size`
  - `estimated_export_time`
  - `export_space_available`
- 导出 raw 前必须让用户确认时间和磁盘占用。

## Filesystem mount options

- ext2/ext3/ext4: `ro,noload`
- XFS: `ro,norecovery`
- Btrfs: 先尝试 `ro,norecovery,skip_balance`；失败后按本机 `mount.btrfs` 支持情况尝试 `ro,nologreplay,skip_balance` 等只读选项。
- unknown: 先 `ro`；若失败，报告需要专用安全选项。

## LVM/LUKS

- LVM: 识别 PV/VG/LV，记录 `pvs`, `vgs`, `lvs` 输出；v1 不自动激活。
- LUKS: 识别后报告需要 passphrase/key；v1 不自动解密。
- 可给用户手动继续提示，如 `vgchange -ay --readonly`，但必须说明先确认取证安全流程。
