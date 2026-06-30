# Mounting Workflow

读取时机: 挂载失败、WSL2 loop/FUSE 诊断、E01 降级、LVM/LUKS、文件系统只读参数或验证夹具需要时读取。

## WSL2 Preflight

- 记录 `uname -a`、`/proc/version`、是否 WSL2。
- 检查并记录 `sudo` 状态；无 sudo 时将 loop 探针标为 `unknown`，不要伪造通过。
- 检查输出目录和挂载根目录绝对路径；挂载根被占用时换到 `/mnt/ev-mount-<case-id>/`。
- E01 路径检查 `ewfinfo`、`ewfmount`、`ewfexport`、`/dev/fuse`、`fusermount` 或 `fusermount3`。

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

- FUSE 可用时优先 `ewfmount`，再把 exposed raw 当作 raw/dd/img 处理。
- FUSE 不可用但 `ewfexport` 可用时，先估算:
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
