# Linux 本机只读挂载

本参考仅适用于当前终端是原生 Linux。不要在此参考中调用 Windows/WSL 路由。所有示例先运行工具 probe；把 `<...>` 替换为用户提供的绝对路径后才展示执行命令。不要运行 `ntfsfix`、修复、初始化、恢复日志或 `remove_hiberfile`。

LINUX_RAW_ROUTE: losetup --read-only --partscan
LINUX_OFFSET_ROUTE: mount -o ro,offset=
LINUX_E01_ROUTE: libewf
LINUX_E01_EXPORT: SIZE_TIME_SPACE_APPROVAL_REQUIRED
LINUX_VHD_ROUTE: qemu-nbd --read-only

## 预检与工具探针

```bash
command -v losetup mount umount lsblk findmnt blkid parted fdisk ntfs-3g ewfinfo ewfmount ewfexport qemu-nbd
losetup --help; mount --help; ntfs-3g --help; ewfmount --help; ewfexport --help; qemu-nbd --help
test -e /dev/loop-control; test -e /dev/nbd0; test -r /dev/fuse; df -h --output=avail /tmp
```

记录版本、绝对路径、sudo 可用性和内核设备状态。缺工具时仅提出不可变安装计划；发行版与包管理器必须按 `install-authorization.md` 路由。

## raw/dd/img：loop 与 offset

先用只读 loop 暴露分区，再让内核分区表可见：

```bash
sudo losetup --find --show --read-only --partscan '/evidence/guest.img'
lsblk -o NAME,RO,TYPE,SIZE /dev/loopN
sudo mount -o ro /dev/loopNp1 '/mnt/case/volume-1'
findmnt -no SOURCE,OPTIONS '/mnt/case/volume-1'
```

若只能得到偏移，先由 `parted -s <image> unit B print` 记录开始字节，再使用 `sudo mount -o ro,offset=<bytes> <image> <target>`。只读 verify：`lsblk` 的 `RO=1` 且 `findmnt` 选项含 `ro`。NTFS 必须使用：

```bash
sudo ntfs-3g -o ro,norecover /dev/loopNp1 '/mnt/case/volume-1'
findmnt -no OPTIONS '/mnt/case/volume-1'
```

`norecover` 防止日志回放；不得追加可写、修复或删除休眠文件选项。

## E01：libewf

先用 `ewfinfo '/evidence/segment.E01'` 验证段集。FUSE 可用时，按 `ewfmount --help` 的当前语法挂到 case 外的 FUSE 目录，随后对暴露的 raw 文件用 `losetup --read-only`，再按 raw 路线挂载。只读 verify 仍要求 `RO=1` 与挂载选项 `ro`。

若只能 `ewfexport`，先计算并展示导出大小、预计耗时和可用空间，等待单独确认后才提出导出计划；导出目的地不得是原始证据或挂载点。

## VHD/VHDX：qemu-nbd

先确认 `qemu-nbd --help` 中存在 `--read-only` 和连接/断开语法，并确认 `/dev/nbdN` 可用：

```bash
sudo qemu-nbd --read-only --connect=/dev/nbd0 '/evidence/guest.vhdx'
lsblk -o NAME,RO,TYPE,SIZE /dev/nbd0
sudo mount -o ro /dev/nbd0p1 '/mnt/case/volume-1'
findmnt -no SOURCE,OPTIONS '/mnt/case/volume-1'
```

只读 verify：NBD 与分区均显示 `RO=1`，且 `findmnt` 包含 `ro`。未满足任何一项即视为失败。

## 常见失败与清理

- `sudo`、loop、nbd 或 FUSE 缺失：停止并报告 probe；不要自动安装、加载模块或提升权限。
- 分区表损坏/无卷：记录 `blkid`/`parted` 事实，不运行修复工具。
- NTFS 休眠/脏卷：保持 `ro,norecover`，不要回放日志。

PARTIAL_FAILURE: IMMEDIATE_CLEANUP
SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP

部分失败立即从后往前 cleanup：`sudo umount '<target>'`（若已挂载）、`sudo qemu-nbd --disconnect /dev/nbd0`（若已连接）、`sudo losetup --detach /dev/loopN`（若已关联）、`fusermount -u '<ewf-target>'`（若 E01 FUSE 已挂）。成功挂载则保留到用户请求 cleanup，再执行同一顺序，并 verify `findmnt <target>` 失败、`losetup /dev/loopN` 无关联、`qemu-nbd` 已断开。

## 一手来源

- util-linux 项目：<https://github.com/util-linux/util-linux>
- libewf 项目：<https://github.com/libyal/libewf>
- QEMU `qemu-nbd`：<https://qemu.readthedocs.io/en/latest/tools/qemu-nbd.html>
- NTFS-3G 项目：<https://github.com/tuxera/ntfs-3g>
