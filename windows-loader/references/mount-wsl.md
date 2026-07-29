# WSL 只读挂载

本参考只适用于当前终端是 WSL，不是 Windows 或 Linux 参考的适配器。只在 WSL probe 明确满足时使用 Linux 风格只读路线；不具备能力时只能请求用户自行在原生 Windows 重新开始，绝不调用、切换或重启另一环境。

WSL_WINDOWS_PATH_CONVERSION: wslpath
WSL_PREFLIGHT: sudo + loop + nbd + FUSE + kernel
WSL_INCAPABLE: ASK_USER_TO_RESTART_IN_WINDOWS_ONLY
WSL_AUTO_SWITCH: PROHIBITED

## 预检与工具 probe

```bash
uname -a
cat /proc/version
cat /proc/sys/kernel/osrelease
wslpath -u 'C:\evidence\guest.vhdx'
sudo -n true
test -e /dev/loop-control; test -e /dev/nbd0; test -r /dev/fuse
test -r /proc/filesystems; grep -E 'fuse|ntfs' /proc/filesystems
command -v losetup mount umount lsblk findmnt ewfinfo ewfmount ewfexport qemu-nbd ntfs-3g
losetup --help; ewfmount --help; ewfexport --help; qemu-nbd --help; ntfs-3g --help
```

用 `uname -a`、`/proc/version` 和 `/proc/sys/kernel/osrelease` 识别 WSL；用 `wslpath` 把 Windows 路径转换为当前 WSL 可读的绝对路径并用 `test -r` 复查。确认非交互 sudo、loop、NBD、FUSE、内核文件系统与工具版本。不要调用任何 Windows 可执行文件，也不要把 WSL 特有的挂载接口当作通用只读替代。

## 满足能力时的只读路线

raw/dd/img：`sudo losetup --find --show --read-only --partscan '<image>'`，再执行 `lsblk -o NAME,RO,TYPE,SIZE /dev/loopN`，然后 `sudo mount -o ro /dev/loopNp1 '<target>'` 与 `findmnt -no SOURCE,OPTIONS '<target>'`。有 offset 时使用 `sudo mount -o ro,offset=<bytes> '<image>' '<target>'`。

E01：先执行 `ewfinfo '<first.E01>'`；FUSE 可用时按实际 `ewfmount --help` 语法暴露，再对输出使用只读 loop。只能导出时先展示 size、time、space 并等待独立确认，不能自行运行 `ewfexport`。

VHD/VHDX：只在 NBD probe 成功时执行 `sudo qemu-nbd --read-only --connect=/dev/nbd0 '<image>'`，随后对 `/dev/nbd0p1` 使用 `mount -o ro`。NTFS 使用 `sudo ntfs-3g -o ro,norecover <device> '<target>'`；不得回放日志、修复或移除休眠文件。

精确 read-only verify：每条路线都必须显示 `lsblk` 中设备 `RO=1` 与 `findmnt` 中目标选项含 `ro`；缺任一项即失败且不读文件。

## 无能力、常见失败与 cleanup

若 sudo、loop、nbd、FUSE、内核或工具 probe 失败，唯一可给出的操作请求是：“请由用户自行在原生 Windows 终端重新开始此任务。” 不安装、不加载模块、不重启、不切换。

- 路径转换失败或不可读：记录原路径和 `wslpath` 错误，不猜测挂载点。
- NBD/FUSE 设备缺失：停止，不运行 `modprobe`。
- 分区或 NTFS 报错：保持只读、记录错误，不修复。

PARTIAL_FAILURE: IMMEDIATE_CLEANUP
SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP

部分失败立即 cleanup：`sudo umount '<target>'`（如已挂载）、`sudo qemu-nbd --disconnect /dev/nbd0`（如已连接）、`sudo losetup --detach /dev/loopN`（如已关联）、`fusermount -u '<ewf-target>'`（如已挂 FUSE）。成功挂载保留到用户请求 cleanup；届时按相同逆序执行，并以 `findmnt`、`losetup`、`qemu-nbd` 状态确认已释放。

## 一手来源

- Microsoft WSL 磁盘挂载：<https://learn.microsoft.com/en-us/windows/wsl/wsl2-mount-disk>
- Microsoft WSL 基本命令：<https://learn.microsoft.com/en-us/windows/wsl/basic-commands>
- QEMU `qemu-nbd`：<https://qemu.readthedocs.io/en/latest/tools/qemu-nbd.html>
- libewf 项目：<https://github.com/libyal/libewf>
