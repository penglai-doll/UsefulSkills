# Windows 本机只读挂载

本参考只适用于当前终端是原生 Windows。它描述的是挂载工具路线，不是 `safety-gates.md` 中需要用户选择的安全门失败选项列表。未经不可变安装计划批准，不下载、安装或启用工具；所有版本、参数、驱动和服务行为以本机帮助探针为准。

WINDOWS_VHD_ROUTE: Mount-DiskImage -Access ReadOnly
WINDOWS_RAW_E01_PRIMARY: Arsenal Image Mounter
WINDOWS_RAW_E01_FALLBACK: OSFMount
VERSION_HELP_PROBE_REQUIRED

## 预检与工具探针

```powershell
Get-Command Mount-DiskImage,Dismount-DiskImage,Get-DiskImage,Get-Disk,Get-Partition,Get-Volume -ErrorAction SilentlyContinue
Get-Help Mount-DiskImage -Full
$aim = Get-Command aim_cli.exe -ErrorAction SilentlyContinue
if ($aim) { & $aim.Source --help }
$osf = Get-Command OSFMount.com -ErrorAction SilentlyContinue
if ($osf) { & $osf.Source --help }
```

只有 `Get-Command` 成功时才调用 AIM/OSFMount 帮助；`aim_cli.exe` 与 `OSFMount.com` 只是已安装名称 probe，绝不假定它们的挂载、只读或卸载语法。记录发现的绝对路径和版本；缺失时停止并提出新的精确安装计划。

## VHD/VHDX 系统路线

先按 `Get-Help Mount-DiskImage -Full` 核对当前版本，再把用户给出的绝对路径替换到命令中。`-PassThru` 返回的对象必须派生出同一个磁盘，禁止用泛化位置匹配猜测关联。

```powershell
$image = 'C:\evidence\guest.vhdx'
$diskImage = $null
$disks = @()
$verified = $false
try {
    $diskImage = Mount-DiskImage -ImagePath $image -Access ReadOnly -PassThru
    $disks = @($diskImage | Get-Disk)
    if ($diskImage.Attached -and $disks.Count -eq 1 -and $disks[0].IsReadOnly) {
        # Verification passed; record the exact association before declaring success.
    } else {
        throw 'Read-only verification failed: attached state, disk association, or IsReadOnly is invalid.'
    }
    $diskImage | Format-List ImagePath,Attached
    $disks[0] | Select-Object Number,IsReadOnly,Location
    $verified = $true
}
catch {
    throw
}
finally {
    if (-not $verified) {
        Dismount-DiskImage -ImagePath $image -ErrorAction SilentlyContinue
    }
}
```

read-only verify 同时要求 `$diskImage.Attached` 为真、`@($diskImage | Get-Disk)` 恰好返回一个磁盘、该磁盘的 `IsReadOnly` 为真，并把该对象的 `Number` 和 `ImagePath` 记入 case state。`finally` 会在挂载抛错、关联为零/多个、Attached 为假或只读验证失败时，对 `$image` 指定的同一绝对路径尝试分离；这类结果都是部分失败。不得把 `$verified = $true` 移到三项验证之前。失败后再次核实：

```powershell
Dismount-DiskImage -ImagePath $image
Get-DiskImage -ImagePath $image | Format-List ImagePath,Attached
```

## raw/dd/img 与 E01

对 raw/dd/img、单段 E01 与分段 E01，第一推荐是已经批准、实际探测到且版本帮助可用的 Arsenal Image Mounter。AIM 不可用或用户明确选择时，OSFMount 才是显式 fallback。先读取上方实际帮助的只读标志、格式支持和卸载语法，再展示要执行的精确命令；不编造 CLI 参数。

read-only verify：记录工具返回的映像绝对路径、设备/卷标识和只读状态；用该标识关联的 `Get-Disk` 或 `Get-Volume` 再验证。若显示可写、未能唯一关联或验证失败，立即按刚才探测到的精确工具卸载语法分离。

## 常见失败与清理

- 拒绝访问/UAC：记录需要的权限，等待用户确认范围，不自行提升。
- 映像被占用、分段缺失或 E01 顺序异常：停止，记录段清单与哈希状态。
- 驱动、服务或帮助版本不匹配：不自行修复；新计划 ID 必须列明驱动、服务、UAC 与重启影响。
- 卷未出现或盘符冲突：不要初始化、格式化、修复或分配可写卷，撤销本次附加。

PARTIAL_FAILURE: IMMEDIATE_CLEANUP
SUCCESSFUL_MOUNT: RETAIN_UNTIL_USER_REQUESTS_CLEANUP

部分失败立即 cleanup：VHD/VHDX 使用 `Dismount-DiskImage -ImagePath $image`；AIM/OSFMount 仅使用本次已探测帮助中展示且已记录的精确卸载命令。成功挂载保留到用户请求 cleanup；届时先卸载卷，再分离对应精确镜像，并 verify `$diskImage.Attached` 为假或 `Get-DiskImage -ImagePath $image` 不再 Attached。

## 一手来源

- Microsoft `Mount-DiskImage`：<https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage>
- Microsoft `Get-DiskImage`：<https://learn.microsoft.com/en-us/powershell/module/storage/get-diskimage>
- Microsoft `Dismount-DiskImage`：<https://learn.microsoft.com/en-us/powershell/module/storage/dismount-diskimage>
- Arsenal Image Mounter：<https://arsenalrecon.com/products/arsenal-image-mounter>
- OSFMount：<https://www.osforensics.com/tools/mount-disk-images.html>
