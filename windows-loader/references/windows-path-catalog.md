# Windows 来宾路径目录

## 目录

- 系统、注册表与执行痕迹
- 程序、服务与持久化
- 用户目录、UWP 与浏览器
- 网络与搜索规则

按来宾路径段路由，不按宿主盘符猜测。先执行高优先级的第一阶段搜索，再以深度 4、上限 50、不跟随 reparse point 的第二阶段补充。ACL 错误必须记录为错误，不得推断文件缺失。

CATALOG_FIELDS: guest_path_segments, scope, category, priority, common_files, cautions

## 系统、注册表与执行痕迹

| guest_path_segments | scope | category | priority | common_files | cautions |
| --- | --- | --- | --- | --- |
| `Windows/System32` | machine | SYSTEM_BINARIES | medium | `cmd.exe`, `WindowsPowerShell`, DLL metadata | 只读取元数据，不执行来宾二进制 |
| `Windows/SysWOW64` | machine | SYSTEM_BINARIES | medium | 32-bit DLL and EXE metadata | 与 System32 分开记录架构 |
| `Windows/System32/config/SYSTEM` | machine | REGISTRY_HIVES | high | `SYSTEM` | 解析 Select 后再解析 CurrentControlSet |
| `Windows/System32/config/SOFTWARE` | machine | REGISTRY_HIVES | high | `SOFTWARE` | 记录安装与 NetworkList 路径 |
| `Windows/System32/config/SAM` | machine | REGISTRY_HIVES | high | `SAM` | 可能含敏感账户材料 |
| `Windows/System32/config/SECURITY` | machine | REGISTRY_HIVES | high | `SECURITY` | 可能含敏感策略材料 |
| `Windows/System32/config/DEFAULT` | machine | REGISTRY_HIVES | high | `DEFAULT` | 不与用户 NTUSER 混同 |
| `Windows/System32/winevt/Logs` | machine | EVENT_LOGS | high | `Security.evtx`, `System.evtx` | 解析器不可用时诚实标记 |
| `Windows/System32/Tasks` | machine | SCHEDULED_TASKS | high | task XML | 不运行任务动作 |
| `Windows/Prefetch` | machine | EXECUTION_ARTIFACTS | medium | `*.pf` | 仅基于解析器支持声明结论 |
| `Windows/AppCompat/Programs/Amcache.hve` | machine | EXECUTION_ARTIFACTS | high | `Amcache.hve` | 与 SOFTWARE 和 NTUSER 分开来源标注 |
| `Windows/System32/sru/SRUDB.dat` | machine | USAGE_ARTIFACTS | high | `SRUDB.dat` | 可能需要只读 SQLite 解析 |

## 程序、服务与持久化

| guest_path_segments | scope | category | priority | common_files | cautions |
| --- | --- | --- | --- | --- |
| `Program Files` | machine | APPLICATION_DATA | high | product configuration and logs | 不执行来宾程序 |
| `Program Files (x86)` | machine | APPLICATION_DATA | high | 32-bit product configuration | 与 Program Files 分开盘点 |
| `ProgramData` | machine | APPLICATION_DATA | high | service configuration and logs | 可能含所有用户共享数据 |
| `Tools` | machine | PORTABLE_APPLICATIONS | medium | portable EXE and INI | 只读元数据与配置 |
| `PortableApps` | machine | PORTABLE_APPLICATIONS | medium | portable launchers and data | 不执行 launcher |
| `Users/Public/Tools` | shared | PORTABLE_APPLICATIONS | medium | shared portable data | 标注共享范围 |
| `Windows/System32/config/systemprofile` | service | SERVICE_PROFILES | high | service account profile data | 与普通用户路径分离 |
| `Windows/ServiceProfiles/LocalService` | service | SERVICE_PROFILES | high | LocalService profile files | 服务身份范围独立 |
| `Windows/ServiceProfiles/NetworkService` | service | SERVICE_PROFILES | high | NetworkService profile files | 服务身份范围独立 |
| `Windows/System32/config/SYSTEM/ControlSet00x/Services` | machine | SERVICES | high | service configuration | 先由 Select CurrentControlSet resolution 确定实际 ControlSet |
| `Users/<user>/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup` | user | STARTUP | high | `.lnk`, `.bat`, `.cmd`, `.ps1` | 只读目标与元数据 |
| `ProgramData/Microsoft/Windows/Start Menu/Programs/Startup` | machine | STARTUP | high | common startup entries | 不执行启动项 |
| `Windows/System32/config/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Schedule/TaskCache` | machine | SCHEDULED_TASKS | high | TaskCache registry data | 与 task XML 交叉关联 |

## 用户目录、UWP 与浏览器

| guest_path_segments | scope | category | priority | common_files | cautions |
| --- | --- | --- | --- | --- |
| `Users/<user>/AppData/Roaming` | user | USER_DATA | high | application config | 按用户隔离 |
| `Users/<user>/AppData/Local` | user | USER_DATA | high | application data | 按用户隔离 |
| `Users/<user>/AppData/LocalLow` | user | USER_DATA | medium | sandboxed application data | 不与 Local 合并 |
| `Users/<user>/AppData/Local/Packages/<PFN>/LocalState` | user | UWP_DATA | high | UWP local data | PFN 必须逐包记录 |
| `Users/<user>/AppData/Local/Packages/<PFN>/RoamingState` | user | UWP_DATA | high | UWP roaming data | PFN 必须逐包记录 |
| `Users/<user>/AppData/Local/Packages/<PFN>/Settings` | user | UWP_DATA | high | UWP settings | PFN 必须逐包记录 |
| `Users/<user>/Documents` | user | USER_CONTENT | medium | documents | 内容可能很大，使用限额 |
| `Users/<user>/Downloads` | user | USER_CONTENT | medium | downloaded files | 内容可能含不可信执行文件 |
| `Users/<user>/Saved Games` | user | USER_CONTENT | medium | game saves | 不执行存档相关程序 |
| `Users/<user>/Desktop` | user | USER_CONTENT | medium | desktop files | 内容可能很大，使用限额 |
| `Users/<user>/AppData/Local/Google/Chrome/User Data` | user | BROWSER_HISTORY | high | `History`, `Login Data`, `Cookies` | DPAPI 解密须独立确认 |
| `Users/<user>/AppData/Local/Microsoft/Edge/User Data` | user | BROWSER_HISTORY | high | `History`, `Login Data`, `Cookies` | DPAPI 解密须独立确认 |
| `Users/<user>/AppData/Roaming/Mozilla/Firefox/Profiles` | user | BROWSER_HISTORY | high | `places.sqlite`, `cookies.sqlite` | 只读 SQLite 打开 |
| `Users/<user>/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine` | user | POWERSHELL_HISTORY | high | `ConsoleHost_history.txt` | 可能包含令牌和口令 |
| `Users/<user>/NTUSER.DAT` | user | REGISTRY_HIVES | high | `NTUSER.DAT` | 每用户独立记录 |
| `Users/<user>/AppData/Local/Microsoft/Windows/UsrClass.dat` | user | REGISTRY_HIVES | high | `UsrClass.dat` | 每用户独立记录 |
| `Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations` | user | JUMP_LISTS | medium | `*.automaticDestinations-ms` | 可泄露最近文档路径 |
| `Users/<user>/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations` | user | JUMP_LISTS | medium | `*.customDestinations-ms` | 可泄露最近文档路径 |
| `Users/<user>/Local Settings` | user | LEGACY_JUNCTION | low | legacy junction target | Local Settings 常是 junction；不跟随 reparse point |

## 网络与搜索规则

| guest_path_segments | scope | category | priority | common_files | cautions |
| --- | --- | --- | --- | --- |
| `ProgramData/Microsoft/Wlansvc/Profiles/Interfaces` | machine | NETWORK | high | WLAN profile XML | 凭据材料另行确认 |
| `Windows/System32/config/SOFTWARE/Microsoft/Windows NT/CurrentVersion/NetworkList` | machine | NETWORK | high | NetworkList profiles | 从 SOFTWARE hive 读取 |
| `Windows/System32/drivers/etc/hosts` | machine | NETWORK | high | `hosts` | 保留原始换行与编码事实 |

第一阶段只搜索本目录的 high 条目和用户目标。第二阶段才在目录表的受限根下继续；每条命中输出 guest_path_segments、scope、category、priority、common_files、cautions 六字段。不要对整个挂载根作无限递归。

## 一手来源

- Microsoft registry hives：<https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives>
- Microsoft PSReadLine：<https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline>
- Microsoft Scheduled Tasks：<https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-1-0-examples>
