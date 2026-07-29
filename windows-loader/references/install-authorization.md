# 安装与下载授权

仅当当前终端缺少已选只读路线必需的工具时才提出计划。不得自行安装、下载、更新、启用服务、加载驱动或重启。

## 不可变计划与可复算 ID

计划只包含 `tool`、`source`、`version_or_channel`、`commands`、`scope`、`privileges`、`uac_driver_service_reboot_effects` 七个批准字段。将这七字段组成对象，按 UTF-8 编码为 canonical JSON：键按字典序排序、`commands` 数组维持展示顺序、分隔符为紧凑的 `,` 与 `:`、最后只追加一个 LF；对得到的字节串计算完整 SHA-256 十六进制值，即 `install_plan_id`。

PLAN_FIELDS: tool, source, version_or_channel, commands, scope, privileges, uac_driver_service_reboot_effects
CANONICAL_UTF8_JSON: SORTED_KEYS + STABLE_COMMAND_ARRAY_ORDER + COMPACT_SEPARATORS + LF
INSTALL_PLAN_APPROVAL: IMMUTABLE_EXACT_PLAN_ID_REQUIRED
APPROVAL: EXACT_INSTALL_PLAN_ID_ONLY
PLAN_CHANGE: NEW_PLAN_ID_REQUIRED

```json canonical-plan.json
{"commands":["apt-get update","apt-get install --yes ewf-tools"],"privileges":"sudo","scope":"system","source":"https://github.com/libyal/libewf","tool":"ewf-tools","uac_driver_service_reboot_effects":"none","version_or_channel":"distro-default"}
```

INSTALL_PLAN_ID_EXAMPLE_SHA256: e5870bf54ad639d4f609f513dc8b670e4e1171171315a141e480184998fd1f00

复制上述对象后，使用同一算法复算 ID；即使只改变 `scope`、一个命令元素、来源、权限或版本/通道，哈希也不同并且必须生成新计划 ID。只有用户逐字确认完整 ID 才能批准；“继续”“可以”“装吧”无效。不得把批准移植到其它工具、来源、范围、权限、驱动/服务/UAC/重启影响或命令。

## 传输回退与 Linux 路由

在同一已批准计划中，传输失败时只能在 `commands` 字段已经批准的精确传输命令之间切换。存在多个备选时，`commands` 必须在生成 ID 前包含一个带 `type: one_of` 标签的 `alternatives` 对象，并在其中逐条列出每条完整命令；普通字符串绝不表示备选。这些备选条目表示“择一执行”，不能临时拼接参数。允许的传输器仍只限 `curl`、`wget`、`Invoke-WebRequest` 或 BITS，且不得改变工件、来源、版本、校验、范围或权限。任何未列入已批准 `commands`/`alternatives` 的传输命令都会改变计划，必须生成并重新批准新的计划 ID。安装后先重新验证真实版本和可执行绝对路径。

`commands` 中普通字符串是依次执行的独立命令；传输回退必须使用以下带 `type: one_of` 标签的对象，执行器只能选择其中一个完整字符串，不能把它当成顺序命令或自由组合参数：

```json TRANSPORT_ALTERNATIVES_OBJECT
{"type":"one_of","alternatives":["curl --fail --location --output tool.zip https://official.example/tool.zip","wget --output-document=tool.zip https://official.example/tool.zip"]}
```

TRANSPORT_ONLY_FALLBACK: curl|wget|Invoke-WebRequest|BITS
TRANSPORT_ONLY_FALLBACK: APPROVED_PLAN_REQUIRED
PREAPPROVED_TRANSPORT_ALTERNATIVES_ONLY: REQUIRED
UNLISTED_TRANSPORT_COMMAND: NEW_PLAN_ID_REQUIRED
SEQUENTIAL_COMMANDS_REMAIN_DISTINCT: REQUIRED
COMMAND_ENTRY_SCHEMA: STRING_IS_SEQUENTIAL | TYPE_ONE_OF_HAS_ALTERNATIVES

Linux 先探测 `/etc/os-release` 与 `command -v apt-get dnf yum zypper pacman apk`。只生成与实际发行版/包管理器匹配的计划，不能复用其它发行版的命令。

LINUX_PACKAGE_MANAGER_ROUTING: REQUIRED

## 一手来源

- Microsoft PowerShell 存储模块：<https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage>
- QEMU 项目文档：<https://qemu.readthedocs.io/en/latest/tools/qemu-nbd.html>
- libewf 项目：<https://github.com/libyal/libewf>
- Arsenal Image Mounter：<https://arsenalrecon.com/products/arsenal-image-mounter>
- OSFMount：<https://www.osforensics.com/tools/mount-disk-images.html>
