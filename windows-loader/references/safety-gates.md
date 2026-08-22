# 安全确认门

先说明范围、风险和可逆性，再等待只针对该动作的确认；不得把一个确认复用给另一个动作。

## 四路线失败阶梯

挂载或读取失败时，始终同时展示以下四个选项，包含 availability、risk 和 user choice 栏。代理只描述可用性，不替用户选，也不因某路线不可用而自动转到另一路线。

FOUR_ROUTE_FALLBACK: PRESENT_ALL_ROUTES; AGENT_CHOICE: PROHIBITED

| route | availability | risk | user choice |
| --- | --- | --- | --- |
| 1. readonly diagnose/retry | 已有只读工具、未写入原件时可用 | 最低；可能无法恢复损坏文件系统 | 用户明确选择后才重试 |
| 2. direct readonly extraction (TSK/libewf) | TSK 或 libewf 已安装且格式支持时可用 | 低；可能只能获得部分内容 | 用户选择直接提取范围 |
| 3. estimate then working copy repair/write | 有足够空间、时间和批准的工作副本时可用 | 中；工作副本会改变，需先估算 | 用户选择并批准工作副本计划 |
| 4. original-evidence repair/write | 其它路线被用户拒绝或不可行且用户明确要求时可用 | 最高；原件失去 pristine 状态 | 用户完成两次精确确认后才执行 |

## 原始证据写入

默认禁止写原始证据、修复、初始化、恢复日志或删除休眠文件。仅当用户明确要求原件写入时，先采集 size、mtime 和所有可用哈希，显示失去原始性警告，再要求两次精确确认。

ORIGINAL_WRITE: TWO_CONFIRMATIONS_REQUIRED
ORIGINAL_WRITE_FIRST_CONFIRMATION: PREFIX I_CONFIRM_ORIGINAL_WRITE + EXACT_ABSOLUTE_PATH
ORIGINAL_WRITE_SECOND_CONFIRMATION: PREFIX I_CONFIRM_COMMAND + EXACT_ABSOLUTE_PATH + FULL_COMMAND
PRE_POST_EVIDENCE: SIZE + MTIME + AVAILABLE_HASHES
LOSS_OF_PRISTINE_WARNING: REQUIRED
GENERIC_CONFIRMATION_ACCEPTED: NO

机器确认仍必须完整匹配：先输入 `I_CONFIRM_ORIGINAL_WRITE <exact-absolute-path>`，再输入 `I_CONFIRM_COMMAND <exact-absolute-path> <full-command>`。中文用户界面必须在机器确认之前单独显示以下两行；中文提示不替代机器确认。

```text
确认写入原镜像: <absolute-path>
完整命令: <full-command>
```

写后比较 size、mtime、可用哈希，并持久化两次确认与结果。

## 独立敏感操作

每一项都需独立确认：访问或解锁 BitLocker；访问 VSS；导出或使用 DPAPI 密钥；安装或调用 DPAPI 工具；解密 DPAPI 数据。任何一项确认都不授权其它项。

BITLOCKER: CONFIRMATION_REQUIRED
VSS: CONFIRMATION_REQUIRED
DPAPI: CONFIRMATION_REQUIRED
DPAPI_KEYS: CONFIRMATION_REQUIRED
DPAPI_TOOLS: CONFIRMATION_REQUIRED
DPAPI_DECRYPT: CONFIRMATION_REQUIRED

首次把明文秘密写入持久化 case state 前，警告明文风险并等待确认；不要收紧 ACL、加密、改权限或复制原证据作为副作用。

确认后只允许通过有明确字符上限的标准输入把秘密交给 `case_state.py record-secret`。禁止任何命令行秘密值参数、禁止把值写进 command journal、终端回显或交互摘要。

PLAINTEXT_SECRET_FIRST_WRITE_WARNING: REQUIRED
PLAINTEXT_SECRET_INPUT: BOUNDED_STDIN
COMMAND_LINE_SECRET_VALUE: PROHIBITED
ACL_TIGHTENING: PROHIBITED
PERSISTENT_CASE_STATE: REQUIRED
END_TURN_SUMMARY: ABSOLUTE_PATH + PLAINTEXT + MOUNT + CLEANUP

## 一手来源

- Microsoft BitLocker 文档：<https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/>
- Microsoft VSS 文档：<https://learn.microsoft.com/en-us/windows/win32/vss/volume-shadow-copy-service-portal>
- Microsoft DPAPI 文档：<https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi>
