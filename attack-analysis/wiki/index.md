# Wiki Index

One line per pattern: PROBLEM -> ROOT CAUSE -> FIX. Maintained by the
evolution harness (`wiki_cli.py consolidate`); do not edit by hand.

- [P-001 windows-tzdata-naive-timestamps](patterns/P-001-windows-tzdata-naive-timestamps.md) — PROBLEM: Windows 下命名时区无法解析，时间戳退化为 unknown，时间线不可信 → ROOT CAUSE: zoneinfo 在 Windows 无系统时区库且未装 tzdata → FIX: 先 `pip install -r requirements.txt`，把 timezone_notes 警告当环境故障修复后再信任时间线
- [P-002 xff-port-ipchain-normalization](patterns/P-002-xff-port-ipchain-normalization.md) — PROBLEM: IP:端口 / XFF 代理链未归一化导致同源被拆、跨日志关联漏配 → ROOT CAUSE: remote host 字段含端口/代理链，直接当关联键 → FIX: 归一化为 actor_ip_normalized + actor_port + ip_chain，关联只用归一化 IP，报告保留原值
- [P-003 p6spy-embedded-in-spring](patterns/P-003-p6spy-embedded-in-spring.md) — PROBLEM: P6Spy SQL 行内嵌在 Spring 日志中被单一 parser 漏提取 → ROOT CAUSE: 按文件主类型二选一，混合格式只走一条解析链 → FIX: p6spy_sql 映射到 [p6spy_sql, spring_app] parser 链，检测命中 `p6spy`/`SQL 语句`，事后核对 parser_stats
- [P-004 xlsx-header-variants](patterns/P-004-xlsx-header-variants.md) — PROBLEM: 登录/操作导出表头变体被判为 xlsx_table，登录爆破序列丢失 → ROOT CAUSE: 固定表头精确匹配扛不住导出模板改名 → FIX: 大写化取交集匹配 + 多候选时间列扫描，低置信度在 interactive 模式必须人工确认 declared_type
- [P-005 rotated-syslog-no-extension](patterns/P-005-rotated-syslog-no-extension.md) — PROBLEM: secure/messages 等无扩展名轮转 syslog 被当未知文本，auth 线索被降权 → ROOT CAUSE: 内容检测未利用文件名强信号 → FIX: generic 检测 + 已知 syslog 名单时改判 system_text 并加 note，二进制记账文件仍排除
- [P-006 gold-attack-chain-strategy](patterns/P-006-gold-attack-chain-strategy.md) — PROBLEM: 分布在四类日志里的攻击链单看全是噪声 → ROOT CAUSE: 链证据横跨 access/app/SQL/登录导出，必须靠同 IP+时间窗串接 → FIX: 归一化 IP ±5min 强窗关联，盯 探测→登录失败成功→sql_suspicious→上传 序列，xlsx 与 access 按账号互证
- [P-007 large-log-windowing](patterns/P-007-large-log-windowing.md) — PROBLEM: GB 级日志塞上下文必然失败或丢关键窗口 → ROOT CAUSE: 上下文有限且无序抽样错过攻击窗口 → FIX: 按边界→时间窗→安全关键词→高信号状态码→top talker 的固定顺序窗口化提取
- [P-008 evidence-wording-discipline](patterns/P-008-evidence-wording-discipline.md) — PROBLEM: 候选关联被写成确定事实，或输出威胁评分/风险总分 → ROOT CAUSE: candidate 与 AI 推断混同，评分是未校准的伪量化 → FIX: 按证据强度用 confirmed by/suggests/consistent with 措辞，禁评分红线，每条结论标注证据类型
