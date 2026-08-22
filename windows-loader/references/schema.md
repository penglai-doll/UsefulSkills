# 统一 Case Schema

所有 case state 与交互摘要使用 `windows-loader.v1`，并保留证据事实、推断、命令、错误和待确认事项的来源边界。ACL 或权限错误必须进入 `errors`，绝不能解释成路径不存在。

REQUIRED_CASE_SCHEMA_FIELDS: case_id, evidence, hash_policy, environment, format, mounts, windows_installations, users, path_hits, artifacts, routes, cleanup, errors
AVAILABLE_HASH_ALGORITHMS: RECORDED_INDEPENDENTLY_OF_HASH_POLICY
OPTIONAL_CLI_FIELDS: EXTENSIONS_NOT_SUBSTITUTIONS
BOUNDED_ENVELOPE: items, total_count, shown_count, truncated, details_path
SEARCH_DEFAULTS: depth=4, limit=50, follow_reparse=false
ACL_ERROR: NOT_EVIDENCE_OF_ABSENCE

```json CASE_SCHEMA_REQUIRED_FIELDS
["case_id","evidence","hash_policy","environment","format","mounts","windows_installations","users","path_hits","artifacts","routes","cleanup","errors"]
```

## 自动创建与目录布局

在 mount、install proposal、long scan、multi-turn、large artifact 或 imminent context compression 之前自动创建 case。默认目录固定为 `./tmp/windows-loader/<case-id>/`，且不得位于原始证据内。

```text
./tmp/windows-loader/<case-id>/
├── session.json
├── notes.md
├── commands.jsonl
├── findings.jsonl
├── secrets.jsonl
├── inspect.json
├── mounts.json
└── raw/
```

`case_id` 是这个目录和所有关联记录的稳定标识。`evidence` 记录绝对路径、完整连续 EWF 段集、size、mtime 与 `available_hash_algorithms`；顶层同样保留 `available_hash_algorithms`。`hash_policy` 只能为 now、later 或 skip；later/skip 只记录算法能力，不读取内容计算哈希。`format` 是识别出的输入格式。`environment` 记录当前 Windows/Linux/WSL、探针、权限和选中的独立参考。

`mounts` 记录路线、设备、目标、精确只读验证和保留/清理状态；`windows_installations`、`users`、`path_hits` 与 `artifacts` 都使用有界信封；`routes` 记录展示给用户的可选路线和选择；`cleanup` 记录执行过或待执行的精确命令；`errors` 保留权限、解析和未尝试原因。

可选 CLI 字段如 `schema`、`mode`、`commands`、`findings`、`details_path` 可以扩展输出，但不能替代上述任何必填字段。

## 有界信封

任何列表都使用同一信封：`items`、`total_count`、`shown_count`、`truncated`、`details_path`。默认搜索深度 4、上限 50、不跟随 reparse point；超出内容保存到 case 目录下的绝对路径，而非原始证据。

有界文件扫描记录 `enumeration_order=host-filesystem-order` 与 `deterministic_order_guaranteed=false`。目录预算截断时不得声称结果顺序稳定或扫描完整，因为预先排序必须先无界枚举目录。

SQLite 结果在打开主数据库前枚举同名 `-wal`、`-shm` 与 `-journal`。发现任一 sidecar 时，首版拒绝 immutable main-only 解析，输出有界 `sidecars` 元数据、`completeness=incomplete-sidecars-not-applied`、非高置信度、错误和下一路线；不得静默忽略已提交但尚未 checkpoint 的记录。二进制 EVTX 同样记录 parser status、attempts 和 completeness，解析器异常不得标记为高置信度。

## 一手来源

- Python JSON 文档：<https://docs.python.org/3/library/json.html>
- Microsoft Windows reparse point 文档：<https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points>
