# APK 专用持久化台账

本文件负责“共享经验如何写入和压缩”；已知坑点枚举与推荐 `ledger_key` 见 [gotchas.md](./gotchas.md)。

在需要跨多次 APK 分析复用已验证的坑点和 fallback 时使用本文件。

## 适用范围

- 仅用于 APK 分析或解包产物分析。
- 不用于一般 Android 开发、SDK 接入或代码问答。

## 推荐路径

- 默认放在 skill 根目录的 `skill-ledger.json`
- 只有在需要隔离实验、临时验证或对比不同规则时，才显式改用 `--path`

## 先读后写

开始分析前先读：

```bash
python scripts/skill_ledger.py review
```

只有在以下情况才写入：

- 这是新的问题
- 或者你找到了比旧记录更好的 fallback
- 而且该 fallback 已被当前样本验证

写入命令：

```bash
python scripts/skill_ledger.py record --key <gotcha-key> --symptom "<symptom>" --preferred-action "<action>" --avoid "<avoid>" --stage "<stage>"
```

如果确实需要临时隔离一份 ledger，再额外传：

```bash
python scripts/skill_ledger.py review --path /tmp/custom-skill-ledger.json
```

## 去重规则

- 同一个 `key` 再次出现时，只增加 `count` 并更新时间，不新增长记录。
- 如果旧问题再次出现且已被压缩，脚本会把它恢复为 active lesson，方便本轮直接复用。
- 优先使用 [gotchas.md](./gotchas.md) 里的稳定 `ledger_key`。

## 压缩规则

- 最多保留 20 条 active lessons。
- 更老的 lessons 会转成 compact records，只保留 `key`、`preferred_action`、`avoid`、`stage`、`count`、时间戳。
- recent incidents 最多保留 8 条，且每条都会截短成短 note。
- 所有 symptom / action / avoid / note 都会自动截断，避免长期运行后把台账写成大日志。

## 使用目标

- 遇到同一个坑时，直接避开旧失败路径。
- 把真正有复用价值的 lessons 留下来，而不是把每次分析过程都写进去。
