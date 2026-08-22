# 报告与证据结构

输出必须让另一名分析员可以从报告结论回到原始命令输出。字段可以扩展，但不要删除来源、状态和局限。

## manifest.json

```json
{
  "schema_version": "1.0",
  "case_id": "case-id",
  "mode": "quick-report",
  "created_at_utc": "2026-01-01T00:00:00Z",
  "host": {
    "platform": "macOS",
    "hostname": "redacted-or-local-policy",
    "tools": {
      "mmls": "version-or-missing",
      "ewfverify": "version-or-missing",
      "utmctl": "version-or-missing"
    }
  },
  "evidence": [
    {
      "path": "/absolute/path/case.E01",
      "segments": [],
      "size_bytes": 0,
      "hash_policy": "sha256-now",
      "sha256": "...",
      "ewf_verify": "passed|failed|not-run|not-applicable"
    }
  ],
  "utm": {
    "vm_identifier": "complete-name-or-uuid",
    "transport": "guest-agent|ssh|shared-readonly",
    "start_mode": "disposable|persistent",
    "guest_evidence_path": "/evidence/case.E01",
    "guest_hash": "..."
  },
  "partitions": [],
  "artifacts": [],
  "findings": [],
  "decisions": [],
  "errors": []
}
```

不记录密码、私钥内容或不必要的完整敏感日志。路径是否需要脱敏按用户要求处理，但本地 artifact 的真实路径必须能被复核。

## artifact

每个 artifact 至少包含：

```json
{
  "artifact_id": "A-0001",
  "kind": "command-output|file-extract|hash|mount-state|timeline|yara-match",
  "path": "/absolute/case-output/raw/mmls.txt",
  "source": "mmls <RAW>",
  "execution_plane": "host|guest",
  "started_at_utc": "...",
  "exit_code": 0,
  "sha256": "...",
  "truncated_for_model": false,
  "notes": ""
}
```

原始输出保存到文件；模型摘要要包含 `artifact_id`、行数/截断状态和下一步定位信息。

## finding

```json
{
  "finding_id": "F-0001",
  "title": "",
  "status": "confirmed|derived|candidate|pending|suppressed",
  "severity": "informational|low|medium|high|unknown",
  "claim": "只写证据能支持的最小结论",
  "evidence_ids": ["A-0001"],
  "locations": [
    {
      "path": "/etc/cron.d/example",
      "partition_start_sector": 2048,
      "metadata_address": "12345",
      "time_field": "mtime"
    }
  ],
  "method": "fls+istat+icat",
  "confidence_basis": "",
  "limitations": "",
  "next_action": ""
}
```

`candidate` 表示需要继续核验，不能在摘要中写成已经确认。单个字符串、可疑文件名、异常时间或未知 SSH key 只能作为候选，除非有额外上下文和交叉证据。

## forensic-report.md

推荐顺序：

1. 范围与模式；
2. 证据与完整性；
3. UTM/工具/传输环境；
4. 分区与文件系统；
5. 关键发现（按状态分组）；
6. 时间线候选；
7. 提取物与 Hash；
8. 局限、未完成步骤和复现命令；
9. artifact 索引。

报告不要使用无证据的总风险分数，也不要把工具输出原文大段复制进正文。引用 artifact 路径和短摘录即可。
