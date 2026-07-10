# Attack Analysis v1.0.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `attack-analysis` 升级为 AI 主导、脚本仅负责有界类型嗅探和大日志透明降噪的 v1.0.0，并将缓存与 Markdown 报告输出到调用目录下按 case 分组的 `cache/` 和 `report/`。

**Architecture:** 保留现有 inventory、extract、correlate 三个入口，将格式规则拆入 `detectors/`，将 parser 改为逐记录生成器并把候选写成 JSONL。AI 读取检测依据、扫描摘要和候选后，按需调用上下文提取器复核原文，维护证据台账并编写报告；脚本只生成机械关联候选和验证报告结构，不输出攻击结论。

**Tech Stack:** Python 3 标准库、`unittest`、JSON/JSONL、gzip、ZIP/XML 流式读取、SQLite 临时关联索引、Markdown。

## Global Constraints

- 每次运行 analysis 工具前必须在当前用户回合明确选择 `quick-report` 或 `interactive`。
- 仅 `high` 格式置信度可以自动采用；所有非 `high`、声明冲突和 parser 缺失均需用户确认。
- 有界采样只判断日志格式；纳入范围的日志默认完整流式扫描，不允许因候选数量达到上限而提前退出。
- AI 判断攻击性质、攻击链、因果关系和入侵结果；脚本只做盘点、过滤、索引、标准化、上下文提取、机械关联和报告结构验证。
- 脚本输出使用中性记录类型，不输出攻击成功、高危攻击者、威胁评分、风险总分或数字化等级。
- 默认仅使用 Python 3 标准库，不引入新的运行时依赖。
- 默认输出根目录是调用 skill 时的 `$PWD`：缓存写入 `cache/<case-id>/`，报告写入 `report/<case-id>/log-analysis-report.md`。
- 网络富化保持默认开启、失败自动离线；不得上传完整日志、请求体、凭据、数据库结果或内部业务参数。
- Windows EVTX、云审计、Kubernetes、二进制 MySQL/MariaDB binlog、PCAP、内存和磁盘镜像仍属于后续扩展。
- 真实案件日志、生成缓存和报告不进入 Git。

---

## File Structure Map

### New files

- `attack-analysis/scripts/common/output_layout.py`: case ID、当前工作目录输出路径和覆盖保护。
- `attack-analysis/scripts/common/bounded_io.py`: magic bytes、编码、gzip 和文本有界采样。
- `attack-analysis/scripts/common/detection_schema.py`: 格式检测结果数据契约。
- `attack-analysis/scripts/common/streaming.py`: parser 上下文、扫描统计和透明噪声台账。
- `attack-analysis/scripts/detectors/__init__.py`: detector 包入口。
- `attack-analysis/scripts/detectors/registry.py`: detector 调度和候选合并。
- `attack-analysis/scripts/detectors/text_signatures.py`: 文本日志可解释特征。
- `attack-analysis/scripts/detectors/xlsx_table.py`: XLSX 表头和少量记录识别。
- `attack-analysis/scripts/extract_context.py`: AI 按原始位置或过滤条件补取证据。
- `attack-analysis/scripts/validate_report.py`: 证据编号、章节、禁用词和原子落盘验证。
- `attack-analysis/tests/test_output_layout_v1.py`: 当前目录输出和覆盖保护。
- `attack-analysis/tests/test_xlsx_streaming_v1.py`: XLSX 流式读取和列位置。
- `attack-analysis/tests/test_detection_v1.py`: 有界嗅探和格式识别矩阵。
- `attack-analysis/tests/test_streaming_v1.py`: 全文件扫描、尾部候选和降噪透明度。
- `attack-analysis/tests/test_context_correlation_v1.py`: 原文补取和机械关联。
- `attack-analysis/tests/test_report_contract_v1.py`: AI 报告契约和落盘验证。

### Existing files to modify

- `attack-analysis/scripts/inventory_logs.py:1-263`: 使用输出布局和 detector registry，删除内嵌格式判断。
- `attack-analysis/scripts/extract_log_events.py:1-92`: 流式写入中性候选和扫描摘要。
- `attack-analysis/scripts/correlate_events.py:1-117`: 读取 JSONL 并生成更多机械键关联候选。
- `attack-analysis/scripts/common/io_utils.py:1-57`: 使用 magic bytes 判断 gzip/文本，暴露有界二进制读取。
- `attack-analysis/scripts/common/event_schema.py:1-48`: 改为中性记录 schema 和 correlation keys。
- `attack-analysis/scripts/common/xlsx_utils.py:1-58`: 将 worksheet DOM 读取改为 `iterparse`。
- `attack-analysis/scripts/parsers/apache_access.py:1-58`: 生成 `http_request`，完整扫描并登记噪声。
- `attack-analysis/scripts/parsers/nginx_access.py:1-5`: 继续复用 Web access 解析，但使用统一生成器接口。
- `attack-analysis/scripts/parsers/spring_app.py:1-65`: 生成 `application_record`，避免重复处理 P6Spy 行。
- `attack-analysis/scripts/parsers/p6spy_sql.py:1-66`: 生成 `sql_record`，不使用 `sql_suspicious`。
- `attack-analysis/scripts/parsers/generic_text.py:1-40`: 生成 `text_record` 并保存规则依据。
- `attack-analysis/scripts/parsers/xlsx_login.py:1-53`: 使用流式 XLSX 行生成 `login_record`。
- `attack-analysis/scripts/parsers/xlsx_operate.py:1-53`: 使用流式 XLSX 行生成 `operation_record`。
- `attack-analysis/tests/test_attack_analysis_contract.py:1-104`: 更新 v1.0.0 总契约和新输出格式。
- `attack-analysis/tests/fixtures/gold_attack_case/*`: 扩展端到端攻击链和报告验证 fixture。
- `attack-analysis/SKILL.md:1-91`: 更新 v1.0.0 工作流和 AI/脚本边界。
- `attack-analysis/references/*.md`: 同步 detection、streaming、correlation、reporting、错误处理和验收规则。
- `attack-analysis/agents/openai.yaml:1-4`: 强化 AI 调查员角色和当前目录报告输出。
- `attack-analysis/.gitignore:1-16`: 忽略 `report/` 并继续保护真实日志和缓存。
- `README.md`: 将 Attack Analysis 条目更新为 1.0.0。

Every new test module that imports `scripts.*` must place this bootstrap before those imports so commands work from the repository root:

```python
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
```

---

### Task 1: Case 输出布局与覆盖保护

**Files:**
- Create: `attack-analysis/scripts/common/output_layout.py`
- Modify: `attack-analysis/scripts/inventory_logs.py:48-62,172-231,234-263`
- Test: `attack-analysis/tests/test_output_layout_v1.py`

**Interfaces:**
- Produces: `CasePaths`, `safe_case_id(value)`, `default_case_id(source_paths, now)`, `resolve_case_paths(workdir, case_id)`, `prepare_case_paths(paths, allow_existing)`。
- Produces manifest fields: `invocation_cwd` and `output_paths.{cache_dir,report_dir,report_path}`。
- Later tasks consume `manifest["output_paths"]` rather than reconstructing output paths independently.

- [ ] **Step 1: Write failing output-layout tests**

Create `attack-analysis/tests/test_output_layout_v1.py` with these assertions:

```python
from __future__ import annotations

import tempfile
import unittest
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.common.output_layout import (
    default_case_id,
    prepare_case_paths,
    resolve_case_paths,
    safe_case_id,
)


class OutputLayoutV1Tests(unittest.TestCase):
    def test_case_paths_live_under_invocation_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths = resolve_case_paths(root, "incident-01")
            self.assertEqual(paths.cache_dir, root / "cache" / "incident-01")
            self.assertEqual(paths.report_dir, root / "report" / "incident-01")
            self.assertEqual(paths.report_path, paths.report_dir / "log-analysis-report.md")

    def test_existing_case_is_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = resolve_case_paths(Path(tmp), "incident-01")
            prepare_case_paths(paths, allow_existing=False)
            with self.assertRaises(FileExistsError):
                prepare_case_paths(paths, allow_existing=False)

    def test_default_case_id_is_safe_and_deterministic_for_fixed_time(self):
        now = datetime(2026, 7, 10, 12, 30, 45)
        case_id = default_case_id([Path("/srv/logs/nginx")], now=now)
        self.assertEqual(case_id, "nginx-20260710-123045")
        self.assertEqual(safe_case_id("趣工宝 / incident #1"), "incident-1")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the focused test and verify the red state**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_output_layout_v1.py -v
```

Expected: import failure for `scripts.common.output_layout`.

- [ ] **Step 3: Implement the output path module**

Create `attack-analysis/scripts/common/output_layout.py` with this public contract:

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class CasePaths:
    workdir: Path
    cache_dir: Path
    report_dir: Path
    manifest_path: Path
    report_path: Path


def safe_case_id(value: str) -> str:
    ascii_value = value.encode("ascii", "ignore").decode("ascii").lower()
    cleaned = re.sub(r"[^a-z0-9._-]+", "-", ascii_value).strip("-._")
    return cleaned or "case"


def default_case_id(source_paths: Sequence[Path], now: datetime | None = None) -> str:
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    first = source_paths[0] if source_paths else Path("case")
    base = first.name if first.name else first.parent.name
    return f"{safe_case_id(base)}-{stamp}"


def resolve_case_paths(workdir: Path, case_id: str) -> CasePaths:
    root = workdir.expanduser().resolve()
    safe_id = safe_case_id(case_id)
    cache_dir = root / "cache" / safe_id
    report_dir = root / "report" / safe_id
    return CasePaths(
        workdir=root,
        cache_dir=cache_dir,
        report_dir=report_dir,
        manifest_path=cache_dir / "analysis-manifest.json",
        report_path=report_dir / "log-analysis-report.md",
    )


def prepare_case_paths(paths: CasePaths, allow_existing: bool = False) -> None:
    exists = paths.cache_dir.exists() or paths.report_dir.exists()
    if exists and not allow_existing:
        raise FileExistsError(f"case output already exists: {paths.cache_dir.name}")
    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    paths.report_dir.mkdir(parents=True, exist_ok=True)
```

Modify inventory CLI to add `--workdir` with default `Path.cwd()`, add explicit `--overwrite-case`, preserve `--output-dir` only as a legacy cache override, and write `output_paths` into the manifest. `discover()` must receive excluded roots and skip resolved paths beneath `$PWD/cache` and `$PWD/report`.

- [ ] **Step 4: Run output-layout and existing contract tests**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_output_layout_v1.py attack-analysis/tests/test_attack_analysis_contract.py -v
```

Expected: all tests pass; existing tests may require fixture command updates to pass an isolated `--workdir`.

- [ ] **Step 5: Commit Task 1**

```bash
git add attack-analysis/scripts/common/output_layout.py attack-analysis/scripts/inventory_logs.py attack-analysis/tests/test_output_layout_v1.py attack-analysis/tests/test_attack_analysis_contract.py
git commit -m "feat: add attack analysis case output layout"
```

---

### Task 2: XLSX 流式行读取

**Files:**
- Modify: `attack-analysis/scripts/common/xlsx_utils.py:1-58`
- Test: `attack-analysis/tests/test_xlsx_streaming_v1.py`

**Interfaces:**
- Preserves: `iter_rows(path, max_rows=None)` and `read_header(path)`.
- Adds: `sheet_index=0` optional argument without changing existing callers.
- Detector and XLSX parsers in later tasks consume this interface.

- [ ] **Step 1: Write failing streaming and sparse-column tests**

Create a test that builds a minimal XLSX ZIP with cells `A1`, `C1`, `A2`, and `C2`, then asserts the missing B column is preserved and `max_rows=1` stops after the header. Patch `xml.etree.ElementTree.fromstring` to raise so the test fails if worksheet DOM loading remains.

```python
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from scripts.common.xlsx_utils import iter_rows


SHEET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="inlineStr"><is><t>USER</t></is></c><c r="C1" t="inlineStr"><is><t>IP</t></is></c></row>
    <row r="2"><c r="A2" t="inlineStr"><is><t>alice</t></is></c><c r="C2" t="inlineStr"><is><t>198.51.100.23</t></is></c></row>
  </sheetData>
</worksheet>"""


class XlsxStreamingV1Tests(unittest.TestCase):
    def test_iter_rows_streams_and_preserves_sparse_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.xlsx"
            with ZipFile(path, "w") as zf:
                zf.writestr("xl/worksheets/sheet1.xml", SHEET_XML)
            with patch("xml.etree.ElementTree.fromstring", side_effect=AssertionError("DOM read forbidden")):
                rows = list(iter_rows(path))
            self.assertEqual(rows[0][1], ["USER", "", "IP"])
            self.assertEqual(rows[1][1], ["alice", "", "198.51.100.23"])
            self.assertEqual(len(list(iter_rows(path, max_rows=1))), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Verify the existing DOM implementation fails**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_xlsx_streaming_v1.py -v
```

Expected: FAIL because `iter_rows()` calls `ET.fromstring` and loses sparse column positions.

- [ ] **Step 3: Replace worksheet DOM parsing with `iterparse`**

Implement `_column_index(cell_ref)` and parse each `<row>` on its closing event. Build each row list by cell reference, clear processed elements immediately, and stop after `max_rows`. Parse shared strings with `iterparse` as well; retaining the resulting string table is allowed, but retaining the worksheet DOM is not.

```python
def _column_index(cell_ref: str) -> int:
    letters = "".join(ch for ch in cell_ref if ch.isalpha()).upper()
    value = 0
    for char in letters:
        value = value * 26 + ord(char) - ord("A") + 1
    return max(0, value - 1)


def iter_rows(path: str | Path, max_rows: int | None = None, sheet_index: int = 0):
    with ZipFile(path) as zf:
        shared = _shared_strings(zf)
        sheets = sorted(
            [name for name in zf.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name)],
            key=lambda name: int(re.search(r"sheet(\d+)\.xml", name).group(1)),
        )
        if sheet_index >= len(sheets):
            return
        emitted = 0
        with zf.open(sheets[sheet_index]) as stream:
            for event, elem in ET.iterparse(stream, events=("end",)):
                if event != "end" or not elem.tag.endswith("}row"):
                    continue
                row_number = int(elem.get("r") or emitted + 1)
                values: list[str] = []
                for cell in elem.findall("a:c", NS):
                    position = _column_index(cell.get("r") or "A1")
                    while len(values) <= position:
                        values.append("")
                    values[position] = _cell_value(cell, shared)
                yield row_number, values
                emitted += 1
                elem.clear()
                if max_rows is not None and emitted >= max_rows:
                    break
```

- [ ] **Step 4: Run XLSX parser regression tests**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_xlsx_streaming_v1.py attack-analysis/tests/test_attack_analysis_contract.py -v
```

Expected: sparse-column test and existing XLSX login/operation fixture tests pass.

- [ ] **Step 5: Commit Task 2**

```bash
git add attack-analysis/scripts/common/xlsx_utils.py attack-analysis/tests/test_xlsx_streaming_v1.py
git commit -m "refactor: stream attack analysis xlsx rows"
```

---

### Task 3: 有界日志类型 detector 架构

**Files:**
- Create: `attack-analysis/scripts/common/bounded_io.py`
- Create: `attack-analysis/scripts/common/detection_schema.py`
- Create: `attack-analysis/scripts/detectors/__init__.py`
- Create: `attack-analysis/scripts/detectors/registry.py`
- Create: `attack-analysis/scripts/detectors/text_signatures.py`
- Create: `attack-analysis/scripts/detectors/xlsx_table.py`
- Modify: `attack-analysis/scripts/common/io_utils.py:9-50`
- Modify: `attack-analysis/scripts/inventory_logs.py:17-19,21-45,73-169,172-217`
- Test: `attack-analysis/tests/test_detection_v1.py`

**Interfaces:**
- Produces: `SamplingBudget`, `TextSample`, `DetectionResult`.
- Produces: `detect_file(path, default_timezone, budget) -> DetectionResult`.
- Inventory writes detection fields directly from `DetectionResult.to_dict()`.
- Later parser dispatch consumes only `primary_type` and `candidate_types`; it must not infer type again.

- [ ] **Step 1: Write detection matrix and sampling-budget tests**

Tests must create extensionless Web access, Spring/P6Spy mixed, auth, firewall, mysqlbinlog text, JSONL, unknown text, gzip, and XLSX files. Assert that extensionless text is recognized by content, mixed logs return a primary and secondary candidate, unknown logs are not forced, and `bytes_sampled` does not exceed the configured phase budget. Place the shown test methods inside `class DetectionV1Tests(unittest.TestCase)`.

```python
import tempfile
import unittest
from pathlib import Path

from scripts.common.detection_schema import SamplingBudget
from scripts.detectors.registry import detect_file

MIXED_SPRING_P6SPY = """2026-07-10 12:00:00.000 INFO 1 --- [http-nio-8080-exec-1] c.e.LoginController:42 - login user=alice
2026-07-10 12:00:01.000 INFO 1 --- [http-nio-8080-exec-1] p6spy:1 - 2026-07-10 12:00:01.000 | SQL 语句：SELECT id FROM users WHERE login_name='alice'
"""


def test_extensionless_access_log_is_detected_from_content(self):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "access-current"
        path.write_text(
            '198.51.100.23 - - [10/Jul/2026:12:00:00 +0800] "GET /.git/config HTTP/1.1" 404 123 "-" "curl/8"\n',
            encoding="utf-8",
        )
        result = detect_file(path, "Asia/Shanghai", SamplingBudget(head_bytes=4096, max_records=50))
        self.assertEqual(result.primary_type, "web_access")
        self.assertEqual(result.confidence, "high")
        self.assertLessEqual(result.bytes_sampled, 4096)


def test_mixed_spring_p6spy_exposes_secondary_candidate(self):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "mixed.log"
        path.write_text(MIXED_SPRING_P6SPY, encoding="utf-8")
        result = detect_file(path, "Asia/Shanghai", SamplingBudget())
        self.assertEqual(result.primary_type, "spring_app")
        self.assertIn("p6spy_sql", result.candidate_types)
        self.assertFalse(result.needs_confirmation)


def test_unknown_text_requires_confirmation(self):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "unknown.data"
        path.write_text("custom record without known fields\n", encoding="utf-8")
        result = detect_file(path, "Asia/Shanghai", SamplingBudget())
        self.assertEqual(result.primary_type, "generic_text")
        self.assertNotEqual(result.confidence, "high")
        self.assertTrue(result.needs_confirmation)
```

- [ ] **Step 2: Run detection tests and verify missing modules fail**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_detection_v1.py -v
```

Expected: import failures for the new detection modules.

- [ ] **Step 3: Implement the schemas and bounded sampler**

Use these exact public data fields:

```python
@dataclass(frozen=True)
class SamplingBudget:
    head_bytes: int = 128 * 1024
    max_records: int = 500
    middle_bytes: int = 64 * 1024
    tail_bytes: int = 128 * 1024
    gzip_decompressed_bytes: int = 1024 * 1024


@dataclass(frozen=True)
class TextSample:
    head: str
    middle: str
    tail: str
    encoding: str
    compression: str | None
    bytes_sampled: int
    records_sampled: int
    notes: tuple[str, ...]


@dataclass(frozen=True)
class DetectionResult:
    primary_type: str
    candidate_types: tuple[str, ...]
    confidence: str
    matched_features: tuple[str, ...]
    bytes_sampled: int
    records_sampled: int
    needs_confirmation: bool
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
```

`bounded_io.sample_text()` must inspect gzip by `1f 8b` magic, cap decompressed bytes during detection, decode in the deterministic order BOM-aware UTF-8, UTF-8, GB18030, then UTF-8 replacement, and only read middle/tail slices during the extended phase for seekable uncompressed files.

- [ ] **Step 4: Implement explainable detector profiles and inventory dispatch**

Each profile returns named features, not a numeric threat score. Use these minimum high-confidence combinations:

| Type | Required high-confidence features |
|---|---|
| `web_access` | access timestamp + quoted request + HTTP status |
| `spring_app` | ISO timestamp + level + thread/logger layout |
| `p6spy_sql` | P6Spy marker + SQL statement layout |
| `auth_text` | syslog/auth timestamp + sshd/PAM/password result |
| `firewall_text` | source/destination tuple + DROP/REJECT/DENY/action |
| `mysqlbinlog_text` | `# at`/`end_log_pos` + table/row/query event marker |
| `json_text` | valid records + at least two security-relevant field names |
| `csv_table` | stable header row + time/IP/account/action field family |
| `xlsx_login` | login time/IP plus user field family |
| `xlsx_operate` | operation/module/function field family |

One feature family produces non-high confidence and `needs_confirmation=True`. If Spring and P6Spy both meet high confidence, keep Spring as primary and P6Spy as a secondary candidate. If Apache and nginx cannot be distinguished from line format, return `web_access`.

Refactor `inventory_logs.py` to call `detect_file()`, preserve `declared_type`, and set `needs_confirmation=True` whenever declared and detected types conflict.

- [ ] **Step 5: Run detector and inventory regression tests**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_detection_v1.py attack-analysis/tests/test_attack_analysis_contract.py -v
```

Expected: all detector fixtures pass; existing verified formats remain recognized.

- [ ] **Step 6: Commit Task 3**

```bash
git add attack-analysis/scripts/common/bounded_io.py attack-analysis/scripts/common/detection_schema.py attack-analysis/scripts/common/io_utils.py attack-analysis/scripts/detectors attack-analysis/scripts/inventory_logs.py attack-analysis/tests/test_detection_v1.py attack-analysis/tests/test_attack_analysis_contract.py
git commit -m "feat: add bounded attack log type detection"
```

---

### Task 4: 中性记录与完整流式扫描

**Files:**
- Create: `attack-analysis/scripts/common/streaming.py`
- Modify: `attack-analysis/scripts/common/event_schema.py:1-48`
- Modify: `attack-analysis/scripts/extract_log_events.py:16-92`
- Modify: `attack-analysis/scripts/parsers/apache_access.py:21-58`
- Modify: `attack-analysis/scripts/parsers/nginx_access.py:1-5`
- Modify: `attack-analysis/scripts/parsers/spring_app.py:24-65`
- Modify: `attack-analysis/scripts/parsers/p6spy_sql.py:24-66`
- Modify: `attack-analysis/scripts/parsers/generic_text.py:16-40`
- Modify: `attack-analysis/scripts/parsers/xlsx_login.py:20-53`
- Modify: `attack-analysis/scripts/parsers/xlsx_operate.py:20-53`
- Test: `attack-analysis/tests/test_streaming_v1.py`

**Interfaces:**
- Parser interface: `iter_records(path: str | Path, context: ParserContext) -> Iterator[dict[str, Any]]`.
- Dispatcher interface: `extract(manifest: dict[str, Any], cache_dir: Path, preview_limit: int = 50) -> dict[str, Any]`.
- Produces: `record-candidates.jsonl` and `scan-summary.json`.
- `extract_log_events.py --json` prints summary and a bounded preview, never the full candidate list.
- Task 5 consumes source locations and noise samples from `ParserContext`.

- [ ] **Step 1: Write the long-tail red test**

Generate 100,001 access-log records, with retained candidates at rows 50,001 and 100,001, and repeat the same content through gzip. Run extraction with `--preview-limit 1` and assert both records exist in JSONL while preview remains one record. Keep module helpers outside the class and place test methods inside `class StreamingV1Tests(unittest.TestCase)`.

```python
import gzip
import json
import tempfile
import tracemalloc
from pathlib import Path

from scripts.extract_log_events import extract


def run_pipeline_for_single_log(root: Path, log: Path, preview_limit: int):
    cache_dir = root / "case-cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "case_id": "tail-case",
        "mode": "quick-report",
        "default_timezone": "Asia/Shanghai",
        "output_paths": {"cache_dir": str(cache_dir)},
        "files": [
            {
                "path": str(log.resolve()),
                "include": True,
                "primary_type": "web_access",
                "candidate_types": [],
                "timezone": "Asia/Shanghai",
            }
        ],
    }
    summary = extract(manifest, cache_dir, preview_limit=preview_limit)
    candidate_path = cache_dir / "record-candidates.jsonl"
    candidates = [json.loads(line) for line in candidate_path.read_text(encoding="utf-8").splitlines() if line]
    return summary, candidates


def _write_long_access_log(path: Path, compressed: bool) -> None:
    opener = gzip.open if compressed else open
    with opener(path, "wt", encoding="utf-8") as fh:
        for line_no in range(1, 100002):
            request_path = "/health"
            status = 200
            if line_no == 50001:
                request_path = "/.git/config"
                status = 404
            if line_no == 100001:
                request_path = "/upload/shell.php"
                status = 200
            fh.write(
                f'198.51.100.23 - - [10/Jul/2026:12:00:00 +0800] "GET {request_path} HTTP/1.1" {status} 123 "-" "curl/8"\n'
            )


def test_plain_and_gzip_scans_reach_tail_candidates(self):
    for compressed in (False, True):
        with self.subTest(compressed=compressed), tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / ("access.log.gz" if compressed else "access.log")
            _write_long_access_log(log, compressed)
            summary, candidates = run_pipeline_for_single_log(root, log, preview_limit=1)
            self.assertEqual(summary["files"][0]["records_scanned"], 100001)
            self.assertEqual([item["source"]["line"] for item in candidates], [50001, 100001])
            self.assertEqual(len(summary["preview"]), 1)


def test_streaming_peak_memory_does_not_scale_with_line_count(self):
    peaks: list[int] = []
    for line_count in (10000, 100000):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "access.log"
            with log.open("w", encoding="utf-8") as fh:
                for _ in range(line_count):
                    fh.write('127.0.0.1 - - [10/Jul/2026:12:00:00 +0800] "GET /health HTTP/1.1" 200 2 "-" "probe"\n')
            tracemalloc.start()
            run_pipeline_for_single_log(root, log, preview_limit=1)
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            peaks.append(peak)
    self.assertLess(peaks[1], peaks[0] * 4 + 8 * 1024 * 1024)
```

- [ ] **Step 2: Run the long-tail test and verify current `break` behavior fails**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_streaming_v1.py -v
```

Expected: FAIL because current parsers stop after their candidate limit and extraction returns an in-memory `events` list instead of JSONL.

- [ ] **Step 3: Add parser context and streaming stats**

Create these shared types in `common/streaming.py`:

```python
@dataclass
class ScanStats:
    records_scanned: int = 0
    records_retained: int = 0
    bad_record_count: int = 0
    decode_error_count: int = 0
    scan_status: str = "complete"
    bytes_scanned: int = 0


@dataclass
class NoiseLedger:
    counts: Counter[str] = field(default_factory=Counter)
    samples: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    max_samples_per_bucket: int = 2

    def observe(self, rule: str, timestamp: str | None, sample: dict[str, Any]) -> None:
        bucket = (timestamp or "unknown")[:13]
        key = f"{rule}|{bucket}"
        self.counts[key] += 1
        values = self.samples.setdefault(key, [])
        if len(values) < self.max_samples_per_bucket:
            values.append(sample)

    def to_dict(self) -> dict[str, Any]:
        return {"counts": dict(self.counts), "samples": self.samples}


@dataclass
class ParserContext:
    file_entry: dict[str, Any]
    stats: ScanStats = field(default_factory=ScanStats)
    noise: NoiseLedger = field(default_factory=NoiseLedger)
```

Replace `make_event()` with this exact neutral constructor in `common/event_schema.py`:

```python
def make_record(
    *,
    timestamp_text: str | None,
    source_file: str,
    source_location: dict[str, int],
    log_type: str,
    record_type: str,
    raw_ref: str,
    actor_ip: str | None = None,
    account_or_user: str | None = None,
    request_or_action: str | None = None,
    status_or_result: str | None = None,
    evidence: str | None = None,
    matched_signals: tuple[str, ...] = (),
    filter_reason: str = "retained_by_parser_rule",
    correlation_keys: dict[str, str | None] | None = None,
    default_timezone: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    parsed_time = parse_timestamp(timestamp_text, default_timezone)
    normalized_ip = normalize_ip(actor_ip)
    keys = dict(correlation_keys or {})
    keys.setdefault("actor_ip", normalized_ip["ip"])
    keys.setdefault("account", account_or_user)
    record: dict[str, Any] = {
        "record_id": None,
        "record_type": record_type,
        "review_status": "unreviewed",
        "timestamp": parsed_time["timestamp"],
        "timestamp_status": parsed_time["status"],
        "timestamp_raw": parsed_time["raw"],
        "source": {"file": source_file, **source_location},
        "log_type": log_type,
        "actor_ip": actor_ip,
        "actor_ip_normalized": normalized_ip["ip"],
        "actor_port": normalized_ip["port"],
        "account_or_user": account_or_user,
        "request_or_action": request_or_action,
        "status_or_result": status_or_result,
        "raw_ref": raw_ref,
        "evidence": evidence,
        "matched_signals": list(matched_signals),
        "filter_reason": filter_reason,
        "correlation_keys": keys,
    }
    if extra:
        record.update(extra)
    return record
```

- [ ] **Step 4: Convert every parser to the generator protocol**

Remove every `if len(events) >= limit: break`. Use this neutral type mapping:

| Parser | `record_type` |
|---|---|
| Apache/nginx | `http_request` |
| Spring | `application_record` |
| P6Spy | `sql_record` |
| Generic text | `text_record` |
| XLSX login | `login_record` |
| XLSX operation | `operation_record` |

The Web parser must treat exact `/health` and routine static assets as transparent noise unless another signal is present. Signals include sensitive paths, non-GET/HEAD methods, 4xx/5xx results, encoded or unusually long paths, upload-like paths, and new parser-specific structural anomalies. Spring must skip lines owned by the P6Spy profile to prevent duplicate records. P6Spy may record mutation operations and credential/table predicates as signals but must not label them malicious.

`extract_log_events.py` must open `record-candidates.jsonl` once, assign `rec-000001` IDs while iterating generators, write each record immediately, and write aggregate file stats to `scan-summary.json` after all files finish. The preview list is bounded independently and does not affect scanning.

- [ ] **Step 5: Run streaming, parser and compilation checks**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_streaming_v1.py attack-analysis/tests/test_attack_analysis_contract.py -v
python3 -m py_compile attack-analysis/scripts/*.py attack-analysis/scripts/parsers/*.py attack-analysis/scripts/common/*.py attack-analysis/scripts/detectors/*.py
```

Expected: long-tail plain/gzip tests pass, existing fixture candidates use neutral record types, and compilation exits 0.

- [ ] **Step 6: Commit Task 4**

```bash
git add attack-analysis/scripts/common/event_schema.py attack-analysis/scripts/common/streaming.py attack-analysis/scripts/extract_log_events.py attack-analysis/scripts/parsers attack-analysis/tests/test_streaming_v1.py attack-analysis/tests/test_attack_analysis_contract.py
git commit -m "refactor: stream neutral attack log candidates"
```

---

### Task 5: 透明降噪复核与上下文提取

**Files:**
- Create: `attack-analysis/scripts/extract_context.py`
- Modify: `attack-analysis/scripts/common/streaming.py`
- Modify: `attack-analysis/scripts/extract_log_events.py`
- Test: `attack-analysis/tests/test_context_correlation_v1.py`

**Interfaces:**
- Produces: `extract_text_context(path, line_start, line_end, before, after, contains, start_time, end_time, timezone, max_records) -> dict[str, Any]`.
- Produces: `extract_xlsx_context(path, row_start, row_end, before, after, contains, max_records) -> dict[str, Any]`.
- CLI consumes exact source paths from candidate records; it never accepts an unverified path from network enrichment.
- Produces context output with `records`, `records_scanned`, `records_returned`, `truncated`, and query metadata.

- [ ] **Step 1: Write context extraction and noise transparency tests**

```python
def test_extract_context_returns_exact_line_window(self):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "app.log"
        path.write_text("one\ntwo\nthree\nfour\nfive\n", encoding="utf-8")
        result = extract_text_context(path, line_start=3, line_end=3, before=1, after=1)
        self.assertEqual([item["line"] for item in result["records"]], [2, 3, 4])
        self.assertEqual([item["text"] for item in result["records"]], ["two", "three", "four"])
        self.assertFalse(result["truncated"])


def test_noise_summary_keeps_rule_counts_and_time_bucket_samples(self):
    ledger = NoiseLedger(max_samples_per_bucket=1)
    ledger.observe("routine_health", "2026-07-10T12:00:00+08:00", {"line": 1})
    ledger.observe("routine_health", "2026-07-10T12:30:00+08:00", {"line": 2})
    summary = ledger.to_dict()
    self.assertEqual(summary["counts"]["routine_health|2026-07-10T12"], 2)
    self.assertEqual(summary["samples"]["routine_health|2026-07-10T12"], [{"line": 1}])
```

- [ ] **Step 2: Verify the context module is absent**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_context_correlation_v1.py -v
```

Expected: import failure for `scripts.extract_context`.

- [ ] **Step 3: Implement bounded context queries**

Implement this text function and an XLSX equivalent using `iter_rows()`:

```python
from datetime import datetime


def _iso_epoch(value: str | None) -> float | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def extract_text_context(
    path: Path,
    line_start: int | None = None,
    line_end: int | None = None,
    before: int = 0,
    after: int = 0,
    contains: tuple[str, ...] = (),
    start_time: str | None = None,
    end_time: str | None = None,
    timezone: str | None = None,
    max_records: int = 500,
) -> dict[str, Any]:
    target_start = max(1, (line_start or 1) - before)
    target_end = (line_end if line_end is not None else line_start)
    if target_end is not None:
        target_end += after
    records: list[dict[str, Any]] = []
    scanned = 0
    truncated = False
    start_epoch = _iso_epoch(start_time)
    end_epoch = _iso_epoch(end_time)
    for line_no, text in iter_text_lines(path):
        scanned = line_no
        if target_end is not None and line_no > target_end:
            break
        if line_no < target_start:
            continue
        if contains and not all(value.lower() in text.lower() for value in contains):
            continue
        parsed = parse_timestamp(text, timezone)
        timestamp = parsed.get("timestamp")
        timestamp_epoch = _iso_epoch(timestamp)
        if start_epoch is not None and timestamp_epoch is not None and timestamp_epoch < start_epoch:
            continue
        if end_epoch is not None and timestamp_epoch is not None and timestamp_epoch > end_epoch:
            continue
        if len(records) >= max_records:
            truncated = True
            continue
        records.append({"line": line_no, "text": text, "timestamp": timestamp})
    return {
        "path": str(path.resolve()),
        "records_scanned": scanned,
        "records_returned": len(records),
        "truncated": truncated,
        "records": records,
    }
```

Implement `extract_xlsx_context()` with the same window, content-filter and truncation semantics, replacing line numbers with XLSX row numbers and using `iter_rows(path)`.

CLI options: `--path`, `--line-start`, `--line-end`, `--before`, `--after`, repeatable `--contains`, `--start-time`, `--end-time`, `--timezone`, `--max-records`, `--output`, and `--json`. Refuse negative line numbers and require at least a line range, content filter, or time range.

- [ ] **Step 4: Extend scan summaries with recoverable noise references**

Every noise sample written to `scan-summary.json` must contain source file and line/row. Add aggregate counts for retained and suppressed records. Do not copy complete suppressed records into memory; retain only the configured per-rule/time-bucket samples.

- [ ] **Step 5: Run focused tests and commit**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_context_correlation_v1.py attack-analysis/tests/test_streaming_v1.py -v
```

Expected: context windows and noise ledger tests pass.

```bash
git add attack-analysis/scripts/extract_context.py attack-analysis/scripts/common/streaming.py attack-analysis/scripts/extract_log_events.py attack-analysis/tests/test_context_correlation_v1.py
git commit -m "feat: add AI-directed log context extraction"
```

---

### Task 6: 可扩展机械关联候选

**Files:**
- Modify: `attack-analysis/scripts/correlate_events.py:1-117`
- Modify: `attack-analysis/scripts/common/event_schema.py`
- Modify: `attack-analysis/tests/test_context_correlation_v1.py`

**Interfaces:**
- Consumes: `record-candidates.jsonl` records with `correlation_keys`.
- Produces: `correlation-candidates.json`, optional `correlation-index.sqlite3`, and only `status="candidate"` results.
- Public function: `correlate_jsonl(events_path, index_path, window_seconds, limit) -> dict[str, Any]`.

- [ ] **Step 1: Add failing multi-key candidate tests**

Create records from different files sharing IP and session within 300 seconds, plus a same-IP record outside the window. Assert only the nearby pair is returned, basis contains both mechanical keys, and status remains candidate.

```python
import json
import tempfile
from pathlib import Path

from scripts.correlate_events import correlate_jsonl


def record(record_id: str, timestamp: str, source_file: str, keys: dict[str, str]) -> dict[str, object]:
    return {
        "record_id": record_id,
        "timestamp": timestamp,
        "source": {"file": source_file, "line": 1},
        "correlation_keys": {
            "actor_ip": keys.get("ip"),
            "account": keys.get("account"),
            "request_id": keys.get("request"),
            "session_id": keys.get("session"),
            "http_path": keys.get("path"),
            "thread": keys.get("thread"),
            "sql_table": keys.get("sql_table"),
        },
    }


def correlate_fixture(records: list[dict[str, object]], window_seconds: int) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        events_path = root / "record-candidates.jsonl"
        events_path.write_text(
            "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
            encoding="utf-8",
        )
        return correlate_jsonl(events_path, root / "correlation-index.sqlite3", window_seconds, limit=100)


def test_correlation_uses_multiple_keys_without_asserting_causality(self):
    records = [
        record("rec-1", "2026-07-10T12:00:00+08:00", "access.log", {"ip": "198.51.100.23", "session": "s-1"}),
        record("rec-2", "2026-07-10T12:02:00+08:00", "app.log", {"ip": "198.51.100.23", "session": "s-1"}),
        record("rec-3", "2026-07-10T13:00:00+08:00", "app.log", {"ip": "198.51.100.23"}),
    ]
    result = correlate_fixture(records, window_seconds=300)
    self.assertEqual(len(result["correlations"]), 1)
    self.assertEqual(result["correlations"][0]["status"], "candidate")
    self.assertEqual(set(result["correlations"][0]["basis"]), {"same_ip", "same_session"})
```

- [ ] **Step 2: Run the focused test and observe the old JSON contract fail**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_context_correlation_v1.py -v
```

Expected: FAIL because the existing correlator expects a JSON object containing `events` and lacks session/request/path/thread keys.

- [ ] **Step 3: Implement a disk-backed ordered index**

Stream JSONL records into SQLite columns `record_id`, `timestamp_epoch`, `source_file`, `source_location`, and normalized correlation fields. Create indexes for non-empty `actor_ip`, `account`, `request_id`, `session_id`, `http_path`, `thread`, and `sql_table`. For each field, query ordered values and maintain a deque limited to `window_seconds`; only pair records from different source files or different parser profiles.

Use this basis mapping:

```python
KEY_BASIS = {
    "actor_ip": "same_ip",
    "account": "same_account",
    "request_id": "same_request_id",
    "session_id": "same_session",
    "http_path": "same_path",
    "thread": "same_thread",
    "sql_table": "same_sql_table",
}
```

Merge duplicate record pairs by sorted record IDs and combine basis values. Output `time_delta_seconds`, original evidence references, `status: candidate`, and `notes: ["mechanical match only; AI review required"]`. `limit` may cap written correlation candidates but must report `candidate_pairs_seen` and `output_truncated`; it must not change record scan completeness.

- [ ] **Step 4: Run correlation and gold fixture tests**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_context_correlation_v1.py attack-analysis/tests/test_attack_analysis_contract.py -v
```

Expected: multi-key correlation passes and no output asserts causality.

- [ ] **Step 5: Commit Task 6**

```bash
git add attack-analysis/scripts/correlate_events.py attack-analysis/scripts/common/event_schema.py attack-analysis/tests/test_context_correlation_v1.py attack-analysis/tests/test_attack_analysis_contract.py
git commit -m "feat: expand mechanical log correlation candidates"
```

---

### Task 7: AI 证据台账与 Markdown 报告验证

**Files:**
- Create: `attack-analysis/scripts/validate_report.py`
- Create: `attack-analysis/tests/test_report_contract_v1.py`
- Modify: `attack-analysis/references/reporting.md:1-36`

**Interfaces:**
- AI writes draft Markdown and `evidence-ledger.json`.
- Produces: `validate_report(report_text, ledger) -> list[str]` and `finalize_report(draft_path, final_path, ledger_path) -> dict[str, Any]`.
- Validator only checks structure and performs atomic rename after success; it never edits report content.

- [ ] **Step 1: Write passing and failing report fixtures in the test**

The valid report must contain all required headings and cite `E001`; the ledger must define `E001`. Add failing cases for missing evidence, forbidden score language, missing heading, and attempted finalization into the wrong directory.

```python
import json
import tempfile
from pathlib import Path

from scripts.validate_report import REQUIRED_HEADINGS, finalize_report, validate_report

VALID_REPORT = "\n\n".join(f"{heading}\n结论引用证据 E001。" for heading in REQUIRED_HEADINGS) + "\n"


def test_valid_ai_report_is_atomically_finalized(self):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        report_dir = root / "report" / "case-1"
        report_dir.mkdir(parents=True)
        draft = report_dir / ".log-analysis-report.md.tmp"
        final = report_dir / "log-analysis-report.md"
        ledger = root / "cache" / "case-1" / "evidence-ledger.json"
        ledger.parent.mkdir(parents=True)
        draft.write_text(VALID_REPORT, encoding="utf-8")
        ledger.write_text(json.dumps({"evidence": [{"evidence_id": "E001"}]}), encoding="utf-8")
        result = finalize_report(draft, final, ledger)
        self.assertTrue(result["valid"])
        self.assertTrue(final.exists())
        self.assertFalse(draft.exists())


def test_report_rejects_missing_evidence_and_threat_score(self):
    errors = validate_report(VALID_REPORT + "\n威胁评分：98\n证据 E999", {"evidence": [{"evidence_id": "E001"}]})
    self.assertIn("forbidden_rating_language", errors)
    self.assertIn("unknown_evidence_id:E999", errors)
```

- [ ] **Step 2: Run the report test and verify missing validator failure**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_report_contract_v1.py -v
```

Expected: import failure for `scripts.validate_report`.

- [ ] **Step 3: Implement structural validation and atomic finalization**

Use the exact required headings from the approved design. Extract evidence IDs with `\bE\d{3,}\b`. Reject `威胁评分`, `风险总分`, `threat score`, and `risk score` case-insensitively. Require the final filename to be `log-analysis-report.md`, require its parent path to include `report/<case-id>`, and use `os.replace(draft_path, final_path)` only when the error list is empty.

```python
REQUIRED_HEADINGS = (
    "## 摘要结论",
    "## 分析范围与日志类型识别结果",
    "## 时间范围、时区和日志缺口",
    "## 攻击来源 IP、ASN、运营商、初步定位及查询来源",
    "## 完整攻击时间线",
    "## 攻击方式与实现过程",
    "## 跨日志证据链",
    "## 是否存在成功入侵的证据判断",
    "## 关键证据表",
    "## 当前存在的问题",
    "## 立即处置、短期修复和长期加固建议",
    "## 不确定性、缺失日志和待补证事项",
)
EVIDENCE_RE = re.compile(r"\bE\d{3,}\b")
FORBIDDEN_RATING_RE = re.compile(r"威胁评分|风险总分|threat\s+score|risk\s+score", re.I)


def validate_report(report_text: str, ledger: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for heading in REQUIRED_HEADINGS:
        if heading not in report_text:
            errors.append(f"missing_heading:{heading}")
    if FORBIDDEN_RATING_RE.search(report_text):
        errors.append("forbidden_rating_language")
    known = {item["evidence_id"] for item in ledger.get("evidence", []) if item.get("evidence_id")}
    for evidence_id in sorted(set(EVIDENCE_RE.findall(report_text))):
        if evidence_id not in known:
            errors.append(f"unknown_evidence_id:{evidence_id}")
    return errors


def finalize_report(draft_path: Path, final_path: Path, ledger_path: Path) -> dict[str, Any]:
    if final_path.name != "log-analysis-report.md" or final_path.parent.parent.name != "report":
        return {"valid": False, "errors": ["invalid_report_output_path"]}
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    text = draft_path.read_text(encoding="utf-8")
    errors = validate_report(text, ledger)
    if errors:
        return {"valid": False, "errors": errors}
    final_path.parent.mkdir(parents=True, exist_ok=True)
    os.replace(draft_path, final_path)
    return {"valid": True, "errors": [], "report_path": str(final_path.resolve())}
```

- [ ] **Step 4: Run report contract tests**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_report_contract_v1.py -v
```

Expected: valid report finalizes; invalid reports remain drafts and return exact error codes.

- [ ] **Step 5: Commit Task 7**

```bash
git add attack-analysis/scripts/validate_report.py attack-analysis/tests/test_report_contract_v1.py attack-analysis/references/reporting.md
git commit -m "feat: validate AI-written attack analysis reports"
```

---

### Task 8: v1.0.0 Skill 工作流与文档契约

**Files:**
- Modify: `attack-analysis/SKILL.md:1-91`
- Modify: `attack-analysis/references/workflow.md:1-67`
- Modify: `attack-analysis/references/log-types.md:1-35`
- Modify: `attack-analysis/references/correlation.md:1-35`
- Modify: `attack-analysis/references/error-handling.md:1-25`
- Modify: `attack-analysis/references/ip-enrichment.md:1-38`
- Modify: `attack-analysis/references/reporting.md`
- Modify: `attack-analysis/references/validation.md:1-19`
- Modify: `attack-analysis/agents/openai.yaml:1-4`
- Modify: `attack-analysis/.gitignore:1-16`
- Modify: `README.md`
- Modify: `attack-analysis/tests/test_attack_analysis_contract.py`

**Interfaces:**
- `SKILL.md` remains the single behavior contract.
- Documentation must reference the exact CLI and output paths introduced by Tasks 1-7.
- No document may describe script candidates as final attack conclusions.

- [ ] **Step 1: Strengthen contract tests before editing docs**

Add assertions for all approved invariants:

```python
def test_v1_ai_first_contract_and_output_layout(self):
    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    self.assertIn("Version: 1.0.0", skill)
    self.assertIn("AI 决定", skill)
    self.assertIn("脚本不得判定", skill)
    self.assertIn("cache/<case-id>", skill)
    self.assertIn("report/<case-id>/log-analysis-report.md", skill)
    self.assertIn("完整流式扫描", skill)
    self.assertIn("非高置信度", skill)
    self.assertIn("禁止输出威胁评分", skill)


def test_generated_outputs_are_ignored(self):
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    self.assertIn("cache/", ignore)
    self.assertIn("report/", ignore)
```

- [ ] **Step 2: Run contract tests and verify old version wording fails**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_attack_analysis_contract.py -v
```

Expected: FAIL because current docs describe 0.1.0-era output and lack v1.0.0 AI-first wording.

- [ ] **Step 3: Rewrite the skill entrypoint and references**

Keep `SKILL.md` concise and route details to references. Its fixed order must be:

1. Confirm current-turn mode.
2. Confirm source paths and invocation workdir.
3. Run bounded type detection.
4. Automatically accept only high-confidence types; consolidate all other confirmations.
5. Build manifest under `cache/<case-id>`.
6. Run complete streaming filtering and read `scan-summary.json`.
7. AI reviews candidates, noise samples and raw context.
8. Generate mechanical correlation candidates; AI accepts or rejects them.
9. Perform privacy-bounded network enrichment.
10. AI writes evidence ledger and report draft.
11. Validate and atomically finalize Markdown under `report/<case-id>`.
12. Return absolute report path.

Add an explicit table separating AI decisions from script mechanics. Replace all old script commands with current CLI examples. Update `log-types.md` with v1.0 verified/best-effort/future boundaries. Update `error-handling.md` with encoding, corrupt gzip, source mutation, partial cache and self-output exclusion. Update `validation.md` with all new test commands.

Set agent prompt to instruct the model to act as investigator, treat script output as candidates, and write the local report. Update README from `Attack Analysis 0.1.0` to `Attack Analysis 1.0.0`. Add `report/` to the skill `.gitignore`.

- [ ] **Step 4: Run contract, frontmatter and banned-language checks**

Run:

```bash
python3 -m unittest attack-analysis/tests/test_attack_analysis_contract.py attack-analysis/tests/test_report_contract_v1.py -v
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py attack-analysis
! rg -n '"event_type": "(web_probe|sql_suspicious)"|"record_type": "(web_probe|sql_suspicious)"' attack-analysis README.md
```

Expected: tests pass, validator prints `Skill is valid!`, and no script or fixture still emits the old conclusion-style record types.

- [ ] **Step 5: Commit Task 8**

```bash
git add README.md attack-analysis/SKILL.md attack-analysis/agents/openai.yaml attack-analysis/.gitignore attack-analysis/references attack-analysis/tests/test_attack_analysis_contract.py
git commit -m "docs: define attack analysis v1.0.0 workflow"
```

---

### Task 9: Gold case、异常回归与最终验收

**Files:**
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/access.log`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/app.log`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/p6spy.log`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/login.xlsx`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/operate.xlsx`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/expected_timeline.json`
- Modify: `attack-analysis/tests/fixtures/gold_attack_case/expected_findings.md`
- Create: `attack-analysis/tests/fixtures/gold_attack_case/evidence-ledger.json`
- Create: `attack-analysis/tests/fixtures/gold_attack_case/log-analysis-report.md`
- Modify: `attack-analysis/tests/test_attack_analysis_contract.py`
- Modify: `attack-analysis/tests/test_detection_v1.py`
- Modify: `attack-analysis/tests/test_streaming_v1.py`
- Modify: `attack-analysis/tests/test_report_contract_v1.py`

**Interfaces:**
- Exercises the exact CLI chain from inventory through report validation.
- Static gold report represents AI output only for deterministic validator testing; production scripts still do not generate conclusions.
- Final test output must use temporary workdirs and never write into tracked fixture directories.

- [ ] **Step 1: Expand the gold scenario and write the failing end-to-end assertion**

The fixture must include these evidence anchors:

- External scan against a sensitive path.
- Authentication attempts from the same source.
- One successful login candidate that requires AI context review.
- Application request and P6Spy SQL operation within a plausible window.
- One normal administrator action from a different source.
- One same-IP event outside the correlation window.
- Mixed explicit `+0800`, inferred `Asia/Shanghai`, and unknown timezone records.
- A proxy chain where attacker position cannot be inferred without proxy configuration.
- One candidate that the static gold report explicitly rejects as unrelated.

The end-to-end test runs inventory, extraction, correlation, copies the static AI ledger/report draft to the generated case paths, validates it, and asserts the final report exists.

```python
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from scripts.validate_report import finalize_report

PY = sys.executable
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "gold_attack_case"


def run_inventory(source: Path, workdir: Path, case_id: str) -> dict[str, object]:
    result = subprocess.run(
        [
            PY,
            str(ROOT / "scripts" / "inventory_logs.py"),
            str(source),
            "--mode",
            "quick-report",
            "--case-id",
            case_id,
            "--workdir",
            str(workdir),
            "--json",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def run_extract(manifest: dict[str, object]) -> None:
    cache_dir = Path(manifest["output_paths"]["cache_dir"])
    subprocess.run(
        [PY, str(ROOT / "scripts" / "extract_log_events.py"), "--manifest", str(cache_dir / "analysis-manifest.json")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )


def run_correlate(manifest: dict[str, object]) -> None:
    cache_dir = Path(manifest["output_paths"]["cache_dir"])
    subprocess.run(
        [
            PY,
            str(ROOT / "scripts" / "correlate_events.py"),
            "--events",
            str(cache_dir / "record-candidates.jsonl"),
            "--output-dir",
            str(cache_dir),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )


def install_gold_ai_outputs(workdir: Path, case_id: str) -> tuple[Path, Path, Path]:
    report_dir = workdir / "report" / case_id
    cache_dir = workdir / "cache" / case_id
    draft = report_dir / ".log-analysis-report.md.tmp"
    final = report_dir / "log-analysis-report.md"
    ledger = cache_dir / "evidence-ledger.json"
    shutil.copyfile(FIXTURE / "log-analysis-report.md", draft)
    shutil.copyfile(FIXTURE / "evidence-ledger.json", ledger)
    return draft, final, ledger


def test_v1_gold_case_pipeline_writes_valid_local_report(self):
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        manifest = run_inventory(FIXTURE, workdir, case_id="gold-v1")
        self.assertEqual(Path(manifest["output_paths"]["cache_dir"]), workdir / "cache" / "gold-v1")
        run_extract(manifest)
        run_correlate(manifest)
        draft, final, ledger = install_gold_ai_outputs(workdir, "gold-v1")
        validation = finalize_report(draft, final, ledger)
        self.assertTrue(validation["valid"])
        self.assertTrue(final.exists())
        cache_dir = workdir / "cache" / "gold-v1"
        candidates = [
            json.loads(line)
            for line in (cache_dir / "record-candidates.jsonl").read_text(encoding="utf-8").splitlines()
            if line
        ]
        record_types = {item["record_type"] for item in candidates}
        self.assertTrue({"http_request", "application_record", "sql_record", "login_record"}.issubset(record_types))
        correlations = json.loads((cache_dir / "correlation-candidates.json").read_text(encoding="utf-8"))
        self.assertTrue(all(item["status"] == "candidate" for item in correlations["correlations"]))
        report_text = final.read_text(encoding="utf-8")
        self.assertIn("正常管理员操作未纳入攻击链", report_text)
        self.assertIn("代理配置未知", report_text)
```

- [ ] **Step 2: Add explicit failure fixtures**

Add tests that create a truncated gzip stream, invalid UTF-8 mixed with GB18030-compatible bytes, a source file modified between stat snapshots, an unsupported binary file, and a source directory containing generated `cache/` and `report/`. Assert exact states: `partial`, nonzero decode errors, `source_changed_during_scan=True`, `include=False` with `unsupported_or_binary_unknown`, and generated outputs absent from manifest.

- [ ] **Step 3: Implement deterministic failure-state handling**

Update bounded IO and dispatcher boundaries so `EOFError`, `gzip.BadGzipFile`, `UnicodeError`, malformed XLSX, and parser exceptions are caught per file. Preserve records emitted before failure, set `scan_status="partial"`, and append a machine-readable error string to that file's scan summary. Count Unicode replacement characters as `decode_error_count`. Record source `stat()` before and after parsing and set `source_changed_during_scan` when size or `mtime_ns` differs. Inventory must mark unsupported binary input `include=False` with `unsupported_or_binary_unknown`, and `discover()` must exclude resolved output roots before recursion.

- [ ] **Step 4: Run the entire suite**

Run:

```bash
python3 -m unittest discover -s attack-analysis/tests -v
```

Expected: all tests pass with zero errors and zero failures. Do not weaken assertions to accommodate old behavior; correct implementation defects at their source.

- [ ] **Step 5: Run compilation, skill validation and CLI smoke tests**

Run:

```bash
python3 -m py_compile attack-analysis/scripts/*.py attack-analysis/scripts/parsers/*.py attack-analysis/scripts/common/*.py attack-analysis/scripts/detectors/*.py
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py attack-analysis
tmpdir="$(mktemp -d)"
python3 attack-analysis/scripts/inventory_logs.py attack-analysis/tests/fixtures/gold_attack_case --mode quick-report --case-id gold-smoke --workdir "$tmpdir" --json >"$tmpdir/inventory.json"
python3 attack-analysis/scripts/extract_log_events.py --manifest "$tmpdir/cache/gold-smoke/analysis-manifest.json" --json >"$tmpdir/extract.json"
python3 attack-analysis/scripts/correlate_events.py --events "$tmpdir/cache/gold-smoke/record-candidates.jsonl" --output-dir "$tmpdir/cache/gold-smoke" --json >"$tmpdir/correlate.json"
test -f "$tmpdir/cache/gold-smoke/scan-summary.json"
test -f "$tmpdir/cache/gold-smoke/correlation-candidates.json"
```

Expected: compilation exits 0, skill validator prints `Skill is valid!`, CLI commands exit 0, and both cache files exist.

- [ ] **Step 6: Run optional local real-sample regression without staging data**

If local private samples are present, run them from a temporary workdir in `quick-report` mode. Verify parser errors, scan completeness, output locations and report workflow manually. Never use `git add -f` on real logs, local reports or generated cache files.

- [ ] **Step 7: Verify the final diff contains only intended v1 files**

Run:

```bash
git status --short
git diff --check
git diff --name-only origin/main...HEAD
git ls-files attack-analysis | rg "(^|/)(cache|report|output)/|access_qugongbao_com|趣工宝运营后台|系统操作、登录记录" && exit 1 || true
```

Expected: no whitespace errors, no private samples or generated outputs tracked, and unrelated `attack-analysis.zip` plus `osint-skill/` remain untouched.

- [ ] **Step 8: Commit final fixtures and regression coverage**

```bash
git add attack-analysis/tests attack-analysis/scripts attack-analysis/references attack-analysis/SKILL.md attack-analysis/agents/openai.yaml attack-analysis/.gitignore README.md
git diff --cached --check
git commit -m "test: validate attack analysis v1.0.0 workflow"
```

---

## Final Completion Gate

Before claiming v1.0.0 complete, rerun from a clean shell:

```bash
python3 -m unittest discover -s attack-analysis/tests -v
python3 -m py_compile attack-analysis/scripts/*.py attack-analysis/scripts/parsers/*.py attack-analysis/scripts/common/*.py attack-analysis/scripts/detectors/*.py
python3 /Users/penglai/.codex/skills/.system/skill-creator/scripts/quick_validate.py attack-analysis
git diff --check origin/main...HEAD
git status --short --branch
```

Read every command's exit code and full summary. Completion requires zero test failures, zero compilation errors, `Skill is valid!`, no diff whitespace errors, and no tracked private or generated artifacts.
