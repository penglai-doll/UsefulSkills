"""Small stdlib-only xlsx reader for simple exported tables."""

from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile
import re
import xml.etree.ElementTree as ET

NS = {"a": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def _shared_strings(zf: ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for si in root.findall("a:si", NS):
        values.append("".join(t.text or "" for t in si.findall(".//a:t", NS)))
    return values


def _cell_value(cell: ET.Element, shared: list[str]) -> str:
    value_node = cell.find("a:v", NS)
    inline = cell.find("a:is", NS)
    if inline is not None:
        return "".join(t.text or "" for t in inline.findall(".//a:t", NS))
    if value_node is None:
        return ""
    value = value_node.text or ""
    if cell.get("t") == "s" and value.isdigit():
        idx = int(value)
        if 0 <= idx < len(shared):
            return shared[idx]
    return value


def iter_rows(path: str | Path, max_rows: int | None = None):
    with ZipFile(path) as zf:
        shared = _shared_strings(zf)
        sheets = sorted(
            [n for n in zf.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)],
            key=lambda n: int(re.search(r"sheet(\d+)\.xml", n).group(1)),
        )
        if not sheets:
            return
        root = ET.fromstring(zf.read(sheets[0]))
        for idx, row in enumerate(root.findall(".//a:sheetData/a:row", NS), 1):
            cells = row.findall("a:c", NS)
            yield idx, [_cell_value(cell, shared) for cell in cells]
            if max_rows is not None and idx >= max_rows:
                break


def read_header(path: str | Path) -> list[str]:
    for _, row in iter_rows(path, max_rows=1):
        return [str(v).strip() for v in row]
    return []
