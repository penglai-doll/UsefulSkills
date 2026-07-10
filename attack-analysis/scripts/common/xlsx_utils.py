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
    values: list[str] = []
    with zf.open("xl/sharedStrings.xml") as stream:
        for _, elem in ET.iterparse(stream, events=("end",)):
            if elem.tag.endswith("}si"):
                values.append("".join(t.text or "" for t in elem.findall(".//a:t", NS)))
                elem.clear()
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
            [n for n in zf.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", n)],
            key=lambda n: int(re.search(r"sheet(\d+)\.xml", n).group(1)),
        )
        if sheet_index < 0 or sheet_index >= len(sheets):
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
                elem.clear()
                yield row_number, values
                emitted += 1
                if max_rows is not None and emitted >= max_rows:
                    break


def read_header(path: str | Path) -> list[str]:
    for _, row in iter_rows(path, max_rows=1):
        return [str(v).strip() for v in row]
    return []
