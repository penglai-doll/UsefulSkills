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
