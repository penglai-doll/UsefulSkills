"""Protocol association and cache tests that do not require installed TShark."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from wiretoutetu_core import analyzer, tshark_backend
from wiretoutetu_core.case_state import CaseState


class ParserRegressions(unittest.TestCase):
    def test_http2_connection_control_is_not_a_partial_transaction(self):
        packets = [
            {"frame.number": "1", "tcp.stream": "0", "http2.streamid": "0"},
            {"frame.number": "2", "tcp.stream": "0", "http2.streamid": "1", "http2.headers.method": "GET"},
            {"frame.number": "3", "tcp.stream": "0", "http2.streamid": "1", "http2.headers.status": "200"},
        ]
        transactions = analyzer._build_http2(packets, "a" * 64)
        self.assertEqual(len(transactions), 1)
        self.assertEqual(transactions[0]["transport_index"]["substream"], 1)
        self.assertEqual(transactions[0]["completeness"], "complete")

    def test_record_separator_stays_inside_a_tsv_field(self):
        fields = ("frame.number", "tcp.stream", "http2.streamid")
        output = '\t'.join(fields) + '\n"1"\t"0"\t"1\x1e3"\n'
        with patch.object(tshark_backend, "tshark_path", return_value="tshark"), \
             patch.object(tshark_backend, "available_fields", return_value=frozenset(fields)), \
             patch.object(tshark_backend.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            result = tshark_backend.extract_packets("capture.pcap")
        self.assertEqual(len(result.packets), 1)
        self.assertEqual(result.packets[0]["http2.streamid"], "1\x1e3")

    def test_http2_multiplexing_is_retained_without_inventing_header_associations(self):
        packets = [{"frame.number": "12", "tcp.stream": "0", "http2.streamid": "1\x1e3",
                    "http2.headers.method": "GET\x1ePOST", "http2.headers.path": "/one\x1e/three",
                    "http2.headers.status": "200"}]
        transactions = analyzer._build_http2(packets, "a" * 64)
        self.assertEqual([row["transport_index"]["substream"] for row in transactions], [1, 3])
        for row in transactions:
            self.assertEqual(row["completeness"], "partial")
            self.assertEqual(row["request"], {})
            self.assertEqual(row["response"], {})
            self.assertEqual(row["ambiguous_frames"], [12])
        packets += [
            {"frame.number": "13", "tcp.stream": "0", "http2.streamid": "1", "http2.headers.method": "GET", "http2.headers.path": "/one"},
            {"frame.number": "14", "tcp.stream": "0", "http2.streamid": "1", "http2.headers.status": "200"},
        ]
        first = analyzer._build_http2(packets, "a" * 64)[0]
        self.assertEqual(first["request"]["path"], "/one")
        self.assertEqual(first["response"]["status"], 200)
        self.assertEqual(first["completeness"], "partial")

    def test_http_informational_response_does_not_consume_the_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture.pcap"
            capture.write_bytes(b"synthetic")
            state = CaseState.create(root / "case", capture, [])
            packets = [
                {"frame.number": "1", "tcp.stream": "0", "http.request.method": "POST", "http.request.uri": "/upload"},
                {"frame.number": "2", "tcp.stream": "0", "http.response.code": "100"},
                {"frame.number": "3", "tcp.stream": "0", "http.response.code": "103"},
                {"frame.number": "4", "tcp.stream": "0", "http.response.code": "200", "http.file_data": "4f4b"},
            ]
            transactions, objects = analyzer._build_http(packets, "a" * 64, state)
            self.assertEqual(len(transactions), 1)
            self.assertEqual(transactions[0]["request"]["uri"], "/upload")
            self.assertEqual(transactions[0]["response"]["status"], 200)
            self.assertEqual([r["status"] for r in transactions[0]["request"]["informational_responses"]], [100, 103])
            self.assertEqual(Path(objects[0]["extraction_path"]).read_bytes(), b"OK")

    def test_tls_sidecar_changes_rerun_inventory_but_webshell_profiles_do_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture.pcap"
            capture.write_bytes(b"synthetic")
            keylog = root / "keys.log"
            # Long comment and a server-only TLS 1.3 secret must still be recognized.
            keylog.write_text("#" + "x" * 300 + "\nSERVER_TRAFFIC_SECRET_0 aa bb\n", encoding="ascii")
            extraction = tshark_backend.TSharkExtraction([], [], "", ())
            with patch.object(analyzer, "run_preflight", return_value={"platform_route": "windows", "tools": {}}), \
                 patch.object(analyzer, "extract_packets", return_value=extraction) as extract:
                first = analyzer.analyze_capture(capture, case_dir=root / "case", sidecars=[])
                second = analyzer.analyze_capture(capture, case_dir=root / "case", sidecars=[keylog])
                self.assertFalse(second["summary"]["inventory_cache_reused"])
                self.assertEqual(extract.call_count, 2)
                keylog.write_text("SERVER_TRAFFIC_SECRET_0 aa cc\n", encoding="ascii")
                analyzer.analyze_capture(capture, case_dir=root / "case", sidecars=[keylog])
                self.assertEqual(extract.call_count, 3)
                profile = root / "profile.json"
                profile.write_text(json.dumps({"webshell_profiles": []}), encoding="utf-8")
                fourth = analyzer.analyze_capture(capture, case_dir=root / "case", sidecars=[keylog, profile])
                self.assertTrue(fourth["summary"]["inventory_cache_reused"])
                self.assertEqual(extract.call_count, 3)

    def test_external_keylog_referenced_by_preferences_is_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keylog = root / "keys.log"
            keylog.write_text("CLIENT_RANDOM aa bb\n", encoding="ascii")
            config = root / "settings.json"
            config.write_text(json.dumps({"tshark_preferences": ["tls.keylog_file:" + str(keylog)]}), encoding="utf-8")
            before = tshark_backend.parsing_sidecar_fingerprint([config])
            keylog.write_text("CLIENT_RANDOM aa cc\n", encoding="ascii")
            self.assertNotEqual(before, tshark_backend.parsing_sidecar_fingerprint([config]))


if __name__ == "__main__":
    unittest.main()
