from __future__ import annotations

import base64
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


def row(**values: str) -> dict[str, str]:
    defaults = {"frame.number": "1", "frame.time_epoch": "1.0", "frame.protocols": "eth:ip:tcp", "tcp.stream": "0"}
    defaults.update(values)
    return defaults


class ProtocolExtractorTests(unittest.TestCase):
    def test_dns_icmp_ftp_smtp_usb_and_objects(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.protocols import extract_protocol_records

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "fixture.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            mime = (
                b"Content-Type: multipart/mixed; boundary=x\r\nMIME-Version: 1.0\r\n\r\n"
                b"--x\r\nContent-Type: application/octet-stream\r\n"
                b"Content-Disposition: attachment; filename=flag.bin\r\n"
                b"Content-Transfer-Encoding: base64\r\n\r\n"
                + base64.b64encode(b"flag{smtp-object}")
                + b"\r\n--x--\r\n"
            )
            packets = [
                row(**{"frame.number": "1", "frame.protocols": "eth:ip:udp:dns", "tcp.stream": "", "udp.stream": "0", "dns.id": "0x10", "dns.qry.name": "fixture.local", "dns.flags.response": "0"}),
                row(**{"frame.number": "2", "frame.protocols": "eth:ip:udp:dns", "tcp.stream": "", "udp.stream": "0", "dns.id": "0x10", "dns.qry.name": "fixture.local", "dns.flags.response": "1", "dns.a": "10.0.0.2"}),
                row(**{"frame.number": "3", "frame.protocols": "eth:ip:icmp", "tcp.stream": "", "icmp.type": "8", "icmp.ident": "7", "icmp.seq": "1", "data.data": "666c6167"}),
                row(**{"frame.number": "4", "frame.protocols": "eth:ip:tcp:ftp", "tcp.stream": "1", "ftp.request.command": "RETR", "ftp.request.arg": "flag.bin"}),
                row(**{"frame.number": "5", "frame.protocols": "eth:ip:tcp:ftp", "tcp.stream": "1", "ftp.response.code": "150", "ftp.response.arg": "Opening data"}),
                row(**{"frame.number": "6", "frame.protocols": "eth:ip:tcp:ftp-data", "tcp.stream": "2", "tcp.payload": b"flag{ftp-object}".hex()}),
                row(**{"frame.number": "7", "frame.protocols": "eth:ip:tcp:smtp", "tcp.stream": "3", "smtp.req.command": "DATA", "tcp.payload": mime.hex()}),
                row(**{"frame.number": "8", "frame.protocols": "usb:usbhid", "tcp.stream": "", "usbhid.data": "0000040000000000", "usb.bus_id": "1", "usb.device_address": "2", "usb.endpoint_address": "0x81"}),
            ]

            transactions, objects, events = extract_protocol_records(packets, "a" * 64, state)
            protocols = {item["protocol"] for item in transactions}

            self.assertTrue({"dns", "icmp", "ftp", "smtp", "ftp-data", "usb-hid"}.issubset(protocols))
            restored = {Path(item["extraction_path"]).read_bytes() for item in objects}
            self.assertIn(b"flag{ftp-object}", restored)
            self.assertIn(b"flag{smtp-object}", restored)
            self.assertEqual(len(events), len(transactions))

    def test_protocol_events_carry_transaction_times(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.protocols import extract_protocol_records

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "fixture.pcap"
            capture.write_bytes(b"fixture")
            state = CaseState.create(root / "case", capture, [])
            packets = [
                row(**{"frame.number": "11", "frame.time_epoch": "100.5", "frame.protocols": "eth:ip:udp:dns", "tcp.stream": "", "udp.stream": "0", "dns.id": "0x20", "dns.qry.name": "a.local", "dns.flags.response": "0"}),
                row(**{"frame.number": "12", "frame.time_epoch": "100.9", "frame.protocols": "eth:ip:udp:dns", "tcp.stream": "", "udp.stream": "0", "dns.id": "0x20", "dns.qry.name": "a.local", "dns.flags.response": "1", "dns.a": "10.0.0.2"}),
                row(**{"frame.number": "13", "frame.time_epoch": "101.0", "frame.protocols": "eth:ip:icmp", "tcp.stream": "", "icmp.type": "8", "icmp.ident": "7", "icmp.seq": "1", "data.data": "666c6167"}),
                row(**{"frame.number": "14", "frame.time_epoch": "102.1", "frame.protocols": "eth:ip:tcp:ftp", "tcp.stream": "1", "ftp.request.command": "RETR", "ftp.request.arg": "x"}),
                row(**{"frame.number": "15", "frame.time_epoch": "102.4", "frame.protocols": "eth:ip:tcp:ftp", "tcp.stream": "1", "ftp.response.code": "150", "ftp.response.arg": "Opening"}),
                row(**{"frame.number": "16", "frame.time_epoch": "103.0", "frame.protocols": "eth:ip:tcp:smtp", "tcp.stream": "2", "smtp.req.command": "DATA"}),
                row(**{"frame.number": "17", "frame.time_epoch": "104.0", "frame.protocols": "eth:ip:udp:dns", "tcp.stream": "", "udp.stream": "1", "dns.id": "0x21", "dns.qry.name": "orphan.local", "dns.flags.response": "1", "dns.a": "10.0.0.9"}),
            ]

            transactions, _objects, events = extract_protocol_records(packets, "b" * 64, state)

            by_protocol = {}
            for event, transaction in zip(events, transactions):
                by_protocol.setdefault(transaction["protocol"], []).append((event, transaction))
            dns_event = by_protocol["dns"][0][0]
            icmp_event = by_protocol["icmp"][0][0]
            ftp_event = by_protocol["ftp"][0][0]
            smtp_event = by_protocol["smtp"][0][0]
            orphan_dns_event = by_protocol["dns"][1][0]

            self.assertEqual(dns_event["time"], 100.5)
            self.assertEqual(icmp_event["time"], 101.0)
            self.assertEqual(ftp_event["time"], 102.1)
            self.assertEqual(smtp_event["time"], 103.0)
            self.assertEqual(orphan_dns_event["time"], 104.0)
            for event in events:
                self.assertIsInstance(event["time"], float)


if __name__ == "__main__":
    unittest.main()
