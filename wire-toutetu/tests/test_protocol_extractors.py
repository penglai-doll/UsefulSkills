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

            self.assertTrue({"dns", "icmp", "ftp", "ftp-data", "smtp", "usb-hid"}.issubset(protocols))
            restored = {Path(item["extraction_path"]).read_bytes() for item in objects}
            self.assertIn(b"flag{ftp-object}", restored)
            self.assertIn(b"flag{smtp-object}", restored)
            self.assertEqual(len(events), len(transactions))


if __name__ == "__main__":
    unittest.main()
