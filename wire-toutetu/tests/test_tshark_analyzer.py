from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
import json
import gzip
import subprocess
from pathlib import Path
from unittest import mock


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


def build_http_fixture(path: Path) -> None:
    try:
        from scapy.all import Ether, IP, Raw, TCP, wrpcap
    except ImportError as exc:  # pragma: no cover - CI prerequisite gate
        raise unittest.SkipTest("Scapy fixture dependency missing") from exc
    request = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=43210, dport=80, seq=1, flags="PA")
        / Raw(load=b"GET /flag.txt HTTP/1.1\r\nHost: target.local\r\n\r\n")
    )
    response = (
        Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=80, dport=43210, seq=1, flags="PA")
        / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\n\r\nflag{ok}")
    )
    wrpcap(str(path), [request, response])


def build_udp_dns_icmp_fixture(path: Path) -> None:
    try:
        from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, UDP, Raw, wrpcap
    except ImportError as exc:  # pragma: no cover
        raise unittest.SkipTest("Scapy fixture dependency missing") from exc
    query = Ether() / IP(src="10.0.0.1", dst="10.0.0.53") / UDP(sport=53000, dport=53) / DNS(id=7, qd=DNSQR(qname="fixture.local"))
    answer = Ether() / IP(src="10.0.0.53", dst="10.0.0.1") / UDP(sport=53, dport=53000) / DNS(id=7, qr=1, aa=1, qd=DNSQR(qname="fixture.local"), an=DNSRR(rrname="fixture.local", rdata="10.0.0.2"))
    echo = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, id=3, seq=1) / Raw(load=b"fixture")
    wrpcap(str(path), [query, answer, echo])


def build_behinder_post_fixture(path: Path) -> tuple[bytes, bytes]:
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from scapy.all import Ether, IP, Raw, TCP, wrpcap
    except ImportError as exc:  # pragma: no cover
        raise unittest.SkipTest("fixture dependency missing") from exc
    key = b"e45e329feb5d925b"
    plain = b'{"cmd":"whoami"}'
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    request_body = (
        b"POST /shell.php HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/octet-stream\r\n"
        + f"Content-Length: {len(encrypted)}\r\n\r\n".encode()
        + encrypted
    )
    response_body = b"ok"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n" + response_body
    packets = [
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=42000, dport=80, seq=1, flags="PA") / Raw(load=request_body),
        Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=42000, seq=1, flags="PA") / Raw(load=response),
    ]
    wrpcap(str(path), packets)
    return key, plain


@unittest.skipUnless(shutil.which("tshark"), "TShark integration dependency missing")
class TSharkAnalyzerTests(unittest.TestCase):
    def test_capture_size_routes_match_contract_boundaries(self) -> None:
        from wiretoutetu_core.analyzer import determine_size_route

        self.assertEqual(determine_size_route(100 * 1024 * 1024 - 1), "full-pipeline")
        self.assertEqual(determine_size_route(100 * 1024 * 1024), "stream-index")
        self.assertEqual(determine_size_route(2 * 1024 * 1024 * 1024), "stream-index")
        self.assertEqual(determine_size_route(2 * 1024 * 1024 * 1024 + 1), "inventory-then-slice")

    def test_pcap_pcapng_cap_and_gzip_inputs(self) -> None:
        from wiretoutetu_core.analyzer import analyze_capture

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pcap = root / "base.pcap"
            build_http_fixture(pcap)
            cap = root / "alias.cap"
            cap.write_bytes(pcap.read_bytes())
            pcapng = root / "converted.pcapng"
            subprocess.run([shutil.which("editcap") or "editcap", "-F", "pcapng", str(pcap), str(pcapng)], check=True, capture_output=True)
            compressed = root / "base.pcap.gz"
            with pcap.open("rb") as source, gzip.open(compressed, "wb") as output:
                output.write(source.read())
            for index, capture in enumerate((pcap, pcapng, cap, compressed)):
                result = analyze_capture(capture, case_dir=root / f"case-{index}", sidecars=[])
                self.assertEqual(result["status"], "ok", capture.name)
                self.assertEqual(result["counts"]["transactions"], 1, capture.name)

    def test_real_tshark_extracts_flow_http_transaction_and_object(self) -> None:
        from wiretoutetu_core.analyzer import analyze_capture

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "http.pcap"
            build_http_fixture(capture)

            result = analyze_capture(capture, case_dir=root / "case", sidecars=[])

            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["completeness"], "complete")
            self.assertEqual(result["counts"]["flows"], 1)
            self.assertEqual(result["counts"]["transactions"], 1)
            self.assertEqual(result["counts"]["objects"], 1)
            self.assertIn("proto.http1", result["routes"]["selected_plugins"])

            state = result["state"]
            transactions = state.query_records("transactions")["items"]
            objects = state.query_records("objects")["items"]
            self.assertEqual(transactions[0]["request"]["uri"], "/flag.txt")
            self.assertEqual(transactions[0]["response"]["status"], 200)
            self.assertEqual(Path(objects[0]["extraction_path"]).read_bytes(), b"flag{ok}")

    def test_reanalysis_reuses_completed_inventory_stage(self) -> None:
        from wiretoutetu_core.analyzer import analyze_capture

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "http.pcap"
            build_http_fixture(capture)
            first = analyze_capture(capture, case_dir=root / "case", sidecars=[])
            second = analyze_capture(capture, case_dir=root / "case", sidecars=[])

            self.assertFalse(first["summary"]["cache_reused"])
            self.assertTrue(second["summary"]["cache_reused"])

    def test_real_tshark_extracts_udp_dns_and_icmp(self) -> None:
        from wiretoutetu_core.analyzer import analyze_capture

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "network.pcapng"
            build_udp_dns_icmp_fixture(capture)
            result = analyze_capture(capture, case_dir=root / "case", sidecars=[])
            protocols = {row["protocol"] for row in result["state"].query_records("protocols")["items"]}
            transactions = {row["protocol"] for row in result["state"].query_records("transactions")["items"]}

            self.assertEqual(result["status"], "ok")
            self.assertIn("udp", protocols)
            self.assertIn("dns", protocols)
            self.assertIn("icmp", protocols)
            self.assertTrue({"dns", "icmp"}.issubset(transactions))

    def test_new_sidecar_invalidates_decode_only_and_recovers_webshell_payload(self) -> None:
        from wiretoutetu_core.analyzer import analyze_capture

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "behinder.pcap"
            key, plain = build_behinder_post_fixture(capture)
            first = analyze_capture(capture, case_dir=root / "case", sidecars=[])
            sidecar = root / "profile.json"
            sidecar.write_text(json.dumps({"webshell_profiles": [{
                "family": "behinder", "tcp_stream": 0, "direction": "request",
                "cipher": "aes-ecb", "wrapper": "raw", "key": key.decode(), "version": "v3",
            }]}), encoding="utf-8")

            with mock.patch("wiretoutetu_core.analyzer.extract_packets", side_effect=AssertionError("inventory reran")):
                second = analyze_capture(capture, case_dir=root / "case", sidecars=[sidecar])

            self.assertTrue(second["summary"]["inventory_cache_reused"])
            self.assertFalse(second["summary"]["decode_cache_reused"])
            event = second["state"].query_records("webshell")["items"][0]
            self.assertEqual(event["family"], "behinder")
            self.assertEqual(Path(event["output"]["path"]).read_bytes(), plain)
            self.assertEqual(first["counts"]["webshell_events"], 0)


if __name__ == "__main__":
    unittest.main()
