from __future__ import annotations

import base64
import hashlib
import json
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


def aes_ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def suo5_frame(fields: dict[str, bytes]) -> bytes:
    klv = b"".join(bytes([len(key)]) + key.encode() + struct.pack(">I", len(value)) + value for key, value in fields.items())
    obs = b"\x23\x42"
    encoded = base64.urlsafe_b64encode(xor(klv, obs)).rstrip(b"=")
    length = struct.pack(">I", len(encoded))
    header = base64.urlsafe_b64encode(obs + xor(length, obs)).rstrip(b"=")
    return header + encoded


def http_transaction(txn_id: str, tcp_stream: int, body: bytes, root: Path, epoch: float = 1.0) -> dict:
    body_path = root / f"{txn_id}-request.bin"
    body_path.write_bytes(body)
    return {
        "id": txn_id,
        "protocol": "http/1.x",
        "transport_index": {"tcp_stream": tcp_stream, "substream": None},
        "request": {
            "packet": 1,
            "time": epoch,
            "method": "POST",
            "uri": "/tunnel",
            "host": "target.local",
            "headers": {},
            "body": {"path": str(body_path), "size": len(body), "sha256": hashlib.sha256(body).hexdigest()},
        },
        "response": {"packet": 2, "time": epoch + 1.0, "status": 200, "content_type": ""},
        "completeness": "complete",
    }


class WebShellDecoderTests(unittest.TestCase):
    def test_suo5_invalid_port_becomes_failed_result(self) -> None:
        import base64
        import struct
        from wiretoutetu_core.webshell import decode_suo5_frame

        fields = {b"ac": b"0", b"p": b"nope"}
        body = b"".join(bytes([len(key)]) + key + struct.pack(">I", len(value)) + value for key, value in fields.items())
        random = b"xy"
        encoded = base64.urlsafe_b64encode(xor(body, random)).rstrip(b"=")
        header = base64.urlsafe_b64encode(random + xor(struct.pack(">I", len(encoded)), random)).rstrip(b"=")
        frame = header + encoded

        result = decode_suo5_frame(frame)

        self.assertEqual(result["status"], "failed")
        self.assertIn("port", result["error"])
    def test_behinder_v3_aes_base64_and_missing_key(self) -> None:
        from wiretoutetu_core.webshell import decode_behinder

        key = b"e45e329feb5d925b"
        payload = base64.b64encode(aes_ecb_encrypt(b'{"cmd":"whoami"}', key))
        decoded = decode_behinder(payload, key=key, cipher="aes-ecb", wrapper="base64", version="v3")
        missing = decode_behinder(payload, key=None, cipher="aes-ecb", wrapper="base64", version="v3")

        self.assertEqual(decoded["status"], "text")
        self.assertEqual(decoded["output"], b'{"cmd":"whoami"}')
        self.assertEqual(missing["status"], "not-attempted")

    def test_godzilla_java_aes_and_php_xor_profiles(self) -> None:
        from wiretoutetu_core.webshell import decode_godzilla

        key = b"3c6e0b8a9c15224a"
        java_payload = base64.b64encode(aes_ecb_encrypt(b"methodName=test", key))
        php_payload = base64.b64encode(xor(b"methodName=exec&cmd=id", key))

        java = decode_godzilla(java_payload, key=key, profile="java-aes-base64")
        php = decode_godzilla(php_payload, key=key, profile="php-xor-base64")

        self.assertEqual(java["output"], b"methodName=test")
        self.assertEqual(php["output"], b"methodName=exec&cmd=id")

    def test_antsword_random_prefix_base64_rot13_and_chopper(self) -> None:
        from wiretoutetu_core.webshell import decode_antsword, decode_chopper

        import codecs

        encoded = b"RANDOM12" + base64.b64encode(codecs.encode("@eval($_POST[x]);", "rot_13").encode())
        antsword = decode_antsword(encoded, chain=["strip-prefix:8", "base64", "rot13"])
        chopper = decode_chopper(b"pass=%40eval%28%24_POST%5Bx%5D%29%3B", language="php")

        self.assertEqual(antsword["output"], b"@eval($_POST[x]);")
        self.assertEqual(chopper["parameters"]["pass"], "@eval($_POST[x]);")

    def test_weevely3_official_obfpost_codec(self) -> None:
        from wiretoutetu_core.webshell import decode_weevely3

        password = "fixture-password"
        digest = hashlib.md5(password.encode()).hexdigest().lower()
        key = digest[:8].encode()
        header, trailer = digest[8:20].encode(), digest[20:32].encode()
        body = b"junk" + header + base64.b64encode(xor(zlib.compress(b"id"), key)).rstrip(b"=") + trailer + b"tail"

        result = decode_weevely3(body, password=password)

        self.assertEqual(result["output"], b"id")
        self.assertEqual(result["status"], "text")

    def test_suo5_random_xor_frame_klv_and_actions(self) -> None:
        from wiretoutetu_core.webshell import decode_suo5_frame

        fields = {"ac": b"\x00", "id": b"conn-1", "h": b"127.0.0.1", "p": b"8080"}
        klv = b"".join(bytes([len(k)]) + k.encode() + struct.pack(">I", len(v)) + v for k, v in fields.items())
        obs = b"\x12\x34"
        encoded_data = base64.urlsafe_b64encode(xor(klv, obs)).rstrip(b"=")
        length = struct.pack(">I", len(encoded_data))
        encoded_header = base64.urlsafe_b64encode(obs + xor(length, obs)).rstrip(b"=")
        result = decode_suo5_frame(encoded_header + encoded_data)

        self.assertEqual(result["action"], "create")
        self.assertEqual(result["connection_id"], "conn-1")
        self.assertEqual(result["target"], {"host": "127.0.0.1", "port": 8080})

    def test_regeorg_control_plane(self) -> None:
        from wiretoutetu_core.webshell import decode_regeorg_control

        result = decode_regeorg_control(
            {"X-CMD": "CONNECT", "X-TARGET": "10.0.0.8", "X-PORT": "3389"}, b""
        )
        self.assertEqual(result["operation"], "connect")
        self.assertEqual(result["target"], {"host": "10.0.0.8", "port": 3389})

    def test_suo5_http_transaction_decodes_request_body_instead_of_skipping(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.webshell_pipeline import apply_webshell_profiles

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture.pcap"
            capture.write_bytes(b"capture")
            state = CaseState.create(root / "case", capture, [])
            frame = suo5_frame({"ac": b"\x00", "id": b"c1", "h": b"127.0.0.1", "p": b"80"})
            sidecar = root / "profile.json"
            sidecar.write_text(json.dumps({"webshell_profiles": [
                {"family": "suo5", "tcp_stream": 7, "direction": "request"},
                {"family": "suo5", "tcp_stream": 8, "direction": "request"},
            ]}), encoding="utf-8")
            transactions = [
                http_transaction("TXN-http-suo5", 7, frame, root),
                http_transaction("TXN-http-plain", 8, b"ordinary post body", root, epoch=2.0),
            ]

            decodes, events, failures = apply_webshell_profiles(state, transactions, [sidecar])

            self.assertEqual(failures, [])
            self.assertEqual(len(events), 2, "HTTP-transport suo5 must not be silently skipped")
            good, bad = events
            self.assertEqual(good["transaction_id"], "TXN-http-suo5")
            self.assertEqual(good["details"]["action"], "create")
            self.assertEqual(good["details"]["target"], {"host": "127.0.0.1", "port": 80})
            self.assertEqual(bad["transaction_id"], "TXN-http-plain")
            self.assertEqual(bad["status"], "failed")
            self.assertIn("suo5", bad["details"]["error"])
            self.assertEqual(decodes, [])

    def test_output_artifact_is_named_after_this_transactions_decode_id(self) -> None:
        from wiretoutetu_core.case_state import CaseState
        from wiretoutetu_core.contracts import stable_evidence_id
        from wiretoutetu_core.webshell_pipeline import apply_webshell_profiles

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            capture = root / "capture.pcap"
            capture.write_bytes(b"capture")
            state = CaseState.create(root / "case", capture, [])
            key = b"e45e329feb5d925b"
            encrypted = aes_ecb_encrypt(b'{"cmd":"whoami"}', key)
            plain = b"@eval($_POST[x]);"
            sidecar = root / "profile.json"
            sidecar.write_text(json.dumps({"webshell_profiles": [
                {"family": "behinder", "tcp_stream": 0, "direction": "request", "cipher": "aes-ecb", "wrapper": "raw", "key": key.decode()},
                {"family": "antsword", "tcp_stream": 1, "direction": "request", "chain": []},
            ]}), encoding="utf-8")
            transactions = [
                http_transaction("TXN-first", 0, encrypted, root),
                http_transaction("TXN-second", 1, plain, root, epoch=2.0),
            ]

            decodes, events, _failures = apply_webshell_profiles(state, transactions, [sidecar])

            first_ids = {record["id"] for record in decodes if record["source_transaction"] == "TXN-first"}
            expected = stable_evidence_id("DEC", {"transaction": "TXN-second", "family": "antsword", "sha256": hashlib.sha256(plain).hexdigest()})
            antsword_event = next(event for event in events if event["family"] == "antsword")
            output_path = Path(antsword_event["output"]["path"])

            self.assertEqual(output_path.name, f"{expected}-request.bin")
            self.assertNotIn(output_path.stem.removesuffix("-request"), first_ids)


if __name__ == "__main__":
    unittest.main()
