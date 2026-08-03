from __future__ import annotations

import base64
import codecs
import hashlib
import json
import struct
import sys
import unittest
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


def pad_encrypt(data: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def cycle_xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


class WebShellAcceptanceMatrixTests(unittest.TestCase):
    def test_behinder_verified_variants_and_negative_controls(self) -> None:
        from wiretoutetu_core.webshell import decode_behinder

        key = b"e45e329feb5d925b"
        plain = b'{"cmd":"whoami"}'
        variants = [
            (pad_encrypt(plain, key), "aes-ecb", "raw", None),
            (base64.b64encode(pad_encrypt(plain, key)), "aes-ecb", "base64", None),
            (json.dumps({"data": base64.b64encode(pad_encrypt(plain, key)).decode()}).encode(), "aes-ecb", "json", {"field": "data"}),
            (b"PNG!" + pad_encrypt(plain, key) + b"!END", "aes-ecb", "image", {"prefix": b"PNG!", "suffix": b"!END"}),
            (cycle_xor(plain, key), "xor", "raw", None),
        ]
        for payload, cipher, wrapper, options in variants:
            result = decode_behinder(payload, key=key, cipher=cipher, wrapper=wrapper, wrapper_options=options, version="fixture")
            self.assertEqual(result["output"], plain, (cipher, wrapper, result))
        wrong = decode_behinder(variants[0][0], key=b"0123456789abcdef", cipher="aes-ecb")
        missing = decode_behinder(variants[0][0], key=None, cipher="aes-ecb")
        truncated = decode_behinder(variants[0][0][:-1], key=key, cipher="aes-ecb")
        normal = decode_behinder(b"name=alice&note=hello", key=key, cipher="aes-ecb")
        self.assertEqual([wrong["status"], truncated["status"], normal["status"]], ["failed"] * 3)
        self.assertEqual(missing["status"], "not-attempted")

    def test_godzilla_verified_variants_and_negative_controls(self) -> None:
        from wiretoutetu_core.webshell import decode_godzilla

        key = b"3c6e0b8a9c15224a"
        plain = b"methodName=exec&cmd=id"
        variants = {
            "java-aes-raw": pad_encrypt(plain, key),
            "java-aes-base64": base64.b64encode(pad_encrypt(plain, key)),
            "csharp-aes-raw": pad_encrypt(plain, key),
            "csharp-aes-base64": base64.b64encode(pad_encrypt(plain, key)),
            "php-xor-raw": cycle_xor(plain, key),
            "php-xor-base64": base64.b64encode(cycle_xor(plain, key)),
        }
        for profile, payload in variants.items():
            self.assertEqual(decode_godzilla(payload, key=key, profile=profile)["output"], plain, profile)
        self.assertEqual(decode_godzilla(variants["java-aes-raw"], key=None, profile="java-aes-raw")["status"], "not-attempted")
        self.assertEqual(decode_godzilla(variants["java-aes-raw"][:-3], key=key, profile="java-aes-raw")["status"], "failed")
        self.assertEqual(decode_godzilla(b"ordinary post", key=key, profile="java-aes-raw")["status"], "failed")

    def test_antsword_verified_variants_and_negative_controls(self) -> None:
        from wiretoutetu_core.webshell import decode_antsword

        plain = b"@eval($_POST[x]);"
        self.assertEqual(decode_antsword(plain, chain=["raw"])["output"], plain)
        self.assertEqual(decode_antsword(base64.b64encode(plain), chain=["base64"])["output"], plain)
        rot = codecs.encode(plain.decode(), "rot_13").encode()
        self.assertEqual(decode_antsword(rot, chain=["rot13"])["output"], plain)
        prefixed = b"RANDOM12" + base64.b64encode(rot)
        self.assertEqual(decode_antsword(prefixed, chain=["strip-prefix:8", "base64", "rot13"])["output"], plain)
        self.assertEqual(decode_antsword(b"%%%%", chain=["base64"])["status"], "failed")
        self.assertEqual(decode_antsword(b"name=alice", chain=["base64"])["status"], "failed")

    def test_chopper_language_profiles_and_normal_post_counterexample(self) -> None:
        from wiretoutetu_core.webshell import decode_chopper

        for language in ("php", "asp", "aspx", "jsp"):
            result = decode_chopper(b"pass=%40eval%28payload%29%3B", language=language)
            self.assertEqual(result["parameters"]["pass"], "@eval(payload);")
        normal = decode_chopper(b"name=alice&note=hello", language="php")
        self.assertNotIn("eval", " ".join(normal["parameters"].values()).lower())

    def test_weevely_verified_request_response_and_negative_controls(self) -> None:
        from wiretoutetu_core.webshell import decode_weevely3

        password = "fixture-password"
        digest = hashlib.md5(password.encode()).hexdigest()
        key, header, trailer = digest[:8].encode(), digest[8:20].encode(), digest[20:32].encode()
        def wrap(data: bytes) -> bytes:
            encoded = base64.b64encode(cycle_xor(zlib.compress(data), key)).rstrip(b"=")
            return b"prefix" + header + encoded + trailer + b"suffix"
        self.assertEqual(decode_weevely3(wrap(b"id"), password=password)["output"], b"id")
        self.assertEqual(decode_weevely3(wrap(b"uid=1000"), password=password)["output"], b"uid=1000")
        self.assertEqual(decode_weevely3(wrap(b"id"), password="wrong")["status"], "failed")
        self.assertEqual(decode_weevely3(wrap(b"id"), password=None)["status"], "not-attempted")
        self.assertEqual(decode_weevely3(wrap(b"id")[:-9], password=password)["status"], "failed")
        self.assertEqual(decode_weevely3(b"name=alice", password=password)["status"], "failed")

    def test_suo5_verified_klv_actions_and_negative_controls(self) -> None:
        from wiretoutetu_core.webshell import decode_suo5_frame

        def frame(fields: dict[str, bytes]) -> bytes:
            klv = b"".join(bytes([len(key)]) + key.encode() + struct.pack(">I", len(value)) + value for key, value in fields.items())
            obs = b"\x23\x42"
            encoded = base64.urlsafe_b64encode(cycle_xor(klv, obs)).rstrip(b"=")
            header = base64.urlsafe_b64encode(obs + cycle_xor(struct.pack(">I", len(encoded)), obs)).rstrip(b"=")
            return header + encoded
        fixtures = [
            ({"ac": b"\x00", "id": b"c1", "h": b"127.0.0.1", "p": b"80"}, "create"),
            ({"ac": b"\x01", "id": b"c1", "dt": b"GET / HTTP/1.0\r\n\r\n"}, "data"),
            ({"ac": b"\x02", "id": b"c1"}, "delete"),
            ({"ac": b"\x10", "id": b"c1"}, "heartbeat"),
        ]
        for fields, action in fixtures:
            self.assertEqual(decode_suo5_frame(frame(fields))["action"], action)
        self.assertEqual(decode_suo5_frame(b"ordinary post")["status"], "failed")
        self.assertEqual(decode_suo5_frame(frame(fixtures[0][0])[:-3])["status"], "failed")

    def test_regeorg_verified_control_sequence_and_counterexample(self) -> None:
        from wiretoutetu_core.webshell import decode_regeorg_control

        operations = ["CONNECT", "FORWARD", "READ", "DISCONNECT"]
        results = [decode_regeorg_control({"X-CMD": op, "X-TARGET": "10.0.0.8", "X-PORT": "22"}, b"x" if op == "FORWARD" else b"") for op in operations]
        self.assertEqual([row["operation"] for row in results], [op.lower() for op in operations])
        normal = decode_regeorg_control({"Content-Type": "application/json"}, b'{"name":"alice"}')
        self.assertEqual(normal["operation"], "data")
        self.assertIsNone(normal["target"])


if __name__ == "__main__":
    unittest.main()
