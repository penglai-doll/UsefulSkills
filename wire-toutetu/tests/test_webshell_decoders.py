from __future__ import annotations

import base64
import hashlib
import struct
import sys
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


class WebShellDecoderTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
