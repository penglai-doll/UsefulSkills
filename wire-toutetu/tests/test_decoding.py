from __future__ import annotations

import base64
import gzip
import sys
import unittest
import urllib.parse
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT / "scripts"))


class DecodingTests(unittest.TestCase):
    def test_multilayer_url_base64_gzip_chain_records_hashes(self) -> None:
        from wiretoutetu_core.decoding import decode_chain

        original = b"flag{layered-fixture}"
        wrapped = urllib.parse.quote_from_bytes(base64.urlsafe_b64encode(gzip.compress(original))).encode()
        result = decode_chain(wrapped, ["url", "base64url", "gzip"], parameter_source="fixture")

        self.assertEqual(result["output"], original)
        self.assertEqual([row["algorithm"] for row in result["records"]], ["url", "base64url", "gzip"])
        self.assertTrue(all(row["input_sha256"] and row["output_sha256"] for row in result["records"]))
        self.assertEqual(result["records"][-1]["status"], "text")

    def test_wrong_aes_key_is_failed_not_text(self) -> None:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from wiretoutetu_core.decoding import decode_one

        padder = padding.PKCS7(128).padder()
        padded = padder.update(b"fixture-command") + padder.finalize()
        encrypted = Cipher(algorithms.AES(b"0123456789abcdef"), modes.ECB()).encryptor().update(padded)
        _output, record = decode_one(
            encrypted,
            "aes-ecb",
            parameters={"key": b"fedcba9876543210"},
            parameter_source="wrong-fixture-key",
        )

        self.assertEqual(record["status"], "failed")
        self.assertIsNone(record["output_sha256"])

    def test_xor_and_file_magic_classification(self) -> None:
        from wiretoutetu_core.decoding import decode_one, detect_magic

        plain = b"PK\x03\x04fixture"
        encoded = bytes(value ^ b"key"[index % 3] for index, value in enumerate(plain))
        output, record = decode_one(encoded, "xor", parameters={"key": b"key"}, parameter_source="sidecar")

        self.assertEqual(output, plain)
        self.assertEqual(record["status"], "binary")
        self.assertEqual(detect_magic(output), "zip")


if __name__ == "__main__":
    unittest.main()
