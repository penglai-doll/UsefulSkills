"""Auditable single-step and chained decoding primitives."""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import hashlib
import urllib.parse
import zlib
from typing import Any, Mapping

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .contracts import stable_evidence_id


MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"PK\x03\x04", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF-", "pdf"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"Rar!\x1a\x07", "rar"),
    (b"SQLite format 3\x00", "sqlite"),
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def detect_magic(value: bytes) -> str | None:
    for prefix, name in MAGIC:
        if value.startswith(prefix):
            return name
    return None


def _is_text(value: bytes) -> bool:
    if not value:
        return True
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(character.isprintable() or character in "\r\n\t" for character in decoded)
    return printable / max(len(decoded), 1) >= 0.90


def _status(value: bytes) -> str:
    return "text" if _is_text(value) else "binary"


def _key(parameters: Mapping[str, Any]) -> bytes:
    key = parameters.get("key")
    if isinstance(key, str):
        encoding = parameters.get("key_encoding", "utf-8")
        if encoding == "hex":
            return bytes.fromhex(key)
        return key.encode(str(encoding))
    if isinstance(key, bytes):
        return key
    raise ValueError("key is required")


def _unpad(value: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(value) + unpadder.finalize()


def _base64_decode(value: bytes, *, urlsafe: bool) -> bytes:
    compact = b"".join(value.split())
    compact += b"=" * (-len(compact) % 4)
    if urlsafe:
        return base64.urlsafe_b64decode(compact)
    return base64.b64decode(compact, validate=True)


def _perform(value: bytes, algorithm: str, parameters: Mapping[str, Any]) -> bytes:
    if algorithm == "raw":
        return value
    if algorithm == "url":
        return urllib.parse.unquote_to_bytes(value.decode("ascii"))
    if algorithm == "base64":
        return _base64_decode(value, urlsafe=False)
    if algorithm == "base64url":
        return _base64_decode(value, urlsafe=True)
    if algorithm == "hex":
        return bytes.fromhex(value.decode("ascii").replace(":", "").replace(" ", ""))
    if algorithm == "gzip":
        return gzip.decompress(value)
    if algorithm == "zlib":
        return zlib.decompress(value)
    if algorithm == "rot13":
        return codecs.decode(value.decode("utf-8"), "rot_13").encode("utf-8")
    if algorithm == "xor":
        key = _key(parameters)
        if not key:
            raise ValueError("xor key is empty")
        offset = int(parameters.get("offset", 0))
        return bytes(byte ^ key[(index + offset) % len(key)] for index, byte in enumerate(value))
    if algorithm.startswith("strip-prefix:"):
        length = int(algorithm.partition(":")[2])
        if len(value) < length:
            raise ValueError("prefix is longer than input")
        return value[length:]
    if algorithm == "strip-magic":
        prefix = parameters.get("prefix", b"")
        suffix = parameters.get("suffix", b"")
        if isinstance(prefix, str):
            prefix = prefix.encode()
        if isinstance(suffix, str):
            suffix = suffix.encode()
        if prefix and not value.startswith(prefix):
            raise ValueError("magic prefix mismatch")
        if suffix and not value.endswith(suffix):
            raise ValueError("magic suffix mismatch")
        end = -len(suffix) if suffix else None
        return value[len(prefix) : end]
    if algorithm in {"aes-ecb", "aes-cbc"}:
        key = _key(parameters)
        if algorithm == "aes-ecb":
            mode: modes.Mode = modes.ECB()
        else:
            iv = parameters.get("iv")
            if isinstance(iv, str):
                iv = bytes.fromhex(iv) if parameters.get("iv_encoding") == "hex" else iv.encode()
            if not isinstance(iv, bytes):
                raise ValueError("iv is required")
            mode = modes.CBC(iv)
        decryptor = Cipher(algorithms.AES(key), mode).decryptor()
        plain = decryptor.update(value) + decryptor.finalize()
        return _unpad(plain) if parameters.get("padding", "pkcs7") == "pkcs7" else plain
    if algorithm == "aes-gcm":
        key = _key(parameters)
        nonce = parameters.get("nonce")
        associated_data = parameters.get("associated_data")
        if not isinstance(nonce, bytes):
            raise ValueError("nonce is required")
        return AESGCM(key).decrypt(nonce, value, associated_data)
    raise ValueError(f"unsupported algorithm: {algorithm}")


def decode_one(
    value: bytes,
    algorithm: str,
    *,
    parameters: Mapping[str, Any] | None = None,
    parameter_source: str,
) -> tuple[bytes | None, dict[str, Any]]:
    parameters = dict(parameters or {})
    input_hash = sha256_bytes(value)
    safe_parameters = {
        key: ("<redacted>" if key in {"key", "password"} else item.hex() if isinstance(item, bytes) else item)
        for key, item in parameters.items()
    }
    material = {"algorithm": algorithm, "input_sha256": input_hash, "parameter_source": parameter_source, "parameters": safe_parameters}
    try:
        output = _perform(value, algorithm, parameters)
    except (ValueError, TypeError, UnicodeError, binascii.Error, zlib.error) as exc:
        return None, {
            "id": stable_evidence_id("DEC", material),
            "algorithm": algorithm,
            "parameters": safe_parameters,
            "parameter_source": parameter_source,
            "input_sha256": input_hash,
            "output_sha256": None,
            "input_length": len(value),
            "output_length": 0,
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "next_action": "Check wrapper, key material, truncation, and variant profile.",
        }
    return output, {
        "id": stable_evidence_id("DEC", material),
        "algorithm": algorithm,
        "parameters": safe_parameters,
        "parameter_source": parameter_source,
        "input_sha256": input_hash,
        "output_sha256": sha256_bytes(output),
        "input_length": len(value),
        "output_length": len(output),
        "status": _status(output),
        "error": None,
        "next_action": f"Inspect as {detect_magic(output) or _status(output)} or continue the decode chain.",
    }


def decode_chain(
    value: bytes,
    algorithms: list[str],
    *,
    parameters: Mapping[str, Mapping[str, Any]] | None = None,
    parameter_source: str,
) -> dict[str, Any]:
    current: bytes | None = value
    records: list[dict[str, Any]] = []
    for algorithm in algorithms:
        if current is None:
            break
        current, record = decode_one(
            current,
            algorithm,
            parameters=(parameters or {}).get(algorithm, {}),
            parameter_source=parameter_source,
        )
        records.append(record)
        if record["status"] == "failed":
            break
    return {"output": current, "records": records, "status": records[-1]["status"] if records else "not-attempted"}
