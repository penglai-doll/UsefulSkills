"""Offline WebShell and HTTP tunnel payload decoders."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import urllib.parse
import zlib
from typing import Any, Mapping

from .decoding import decode_chain, decode_one, sha256_bytes


def _not_attempted(family: str, reason: str) -> dict[str, Any]:
    return {"family": family, "status": "not-attempted", "output": None, "records": [], "error": reason}


def _unwrap(payload: bytes, wrapper: str, *, wrapper_options: Mapping[str, Any] | None = None) -> tuple[bytes | None, list[dict[str, Any]]]:
    options = dict(wrapper_options or {})
    if wrapper == "raw":
        return payload, []
    if wrapper == "json":
        try:
            value = json.loads(payload.decode("utf-8"))
            field = options.get("field", "data")
            extracted = value[field]
            extracted_bytes = extracted.encode() if isinstance(extracted, str) else bytes(extracted)
            encoding = options.get("encoding", "base64" if isinstance(extracted, str) else "raw")
            if encoding == "raw":
                return extracted_bytes, []
            output, record = decode_one(extracted_bytes, str(encoding), parameter_source="json-wrapper")
            return output, [record]
        except (ValueError, KeyError, TypeError) as exc:
            return None, [{"algorithm": "json-wrapper", "status": "failed", "error": str(exc)}]
    if wrapper in {"image", "magic"}:
        output, record = decode_one(payload, "strip-magic", parameters=options, parameter_source="wrapper")
        return output, [record]
    algorithm = "base64url" if wrapper == "base64url" else "base64"
    output, record = decode_one(payload, algorithm, parameter_source="wrapper")
    return output, [record]


def decode_behinder(
    payload: bytes,
    *,
    key: bytes | None,
    cipher: str,
    wrapper: str = "raw",
    version: str = "unknown",
    wrapper_options: Mapping[str, Any] | None = None,
    iv: bytes | None = None,
) -> dict[str, Any]:
    if key is None:
        return _not_attempted("behinder", "key material is missing")
    unwrapped, records = _unwrap(payload, wrapper, wrapper_options=wrapper_options)
    if unwrapped is None:
        return {"family": "behinder", "version": version, "status": "failed", "output": None, "records": records}
    parameters: dict[str, Any] = {"key": key}
    if iv is not None:
        parameters["iv"] = iv
    output, record = decode_one(unwrapped, cipher, parameters=parameters, parameter_source="sidecar-or-derived-key")
    records.append(record)
    return {"family": "behinder", "version": version, "status": record["status"], "output": output, "records": records}


def decode_godzilla(
    payload: bytes,
    *,
    key: bytes | None,
    profile: str,
    magic_prefix: bytes = b"",
    magic_suffix: bytes = b"",
) -> dict[str, Any]:
    if key is None:
        return _not_attempted("godzilla", "key material is missing")
    wrapper = "base64" if profile.endswith("-base64") else "raw"
    unwrapped, records = _unwrap(payload, wrapper)
    if unwrapped is None:
        return {"family": "godzilla", "profile": profile, "status": "failed", "output": None, "records": records}
    if magic_prefix or magic_suffix:
        unwrapped, record = decode_one(
            unwrapped,
            "strip-magic",
            parameters={"prefix": magic_prefix, "suffix": magic_suffix},
            parameter_source="profile",
        )
        records.append(record)
        if unwrapped is None:
            return {"family": "godzilla", "profile": profile, "status": "failed", "output": None, "records": records}
    if profile.startswith("php-xor"):
        algorithm, parameters = "xor", {"key": key}
    elif profile.startswith("csharp-aes-cbc"):
        algorithm, parameters = "aes-cbc", {"key": key, "iv": b"\x00" * 16}
    else:
        algorithm, parameters = "aes-ecb", {"key": key}
    output, record = decode_one(unwrapped, algorithm, parameters=parameters, parameter_source="sidecar-or-derived-key")
    records.append(record)
    return {"family": "godzilla", "profile": profile, "status": record["status"], "output": output, "records": records}


def decode_antsword(payload: bytes, *, chain: list[str]) -> dict[str, Any]:
    result = decode_chain(payload, chain, parameter_source="antsword-profile")
    return {"family": "antsword", **result}


def decode_chopper(payload: bytes, *, language: str) -> dict[str, Any]:
    try:
        text = payload.decode("ascii")
        parameters = {key: values[-1] for key, values in urllib.parse.parse_qs(text, keep_blank_values=True).items()}
    except (UnicodeDecodeError, ValueError) as exc:
        return {"family": "china-chopper", "language": language, "status": "failed", "parameters": {}, "error": str(exc)}
    status = "text" if parameters else "partial"
    return {"family": "china-chopper", "language": language, "status": status, "parameters": parameters, "error": None}


def decode_weevely3(payload: bytes, *, password: str | None) -> dict[str, Any]:
    if not password:
        return _not_attempted("weevely3", "password candidate is missing")
    digest = hashlib.md5(password.encode("utf-8")).hexdigest().lower()
    key = digest[:8].encode("ascii")
    header, trailer = digest[8:20].encode("ascii"), digest[20:32].encode("ascii")
    match = re.search(re.escape(header) + rb"(.*?)" + re.escape(trailer), payload, re.DOTALL)
    if not match:
        return {"family": "weevely3", "status": "failed", "output": None, "records": [], "error": "password-derived delimiters not found"}
    encoded = match.group(1) + b"=" * (-len(match.group(1)) % 4)
    try:
        xorred = base64.b64decode(encoded, validate=True)
        compressed = bytes(value ^ key[index % len(key)] for index, value in enumerate(xorred))
        output = zlib.decompress(compressed)
    except (ValueError, zlib.error) as exc:
        return {"family": "weevely3", "status": "failed", "output": None, "records": [], "error": str(exc)}
    record = {
        "algorithm": "weevely3-obfpost",
        "parameter_source": "sidecar-or-candidate-password",
        "input_sha256": sha256_bytes(payload),
        "output_sha256": sha256_bytes(output),
        "input_length": len(payload),
        "output_length": len(output),
        "status": "text" if _printable(output) else "binary",
        "error": None,
    }
    return {"family": "weevely3", "status": record["status"], "output": output, "records": [record], "error": None}


def _printable(value: bytes) -> bool:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(len(text), 1) >= 0.9


def _b64url(value: bytes) -> bytes:
    return base64.urlsafe_b64decode(value + b"=" * (-len(value) % 4))


def decode_suo5_frame(payload: bytes) -> dict[str, Any]:
    try:
        if len(payload) < 8:
            raise ValueError("truncated suo5 frame header")
        header = _b64url(payload[:8])
        if len(header) != 6:
            raise ValueError("invalid suo5 header")
        obs = header[:2]
        length_bytes = bytes(value ^ obs[index % 2] for index, value in enumerate(header[2:]))
        encoded_length = struct.unpack(">I", length_bytes)[0]
        if encoded_length > 64 * 1024 * 1024 or len(payload) < 8 + encoded_length:
            raise ValueError("truncated or oversized suo5 payload")
        encrypted = _b64url(payload[8 : 8 + encoded_length])
        data = bytes(value ^ obs[index % 2] for index, value in enumerate(encrypted))
        fields: dict[str, bytes] = {}
        offset = 0
        while offset < len(data):
            key_length = data[offset]
            offset += 1
            if offset + key_length + 4 > len(data):
                raise ValueError("truncated suo5 key")
            key = data[offset : offset + key_length].decode("utf-8")
            offset += key_length
            value_length = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            if offset + value_length > len(data):
                raise ValueError("truncated suo5 value")
            fields[key] = data[offset : offset + value_length]
            offset += value_length
    except (ValueError, UnicodeDecodeError, struct.error) as exc:
        return {"family": "suo5", "status": "failed", "error": str(exc), "fields": {}}
    actions = {0x00: "create", 0x01: "data", 0x02: "delete", 0x03: "status", 0x10: "heartbeat", 0x11: "dirty"}
    action_byte = fields.get("ac", b"\xff")[0] if fields.get("ac") else 0xFF
    target = None
    if "h" in fields or "p" in fields:
        target = {
            "host": fields.get("h", b"").decode("utf-8", "replace"),
            "port": int(fields.get("p", b"0") or b"0"),
        }
    return {
        "family": "suo5",
        "status": "binary" if fields.get("dt") else "text",
        "action": actions.get(action_byte, f"unknown-{action_byte:#x}"),
        "connection_id": fields.get("id", b"").decode("utf-8", "replace") or None,
        "target": target,
        "inner_data": fields.get("dt"),
        "fields": {key: value.hex() for key, value in fields.items()},
        "error": None,
    }


def decode_regeorg_control(headers: Mapping[str, str], body: bytes) -> dict[str, Any]:
    normalized = {key.lower(): value for key, value in headers.items()}
    command = normalized.get("x-cmd") or normalized.get("x-command") or normalized.get("cmd")
    operation = command.lower() if command else "data" if body else "unknown"
    target = None
    host = normalized.get("x-target") or normalized.get("x-host")
    port = normalized.get("x-port")
    if host or port:
        try:
            parsed_port = int(port) if port else None
        except ValueError:
            parsed_port = None
        target = {"host": host, "port": parsed_port}
    return {
        "family": "regeorg",
        "operation": operation,
        "target": target,
        "data_length": len(body),
        "status": "binary" if body else "text",
    }
