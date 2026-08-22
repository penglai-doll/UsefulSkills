"""Apply explicit sidecar WebShell profiles to persisted HTTP transaction payloads."""

from __future__ import annotations

import hashlib
import binascii
import json
import re
from pathlib import Path
from typing import Any, Iterable

from .case_state import CaseState
from .contracts import stable_evidence_id
from .webshell import (
    decode_antsword,
    decode_behinder,
    decode_chopper,
    decode_godzilla,
    decode_regeorg_control,
    decode_suo5_frame,
    decode_weevely3,
)


def _configs(sidecars: Iterable[Path]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    profiles: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for path in sidecars:
        if path.suffix.lower() != ".json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            failures.append({
                "stage": "webshell-config", "path": str(path),
                "message": f"sidecar JSON parse failed: {type(exc).__name__}: {exc}",
            })
            continue
        if not isinstance(data, dict):
            failures.append({
                "stage": "webshell-config", "path": str(path),
                "message": f"sidecar structure must be an object, got {type(data).__name__}",
            })
            continue
        values = data.get("webshell_profiles", data.get("webshell", []))
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            failures.append({
                "stage": "webshell-config", "path": str(path),
                "message": f"sidecar structure webshell_profiles must be an object or list, got {type(values).__name__}",
            })
            continue
        for item in values:
            if isinstance(item, dict) and item.get("family"):
                profiles.append(item)
            else:
                failures.append({
                    "stage": "webshell-config", "path": str(path),
                    "message": "sidecar structure contains a profile without a family",
                })
    return profiles, failures


def _matches(profile: dict[str, Any], transaction: dict[str, Any]) -> bool:
    if profile.get("transaction_id") and profile["transaction_id"] != transaction.get("id"):
        return False
    if "tcp_stream" in profile and int(profile["tcp_stream"]) != transaction.get("transport_index", {}).get("tcp_stream"):
        return False
    uri = transaction.get("request", {}).get("uri") or ""
    if profile.get("uri_regex") and not re.search(str(profile["uri_regex"]), uri):
        return False
    return True


def _key(profile: dict[str, Any]) -> bytes | None:
    if profile.get("key_hex"):
        return bytes.fromhex(str(profile["key_hex"]))
    value = profile.get("key")
    return str(value).encode("utf-8") if value is not None else None


def _serializable(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items() if key != "output"}
    if isinstance(value, list):
        return [_serializable(item) for item in value]
    return value


def _single_value_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        raise TypeError("headers must be an object")
    result: dict[str, str] = {}
    for key, value in headers.items():
        if isinstance(value, list):
            if value:
                result[str(key)] = str(value[-1])
        else:
            result[str(key)] = str(value)
    return result


def apply_webshell_profiles(
    state: CaseState, transactions: list[dict[str, Any]], sidecars: Iterable[Path]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    decodes: list[dict[str, Any]] = []
    webshell_events: list[dict[str, Any]] = []
    profiles, failures = _configs(sidecars)
    for profile in profiles:
        family = str(profile["family"]).lower()
        for transaction in transactions:
            if transaction.get("protocol") not in {"http/1.x", "websocket"}:
                continue
            try:
                matched = _matches(profile, transaction)
            except (ValueError, TypeError, re.error) as exc:
                failures.append({
                    "stage": "webshell-config", "family": family, "transaction_id": transaction.get("id"),
                    "message": f"profile match failed: {type(exc).__name__}: {exc}",
                })
                continue
            if not matched:
                continue
            if family == "suo5" and transaction.get("protocol") != "websocket":
                continue
            if family != "suo5" and transaction.get("protocol") == "websocket":
                continue
            default_direction = "payload" if transaction.get("protocol") == "websocket" else "request"
            direction = str(profile.get("direction", default_direction))
            payload_meta = transaction.get(direction, {}).get("body") or {}
            payload_path = payload_meta.get("path")
            if family in {"regeorg", "neo-regeorg", "neoreg"} and not payload_path:
                payload = b""
            elif not payload_path or not Path(payload_path).is_file():
                failures.append({"stage": "webshell", "family": family, "transaction_id": transaction["id"], "message": f"{direction} body is unavailable"})
                continue
            else:
                payload = Path(payload_path).read_bytes()
            try:
                if family == "behinder":
                    result = decode_behinder(
                        payload, key=_key(profile), cipher=str(profile.get("cipher", "aes-ecb")),
                        wrapper=str(profile.get("wrapper", "raw")), version=str(profile.get("version", "unknown")),
                        wrapper_options=profile.get("wrapper_options"),
                        iv=bytes.fromhex(profile["iv_hex"]) if profile.get("iv_hex") else None,
                    )
                elif family == "godzilla":
                    result = decode_godzilla(payload, key=_key(profile), profile=str(profile.get("profile", "java-aes-raw")))
                elif family == "antsword":
                    result = decode_antsword(payload, chain=list(profile.get("chain", ["raw"])))
                elif family in {"chopper", "china-chopper"}:
                    result = decode_chopper(payload, language=str(profile.get("language", "php")))
                elif family in {"weevely", "weevely3"}:
                    result = decode_weevely3(payload, password=profile.get("password"))
                elif family == "suo5":
                    result = decode_suo5_frame(payload)
                elif family in {"regeorg", "neo-regeorg", "neoreg"}:
                    captured_headers = _single_value_headers(transaction.get("request", {}).get("headers", {}))
                    configured_headers = _single_value_headers(profile.get("headers", {}))
                    result = decode_regeorg_control({**captured_headers, **configured_headers}, payload)
                else:
                    failures.append({"stage": "webshell", "family": family, "transaction_id": transaction["id"], "message": "unknown profile family"})
                    continue
            except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error) as exc:
                failures.append({
                    "stage": "webshell", "family": family, "transaction_id": transaction["id"],
                    "message": f"profile decode failed: {type(exc).__name__}: {exc}",
                })
                continue
            output = result.get("output")
            for record in result.get("records", []):
                if "id" not in record:
                    record["id"] = stable_evidence_id("DEC", {"transaction": transaction["id"], "family": family, "input": record.get("input_sha256")})
                record["source_transaction"] = transaction["id"]
                record["direction"] = direction
                decodes.append(record)
            output_meta = None
            if isinstance(output, bytes):
                digest = hashlib.sha256(output).hexdigest()
                decode_id = decodes[-1]["id"] if decodes else stable_evidence_id("DEC", {"transaction": transaction["id"], "family": family, "sha256": digest})
                output_path = state.root / "objects" / f"{decode_id}-{direction}.bin"
                state.write_artifact(output_path, output, owner="decode")
                output_meta = {"path": str(output_path.resolve()), "size": len(output), "sha256": digest}
            event_id = stable_evidence_id("EVT", {"transaction": transaction["id"], "family": family, "direction": direction})
            webshell_events.append({
                "id": event_id, "time": transaction.get(direction, {}).get("time"), "kind": "webshell-decode",
                "family": family, "transaction_id": transaction["id"], "direction": direction,
                "status": result.get("status", "unknown"), "output": output_meta,
                "details": _serializable(result), "evidence_ids": [transaction["id"]] + [row["id"] for row in result.get("records", []) if row.get("id")],
            })
    return decodes, webshell_events, failures
