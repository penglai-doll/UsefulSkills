"""Read bounded Windows-artifact summaries without changing the input evidence.

The optional registry and EVTX libraries are inspected only at runtime.  This
tool never installs dependencies, launches helpers, mounts evidence, or
attempts DPAPI decryption.
"""

from __future__ import annotations

import argparse
import configparser
from datetime import datetime, timezone
import importlib.util
import itertools
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable
import xml.etree.ElementTree as ElementTree

from common import bounded_list, emit, is_reparse


MAX_INPUT_BYTES = 1024 * 1024
MAX_RESULT_LIMIT = 200
MAX_TEXT_LENGTH = 4096
MAX_DEPTH = 12
MAX_REGISTRY_PARSER_BYTES = 64 * 1024 * 1024
MAX_BINARY_EVTX_BYTES = 128 * 1024 * 1024
MAX_REGISTRY_KEYS = 200
MAX_REGISTRY_VALUES_PER_KEY = 3
MAX_REGISTRY_SUBKEYS_PER_KEY = 20
MAX_BINARY_EVTX_RECORDS = 5000
MAX_SYNTHETIC_EVENT_RECORDS = 5000
MAX_SQLITE_TEXT_PREVIEW = 512
MAX_SQLITE_BLOB_PREFIX = 128
DPAPI_CONFIRMATION = "I_CONFIRM_NO_BUNDLED_DPAPI_DECRYPT"
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")


def artifact_metadata(path: Path, **extra: object) -> dict:
    """Describe the evidence path without changing it."""
    result: dict[str, object] = {"path": str(path.absolute()), "size": None, "mtime": None}
    try:
        status = path.stat()
        result.update({"size": status.st_size, "mtime": status.st_mtime, "regular_file": path.is_file()})
    except OSError as error:
        result["read_error"] = str(error)
    result.update(extra)
    return result


def read_bounded_probe(path: Path) -> tuple[bytes, bool, str | None]:
    """Read one bounded probe while keeping truncation separate from read errors."""
    try:
        with path.open("rb") as source:
            payload = source.read(MAX_INPUT_BYTES + 1)
    except OSError as error:
        return b"", False, str(error)
    truncated = len(payload) > MAX_INPUT_BYTES
    return payload[:MAX_INPUT_BYTES], truncated, None


def read_bounded(path: Path, errors: list[str]) -> bytes:
    """Read a fixed maximum prefix so malformed or huge evidence stays bounded."""
    payload, truncated, read_error = read_bounded_probe(path)
    if read_error is not None:
        errors.append(f"input unavailable: {read_error}")
        return b""
    if truncated:
        errors.append(f"input exceeds {MAX_INPUT_BYTES} byte parser bound; only a prefix was read")
    return payload


def incomplete_status(errors: list[str], default: str = "incomplete-parser-error") -> str:
    """Classify a non-empty parser error list without overstating completeness."""
    if any(
        "only a prefix was read" in error
        or "parser bound" in error
        for error in errors
    ):
        return "incomplete-input-truncated"
    return default


def hive_role(path: Path) -> str:
    name = path.name.casefold()
    roles = {
        "software": "software", "system": "system", "sam": "sam", "security": "security",
        "default": "default", "ntuser.dat": "user", "usrclass.dat": "user-class",
    }
    return roles.get(name, "unknown")


def printable_strings(payload: bytes, limit: int) -> list[str]:
    maximum = max(0, limit) + 1
    return [match.group().decode("ascii", "replace")[:MAX_TEXT_LENGTH] for match in itertools.islice(PRINTABLE.finditer(payload), maximum)]


def registry_fallback(payload: bytes, limit: int) -> tuple[list[dict], list[str]]:
    """Extract deterministic textual hints from a hive or a synthetic text fixture."""
    strings = printable_strings(payload, limit)
    hints = []
    for value in strings:
        if value.startswith("[") and value.endswith("]"):
            hints.append(value)
        elif "\\" in value and ("HKEY_" in value.upper() or "SOFTWARE" in value.upper()):
            hints.append(value)
    record_cap = max(0, limit) + 1
    records: list[dict] = []
    signature = b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf"
    offset = payload.find(signature)
    while offset >= 0 and len(records) < record_cap:
        records.append({
            "kind": "binary-signature",
            "offset": offset,
            "value": signature.hex(),
            "encoding": "hex",
            "protection": "likely-dpapi",
        })
        offset = payload.find(signature, offset + len(signature))
    encoded_signature = b"AQAAANCMnd8BFdER"
    lower_payload = payload.lower()
    offset = lower_payload.find(encoded_signature.lower())
    while offset >= 0 and len(records) < record_cap:
        records.append({
            "kind": "base64-signature",
            "offset": offset,
            "value": payload[offset:offset + len(encoded_signature)].decode(
                "ascii",
                "replace",
            ),
            "encoding": "base64-prefix",
            "protection": "likely-dpapi",
        })
        offset = lower_payload.find(
            encoded_signature.lower(),
            offset + len(encoded_signature),
        )
    for value in strings:
        if len(records) >= record_cap:
            break
        record = {
            "kind": "printable-string",
            "value": value,
        }
        if is_likely_dpapi(value):
            record["protection"] = "likely-dpapi"
        records.append(record)
    return records, sorted(set(hints), key=str.casefold)


def registry_value_record(key_path: str, name: str, value: object) -> dict:
    """Represent a registry value using a bounded preview while testing original bytes."""
    if isinstance(value, bytes):
        preview = value[:MAX_SQLITE_BLOB_PREFIX].hex()
        encoding = "hex"
        truncated = len(value) > MAX_SQLITE_BLOB_PREFIX
    else:
        text = str(value)
        preview = text[:MAX_TEXT_LENGTH]
        encoding = "text"
        truncated = len(text) > MAX_TEXT_LENGTH
    record = {
        "kind": "registry-value",
        "key": key_path,
        "name": name,
        "value": preview,
        "encoding": encoding,
        "truncated": truncated,
    }
    if is_likely_dpapi(value, name):
        record["protection"] = "likely-dpapi"
    return record


def registry_parser_records(path: Path, limit: int, errors: list[str]) -> list[dict]:
    """Use python-registry when installed, keeping traversal depth and count fixed."""
    try:
        from Registry import Registry  # type: ignore[import-not-found]
        hive = Registry.Registry(str(path))
        root = hive.root()
    except Exception as error:  # optional parser failures are evidence, not a fallback claim
        errors.append(f"python-registry could not parse hive: {error}")
        return []
    found: list[dict] = []
    pending: list[tuple[Any, int]] = [(root, 0)]
    record_budget = min(max(0, limit) + 1, MAX_REGISTRY_KEYS)
    while pending and len(found) < record_budget:
        key, depth = pending.pop(0)
        try:
            found.append({"kind": "registry-key", "path": key.path(), "name": key.name(), "depth": depth})
            for value in key.values()[:MAX_REGISTRY_VALUES_PER_KEY]:
                original_value = value.value()
                found.append(
                    registry_value_record(
                        key.path(),
                        value.name(),
                        original_value,
                    )
                )
                if len(found) >= record_budget:
                    break
            if depth < 5:
                remaining_keys = MAX_REGISTRY_KEYS - len(pending) - len(found)
                if remaining_keys > 0:
                    pending.extend((child, depth + 1) for child in key.subkeys()[:min(MAX_REGISTRY_SUBKEYS_PER_KEY, remaining_keys)])
        except Exception as error:
            errors.append(f"python-registry entry skipped: {error}")
    return found


def analyze_registry(path: Path, limit: int) -> dict:
    errors: list[str] = []
    payload = read_bounded(path, errors)
    parser_available = importlib.util.find_spec("Registry") is not None
    role = hive_role(path)
    if role == "unknown":
        upper_payload = payload.upper()
        if b"HKEY_LOCAL_MACHINE\\SOFTWARE" in upper_payload or b"HKLM\\SOFTWARE" in upper_payload:
            role = "software"
        elif b"HKEY_USERS" in upper_payload or b"HKEY_CURRENT_USER" in upper_payload:
            role = "user"
    routes = ["bounded-metadata", "bounded-printable-fallback"]
    records, key_hints = registry_fallback(payload, limit)
    prefix_fallback = any("only a prefix was read" in error for error in errors)
    parser = "fallback-prefix" if prefix_fallback else "fallback"
    confidence = "fallback-prefix-low" if prefix_fallback else "fallback-low"
    parser_skip_reason: str | None = None
    try:
        status = path.stat()
        if not path.is_file():
            parser_skip_reason = "input is not a regular file"
        elif status.st_size > MAX_REGISTRY_PARSER_BYTES:
            parser_skip_reason = f"input exceeds {MAX_REGISTRY_PARSER_BYTES} byte parser budget"
    except OSError as error:
        parser_skip_reason = f"size check failed: {error}"
    if parser_available and parser_skip_reason:
        errors.append(f"python-registry skipped: {parser_skip_reason}")
        routes.insert(1, "python-registry-size-refused-fallback")
    elif parser_available:
        parsed = registry_parser_records(path, limit, errors)
        if parsed:
            records = parsed
            parser = "python-registry"
            confidence = "parser-high"
            routes.insert(1, "python-registry")
        else:
            routes.insert(1, "python-registry-failed-fallback")
    return {
        "artifact": artifact_metadata(path, kind="registry", hive_role=role, parser=parser, confidence=confidence),
        "records": bounded_list(records, limit),
        "key_hints": bounded_list(key_hints, limit),
        "routes": bounded_list(routes, limit),
        "errors": bounded_list(errors, limit),
    }


def parse_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def parse_boundary(value: str | None, label: str, errors: list[str]) -> datetime | None:
    if value is None:
        return None
    parsed = parse_timestamp(value)
    if parsed is None:
        errors.append(f"invalid {label} timestamp: {value}")
    return parsed


def event_from_mapping(item: dict, default_log: str | None = None) -> dict:
    raw_id = item.get("event_id", item.get("EventID", item.get("id")))
    try:
        event_id = int(raw_id) if raw_id is not None else None
    except (TypeError, ValueError):
        event_id = None
    return {
        "log": str(item.get("log", item.get("channel", default_log or "Unknown"))),
        "event_id": event_id,
        "timestamp": str(item.get("timestamp", item.get("time", item.get("TimeCreated", "")))),
        "provider": str(item.get("provider", item.get("Provider", ""))),
        "message": str(item.get("message", item.get("Message", "")))[:MAX_TEXT_LENGTH],
    }


def first_element(parent: ElementTree.Element, wildcard: str, plain: str) -> ElementTree.Element | None:
    """Find a namespaced node first without relying on Element truthiness."""
    found = parent.find(wildcard)
    return found if found is not None else parent.find(plain)


def first_text(parent: ElementTree.Element, wildcard: str, plain: str) -> str:
    found = first_element(parent, wildcard, plain)
    return found.text if found is not None and found.text is not None else ""


def xml_events(payload: bytes, default_log: str | None, errors: list[str]) -> list[dict]:
    if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
        errors.append("XML DTD/entity declarations are refused")
        return []
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        errors.append(f"synthetic XML parse failed: {error}")
        return []
    records: list[dict] = []
    for node in root.iter():
        if node.tag.rsplit("}", 1)[-1].casefold() != "event":
            continue
        if len(records) >= MAX_SYNTHETIC_EVENT_RECORDS:
            errors.append(f"XML event parser budget reached at {MAX_SYNTHETIC_EVENT_RECORDS} records")
            break
        system = first_element(node, ".//{*}System", "System")
        event_id = ""
        provider = ""
        timestamp = ""
        log = default_log or "Unknown"
        if system is not None:
            event_id = first_text(system, "{*}EventID", "EventID")
            provider_node = first_element(system, "{*}Provider", "Provider")
            provider = provider_node.get("Name", "") if provider_node is not None else ""
            time_node = first_element(system, "{*}TimeCreated", "TimeCreated")
            timestamp = time_node.get("SystemTime", "") if time_node is not None else ""
            channel = first_text(system, "{*}Channel", "Channel")
            log = channel or log
        records.append(event_from_mapping({"log": log, "event_id": event_id, "timestamp": timestamp, "provider": provider, "message": " ".join(node.itertext())}, default_log))
    return records


def synthetic_events(payload: bytes, default_log: str | None, errors: list[str]) -> list[dict] | None:
    stripped = payload.lstrip()
    if stripped.startswith((b"{", b"[")):
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            errors.append(f"synthetic JSON parse failed: {error}")
            return []
        values = parsed.get("events", []) if isinstance(parsed, dict) else parsed
        if not isinstance(values, list):
            errors.append("synthetic JSON events must be a list")
            return []
        if len(values) > MAX_SYNTHETIC_EVENT_RECORDS:
            errors.append(f"synthetic event parser budget reached at {MAX_SYNTHETIC_EVENT_RECORDS} records")
        return [event_from_mapping(item, default_log) for item in values[:MAX_SYNTHETIC_EVENT_RECORDS] if isinstance(item, dict)]
    if stripped.startswith(b"<"):
        return xml_events(payload, default_log, errors)
    return None


def binary_evtx_events(
    path: Path,
    default_log: str | None,
    errors: list[str],
) -> tuple[list[dict], str, str, str, list[dict]]:
    attempts = [{
        "parser": "python-evtx",
        "status": "not-attempted",
        "records_attempted": 0,
        "records_parsed": 0,
        "records_failed": 0,
        "budget_reached": False,
    }]
    try:
        if path.stat().st_size > MAX_BINARY_EVTX_BYTES:
            reason = (
                f"input exceeds {MAX_BINARY_EVTX_BYTES} byte parser budget"
            )
            errors.append(f"binary EVTX parser skipped: {reason}")
            attempts[0].update({"status": "refused", "reason": reason})
            return [], "unavailable", "refused", "incomplete-parser-refused", attempts
    except OSError as error:
        errors.append(f"binary EVTX parser size check failed: {error}")
        attempts[0].update({"status": "failed", "reason": str(error)})
        return [], "unavailable", "failed", "incomplete-parser-failed", attempts
    if importlib.util.find_spec("Evtx") is None:
        reason = "optional python-evtx is not installed"
        errors.append(f"binary EVTX parsing unavailable: {reason}")
        attempts[0].update({"status": "unavailable", "reason": reason})
        return [], "unavailable", "unavailable", "incomplete-parser-unavailable", attempts
    try:
        from Evtx.Evtx import Evtx  # type: ignore[import-not-found]
        values = []
        budget_reached = False
        records_attempted = 0
        records_parsed = 0
        records_failed = 0
        with Evtx(str(path)) as log:
            for index, record in enumerate(log.records()):
                if index >= MAX_BINARY_EVTX_RECORDS:
                    errors.append(f"binary EVTX record budget reached at {MAX_BINARY_EVTX_RECORDS}")
                    budget_reached = True
                    break
                records_attempted += 1
                errors_before = len(errors)
                try:
                    parsed = xml_events(
                        record.xml().encode("utf-8"),
                        default_log,
                        errors,
                    )
                except Exception as error:
                    errors.append(
                        f"python-evtx record {index} XML extraction failed: {error}"
                    )
                    records_failed += 1
                    continue
                if len(errors) > errors_before:
                    records_failed += 1
                    continue
                records_parsed += 1
                values.extend(parsed)
        if records_failed:
            parser_status = (
                "partial-failed"
                if records_parsed
                else "failed"
            )
            completeness = (
                "incomplete-record-errors-and-budget"
                if budget_reached
                else "incomplete-record-errors"
            )
        elif budget_reached:
            parser_status = "partial-budget"
            completeness = "incomplete-record-budget"
        else:
            parser_status = "succeeded"
            completeness = "complete-with-python-evtx"
        attempts[0].update({
            "status": parser_status,
            "records_attempted": records_attempted,
            "records_parsed": records_parsed,
            "records_failed": records_failed,
            "budget_reached": budget_reached,
        })
        return values, "python-evtx", parser_status, completeness, attempts
    except Exception as error:
        errors.append(f"python-evtx could not parse binary EVTX: {error}")
        attempts[0].update({"status": "failed", "reason": str(error)})
        return [], "python-evtx", "failed", "incomplete-parser-failed", attempts


def filter_events(events: Iterable[dict], args: argparse.Namespace, errors: list[str]) -> list[dict]:
    start = parse_boundary(args.start, "--from", errors)
    end = parse_boundary(args.end, "--to", errors)
    if (args.start is not None and start is None) or (args.end is not None and end is None):
        return []
    wanted_ids = set(args.event_id or [])
    keyword = (args.keyword or "").casefold()
    selected = []
    for event in events:
        timestamp = parse_timestamp(event.get("timestamp"))
        if args.log and event.get("log", "").casefold() != args.log.casefold():
            continue
        if wanted_ids and event.get("event_id") not in wanted_ids:
            continue
        if start and (timestamp is None or timestamp < start):
            continue
        if end and (timestamp is None or timestamp > end):
            continue
        if keyword and keyword not in json.dumps(event, ensure_ascii=False).casefold():
            continue
        selected.append(event)
        if len(selected) >= args.limit + 1:
            break
    return selected


def analyze_evtx(path: Path, args: argparse.Namespace) -> dict:
    errors: list[str] = []
    payload, probe_truncated, probe_read_error = read_bounded_probe(path)
    if probe_read_error is not None:
        errors.append(f"input unavailable: {probe_read_error}")
    synthetic_errors: list[str] = []
    events = synthetic_events(payload, args.log, synthetic_errors)
    parser = "synthetic-json-or-xml"
    parser_status = "succeeded"
    completeness = "synthetic-fixture-complete"
    attempts = [{"parser": parser, "status": "succeeded"}]
    routes = ["bounded-input", "synthetic-json-or-xml"]
    if events is None:
        events, parser, parser_status, completeness, attempts = binary_evtx_events(
            path,
            args.log,
            errors,
        )
        routes[-1] = "binary-evtx-optional-parser"
    else:
        errors.extend(synthetic_errors)
        if probe_truncated:
            errors.append(
                f"input exceeds {MAX_INPUT_BYTES} byte parser bound; "
                "only a prefix was read"
            )
    parser_error_count = len(errors)
    selected = filter_events(events, args, errors)
    if parser_error_count and parser_status == "succeeded":
        parser_errors = errors[:parser_error_count]
        parser_status = "partial-failed"
        completeness = incomplete_status(
            parser_errors,
            "incomplete-record-errors"
            if parser == "python-evtx"
            else "incomplete-parser-error",
        )
        attempts = [dict(attempt) for attempt in attempts]
        if attempts:
            attempts[-1].update({
                "status": "partial-failed",
                "error_count": len(parser_errors),
            })
    confidence = (
        "parser-high"
        if parser == "python-evtx" and parser_status == "succeeded"
        else "fixture-only"
        if parser_status == "succeeded"
        else "unavailable"
    )
    return {
        "artifact": artifact_metadata(
            path,
            kind="evtx",
            parser=parser,
            parser_status=parser_status,
            confidence=confidence,
            completeness=completeness,
            attempts=attempts,
        ),
        "events": bounded_list(selected, args.limit),
        "routes": bounded_list(routes, args.limit),
        "errors": bounded_list(errors, args.limit),
    }


def is_likely_dpapi(value: object, label: str = "") -> bool:
    if "dpapi" in label.casefold():
        return True
    if isinstance(value, str):
        compact = value.replace(" ", "")
        return (
            "dpapi" in value.casefold()
            or "AQAAANCMnd8BFdER".casefold() in compact.casefold()
        )
    if isinstance(value, bytes):
        return value.startswith(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf")
    return False


def record_value(path: str, value: object) -> dict:
    text = str(value)[:MAX_TEXT_LENGTH]
    record = {"path": path, "value": text}
    if is_likely_dpapi(value, path):
        record["protection"] = "likely-dpapi"
    return record


def flatten_json(value: object, limit: int, path: str = "$", depth: int = 0, output: list[dict] | None = None) -> list[dict]:
    output = output if output is not None else []
    if len(output) >= limit + 1:
        return output
    if depth >= MAX_DEPTH:
        output.append({"path": path, "value": "<depth-limit>"})
        return output
    if isinstance(value, dict):
        for key, item in value.items():
            flatten_json(item, limit, f"{path}.{key}", depth + 1, output)
            if len(output) >= limit + 1:
                break
        return output
    if isinstance(value, list):
        for index, item in enumerate(value):
            flatten_json(item, limit, f"{path}[{index}]", depth + 1, output)
            if len(output) >= limit + 1:
                break
        return output
    output.append(record_value(path, value))
    return output


def sqlite_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def sqlite_projection(column_names: list[str]) -> tuple[str, list[int]]:
    """Select only type/length plus fixed-size text or BLOB prefixes."""
    expressions: list[str] = []
    parameters: list[int] = []
    for index, name in enumerate(column_names):
        column = sqlite_identifier(name)
        expressions.extend((
            f"typeof({column}) AS _type_{index}",
            f"length({column}) AS _length_{index}",
            f"CASE WHEN typeof({column}) = 'blob' THEN NULL ELSE CAST(substr({column}, 1, ?) AS TEXT) END AS _text_{index}",
            f"CASE WHEN typeof({column}) = 'blob' THEN substr({column}, 1, ?) ELSE NULL END AS _blob_{index}",
        ))
        parameters.extend((MAX_SQLITE_TEXT_PREVIEW, MAX_SQLITE_BLOB_PREFIX))
    return ", ".join(expressions), parameters


def sqlite_cell(value_type: object, value_length: object, text_prefix: object, blob_prefix: object) -> tuple[dict, bytes]:
    length = int(value_length) if isinstance(value_length, int) else None
    if value_type == "blob":
        raw_prefix = bytes(blob_prefix) if isinstance(blob_prefix, (bytes, bytearray, memoryview)) else b""
        return ({
            "type": "blob", "length": length, "preview": raw_prefix.hex(), "encoding": "hex",
            "truncated": length is not None and length > len(raw_prefix),
        }, raw_prefix)
    preview = None if text_prefix is None else str(text_prefix)
    return ({
        "type": str(value_type), "length": length, "preview": preview,
        "truncated": length is not None and length > MAX_SQLITE_TEXT_PREVIEW,
    }, b"")


def sqlite_sidecars(path: Path) -> list[dict]:
    """Inventory SQLite journals without opening or replaying any of them."""
    found: list[dict] = []
    for suffix, kind in (
        ("-wal", "wal"),
        ("-shm", "shared-memory"),
        ("-journal", "rollback-journal"),
    ):
        candidate = Path(str(path) + suffix)
        try:
            status = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            found.append({
                "path": str(candidate.absolute()),
                "kind": kind,
                "status": "metadata-unavailable",
                "error": str(error),
            })
            continue
        found.append({
            "path": str(candidate.absolute()),
            "kind": kind,
            "status": "present",
            "size": status.st_size,
            "mtime": status.st_mtime,
            "reparse": is_reparse(candidate),
        })
    return found


def analyze_sqlite(path: Path, limit: int, errors: list[str]) -> tuple[list[dict], list[dict], list[dict]]:
    tables: list[dict] = []
    columns: list[dict] = []
    records: list[dict] = []
    columns_shown_total = 0
    try:
        uri = path.resolve(strict=False).as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True)
        try:
            connection.execute("PRAGMA query_only = ON")
            names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT ?", (limit + 1,))]
            for index, name in enumerate(names):
                escaped = sqlite_identifier(name)
                if index >= limit:
                    tables.append({"name": name, "columns_shown": 0, "columns_truncated": False})
                    break
                schema_remaining = max(0, limit - columns_shown_total)
                schema_probe = connection.execute(f"PRAGMA table_info({escaped})").fetchmany(schema_remaining + 1 if schema_remaining else 1)
                shown_schema = schema_probe[:schema_remaining]
                schema_truncated = len(schema_probe) > len(shown_schema)
                tables.append({
                    "name": name,
                    "columns_shown": len(shown_schema),
                    "columns_truncated": schema_truncated,
                })
                columns.extend({"table": name, "name": row[1], "type": row[2]} for row in shown_schema)
                columns_shown_total += len(shown_schema)
                if schema_truncated and len(columns) < limit + 1:
                    overflow = schema_probe[len(shown_schema)]
                    columns.append({"table": name, "name": overflow[1], "type": overflow[2]})
                record_remaining = max(0, limit + 1 - len(records))
                column_names = [row[1] for row in shown_schema]
                if record_remaining == 0 or not column_names:
                    break
                projection, parameters = sqlite_projection(column_names)
                rows = connection.execute(f"SELECT {projection} FROM {escaped} LIMIT ?", (*parameters, record_remaining)).fetchall()
                for row in rows:
                    item: dict[str, dict] = {}
                    dpapi_detected = False
                    for column_index, column in enumerate(column_names):
                        offset = column_index * 4
                        cell, raw_prefix = sqlite_cell(*row[offset:offset + 4])
                        item[column] = cell
                        dpapi_detected = dpapi_detected or is_likely_dpapi(raw_prefix, column) or is_likely_dpapi(cell["preview"], column)
                    if dpapi_detected:
                        item["protection"] = "likely-dpapi"
                    records.append({"table": name, "record": item})
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError) as error:
        errors.append(f"SQLite read-only parse failed: {error}")
    return tables, columns, records


def bounded_ini_records(parser: configparser.ConfigParser, limit: int) -> list[dict]:
    records: list[dict] = []
    for section in parser.sections():
        for key, value in parser.items(section):
            records.append(record_value(f"{section}.{key}", value))
            if len(records) >= limit + 1:
                return records
    return records


def bounded_xml_records(root: ElementTree.Element, limit: int) -> list[dict]:
    records: list[dict] = []
    for element in root.iter():
        if element.text and element.text.strip():
            records.append(record_value("/" + element.tag.rsplit("}", 1)[-1], element.text.strip()))
            if len(records) >= limit + 1:
                break
    return records


def analyze_structured(path: Path, kind: str, limit: int) -> dict:
    errors: list[str] = []
    records: list[dict] = []
    tables: list[dict] = []
    columns: list[dict] = []
    routes = [f"bounded-{kind}-reader"]
    sidecars: list[dict] = []
    completeness = "complete"
    confidence = "parser-high"
    parser_status = "succeeded"
    if kind == "sqlite":
        sidecars = sqlite_sidecars(path)
        if sidecars:
            completeness = "incomplete-sidecars-not-applied"
            confidence = "incomplete-low"
            parser_status = "refused"
            errors.append(
                "SQLite sidecar files are present; parsing was refused because "
                "immutable main-only access would omit journaled state"
            )
            routes.extend((
                "sqlite-sidecars-detected",
                "sqlite-read-only-sidecar-aware-parser-or-copied-set-required",
            ))
        else:
            tables, columns, records = analyze_sqlite(path, limit, errors)
            completeness = (
                "complete-main-database"
                if not errors
                else "incomplete-parser-error"
            )
            if errors:
                confidence = "failed"
                parser_status = "failed"
            routes.append("sqlite-read-only-uri")
    else:
        payload = read_bounded(path, errors)
        try:
            if kind == "json":
                records = flatten_json(json.loads(payload.decode("utf-8")), limit)
            elif kind == "ini":
                parser = configparser.ConfigParser(interpolation=None)
                parser.read_string(payload.decode("utf-8"))
                records = bounded_ini_records(parser, limit)
            elif kind == "xml":
                if b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper():
                    raise ValueError("XML DTD/entity declarations are refused")
                root = ElementTree.fromstring(payload)
                records = bounded_xml_records(root, limit)
        except (UnicodeDecodeError, ValueError, RecursionError, configparser.Error, ElementTree.ParseError, json.JSONDecodeError) as error:
            errors.append(f"{kind} parse failed: {error}")
        if errors:
            completeness = incomplete_status(errors)
            confidence = "failed"
            parser_status = (
                "partial-failed"
                if completeness == "incomplete-input-truncated"
                else "failed"
            )
    return {
        "artifact": artifact_metadata(
            path,
            kind=kind,
            parser=kind,
            parser_status=parser_status,
            confidence=confidence,
            completeness=completeness,
        ),
        "tables": bounded_list(tables, limit),
        "columns": bounded_list(columns, limit),
        "records": bounded_list(records, limit),
        "sidecars": bounded_list(sidecars, limit),
        "routes": bounded_list(routes, limit),
        "errors": bounded_list(errors, limit),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    registry = commands.add_parser("registry")
    registry.add_argument("--input", required=True, type=Path)
    registry.add_argument("--limit", type=int, default=50, help=f"bounded result count (0-{MAX_RESULT_LIMIT})")
    evtx = commands.add_parser("evtx")
    evtx.add_argument("--input", required=True, type=Path)
    evtx.add_argument("--log")
    evtx.add_argument("--event-id", action="append", type=int)
    evtx.add_argument("--from", dest="start")
    evtx.add_argument("--to", dest="end")
    evtx.add_argument("--keyword")
    evtx.add_argument("--limit", type=int, default=50, help=f"bounded result count (0-{MAX_RESULT_LIMIT})")
    structured = commands.add_parser("structured")
    structured.add_argument("--input", required=True, type=Path)
    structured.add_argument("--kind", required=True, choices=("sqlite", "json", "ini", "xml"))
    structured.add_argument("--limit", type=int, default=50, help=f"bounded result count (0-{MAX_RESULT_LIMIT})")
    structured.add_argument("--decrypt", action="store_true")
    structured.add_argument("--decrypt-confirmation")
    args = parser.parse_args()
    if is_reparse(args.input):
        parser.error("explicit reparse artifact inputs are refused")
    if getattr(args, "decrypt", False) and args.decrypt_confirmation != DPAPI_CONFIRMATION:
        parser.error("DPAPI decryption requires the separate exact confirmation token")
    requested_limit = args.limit
    args.limit = min(max(0, requested_limit), MAX_RESULT_LIMIT)
    if args.mode == "registry":
        document = analyze_registry(args.input, args.limit)
    elif args.mode == "evtx":
        document = analyze_evtx(args.input, args)
    else:
        document = analyze_structured(args.input, args.kind, args.limit)
        if args.decrypt:
            document["decrypt"] = {"requested": True, "confirmation": "accepted", "status": "unsupported", "reason": "no bundled DPAPI backend is available"}
    document["limits"] = {"requested": requested_limit, "effective": args.limit, "maximum": MAX_RESULT_LIMIT}
    document["artifacts"] = bounded_list([document["artifact"]], args.limit)
    emit(document)


if __name__ == "__main__":
    main()
