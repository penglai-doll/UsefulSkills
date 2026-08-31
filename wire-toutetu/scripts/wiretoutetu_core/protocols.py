"""Protocol-specific transaction and object extractors over normalized packet rows."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any

from .case_state import CaseState
from .contracts import stable_evidence_id
from .tshark_backend import FIELD_AGGREGATOR


def _integer(value: str) -> int | None:
    try:
        return int(value, 0)
    except (TypeError, ValueError):
        return None


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _payload(row: dict[str, str]) -> bytes:
    return _hex_field(row.get("data.data") or row.get("tcp.payload") or "")


def _hex_field(value: str) -> bytes:
    compact = value.replace(":", "").replace(FIELD_AGGREGATOR, "")
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return b""
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return b""


def _txn_id(capture_sha256: str, protocol: str, row: dict[str, str], discriminator: str) -> str:
    return stable_evidence_id(
        "TXN",
        {
            "capture_sha256": capture_sha256,
            "protocol": protocol,
            "frame": row.get("frame.number"),
            "discriminator": discriminator,
        },
    )


def _transaction_time(transaction: dict[str, Any]) -> float | None:
    """Best known epoch time for a transaction, so timeline events sort correctly."""
    for candidate in (
        (transaction.get("request") or {}).get("time") if isinstance(transaction.get("request"), dict) else None,
        transaction.get("time"),
        (transaction.get("response") or {}).get("time") if isinstance(transaction.get("response"), dict) else None,
        (transaction.get("payload") or {}).get("time") if isinstance(transaction.get("payload"), dict) else None,
    ):
        if candidate is not None:
            return float(candidate)
    return None


def _write_object(
    state: CaseState, *, source_transaction: str, filename: str, data: bytes, completeness: str = "complete"
) -> dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    object_id = stable_evidence_id("OBJ", {"source_transaction": source_transaction, "sha256": digest})
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name).strip("._") or "object.bin"
    output = state.root / "objects" / f"{object_id}_{safe}"
    state.write_artifact(output, data, owner="inventory")
    return {
        "id": object_id,
        "source_transaction": source_transaction,
        "filename": safe,
        "magic": data[:16].hex(),
        "size": len(data),
        "sha256": digest,
        "extraction_path": str(output.resolve()),
        "completeness": completeness,
    }


def extract_protocol_records(
    packets: list[dict[str, str]], capture_sha256: str, state: CaseState
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    transactions: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    dns_pending: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    ftp_pending: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    smtp_streams: dict[str, bytearray] = defaultdict(bytearray)
    ftp_data_streams: dict[str, bytearray] = defaultdict(bytearray)
    ftp_data_times: dict[str, float | None] = {}

    for row in packets:
        protocols = set(row.get("frame.protocols", "").split(":"))
        frame = _integer(row.get("frame.number", ""))
        timestamp = _float(row.get("frame.time_epoch", ""))
        stream = row.get("tcp.stream") or row.get("udp.stream") or ""

        if row.get("dns.qry.name"):
            dns_id = row.get("dns.id") or f"frame-{frame}"
            response = row.get("dns.flags.response") in {"1", "True", "true"}
            if not response:
                dns_pending[dns_id].append({"frame": frame, "time": timestamp, "name": row["dns.qry.name"]})
            else:
                request = dns_pending[dns_id].popleft() if dns_pending[dns_id] else None
                txn_id = _txn_id(capture_sha256, "dns", row, dns_id)
                transactions.append({
                    "id": txn_id, "protocol": "dns", "transport_index": {"udp_stream": _integer(row.get("udp.stream", "")), "substream": None},
                    "request": request or {"frame": None, "time": None, "name": row["dns.qry.name"]},
                    "response": {"frame": frame, "time": timestamp, "address": row.get("dns.a") or None},
                    "completeness": "complete" if request else "partial",
                })

        if row.get("icmp.type") or row.get("icmpv6.type"):
            kind = "icmpv6" if row.get("icmpv6.type") else "icmp"
            discriminator = f"{row.get('icmp.ident')}:{row.get('icmp.seq')}:{frame}"
            transactions.append({
                "id": _txn_id(capture_sha256, kind, row, discriminator), "protocol": kind,
                "transport_index": {"packet": frame, "substream": None},
                "frame": frame, "time": timestamp,
                "type": _integer(row.get(f"{kind}.type", "")), "identifier": _integer(row.get("icmp.ident", "")),
                "sequence": _integer(row.get("icmp.seq", "")), "data_sha256": hashlib.sha256(_payload(row)).hexdigest() if _payload(row) else None,
                "completeness": "complete",
            })

        if row.get("ftp.request.command"):
            request = {"frame": frame, "time": timestamp, "command": row["ftp.request.command"], "argument": row.get("ftp.request.arg")}
            ftp_pending[stream].append(request)
        if row.get("ftp.response.code"):
            request = ftp_pending[stream].popleft() if ftp_pending[stream] else None
            txn_id = _txn_id(capture_sha256, "ftp", row, f"{stream}:{frame}")
            transactions.append({
                "id": txn_id, "protocol": "ftp", "transport_index": {"tcp_stream": _integer(stream), "substream": None},
                "time": timestamp,
                "request": request, "response": {"frame": frame, "time": timestamp, "code": _integer(row["ftp.response.code"]), "argument": row.get("ftp.response.arg")},
                "completeness": "complete" if request else "partial",
            })
        if "ftp-data" in protocols or "ftp_data" in protocols:
            if stream not in ftp_data_times:
                ftp_data_times[stream] = timestamp
            ftp_data_streams[stream].extend(_payload(row))

        if "smtp" in protocols or row.get("smtp.req.command") or row.get("smtp.response.code"):
            smtp_streams[stream].extend(_payload(row))
            if row.get("smtp.req.command") or row.get("smtp.response.code"):
                txn_id = _txn_id(capture_sha256, "smtp", row, f"{stream}:{frame}")
                transactions.append({
                    "id": txn_id, "protocol": "smtp", "transport_index": {"tcp_stream": _integer(stream), "substream": None},
                    "frame": frame, "time": timestamp,
                    "command": row.get("smtp.req.command") or None, "parameter": row.get("smtp.req.parameter") or None,
                    "response_code": _integer(row.get("smtp.response.code", "")), "response": row.get("smtp.rsp.parameter") or None,
                    "completeness": "complete",
                })

        if "usbhid" in protocols or row.get("usbhid.data"):
            txn_id = _txn_id(capture_sha256, "usb-hid", row, str(frame))
            transactions.append({
                "id": _txn_id(capture_sha256, "usb-hid", row, str(frame)), "protocol": "usb-hid",
                "transport_index": {"bus": _integer(row.get("usb.bus_id", "")), "device": _integer(row.get("usb.device_address", "")), "endpoint": row.get("usb.endpoint_address") or None},
                "frame": frame, "time": timestamp,
                "report_hex": row.get("usbhid.data") or row.get("data.data") or None,
                "completeness": "complete",
            })

        metadata_protocols = protocols.intersection({"websocket", "smb", "smb2", "mysql", "redis", "mongodb", "mongo", "rtp", "rtcp", "rdp", "wlan", "socks", "socks5", "quic", "http3"})
        for protocol in sorted(metadata_protocols):
            normalized = "mongodb" if protocol == "mongo" else "smb" if protocol == "smb2" else protocol
            discriminator = f"{stream}:{row.get('http2.streamid')}:{row.get('http3.stream_id')}:{frame}:{normalized}"
            detail = {
                key: value for key, value in row.items()
                if value and key.startswith(("websocket.", "smb2.", "mysql.", "redis.", "mongo.", "rtp.", "wlan.", "socks.", "quic.", "http3."))
            }
            raw = _hex_field(row.get("websocket.payload", "")) if normalized == "websocket" else _payload(row)
            transaction = {
                "id": _txn_id(capture_sha256, normalized, row, discriminator), "protocol": normalized,
                "transport_index": {"tcp_stream": _integer(row.get("tcp.stream", "")), "udp_stream": _integer(row.get("udp.stream", "")), "substream": _integer(row.get("http3.stream_id", ""))},
                "frame": frame, "time": timestamp, "fields": detail,
                "payload_sha256": hashlib.sha256(raw).hexdigest() if raw else None, "payload_length": len(raw),
                "completeness": "complete" if normalized not in {"quic", "http3", "rdp", "wlan"} else "unknown",
            }
            if normalized == "websocket" and raw:
                payload_path = state.root / "streams" / f"{transaction['id']}-payload.bin"
                state.write_artifact(payload_path, raw, owner="inventory")
                transaction["payload"] = {
                    "time": timestamp,
                    "body": {"path": str(payload_path.resolve()), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
                }
            transactions.append(transaction)

    for stream, data in ftp_data_streams.items():
        if not data:
            continue
        txn_id = stable_evidence_id("TXN", {"capture_sha256": capture_sha256, "protocol": "ftp-data", "stream": stream})
        transactions.append({"id": txn_id, "protocol": "ftp-data", "transport_index": {"tcp_stream": _integer(stream), "substream": None}, "time": ftp_data_times.get(stream), "completeness": "complete"})
        objects.append(_write_object(state, source_transaction=txn_id, filename=f"ftp-stream-{stream}.bin", data=bytes(data)))

    for stream, raw in smtp_streams.items():
        data = bytes(raw)
        marker = data.find(b"Content-")
        if marker < 0:
            continue
        previous_line = data.rfind(b"\r\n", 0, marker)
        message_start = previous_line + 2 if previous_line >= 0 else 0
        message_data = data[message_start:]
        if message_data.endswith(b"\r\n.\r\n"):
            message_data = message_data[:-5]
        try:
            message = BytesParser(policy=policy.default).parsebytes(message_data)
        except Exception:
            continue
        source_txn = next((item["id"] for item in reversed(transactions) if item["protocol"] == "smtp" and item["transport_index"].get("tcp_stream") == _integer(stream)), None)
        if not source_txn:
            source_txn = stable_evidence_id("TXN", {"capture_sha256": capture_sha256, "protocol": "smtp-mime", "stream": stream})
        for part in message.walk():
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if filename and isinstance(payload, bytes):
                objects.append(_write_object(state, source_transaction=source_txn, filename=filename, data=payload))

    for transaction in transactions:
        event_id = stable_evidence_id("EVT", {"transaction": transaction["id"], "kind": transaction["protocol"]})
        events.append({"id": event_id, "time": _transaction_time(transaction), "kind": f"{transaction['protocol']}-transaction", "operation": transaction["protocol"], "result": None, "evidence_ids": [transaction["id"]]})
    return transactions, objects, events
