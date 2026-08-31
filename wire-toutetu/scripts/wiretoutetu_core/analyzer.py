"""Generic capture inventory, evidence extraction, and case persistence."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import platform
import re
import subprocess
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from .case_state import CaseState
from .contracts import stable_evidence_id
from .protocols import extract_protocol_records
from .preflight import run_preflight
from .registry import load_registry, select_plugins
from .tshark_backend import FIELD_AGGREGATOR, TSharkError, capture_inventory, extract_packets, iter_packet_index
from .webshell_pipeline import apply_webshell_profiles


SKILL_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = SKILL_ROOT / "scripts" / "registry.yaml"


def determine_size_route(size: int) -> str:
    if size < 100 * 1024 * 1024:
        return "full-pipeline"
    if size <= 2 * 1024 * 1024 * 1024:
        return "stream-index"
    return "inventory-then-slice"


def _integer(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _hex_bytes(value: str) -> bytes | None:
    cleaned = value.replace(":", "").replace(FIELD_AGGREGATOR, "").strip()
    if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _safe_object_name(uri: str, object_id: str, content_type: str) -> str:
    path = unquote(urlsplit(uri).path)
    candidate = Path(path).name
    candidate = re.sub(r"[^A-Za-z0-9._-]", "_", candidate).strip("._")
    if not candidate:
        extension = mimetypes.guess_extension(content_type.split(";", 1)[0].strip()) or ".bin"
        candidate = f"object{extension}"
    return f"{object_id}_{candidate}"[:180]


def _http_headers(value: str) -> dict[str, list[str]]:
    headers: dict[str, list[str]] = {}
    normalized = value.replace(FIELD_AGGREGATOR, "\\r\\n")
    for line in normalized.split("\\r\\n"):
        name, separator, raw_value = line.strip().partition(":")
        if separator and name:
            headers.setdefault(name.strip(), []).append(raw_value.strip())
    return headers


def _transport(packet: dict[str, str]) -> tuple[str, str, str, str, str] | None:
    src = packet.get("ip.src") or packet.get("ipv6.src")
    dst = packet.get("ip.dst") or packet.get("ipv6.dst")
    if packet.get("tcp.stream"):
        return "tcp", packet["tcp.stream"], src, packet.get("tcp.srcport", ""), dst + ":" + packet.get("tcp.dstport", "")
    if packet.get("udp.stream"):
        return "udp", packet["udp.stream"], src, packet.get("udp.srcport", ""), dst + ":" + packet.get("udp.dstport", "")
    return None


def _build_flows(packets: list[dict[str, str]], capture_sha256: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for packet in packets:
        transport = "tcp" if packet.get("tcp.stream") else "udp" if packet.get("udp.stream") else None
        stream = packet.get(f"{transport}.stream", "") if transport else ""
        if transport and stream:
            grouped[(transport, stream)].append(packet)
    flows: list[dict[str, Any]] = []
    for (transport, stream), rows in sorted(grouped.items()):
        first = rows[0]
        src = first.get("ip.src") or first.get("ipv6.src")
        dst = first.get("ip.dst") or first.get("ipv6.dst")
        src_port = _integer(first.get(f"{transport}.srcport", ""))
        dst_port = _integer(first.get(f"{transport}.dstport", ""))
        flags = {
            "retransmission": any(row.get("tcp.analysis.retransmission") for row in rows),
            "out_of_order": any(row.get("tcp.analysis.out_of_order") for row in rows),
            "missing_segment": any(row.get("tcp.analysis.lost_segment") for row in rows),
            "truncated": any(
                _integer(row.get("frame.cap_len", "")) != _integer(row.get("frame.len", ""))
                for row in rows
                if row.get("frame.cap_len") and row.get("frame.len")
            ),
        }
        completeness = "truncated" if flags["truncated"] else "partial" if flags["missing_segment"] else "complete"
        material = {"capture_sha256": capture_sha256, "transport": transport, "stream": stream}
        flows.append(
            {
                "id": stable_evidence_id("FLOW", material),
                "transport": transport,
                "stream": int(stream),
                "source": {"ip": src, "port": src_port},
                "destination": {"ip": dst, "port": dst_port},
                "packet_range": [_integer(rows[0].get("frame.number", "")), _integer(rows[-1].get("frame.number", ""))],
                "start_time": _float(rows[0].get("frame.time_epoch", "")),
                "end_time": _float(rows[-1].get("frame.time_epoch", "")),
                "bytes": sum(_integer(row.get("frame.len", "")) or 0 for row in rows),
                "reassembly": flags,
                "completeness": completeness,
            }
        )
    return flows


def _build_stream_index(
    packets: Iterable[dict[str, str]], capture_sha256: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str], int]:
    aggregates: dict[tuple[str, str], dict[str, Any]] = {}
    protocols: Counter[str] = Counter()
    signals: set[str] = set()
    packet_count = 0
    for packet in packets:
        packet_count += 1
        observed = [value.lower() for value in packet.get("frame.protocols", "").split(":") if value]
        protocols.update(observed)
        signals.update(observed)
        if packet.get("http.request.method"):
            signals.add(packet["http.request.method"].lower())
        transport = "tcp" if packet.get("tcp.stream") else "udp" if packet.get("udp.stream") else None
        stream = packet.get(f"{transport}.stream", "") if transport else ""
        if not transport or not stream:
            continue
        key = (transport, stream)
        item = aggregates.get(key)
        if item is None:
            item = {
                "first": dict(packet), "last": dict(packet), "bytes": 0,
                "flags": {"retransmission": False, "out_of_order": False, "missing_segment": False, "truncated": False},
            }
            aggregates[key] = item
        item["last"] = dict(packet)
        item["bytes"] += _integer(packet.get("frame.len", "")) or 0
        flags = item["flags"]
        flags["retransmission"] = flags["retransmission"] or bool(packet.get("tcp.analysis.retransmission"))
        flags["out_of_order"] = flags["out_of_order"] or bool(packet.get("tcp.analysis.out_of_order"))
        flags["missing_segment"] = flags["missing_segment"] or bool(packet.get("tcp.analysis.lost_segment"))
        captured, original = _integer(packet.get("frame.cap_len", "")), _integer(packet.get("frame.len", ""))
        flags["truncated"] = flags["truncated"] or (captured is not None and original is not None and captured != original)

    flows: list[dict[str, Any]] = []
    for (transport, stream), item in sorted(aggregates.items(), key=lambda row: (row[0][0], int(row[0][1]))):
        first, last, flags = item["first"], item["last"], item["flags"]
        completeness = "truncated" if flags["truncated"] else "partial" if flags["missing_segment"] else "complete"
        flows.append({
            "id": stable_evidence_id("FLOW", {"capture_sha256": capture_sha256, "transport": transport, "stream": stream}),
            "transport": transport, "stream": int(stream),
            "source": {"ip": first.get("ip.src") or first.get("ipv6.src"), "port": _integer(first.get(f"{transport}.srcport", ""))},
            "destination": {"ip": first.get("ip.dst") or first.get("ipv6.dst"), "port": _integer(first.get(f"{transport}.dstport", ""))},
            "packet_range": [_integer(first.get("frame.number", "")), _integer(last.get("frame.number", ""))],
            "start_time": _float(first.get("frame.time_epoch", "")), "end_time": _float(last.get("frame.time_epoch", "")),
            "bytes": item["bytes"], "reassembly": flags, "completeness": completeness,
        })
    protocol_records = [{"protocol": name, "packets": count} for name, count in sorted(protocols.items())]
    return flows, protocol_records, signals, packet_count


def _build_http(
    packets: list[dict[str, str]], capture_sha256: str, state: CaseState
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pending: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
    transactions: list[dict[str, Any]] = []
    objects: list[dict[str, Any]] = []
    for packet in packets:
        stream = packet.get("tcp.stream", "")
        method = packet.get("http.request.method", "")
        if method:
            request_body = _hex_bytes(packet.get("http.file_data", ""))
            pending[stream].append(
                {
                    "packet": _integer(packet.get("frame.number", "")),
                    "time": _float(packet.get("frame.time_epoch", "")),
                    "method": method,
                    "uri": packet.get("http.request.uri", ""),
                    "host": packet.get("http.host", ""),
                    "headers": _http_headers(packet.get("http.request.line", "")),
                    "_body": request_body,
                }
            )
        status = _integer(packet.get("http.response.code", ""))
        if status is None:
            continue
        request = pending[stream].popleft() if pending[stream] else {
            "packet": None,
            "time": None,
            "method": None,
            "uri": None,
            "host": None,
            "headers": {},
            "_body": None,
            "note": "request frame not captured; request fields are unknown for this response",
        }
        material = {
            "capture_sha256": capture_sha256,
            "stream": stream,
            "request_packet": request["packet"],
            "response_packet": _integer(packet.get("frame.number", "")),
        }
        txn_id = stable_evidence_id("TXN", material)
        request_body = request.pop("_body", None)
        response_body = _hex_bytes(packet.get("http.file_data", ""))
        if request_body is not None:
            digest = hashlib.sha256(request_body).hexdigest()
            payload_path = state.root / "streams" / f"{txn_id}-request.bin"
            state.write_artifact(payload_path, request_body, owner="inventory")
            request["body"] = {"path": str(payload_path.resolve()), "size": len(request_body), "sha256": digest}
        response = {
            "packet": _integer(packet.get("frame.number", "")),
            "time": _float(packet.get("frame.time_epoch", "")),
            "status": status,
            "content_type": packet.get("http.content_type", ""),
        }
        if response_body is not None:
            digest = hashlib.sha256(response_body).hexdigest()
            payload_path = state.root / "streams" / f"{txn_id}-response.bin"
            state.write_artifact(payload_path, response_body, owner="inventory")
            response["body"] = {"path": str(payload_path.resolve()), "size": len(response_body), "sha256": digest}
        txn = {
            "id": txn_id,
            "protocol": "http/1.x",
            "transport_index": {"tcp_stream": _integer(stream), "substream": None},
            "request": request,
            "response": response,
            "completeness": "complete" if request["packet"] is not None else "partial",
        }
        transactions.append(txn)
        body = response_body
        if body is not None:
            digest = hashlib.sha256(body).hexdigest()
            obj_id = stable_evidence_id("OBJ", {"transaction": txn_id, "sha256": digest})
            filename = _safe_object_name(request.get("uri") or "", obj_id, packet.get("http.content_type", ""))
            path = state.root / "objects" / filename
            state.write_artifact(path, body, owner="inventory")
            objects.append(
                {
                    "id": obj_id,
                    "source_transaction": txn_id,
                    "filename": filename,
                    "magic": body[:16].hex(),
                    "size": len(body),
                    "sha256": digest,
                    "extraction_path": str(path.resolve()),
                    "completeness": txn["completeness"],
                }
            )
    for stream, requests in pending.items():
        while requests:
            request = requests.popleft()
            material = {
                "capture_sha256": capture_sha256,
                "stream": stream,
                "request_packet": request["packet"],
                "response_packet": None,
            }
            txn_id = stable_evidence_id("TXN", material)
            request_body = request.pop("_body", None)
            if request_body is not None:
                digest = hashlib.sha256(request_body).hexdigest()
                payload_path = state.root / "streams" / f"{txn_id}-request.bin"
                state.write_artifact(payload_path, request_body, owner="inventory")
                request["body"] = {"path": str(payload_path.resolve()), "size": len(request_body), "sha256": digest}
            transactions.append({
                "id": txn_id,
                "protocol": "http/1.x",
                "transport_index": {"tcp_stream": _integer(stream), "substream": None},
                "request": request,
                "response": {"packet": None, "time": None, "status": None, "content_type": ""},
                "completeness": "partial",
            })
    return transactions, objects


def _signals(packets: list[dict[str, str]]) -> set[str]:
    values: set[str] = set()
    for packet in packets:
        values.update(value.lower() for value in packet.get("frame.protocols", "").split(":") if value)
        if packet.get("http.request.method"):
            values.add(packet["http.request.method"].lower())
    return values


def _build_http2(packets: list[dict[str, str]], capture_sha256: str) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for packet in packets:
        substream = packet.get("http2.streamid")
        if not substream:
            continue
        tcp_stream = packet.get("tcp.stream", "")
        key = (tcp_stream, substream)
        item = grouped.setdefault(key, {
            "frames": [], "request": {}, "response": {}, "data_packets": 0,
        })
        item["frames"].append(_integer(packet.get("frame.number", "")))
        if packet.get("http2.headers.method"):
            item["request"]["method"] = packet["http2.headers.method"]
        if packet.get("http2.headers.path"):
            item["request"]["path"] = packet["http2.headers.path"]
        if packet.get("http2.headers.status"):
            item["response"]["status"] = _integer(packet["http2.headers.status"])
        if packet.get("data.data"):
            item["data_packets"] += 1
    transactions = []
    for (tcp_stream, substream), item in sorted(grouped.items(), key=lambda row: (int(row[0][0]), int(row[0][1]))):
        txn_id = stable_evidence_id("TXN", {"capture_sha256": capture_sha256, "protocol": "http2", "tcp_stream": tcp_stream, "substream": substream})
        transactions.append({
            "id": txn_id, "protocol": "http/2", "transport_index": {"tcp_stream": _integer(tcp_stream), "substream": _integer(substream)},
            "packet_range": [min(item["frames"]), max(item["frames"])], "request": item["request"], "response": item["response"],
            "data_packets": item["data_packets"], "completeness": "complete" if item["request"] and item["response"] else "partial",
        })
    return transactions


def analyze_capture(
    capture: str | Path,
    *,
    case_dir: str | Path,
    sidecars: Iterable[str | Path],
    question: str | None = None,
    network: str = "offline",
    memory_limit_mib: int = 512,
) -> dict[str, Any]:
    if memory_limit_mib <= 0:
        raise ValueError("memory limit must be greater than zero")
    capture_path = Path(capture).resolve(strict=True)
    sidecar_paths = [Path(path).resolve(strict=True) for path in sidecars]
    state_path = Path(case_dir).resolve()
    if (state_path / "case.json").is_file():
        state = CaseState.open(state_path)
        existing_capture = Path(state.read_manifest()["capture"]["path"]).resolve(strict=True)
        if not existing_capture.samefile(capture_path):
            raise ValueError(
                f"case is bound to a different capture: {existing_capture}; create a new case directory for {capture_path}"
            )
        state.set_sidecars(sidecar_paths)
        state.refresh_inputs()
    else:
        state = CaseState.create(state_path, capture_path, sidecar_paths)
    manifest = state.read_manifest()
    if "tooling" not in manifest:
        probe = run_preflight(deep_probe=False)
        manifest["tooling"] = {
            "platform_route": probe["platform_route"],
            "python": platform.python_version(),
            "tools": {
                name: {key: value for key, value in details.items() if key in {"status", "path", "version", "scope"}}
                for name, details in probe["tools"].items()
            },
        }
        state.write_manifest(manifest)
        manifest = state.read_manifest()
    cache_key = state.stage_cache_key("inventory", include_sidecars=False)
    decode_cache_key = state.stage_cache_key("decode", include_sidecars=True)
    cached = manifest["stages"].get("inventory", {}).get("cache_key") == cache_key
    decode_cached = manifest["stages"].get("decode", {}).get("cache_key") == decode_cache_key
    if cached and decode_cached and (state.records_dir / "summary.jsonl").is_file():
        summary = state.query_records("summary", limit=1)["items"][0]
        return {
            "status": "ok",
            "completeness": summary["completeness"],
            "summary": {**summary, "cache_reused": True, "inventory_cache_reused": True, "decode_cache_reused": True},
            "counts": manifest["stages"]["decode"].get("counts", manifest["stages"]["inventory"].get("counts", {})),
            "routes": summary["routes"],
            "errors": [],
            "next_actions": [],
            "state": state,
        }
    if cached and (state.records_dir / "transactions.jsonl").is_file():
        state.clear_generated("decode")
        transactions = state.read_all_records("transactions")
        decodes, webshell_events, failures = apply_webshell_profiles(state, transactions, sidecar_paths)
        events = [item for item in state.read_all_records("events") if item.get("kind") != "webshell-decode"] + webshell_events
        events.sort(key=lambda row: (row.get("time") is None, row.get("time") or 0))
        state.write_records("decodes", decodes)
        state.write_records("webshell", webshell_events)
        state.write_records("failures", failures)
        state.write_records("events", events)
        state.write_records("timeline", events)
        summary = state.query_records("summary", limit=1)["items"][0]
        routes = summary["routes"]
        for event in webshell_events:
            plugin_id = "tunnel.regeorg" if event["family"] in {"regeorg", "neoreg", "neo-regeorg"} else f"webshell.{event['family'].removesuffix('3')}"
            if plugin_id not in routes["selected_plugins"]:
                routes["selected_plugins"].append(plugin_id)
        routes["selected_plugins"].sort()
        counts = dict(manifest["stages"]["inventory"].get("counts", {}))
        counts.update({"decodes": len(decodes), "webshell_events": len(webshell_events), "failures": len(failures), "events": len(events)})
        summary.update({"routes": routes, "cache_reused": False, "inventory_cache_reused": True, "decode_cache_reused": False})
        state.write_records("summary", [summary])
        state.write_records("evidence", state.read_all_records("flows") + transactions + state.read_all_records("objects") + decodes + events)
        state.mark_stage("decode", cache_key=decode_cache_key, status="complete", counts=counts)
        return {
            "status": "ok", "completeness": summary["completeness"], "summary": summary, "counts": counts,
            "routes": routes, "errors": failures, "next_actions": ["Inspect newly decoded WebShell events."], "state": state,
        }

    state.clear_generated("decode")
    state.clear_generated("inventory")
    size = capture_path.stat().st_size
    size_route = determine_size_route(size)
    route_reason = "capture-size"
    if size_route == "full-pipeline" and size * 4 > memory_limit_mib * 1024 * 1024:
        size_route = "stream-index"
        route_reason = "memory-limit"
    if size_route == "stream-index":
        try:
            flows, protocol_records, signals, packet_count = _build_stream_index(
                iter_packet_index(capture_path, sidecars=sidecar_paths), manifest["capture"]["sha256"]
            )
        except (TSharkError, FileNotFoundError, subprocess.SubprocessError) as exc:
            return {
                "status": "error", "completeness": "unknown",
                "summary": {"message": str(exc), "size_route": size_route}, "counts": {},
                "routes": {"selected_plugins": [], "recommended_references": [], "optional_references": [], "recommended_experience": []},
                "errors": [{"stage": "stream-index", "type": type(exc).__name__, "message": str(exc)}],
                "next_actions": ["Inspect TShark output and retry the streaming index."], "state": state,
            }
        selected = select_plugins(load_registry(REGISTRY_PATH), signals)
        recommended = {f"references/{kid.replace('.', '/', 1)}.md" for plugin in selected for kid in plugin["knowledge_ids"]}
        recommended.add("references/tooling/large-captures.md")
        routes = {
            "selected_plugins": sorted(plugin["plugin_id"] for plugin in selected),
            "recommended_references": [
                {"path": path, "reason": "stream index observed the signal; payload materialization is deferred"}
                for path in sorted(recommended)
            ],
            "optional_references": [], "recommended_experience": [],
        }
        counts = {
            "packets": packet_count, "flows": len(flows), "transactions": 0, "objects": 0,
            "events": 0, "decodes": 0, "webshell_events": 0, "failures": 0,
        }
        summary = {
            "capture_sha256": manifest["capture"]["sha256"], "capture_size": size,
            "size_route": size_route, "size_route_reason": route_reason,
            "memory_limit_mib": memory_limit_mib, "network": network, "question": question,
            "payloads_materialized": False, "completeness": "partial", "routes": routes,
            "cache_reused": False, "inventory_cache_reused": False, "decode_cache_reused": False,
        }
        collections = {
            "summary": [summary], "flows": flows, "transactions": [], "objects": [], "events": [],
            "timeline": [], "decodes": [], "webshell": [], "failures": [], "evidence": flows,
            "protocols": protocol_records, "knowledge": routes["recommended_references"],
        }
        for collection, records in collections.items():
            state.write_records(collection, records)
        state.mark_stage("inventory", cache_key=cache_key, status="partial", counts=counts)
        state.mark_stage("decode", cache_key=decode_cache_key, status="not-attempted", counts=counts)
        return {
            "status": "ok", "completeness": "partial", "summary": summary, "counts": counts,
            "routes": routes, "errors": [],
            "next_actions": ["Query the flow index, cut a time/IP/port/stream slice, then analyze that smaller capture."],
            "state": state,
        }
    if size_route == "inventory-then-slice":
        try:
            inventory = capture_inventory(capture_path)
        except (TSharkError, FileNotFoundError) as exc:
            return {
                "status": "error", "completeness": "unknown", "summary": {"message": str(exc), "size_route": size_route},
                "counts": {}, "routes": {"selected_plugins": [], "recommended_references": [], "optional_references": [], "recommended_experience": []},
                "errors": [{"stage": "inventory", "type": type(exc).__name__, "message": str(exc)}],
                "next_actions": ["Inspect capinfos availability and retry inventory."], "state": state,
            }
        packets = int(inventory.get("Number of packets") or 0)
        routes = {
            "selected_plugins": [],
            "recommended_references": [{"path": "references/tooling/large-captures.md", "reason": "capture exceeds 2 GiB"}],
            "optional_references": [], "recommended_experience": [],
        }
        counts = {"packets": packets, "flows": 0, "transactions": 0, "objects": 0, "events": 0, "decodes": 0, "webshell_events": 0, "failures": 0}
        summary = {
            "capture_sha256": manifest["capture"]["sha256"], "capture_size": size, "size_route": size_route,
            "capinfos": inventory, "memory_limit_mib": memory_limit_mib, "network": network, "question": question,
            "completeness": "partial", "routes": routes, "cache_reused": False,
            "inventory_cache_reused": False, "decode_cache_reused": False,
        }
        for collection, records in {"summary": [summary], "flows": [], "transactions": [], "objects": [], "events": [], "timeline": [], "decodes": [], "webshell": [], "failures": [], "evidence": [], "protocols": [], "knowledge": routes["recommended_references"]}.items():
            state.write_records(collection, records)
        state.mark_stage("inventory", cache_key=cache_key, status="partial", counts=counts)
        state.mark_stage("decode", cache_key=decode_cache_key, status="not-attempted", counts=counts)
        return {
            "status": "ok", "completeness": "partial", "summary": summary, "counts": counts, "routes": routes,
            "errors": [], "next_actions": ["Choose a time, IP, port, or stream slice before payload materialization."], "state": state,
        }
    try:
        extraction = extract_packets(capture_path, sidecars=sidecar_paths)
    except (TSharkError, FileNotFoundError) as exc:
        return {
            "status": "error",
            "completeness": "unknown",
            "summary": {"message": str(exc), "cache_reused": False},
            "counts": {},
            "routes": {"selected_plugins": [], "recommended_references": [], "optional_references": [], "recommended_experience": []},
            "errors": [{"stage": "inventory", "type": type(exc).__name__, "message": str(exc)}],
            "next_actions": ["Run preflight and inspect the TShark error."],
            "state": state,
        }

    packets = extraction.packets
    flows = _build_flows(packets, manifest["capture"]["sha256"])
    transactions, objects = _build_http(packets, manifest["capture"]["sha256"], state)
    protocol_transactions, protocol_objects, protocol_events = extract_protocol_records(
        packets, manifest["capture"]["sha256"], state
    )
    transactions.extend(protocol_transactions)
    transactions.extend(_build_http2(packets, manifest["capture"]["sha256"]))
    objects.extend(protocol_objects)
    protocols = Counter()
    for packet in packets:
        for protocol in packet.get("frame.protocols", "").split(":"):
            if protocol:
                protocols[protocol] += 1
    protocol_records = [{"protocol": name, "packets": count} for name, count in sorted(protocols.items())]
    signals = _signals(packets)
    selected = select_plugins(load_registry(REGISTRY_PATH), signals)
    selected_ids = [plugin["plugin_id"] for plugin in selected]
    recommended = sorted({f"references/{kid.replace('.', '/', 1)}.md" for plugin in selected for kid in plugin["knowledge_ids"]})
    routes = {
        "selected_plugins": selected_ids,
        "recommended_references": [{"path": path, "reason": "observed protocol or payload signal"} for path in recommended],
        "optional_references": [],
        "recommended_experience": [],
    }
    events = list(protocol_events)
    for transaction in transactions:
        if transaction.get("protocol") != "http/1.x":
            continue
        event_id = stable_evidence_id("EVT", {"transaction": transaction["id"], "kind": "http"})
        method = transaction["request"].get("method") or "unmatched-response"
        uri = transaction["request"].get("uri") or ""
        events.append(
            {
                "id": event_id,
                "time": transaction["request"]["time"] or transaction["response"]["time"],
                "kind": "http-transaction",
                "operation": f"{method} {uri}".rstrip(),
                "result": transaction["response"]["status"],
                "evidence_ids": [transaction["id"]],
            }
        )
    decodes, webshell_events, failures = apply_webshell_profiles(state, transactions, sidecar_paths)
    events.extend(webshell_events)
    events.sort(key=lambda row: (row.get("time") is None, row.get("time") or 0))
    for event in webshell_events:
        plugin_id = "tunnel.regeorg" if event["family"] in {"regeorg", "neoreg", "neo-regeorg"} else f"webshell.{event['family'].removesuffix('3')}"
        if plugin_id not in routes["selected_plugins"]:
            routes["selected_plugins"].append(plugin_id)
            knowledge_id = "webshell.regeorg" if plugin_id == "tunnel.regeorg" else plugin_id
            routes["recommended_references"].append({
                "path": f"references/{knowledge_id.replace('.', '/', 1)}.md",
                "reason": "explicit sidecar WebShell profile",
            })
    routes["selected_plugins"].sort()
    completeness = "complete"
    if any(flow["completeness"] == "truncated" for flow in flows):
        completeness = "truncated"
    elif any(flow["completeness"] == "partial" for flow in flows):
        completeness = "partial"
    counts = {
        "packets": len(packets),
        "flows": len(flows),
        "transactions": len(transactions),
        "objects": len(objects),
        "events": len(events),
        "decodes": len(decodes),
        "webshell_events": len(webshell_events),
        "failures": len(failures),
    }
    summary = {
        "capture_sha256": manifest["capture"]["sha256"],
        "capture_size": size,
        "size_route": size_route,
        "memory_limit_mib": memory_limit_mib,
        "network": network,
        "question": question,
        "completeness": completeness,
        "routes": routes,
        "cache_reused": False,
        "inventory_cache_reused": False,
        "decode_cache_reused": False,
    }
    state.write_records("flows", flows)
    state.write_records("transactions", transactions)
    state.write_records("objects", objects)
    state.write_records("protocols", protocol_records)
    state.write_records("events", events)
    state.write_records("timeline", events)
    state.write_records("decodes", decodes)
    state.write_records("webshell", webshell_events)
    state.write_records("failures", failures)
    state.write_records("knowledge", routes["recommended_references"])
    state.write_records("summary", [summary])
    state.write_records("evidence", flows + transactions + objects + decodes + events)
    state.mark_stage("inventory", cache_key=cache_key, status="complete", counts=counts)
    state.mark_stage("decode", cache_key=decode_cache_key, status="complete", counts=counts)
    return {
        "status": "ok",
        "completeness": completeness,
        "summary": summary,
        "counts": counts,
        "routes": routes,
        "errors": failures,
        "next_actions": ["Inspect the complete timeline."] if not question else ["Answer the supplied question from evidence."],
        "state": state,
    }
