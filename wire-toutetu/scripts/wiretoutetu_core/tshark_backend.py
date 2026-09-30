"""Version-tolerant TShark extraction backend."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable


REQUESTED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "udp.stream",
    "tcp.analysis.retransmission",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "http.request.method",
    "http.request.uri",
    "http.request.line",
    "http.host",
    "http.response.code",
    "http.content_type",
    "http.content_length",
    "http.file_data",
    "http2.streamid",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.status",
    "http3.stream_id",
    "quic.dcid",
    "websocket.fin",
    "websocket.opcode",
    "websocket.payload",
    "smb2.cmd",
    "smb2.filename",
    "mysql.command",
    "mysql.query",
    "redis.command",
    "mongo.opcode",
    "rtp.ssrc",
    "rtp.seq",
    "rtp.timestamp",
    "rtp.p_type",
    "wlan.bssid",
    "wlan.sa",
    "wlan.da",
    "wlan.fc.type_subtype",
    "socks.version",
    "socks.command",
    "socks.dst",
    "socks.dstport",
    "dns.qry.name",
    "dns.id",
    "dns.flags.response",
    "dns.a",
    "icmp.type",
    "icmp.ident",
    "icmp.seq",
    "icmpv6.type",
    "ftp.request.command",
    "ftp.request.arg",
    "ftp.response.code",
    "ftp.response.arg",
    "smtp.req.command",
    "smtp.req.parameter",
    "smtp.response.code",
    "smtp.rsp.parameter",
    "usb.bus_id",
    "usb.device_address",
    "usb.endpoint_address",
    "usb.transfer_type",
    "usbhid.data",
    "tcp.payload",
    "data.data",
)

INDEX_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.protocols",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream", "udp.stream",
    "tcp.analysis.retransmission", "tcp.analysis.out_of_order", "tcp.analysis.lost_segment",
    "http.request.method",
)

FIELD_AGGREGATOR = "\x1e"


class TSharkError(RuntimeError):
    def __init__(self, message: str, *, command: list[str], stderr: str, returncode: int):
        super().__init__(message)
        self.command = command
        self.stderr = stderr
        self.returncode = returncode


@dataclass(frozen=True)
class TSharkExtraction:
    packets: list[dict[str, str]]
    command: list[str]
    stderr: str
    fields: tuple[str, ...]


def tshark_path() -> str:
    path = shutil.which("tshark")
    if not path:
        raise FileNotFoundError("TShark is required")
    return path


def capture_inventory(capture: str | Path) -> dict[str, str]:
    executable = shutil.which("capinfos")
    if not executable:
        raise FileNotFoundError("capinfos is required for large-capture inventory")
    command = [executable, "-Tm", str(Path(capture).resolve())]
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600, check=False
    )
    if completed.returncode:
        raise TSharkError(
            "capinfos inventory failed", command=command, stderr=completed.stderr, returncode=completed.returncode
        )
    rows = list(csv.DictReader(completed.stdout.splitlines()))
    if not rows:
        raise TSharkError("capinfos returned no inventory", command=command, stderr=completed.stderr, returncode=0)
    return {key: value or "" for key, value in rows[0].items()}


@lru_cache(maxsize=4)
def available_fields(executable: str) -> frozenset[str]:
    completed = subprocess.run(
        [executable, "-G", "fields"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        check=False,
    )
    if completed.returncode:
        raise TSharkError(
            "TShark field probe failed",
            command=[executable, "-G", "fields"],
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
    names: set[str] = set()
    for line in completed.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) > 2 and columns[0] == "F":
            names.add(columns[2])
    return frozenset(names)


def _sidecar_preferences(sidecars: Iterable[str | Path]) -> list[str]:
    preferences = [
        "tcp.desegment_tcp_streams:TRUE",
        "http.desegment_body:TRUE",
        "http.decompress_body:TRUE",
    ]
    for raw_path in sidecars:
        path = Path(raw_path).resolve()
        try:
            with path.open("rb") as handle:
                head = handle.read(4096)
        except OSError:
            continue
        if re.search(rb"(?m)^(?:CLIENT_RANDOM|(?:CLIENT|SERVER)_(?:EARLY_|HANDSHAKE_)?TRAFFIC_SECRET(?:_\d+)?)\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+", head):
            preferences.append(f"tls.keylog_file:{path}")
        if path.suffix.lower() == ".json":
            try:
                config = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(config, dict):
                continue
            configured = config.get("tshark_preferences", [])
            if not isinstance(configured, list):
                raise ValueError(f"tshark_preferences must be a list: {path}")
            for value in configured:
                if isinstance(value, str) and "\x00" not in value:
                    preferences.append(value)
    return preferences


def parsing_sidecar_fingerprint(sidecars: Iterable[str | Path]) -> str:
    """Only parsing inputs invalidate inventory; WebShell profiles affect decode."""
    preferences = _sidecar_preferences(sidecars)
    keylogs = {}
    for value in preferences:
        name, separator, filename = value.partition(":")
        if not separator or name not in {"tls.keylog_file", "dtls.keylog_file"} or not filename:
            continue
        path = Path(filename).expanduser().resolve()
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            keylogs[str(path)] = digest.hexdigest()
        except OSError:
            keylogs[str(path)] = "unavailable"
    material = json.dumps({"preferences": preferences, "keylogs": keylogs}, sort_keys=True).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def extract_packets(
    capture: str | Path,
    *,
    sidecars: Iterable[str | Path] = (),
    display_filter: str | None = None,
) -> TSharkExtraction:
    executable = tshark_path()
    supported = available_fields(executable)
    fields = tuple(field for field in REQUESTED_FIELDS if field in supported)
    command = [
        executable,
        "-r",
        str(Path(capture).resolve()),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-E",
        f"aggregator={FIELD_AGGREGATOR}",
    ]
    for preference in _sidecar_preferences(sidecars):
        command.extend(["-o", preference])
    if display_filter:
        command.extend(["-Y", display_filter])
    for field in fields:
        command.extend(["-e", field])

    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
        check=False,
    )
    if completed.returncode:
        raise TSharkError(
            "TShark extraction failed",
            command=command,
            stderr=completed.stderr,
            returncode=completed.returncode,
        )
    # str.splitlines() also splits the field aggregator (ASCII record separator).
    reader = csv.DictReader(io.StringIO(completed.stdout), delimiter="\t", quotechar='"')
    packets = [{key: value or "" for key, value in row.items()} for row in reader]
    return TSharkExtraction(packets=packets, command=command, stderr=completed.stderr, fields=fields)


def iter_packet_index(
    capture: str | Path,
    *,
    sidecars: Iterable[str | Path] = (),
) -> Iterable[dict[str, str]]:
    """Yield a payload-free packet index without buffering TShark stdout."""
    executable = tshark_path()
    supported = available_fields(executable)
    fields = tuple(field for field in INDEX_FIELDS if field in supported)
    command = [
        executable, "-r", str(Path(capture).resolve()), "-T", "fields",
        "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f",
    ]
    for preference in _sidecar_preferences(sidecars):
        command.extend(["-o", preference])
    for field in fields:
        command.extend(["-e", field])

    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as stderr_file:
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=stderr_file, text=True,
            encoding="utf-8", errors="replace",
        )
        assert process.stdout is not None
        completed = False
        try:
            reader = csv.DictReader(process.stdout, delimiter="\t", quotechar='"')
            for row in reader:
                yield {key: value or "" for key, value in row.items()}
            completed = True
        finally:
            process.stdout.close()
            if not completed and process.poll() is None:
                process.terminate()
        returncode = process.wait(timeout=600)
        stderr_file.seek(0)
        stderr = stderr_file.read()
        if returncode:
            raise TSharkError(
                "TShark streaming index failed", command=command, stderr=stderr, returncode=returncode
            )
