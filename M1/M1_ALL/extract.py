"""Convert raw TShark JSON packets into ordered, protocol-neutral records."""
from __future__ import annotations
import re
from typing import Any
from .models import PacketRecord
from .parsing import as_float, as_int, all_values, layer, nested_values


def _flat_strings(value: Any) -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values(): out.extend(_flat_strings(v))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for v in value: out.extend(_flat_strings(v))
        return out
    return [str(value)] if value is not None else []


def _first_layer_value(layers: dict[str, Any], name: str) -> Any:
    value = layers.get(name)
    if isinstance(value, list): return value[0] if value else None
    return value


def normalize_packets(raw_packets: list[dict[str, Any]]) -> list[PacketRecord]:
    records: list[PacketRecord] = []
    for index, packet in enumerate(raw_packets, 1):
        layers = packet.get("_source", {}).get("layers", {})
        frame = layer(packet, "frame")
        ip = layer(packet, "ip")
        ipv6 = layer(packet, "ipv6")
        tcp = layer(packet, "tcp")
        protocols = _flat_strings(frame.get("frame.protocols"))
        protocol_text = ":".join(protocols).lower()
        src = _first_layer_value(ip, "ip.src") or _first_layer_value(ipv6, "ipv6.src")
        dst = _first_layer_value(ip, "ip.dst") or _first_layer_value(ipv6, "ipv6.dst")
        rec = PacketRecord(
            frame_number=as_int(frame.get("frame.number")) or index,
            timestamp=as_float(frame.get("frame.time_epoch")),
            length=as_int(frame.get("frame.len")),
            protocols=protocols,
            src=src, dst=dst,
            src_port=as_int(tcp.get("tcp.srcport")), dst_port=as_int(tcp.get("tcp.dstport")),
            tcp_stream=as_int(tcp.get("tcp.stream")),
            tcp_flags=first_text(tcp.get("tcp.flags")),
            tcp_payload_length=as_int(tcp.get("tcp.len")),
            layers=layers,
        )
        # Protocol labels are useful even when frame.protocols is absent.
        for name in ("smtp", "imap", "pop", "tls", "tcp"):
            if name in layers and name not in protocol_text:
                rec.protocols.append(name)
        records.append(rec)
    return records


def first_text(value: Any) -> str | None:
    values = _flat_strings(value)
    return values[0] if values else None


def protocol_packets(records: list[PacketRecord], protocol: str) -> list[PacketRecord]:
    return [r for r in records if protocol in {p.lower() for p in r.protocols} or protocol in r.layers]


def stream_evidence(records: list[PacketRecord]) -> list[dict[str, Any]]:
    streams: dict[int, dict[str, Any]] = {}
    for r in records:
        if r.tcp_stream is None: continue
        s = streams.setdefault(r.tcp_stream, {"tcp_stream": r.tcp_stream, "first_frame": r.frame_number, "last_frame": r.frame_number, "packet_count": 0, "src_endpoints": [], "dst_endpoints": [], "payload_bytes": 0, "flags": []})
        s["last_frame"] = r.frame_number; s["packet_count"] += 1; s["payload_bytes"] += r.tcp_payload_length or 0
        if r.src and r.src_port is not None and [r.src, r.src_port] not in s["src_endpoints"]: s["src_endpoints"].append([r.src, r.src_port])
        if r.dst and r.dst_port is not None and [r.dst, r.dst_port] not in s["dst_endpoints"]: s["dst_endpoints"].append([r.dst, r.dst_port])
        if r.tcp_flags and r.tcp_flags not in s["flags"]: s["flags"].append(r.tcp_flags)
    return list(streams.values())


def text_values(record: PacketRecord, layer_name: str) -> list[str]:
    return _flat_strings(record.layers.get(layer_name, {}))


def _protocol_text(record: PacketRecord, protocol: str) -> str:
    return " ".join(text_values(record, protocol)).strip()


def _tcp_payload_text(record: PacketRecord) -> str:
    tcp_layer = record.layers.get("tcp", {})
    values = nested_values(tcp_layer, "tcp.payload")
    decoded: list[str] = []
    for value in values:
        try:
            decoded.append(bytes.fromhex(str(value).replace(":", "")).decode("latin-1", errors="ignore"))
        except ValueError:
            continue
    return " ".join(decoded)


def _protocol_field_values(record: PacketRecord, protocol: str, field_name: str) -> list[str]:
    layer_data = record.layers.get(protocol, {})
    return [str(value) for value in nested_values(layer_data, f"{protocol}.{field_name}")]


def _starttls_command(protocol: str, record: PacketRecord) -> bool:
    pattern = r"\bstarttls\b" if protocol != "pop" else r"\bstls\b"
    field_names = ("command_line", "req") if protocol == "smtp" else ("request",)
    return any(re.search(pattern, value, re.IGNORECASE) for name in field_names for value in _protocol_field_values(record, protocol, name))


def _positive_response(protocol: str, record: PacketRecord) -> bool:
    field_name = "response" if protocol != "smtp" else "response"
    text = " ".join(_protocol_field_values(record, protocol, field_name)).lower()
    if protocol == "smtp":
        codes = re.findall(r"(?:^|[^0-9])([235]\d\d)(?:[^0-9]|$)", text)
        return any(code.startswith(("220", "334")) for code in codes)
    return bool(re.search(r"(?:^|\s)(?:ok|\+ok|ready|go ahead)(?:\s|$)", text))


def _is_tls_record(record: PacketRecord) -> bool:
    return "tls" in {p.lower() for p in record.protocols} or "tls" in record.layers


def _is_client_hello(record: PacketRecord) -> bool:
    tls_layer = record.layers.get("tls", {})
    return any(str(value).lower() in {"1", "0x01"} for value in nested_values(tls_layer, "tls.handshake.type"))


def find_starttls(records: list[PacketRecord]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for protocol in ("smtp", "imap", "pop"):
        subset = protocol_packets(records, protocol)
        for i, rec in enumerate(subset):
            text = _protocol_text(rec, protocol)
            payload_text = _tcp_payload_text(rec)
            if _starttls_command(protocol, rec):
                same_stream = [x for x in subset[i + 1:] if x.tcp_stream == rec.tcp_stream]
                response = next((x for x in same_stream[:4] if _positive_response(protocol, x)), None)
                following_tls = bool(response and any(_is_client_hello(x) and x.frame_number > response.frame_number for x in records if x.tcp_stream == rec.tcp_stream))
                events.append({"protocol": protocol, "frame": rec.frame_number, "advertised": None, "attempted": True, "acknowledged_or_accepted": response is not None, "tls_followed": following_tls, "status": "TLS_FOLLOWED" if following_tls else ("ACKNOWLEDGED" if response else "ATTEMPTED")})
            elif _protocol_field_values(rec, protocol, "response") and re.search(r"\b(?:starttls|stls)\b", f"{text} {payload_text}", re.IGNORECASE):
                events.append({"protocol": protocol, "frame": rec.frame_number, "advertised": True, "attempted": False, "acknowledged_or_accepted": False, "tls_followed": False, "status": "ADVERTISED"})
    return sorted(events, key=lambda x: x["frame"])
