"""Build a small downstream handoff from observed PCAP evidence."""
from __future__ import annotations

from typing import Any

from .extract import protocol_packets
from .parsing import nested_values


SERVER_PORTS = {25, 110, 143, 465, 993, 995}


def _first(values: list[Any]) -> Any:
    return values[0] if values else None


def _tls_values(records: list[Any], field_name: str) -> list[str]:
    values: list[str] = []
    for record in protocol_packets(records, "tls"):
        values.extend(str(value) for value in nested_values(record.layers.get("tls", {}), field_name))
    return list(dict.fromkeys(values))


def _version_label(value: str | None) -> str | None:
    if value is None:
        return None
    return {"0x0304": "TLS 1.3", "0x0303": "TLS 1.2", "0x0302": "TLS 1.1", "0x0301": "TLS 1.0"}.get(value.lower(), value)


def _selected_cipher(records: list[Any]) -> str | None:
    for record in protocol_packets(records, "tls"):
        types = {str(value) for value in nested_values(record.layers.get("tls", {}), "tls.handshake.type")}
        if "2" in types or "0x02" in types:
            values = nested_values(record.layers.get("tls", {}), "tls.handshake.ciphersuite")
            if values:
                return str(values[0])
    return None


def _application(records: list[Any]) -> tuple[str | None, int | None]:
    for protocol, ports in (("imap", {143, 993}), ("smtp", {25, 465}), ("pop", {110, 995})):
        packets = protocol_packets(records, protocol)
        if packets:
            for packet in packets:
                if packet.src_port in ports:
                    return protocol.upper(), packet.src_port
                if packet.dst_port in ports:
                    return protocol.upper(), packet.dst_port
            return protocol.upper(), None
    return None, None


def _endpoints(records: list[Any]) -> tuple[int | None, str | None, str | None]:
    packets = [record for record in records if record.tcp_stream is not None and record.src and record.dst]
    if not packets:
        return None, None, None
    server_packet = next((packet for packet in packets if packet.dst_port in SERVER_PORTS), None)
    if server_packet:
        # stream_id must always match the stream the reported endpoints came
        # from, never an unrelated stream that merely happened to appear first.
        return server_packet.tcp_stream, server_packet.dst, server_packet.src
    return packets[0].tcp_stream, packets[0].dst, packets[0].src


def build_handoff(records: list[Any], certificates: list[dict[str, Any]]) -> dict[str, Any]:
    protocol, port = _application(records)
    stream_id, server_ip, client_ip = _endpoints(records)
    tls_records = protocol_packets(records, "tls")
    tls_versions = _tls_values(records, "tls.handshake.version")
    supported_versions = _tls_values(records, "tls.handshake.extensions.supported_version")
    server_names = _tls_values(records, "tls.handshake.extensions_server_name")
    selected_cipher = _selected_cipher(records)
    leaf = certificates[0] if certificates else {}
    hostname = _first(server_names)
    certificate_name = _common_name(leaf.get("subject"))
    domain = hostname or certificate_name
    sans = leaf.get("subject_alternative_names", [])
    return {
        "network": {
            "total_packets": len(records),
            "stream_id": stream_id,
            "encryption": "tls" if tls_records else "plaintext",
            "protocol": protocol,
            "port": port,
            "client_ip": client_ip,
            "extracted_emails": [],
            "server_ip": server_ip,
            "server_hostname": hostname,
        },
        "tls": {
            "domain": domain,
            "server_hostname": hostname,
            "protocol": protocol,
            "port": port,
            "tls_mode": "starttls" if any(event.get("tls_followed") for event in _starttls_events(records)) else ("implicit" if tls_records else None),
            "tls_version": _version_label(_first(supported_versions) or _first(tls_versions)),
            "cipher_name": selected_cipher,
            "cipher_version": _version_label(_first(supported_versions) or _first(tls_versions)),
            "cipher_bits": None,
            "certificate_common_name": certificate_name,
            "certificate_issuer": leaf.get("issuer"),
            "certificate_version": leaf.get("certificate_version"),
            "certificate_serial_number": leaf.get("serial_number"),
            "certificate_valid_from": leaf.get("not_before"),
            "certificate_valid_until": leaf.get("not_after"),
            "subject_alternative_names": sans,
            "hostname_matches_san": hostname.lower() in {str(value).lower() for value in sans} if hostname and sans else None,
            "certificate_status": "PARSED" if leaf.get("parse_status") == "OK" else None,
            "days_until_expiration": None,
            "starttls_supported": any(event.get("advertised") for event in _starttls_events(records)),
            "reachable": None,
        },
        "m2": {
            "domain": domain,
            "spf": None,
            "dkim": None,
            "dmarc": None,
            "risk": None,
            "ownership": "M2-DNS-and-analysis",
            "note": "M1 does not perform DNS lookups, risk scoring, or live reachability checks. M2 should populate these fields.",
        },
    }


def _common_name(subject: str | None) -> str | None:
    if not subject:
        return None
    for item in subject.split(", "):
        if item.startswith("commonName="):
            return item.split("=", 1)[1]
    return None


def _starttls_events(records: list[Any]) -> list[dict[str, Any]]:
    from .extract import find_starttls
    return find_starttls(records)