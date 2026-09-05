"""Orchestrates extraction into one structured evidence document."""
from __future__ import annotations
from pathlib import Path
from typing import Any
from .analyze import capture_quality, tls_evidence
from .certificates import extract_certificates
from .extract import find_starttls, normalize_packets, protocol_packets, stream_evidence
from .handoff import build_handoff
from .tshark import run_tshark


def build_report(pcap: str | Path, binary: str = "tshark") -> dict[str, Any]:
    raw, verification = run_tshark(pcap, binary)
    records = normalize_packets(raw)
    protocols = {p: len(protocol_packets(records, p)) for p in ("smtp", "imap", "pop", "tls")}
    certificates = extract_certificates(records)
    return {"schema_version": "1.0", "module": "M1-PCAP-Network-Evidence-Extraction", "input": {"path": str(Path(pcap).resolve())}, "tooling": {"tshark_version": verification.tshark_version, "verified_fields": verification.available, "field_verification_error": verification.error}, "capture_quality": capture_quality(records, raw), "protocol_detection": {"packet_counts": protocols, "observed_protocols": [p for p, n in protocols.items() if n]}, "tcp_streams": stream_evidence(records), "starttls": find_starttls(records), "tls": tls_evidence(records), "certificates": certificates, "handoff": build_handoff(records, certificates)}
