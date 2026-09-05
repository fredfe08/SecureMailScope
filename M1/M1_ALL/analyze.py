"""Evidence interpretation only: no risk scores or security judgments."""
from __future__ import annotations
import re
from typing import Any
from .models import INSUFFICIENT_EVIDENCE, NOT_FOUND, UNKNOWN
from .extract import protocol_packets, text_values
from .parsing import all_values, nested_values


def _strings(record: Any, name: str) -> list[str]:
    def walk(v: Any) -> list[str]:
        if isinstance(v, dict): return sum((walk(x) for x in v.values()), [])
        if isinstance(v, list): return sum((walk(x) for x in v), [])
        return [str(v)] if v is not None else []
    return walk(record.layers.get(name, {}))


def _supported_version(value: Any) -> str:
    text = str(value).strip().lower()
    if "1.3" in text or text in {"0x0304", "772"}:
        return "TLS 1.3"
    if "1.2" in text or text in {"0x0303", "771"}:
        return "TLS 1.2"
    if "1.1" in text or text in {"0x0302", "770"}:
        return "TLS 1.1"
    if "1.0" in text or text in {"0x0301", "769"}:
        return "TLS 1.0"
    return str(value)


def tls_evidence(records: list[Any]) -> dict[str, Any]:
    tls = protocol_packets(records, "tls")
    if not tls:
        return {"status": INSUFFICIENT_EVIDENCE, "observed_tls_packets": 0, "tls_versions": [], "supported_versions": [], "handshake_stages": [], "handshake_complete": None}
    stages: list[dict[str, Any]] = []; versions: list[str] = []; supported: list[str] = []
    stages_by_stream: dict[Any, set[str]] = {}
    for rec in tls:
        strings = _strings(rec, "tls")
        lower = " ".join(strings).lower()
        stage_names = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 16: "ClientKeyExchange", 20: "Finished"}
        tls_layer = rec.layers.get("tls", {})
        for value in nested_values(tls_layer, "tls.handshake.type"):
            text = str(value)
            number = int(text, 0) if text.isdigit() or text.lower().startswith("0x") else None
            if number in stage_names:
                stages.append({"frame": rec.frame_number, "stage": stage_names[number]})
                if rec.tcp_stream is not None:
                    stages_by_stream.setdefault(rec.tcp_stream, set()).add(stage_names[number])
        for value in nested_values(tls_layer, "tls.handshake.extensions.supported_version"):
            supported.append(_supported_version(value))
        for value in nested_values(tls_layer, "tls.handshake.version"):
            text = str(value).lower()
            if "1.2" in text or text in {"0x0303", "771"}: versions.append("TLS 1.2")
            elif "1.1" in text or text in {"0x0302", "770"}: versions.append("TLS 1.1")
            elif "1.0" in text or text in {"0x0301", "769"}: versions.append("TLS 1.0")
        if "TLS 1.3" in supported: versions.append("TLS 1.3")
    labels = [s["stage"] for s in stages]
    required = {"ClientHello", "ServerHello", "Finished"}
    # Completion must be observed within a single TCP stream: stages scattered
    # across unrelated streams must never be combined into a false completion claim.
    complete = any(required <= seen for seen in stages_by_stream.values()) if labels else None
    return {"status": "OBSERVED", "observed_tls_packets": len(tls), "tls_versions": sorted(set(versions)), "supported_versions": sorted(set(supported)), "handshake_stages": stages, "handshake_complete": complete}


def capture_quality(records: list[Any], raw_packets: list[dict[str, Any]]) -> dict[str, Any]:
    if not records: return {"status": UNKNOWN, "packet_count": 0, "notes": ["No packets were decoded"]}
    syn = fin = rst = 0
    completeness_values: list[str] = []
    for r in records:
        try:
            flags = int(str(r.tcp_flags), 0)
        except (TypeError, ValueError):
            flags = 0
        syn += int(bool(flags & 0x02)); fin += int(bool(flags & 0x01)); rst += int(bool(flags & 0x04))
        tcp = r.layers.get("tcp", {})
        v = tcp.get("tcp.completeness")
        if v is not None: completeness_values.extend(str(x) for x in (v if isinstance(v, list) else [v]))
    notes = ["Heuristic only; absence of a handshake is not proof of absence."]
    if syn and not fin and not rst: notes.append("Observed TCP opens without observed close/reset; capture may end mid-session.")
    if completeness_values: notes.append("tcp.completeness was observed, but its bitmask semantics must be verified for this TShark/Wireshark version.")
    return {"status": "OBSERVED", "packet_count": len(records), "tcp_syn_packets": syn, "tcp_fin_packets": fin, "tcp_rst_packets": rst, "tcp_completeness_values": sorted(set(completeness_values)), "notes": notes}
