"""TShark field registry and version-sensitive verification helpers."""
from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Iterable

# These are candidate fields. The installed TShark is authoritative.
CANDIDATE_FIELDS = {
    "frame_number": "frame.number",
    "frame_time_epoch": "frame.time_epoch",
    "frame_len": "frame.len",
    "ip_src": "ip.src",
    "ip_dst": "ip.dst",
    "ipv6_src": "ipv6.src",
    "ipv6_dst": "ipv6.dst",
    "tcp_stream": "tcp.stream",
    "tcp_srcport": "tcp.srcport",
    "tcp_dstport": "tcp.dstport",
    "tcp_flags": "tcp.flags",
    "tcp_len": "tcp.len",
    "tcp_completeness": "tcp.completeness",
    "smtp_request": "smtp.req",
    "smtp_response": "smtp.response",
    "smtp_response_code": "smtp.response.code",
    "imap_request": "imap.request",
    "imap_response": "imap.response",
    "pop_request": "pop.request",
    "pop_response": "pop.response",
    "tls_record_content_type": "tls.record.content_type",
    "tls_handshake_type": "tls.handshake.type",
    "tls_handshake_version": "tls.handshake.version",
    "tls_supported_versions": "tls.handshake.extensions.supported_version",
    "tls_server_name": "tls.handshake.extensions_server_name",
    "tls_cipher_suite": "tls.handshake.ciphersuite",
    "tls_certificate": "tls.handshake.certificate",
}

@dataclass
class FieldVerification:
    tshark_version: str | None
    available: dict[str, bool]
    raw_field_lines: int
    error: str | None = None


def tshark_version(binary: str = "tshark") -> str | None:
    try:
        p = subprocess.run([binary, "--version"], text=True, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return p.stdout.splitlines()[0].strip() if p.stdout else None


def verify_fields(binary: str = "tshark", fields: Iterable[str] | None = None) -> FieldVerification:
    wanted = list(fields or CANDIDATE_FIELDS.values())
    try:
        p = subprocess.run([binary, "-G", "fields"], text=True, capture_output=True, check=True)
    except FileNotFoundError:
        return FieldVerification(None, {f: False for f in wanted}, 0, "tshark executable was not found")
    except OSError as exc:
        return FieldVerification(None, {f: False for f in wanted}, 0, f"could not execute tshark: {exc}")
    except subprocess.CalledProcessError as exc:
        return FieldVerification(tshark_version(binary), {f: False for f in wanted}, 0, exc.stderr.strip() or "tshark -G fields failed")
    lines = p.stdout.splitlines()
    available = {f: False for f in wanted}
    for line in lines:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2] in available:
            available[parts[2]] = True
    return FieldVerification(tshark_version(binary), available, len(lines))
