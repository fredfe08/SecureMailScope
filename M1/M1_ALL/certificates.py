"""Certificate extraction from TLS JSON and parsing with cryptography."""
from __future__ import annotations
from datetime import timezone
from typing import Any
from .parsing import nested_values

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa, dsa, ed25519, ed448, padding
except ImportError:  # pragma: no cover
    x509 = None


def _hex_candidates(value: Any) -> list[str]:
    if isinstance(value, dict):
        out: list[str] = []
        for v in value.values(): out.extend(_hex_candidates(v))
        return out
    if isinstance(value, list):
        out: list[str] = []
        for v in value: out.extend(_hex_candidates(v))
        return out
    if isinstance(value, str):
        candidates: list[str] = []
        for part in value.split(","):
            s = part.replace(":", "").strip()
            if len(s) >= 4 and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s):
                candidates.append(s)
        return candidates
    return []


def _name(name: Any) -> str:
    return ", ".join(f"{a.oid._name or a.oid.dotted_string}={a.value}" for a in name)


def parse_der(der: bytes) -> dict[str, Any]:
    base = {"parse_status": "UNKNOWN", "der_hex": der.hex(), "self_issued": None, "self_signed": None}
    if x509 is None:
        base["parse_status"] = "cryptography is not installed"; return base
    try:
        cert = x509.load_der_x509_certificate(der)
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            subject_alternative_names = san.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            subject_alternative_names = []
        base.update({"parse_status": "OK", "subject": _name(cert.subject), "issuer": _name(cert.issuer), "serial_number": str(cert.serial_number), "not_before": cert.not_valid_before_utc.isoformat(), "not_after": cert.not_valid_after_utc.isoformat(), "certificate_version": cert.version.value + 1, "signature_algorithm": cert.signature_algorithm_oid.dotted_string, "public_key_type": type(cert.public_key()).__name__, "subject_alternative_names": subject_alternative_names, "self_issued": cert.subject == cert.issuer, "self_signed": None})
        # A self-issued certificate is not automatically self-signed. Verify only supported key types.
        if cert.subject == cert.issuer:
            try:
                key = cert.public_key()
                if isinstance(key, rsa.RSAPublicKey): key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
                elif isinstance(key, ec.EllipticCurvePublicKey): key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
                elif isinstance(key, dsa.DSAPublicKey): key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
                elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)): key.verify(cert.signature, cert.tbs_certificate_bytes)
                else: return base | {"parse_status": "OK", "self_signed": None}
                base["self_signed"] = True
            except Exception:
                base["self_signed"] = None
        return base
    except Exception as exc:
        base["parse_status"] = f"failed: {exc}"; return base


def extract_certificates(records: list[Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []; seen: set[str] = set()
    for rec in records:
        tls = rec.layers.get("tls", {})
        for candidate in _hex_candidates(nested_values(tls, "tls.handshake.certificate")):
            if candidate in seen: continue
            seen.add(candidate)
            item = parse_der(bytes.fromhex(candidate)); item["frame"] = rec.frame_number; results.append(item)
    return results
