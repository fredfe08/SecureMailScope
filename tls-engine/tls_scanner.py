import ssl
import socket
import json
from datetime import datetime, timezone

# ── Step 1: Connect to the server over Direct/Implicit TLS ────────
def connect_tls(domain, port=443, timeout=10):
    """
    Establish a direct TLS connection to domain:port (for HTTPS/implicit TLS).

    Returns the wrapped SSL socket on success.
    Raises an exception with a clear message on failure.
    """
    context = ssl.create_default_context()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    server = context.wrap_socket(sock, server_hostname=domain)
    server.connect((domain, port))
    return server


# ── Step 2: Protocol-Specific Socket Readers ──────────────────────
def recv_smtp_response(sock):
    """
    Read multiline SMTP response (e.g. '250-...' followed by '250 ...').
    """
    buffer = ""
    while True:
        chunk = sock.recv(4096).decode("utf-8", errors="ignore")
        if not chunk:
            break
        buffer += chunk
        lines = [line.strip() for line in buffer.split("\n") if line.strip()]
        if lines:
            last_line = lines[-1]
            if len(last_line) >= 4 and last_line[:3].isdigit() and last_line[3] == " ":
                break
            elif len(last_line) == 3 and last_line.isdigit():
                break
    return buffer


def recv_imap_response(sock, tag):
    """
    Read IMAP response until tagged completion line (e.g. 'a001 OK ...').
    """
    buffer = ""
    while True:
        chunk = sock.recv(4096).decode("utf-8", errors="ignore")
        if not chunk:
            break
        buffer += chunk
        lines = [line.strip() for line in buffer.split("\n") if line.strip()]
        if any(line.startswith(f"{tag} ") for line in lines):
            break
    return buffer


def recv_pop3_multiline(sock):
    """
    Read POP3 multiline response until '.' on its own line.
    """
    buffer = ""
    while True:
        chunk = sock.recv(4096).decode("utf-8", errors="ignore")
        if not chunk:
            break
        buffer += chunk
        if "\r\n.\r\n" in buffer or "\n.\n" in buffer or buffer.endswith("\n.") or buffer == ".":
            break
        if buffer.startswith("-ERR"):
            break
    return buffer


def recv_pop3_singleline(sock):
    """
    Read POP3 single-line response ending with newline.
    """
    buffer = ""
    while "\n" not in buffer:
        chunk = sock.recv(4096).decode("utf-8", errors="ignore")
        if not chunk:
            break
        buffer += chunk
    return buffer


# ── Step 3: STARTTLS-to-TLS Socket Upgrade on the SAME Socket ─────
def connect_smtp_starttls(domain, port=587, timeout=10):
    """
    Connect to SMTP over plain TCP, detect STARTTLS capability,
    and upgrade the SAME socket to TLS if supported.
    """
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((domain, port))

    # Read greeting banner
    greeting = recv_smtp_response(sock)
    if not greeting:
        sock.close()
        return None, None

    # Send EHLO
    sock.sendall(f"EHLO {domain}\r\n".encode("utf-8"))
    ehlo_resp = recv_smtp_response(sock)

    if "STARTTLS" not in ehlo_resp.upper():
        sock.close()
        return None, False

    # Send STARTTLS command
    sock.sendall(b"STARTTLS\r\n")
    starttls_resp = recv_smtp_response(sock)

    if not (starttls_resp.strip().startswith("220") or "220" in starttls_resp):
        sock.close()
        return None, True

    # Upgrade the same socket with TLS
    server = context.wrap_socket(sock, server_hostname=domain)
    return server, True


def connect_imap_starttls(domain, port=143, timeout=10):
    """
    Connect to IMAP over plain TCP, detect STARTTLS capability,
    and upgrade the SAME socket to TLS if supported.
    """
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((domain, port))

    # Read greeting banner
    greeting = sock.recv(4096).decode("utf-8", errors="ignore")
    if not greeting:
        sock.close()
        return None, None

    # Send CAPABILITY command
    sock.sendall(b"a001 CAPABILITY\r\n")
    capa_resp = recv_imap_response(sock, "a001")

    if "STARTTLS" not in capa_resp.upper():
        sock.close()
        return None, False

    # Send STARTTLS command
    sock.sendall(b"a002 STARTTLS\r\n")
    starttls_resp = recv_imap_response(sock, "a002")

    if "OK" not in starttls_resp.upper():
        sock.close()
        return None, True

    # Upgrade the same socket with TLS
    server = context.wrap_socket(sock, server_hostname=domain)
    return server, True


def connect_pop3_starttls(domain, port=110, timeout=10):
    """
    Connect to POP3 over plain TCP, detect STLS capability,
    and upgrade the SAME socket to TLS if supported.
    """
    context = ssl.create_default_context()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((domain, port))

    # Read greeting banner
    greeting = recv_pop3_singleline(sock)
    if not greeting or not greeting.startswith("+OK"):
        sock.close()
        return None, None

    # Send CAPA command
    sock.sendall(b"CAPA\r\n")
    capa_resp = recv_pop3_multiline(sock)

    if "STLS" not in capa_resp.upper():
        sock.close()
        return None, False

    # Send STLS command
    sock.sendall(b"STLS\r\n")
    stls_resp = recv_pop3_singleline(sock)

    if not stls_resp.startswith("+OK"):
        sock.close()
        return None, True

    # Upgrade the same socket with TLS
    server = context.wrap_socket(sock, server_hostname=domain)
    return server, True


def connect_starttls(domain, port, timeout=10):
    """
    Dispatch STARTTLS connection and upgrade based on email port.
    Returns (server_or_None, supports_starttls_bool_or_None).
    """
    if port in (25, 587):
        return connect_smtp_starttls(domain, port, timeout)
    elif port == 143:
        return connect_imap_starttls(domain, port, timeout)
    elif port == 110:
        return connect_pop3_starttls(domain, port, timeout)
    return None, None


# ── Step 4: Collect TLS connection information ────────────────────
def get_tls_info(server):
    """
    Extract TLS version and cipher details from an established connection.
    """
    tls_version = server.version()
    cipher_name, cipher_version, cipher_bits = server.cipher()

    return {
        "tls_version": tls_version,
        "cipher_name": cipher_name,
        "cipher_version": cipher_version,
        "cipher_bits": cipher_bits,
    }


# ── Step 5: Collect certificate information ───────────────────────
def get_certificate_info(server):
    """
    Retrieve the server's TLS certificate as a parsed dictionary.
    """
    return server.getpeercert()


def extract_field(nested_tuple, field_name):
    """
    Search a certificate 'subject' or 'issuer' tuple for a specific field.
    """
    for rdn in nested_tuple:
        for name, value in rdn:
            if name == field_name:
                return value
    return None


# ── Step 6: Parse certificate into clean fields ──────────────────
def parse_certificate(certificate):
    subject = certificate.get("subject", ())
    issuer = certificate.get("issuer", ())

    date_format = "%b %d %H:%M:%S %Y GMT"

    not_before_str = certificate.get("notBefore", "")
    not_after_str = certificate.get("notAfter", "")

    not_before = None
    not_after = None
    if not_before_str:
        not_before = datetime.strptime(not_before_str, date_format).replace(tzinfo=timezone.utc)
    if not_after_str:
        not_after = datetime.strptime(not_after_str, date_format).replace(tzinfo=timezone.utc)

    raw_sans = certificate.get("subjectAltName", ())
    san_list = [value for san_type, value in raw_sans if san_type == "DNS"]

    return {
        "common_name": extract_field(subject, "commonName"),
        "issuer_org": extract_field(issuer, "organizationName"),
        "issuer_cn": extract_field(issuer, "commonName"),
        "version": certificate.get("version"),
        "serial_number": certificate.get("serial_number") or certificate.get("serialNumber"),
        "not_before": not_before,
        "not_after": not_after,
        "san_list": san_list,
    }


# ── Step 7: Check hostname against SANs ──────────────────────────
def check_hostname_in_sans(domain, san_list):
    """
    Check whether the requested domain is covered by any SAN entry.
    """
    domain_lower = domain.lower()

    for san in san_list:
        san_lower = san.lower()

        # Exact match
        if domain_lower == san_lower:
            return {"matched": True, "matched_san": san}

        # Wildcard match
        if san_lower.startswith("*."):
            wildcard_base = san_lower[2:]
            if domain_lower.endswith("." + wildcard_base):
                prefix = domain_lower[: -(len(wildcard_base) + 1)]
                if "." not in prefix:
                    return {"matched": True, "matched_san": san}

    return {"matched": False, "matched_san": None}


# ── Step 8: Check certificate expiration ─────────────────────────
def check_expiration(not_after):
    """
    Determine the certificate's expiration status.
    """
    if not_after is None:
        return {"status": "Unknown", "days_left": None}

    now = datetime.now(timezone.utc)
    delta = not_after - now
    days_left = delta.days

    if days_left < 0:
        return {"status": "Expired", "days_left": days_left}
    elif days_left <= 30:
        return {"status": "Expiring Soon", "days_left": days_left}
    else:
        return {"status": "Valid", "days_left": days_left}


EMAIL_SERVICE_PORTS = {
    "imap": {143: "starttls", 993: "implicit"},
    "smtp": {25: "starttls", 587: "starttls", 465: "implicit"},
    "pop3": {110: "starttls", 995: "implicit"},
}


def _empty_email_result(port, mode):
    return {
        "port": port,
        "mode": mode,
        "reachable": False,
        "starttls_supported": None if mode == "starttls" else False,
        "tls_version": None,
        "cipher_name": None,
        "cipher_version": None,
        "cipher_bits": None,
        "certificate_common_name": None,
        "certificate_issuer": "Unknown",
        "certificate_version": None,
        "certificate_serial_number": None,
        "certificate_valid_from": None,
        "certificate_valid_until": None,
        "subject_alternative_names": [],
        "hostname_matches_san": None,
        "certificate_status": "Unknown",
        "days_until_expiration": None,
    }


def scan_email_tls(domain, service, port, timeout=5):
    """Scan one implicit-TLS or STARTTLS email endpoint without raising errors."""
    mode = EMAIL_SERVICE_PORTS.get(service, {}).get(port)
    result = _empty_email_result(port, mode or "unknown")
    if mode is None:
        result["error"] = "Unsupported email service port"
        return result

    server = None
    try:
        if mode == "starttls":
            # Establish a small reachability probe so no-capability and
            # unreachable endpoints remain distinguishable in the evidence.
            probe = socket.create_connection((domain, port), timeout=timeout)
            probe.close()
            server, supports_starttls = connect_starttls(domain, port, timeout)
            result["starttls_supported"] = supports_starttls is True
        else:
            server = connect_tls(domain, port, timeout)

        result["reachable"] = True
        if server is None:
            return result

        tls_info = get_tls_info(server)
        cert_info = parse_certificate(get_certificate_info(server))
        hostname_result = check_hostname_in_sans(domain, cert_info["san_list"])
        expiration_result = check_expiration(cert_info["not_after"])
        result.update({
            **tls_info,
            "certificate_common_name": cert_info["common_name"],
            "certificate_issuer": cert_info["issuer_org"] or cert_info["issuer_cn"] or "Unknown",
            "certificate_version": cert_info["version"],
            "certificate_serial_number": cert_info["serial_number"],
            "certificate_valid_from": cert_info["not_before"].strftime("%Y-%m-%d %H:%M:%S UTC") if cert_info["not_before"] else None,
            "certificate_valid_until": cert_info["not_after"].strftime("%Y-%m-%d %H:%M:%S UTC") if cert_info["not_after"] else None,
            "subject_alternative_names": cert_info["san_list"],
            "hostname_matches_san": hostname_result["matched"],
            "certificate_status": expiration_result["status"],
            "days_until_expiration": expiration_result["days_left"],
        })
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as error:
        result["error"] = str(error)
    finally:
        if server is not None:
            server.close()
    return result


# ── Main ──────────────────────────────────────────────────────────
def _load_m1_evidence(path="evidence.json"):
    """Load the exact M1 endpoint that M2 must scan."""
    try:
        with open(path, "r") as file:
            evidence = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError) as error:
        return {"error": f"Unable to read M1 evidence: {error}"}

    network = evidence.get("network", evidence)
    protocol = network.get("protocol")
    port = network.get("port")
    domain = network.get("server_hostname")
    if not protocol or not isinstance(port, int) or not domain:
        return {
            "protocol": protocol,
            "port": port,
            "domain": domain,
            "error": "M1 evidence must contain protocol, integer port, and server_hostname.",
        }
    return {"protocol": protocol.upper(), "port": port, "domain": domain}


def scan_tls(evidence_path="evidence.json", timeout=5):
    """Run M2 against the one endpoint identified by M1 evidence."""
    m1 = _load_m1_evidence(evidence_path)
    protocol = m1.get("protocol")
    port = m1.get("port")
    domain = m1.get("domain")
    service = protocol.lower() if isinstance(protocol, str) else None
    mode = EMAIL_SERVICE_PORTS.get(service, {}).get(port)

    result = _empty_email_result(port, mode or "unknown")
    if m1.get("error"):
        result["error"] = m1["error"]
    elif service not in EMAIL_SERVICE_PORTS or mode is None:
        result["error"] = f"Unsupported email service endpoint: {protocol}:{port}"
    else:
        print(f"\nScanning M1 endpoint {protocol} {domain}:{port} ({mode}) ...\n")
        result = scan_email_tls(domain, service, port, timeout)

    tls_evidence = {
        "domain": domain,
        "server_hostname": domain,
        "protocol": protocol,
        "port": port,
        "tls_mode": result.get("mode"),
        "tls_version": result.get("tls_version"),
        "cipher_name": result.get("cipher_name"),
        "cipher_version": result.get("cipher_version"),
        "cipher_bits": result.get("cipher_bits"),
        "certificate_common_name": result.get("certificate_common_name"),
        "certificate_issuer": result.get("certificate_issuer"),
        "certificate_version": result.get("certificate_version"),
        "certificate_serial_number": result.get("certificate_serial_number"),
        "certificate_valid_from": result.get("certificate_valid_from"),
        "certificate_valid_until": result.get("certificate_valid_until"),
        "subject_alternative_names": result.get("subject_alternative_names", []),
        "hostname_matches_san": result.get("hostname_matches_san"),
        "certificate_status": result.get("certificate_status"),
        "days_until_expiration": result.get("days_until_expiration"),
        "starttls_supported": result.get("starttls_supported"),
        "reachable": result.get("reachable"),
    }
    if result.get("error"):
        tls_evidence["error"] = result["error"]

    return tls_evidence


if __name__ == "__main__":
    scan_tls()
