import json


DEDUCTIONS = {
    "PLAINTEXT_COMMUNICATION": 30,
    "POTENTIAL_STARTTLS_DOWNGRADE": 25,
    "DEPRECATED_TLS_VERSION": 20,
    "WEAK_CIPHER": 20,
    "INVALID_CERTIFICATE": 20,
    "EXPIRED_CERTIFICATE": 20,
    "CERTIFICATE_EXPIRING_SOON": 10,
    "CERTIFICATE_HOSTNAME_MISMATCH": 20,
    "SOFTFAIL_SPF_POLICY": 10,
    "NEUTRAL_SPF_POLICY": 15,
    "PERMISSIVE_SPF_POLICY": 25,
    "SPF_POLICY_NOT_SPECIFIED": 10,
    "SPF_RECORD_MISSING": 20,
    "DKIM_SELECTOR_NOT_FOUND": 0,
    "MODERATE_DMARC_POLICY": 5,
    "MONITOR_ONLY_DMARC_POLICY": 10,
    "DMARC_POLICY_NOT_SPECIFIED": 15,
    "DMARC_RECORD_MISSING": 20,
}


def _load_evidence(path):
    try:
        with open(path, "r", encoding="utf-8") as file:
            evidence = json.load(file)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Evidence file not found: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {path} at line {error.lineno}, column {error.colno}: {error.msg}"
        ) from error
    if not isinstance(evidence, dict):
        raise ValueError(f"Evidence file must contain a JSON object: {path}")
    return evidence


def _section(evidence, *names):
    for name in names:
        value = evidence.get(name)
        if isinstance(value, dict):
            return value
    return evidence


def _add_finding(findings, finding_type, observation, **details):
    finding = {"finding_type": finding_type, **details, "observation": observation}
    findings.append({key: value for key, value in finding.items() if value is not None})


def _analyze_tls(evidence, findings):
    tls = _section(evidence, "tls")
    has_tls_evidence = tls is not evidence or any(
        key in evidence for key in ("reachable", "tls_version", "cipher_name", "certificate_status")
    )
    if not has_tls_evidence:
        return

    reachable = tls.get("reachable")
    if reachable is False:
        _add_finding(
            findings,
            "TLS_CONNECTION_FAILED",
            "The TLS endpoint could not be reached, so TLS and certificate properties could not be verified.",
            protocol=tls.get("protocol", evidence.get("protocol")),
            port=tls.get("port", evidence.get("port")),
            tls_mode=tls.get("tls_mode"),
            error=tls.get("error"),
        )
        return
    tls_version = tls.get("tls_version")
    if tls_version in {"TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"}:
        _add_finding(findings, "DEPRECATED_TLS_VERSION", f"Deprecated TLS/SSL version observed: {tls_version}.", tls_version=tls_version)

    cipher_name = tls.get("cipher_name")
    cipher_upper = cipher_name.upper() if isinstance(cipher_name, str) else ""
    if any(value in cipher_upper for value in ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")):
        _add_finding(
            findings,
            "WEAK_CIPHER",
            "Potentially weak or deprecated cipher detected.",
            cipher_name=cipher_name,
            cipher_version=tls.get("cipher_version"),
            cipher_bits=tls.get("cipher_bits"),
        )

    certificate_status = tls.get("certificate_status")
    certificate_finding = None
    if isinstance(certificate_status, str):
        status = certificate_status.lower()
        if status == "invalid":
            _add_finding(findings, "INVALID_CERTIFICATE", "The TLS certificate is reported as invalid.", certificate_status=certificate_status)
        elif status == "expired":
            _add_finding(findings, "EXPIRED_CERTIFICATE", "The TLS certificate has expired.", certificate_status=certificate_status)
            certificate_finding = "EXPIRED_CERTIFICATE"
        elif status in {"expiring soon", "expiring_soon"}:
            _add_finding(findings, "CERTIFICATE_EXPIRING_SOON", "The TLS certificate is expiring soon.", certificate_status=certificate_status)
            certificate_finding = "CERTIFICATE_EXPIRING_SOON"

    days_until_expiration = tls.get("days_until_expiration")
    if isinstance(days_until_expiration, (int, float)) and not isinstance(days_until_expiration, bool):
        if days_until_expiration < 0 and certificate_finding != "EXPIRED_CERTIFICATE":
            _add_finding(findings, "EXPIRED_CERTIFICATE", "The TLS certificate has expired.", days_until_expiration=days_until_expiration)
        elif days_until_expiration <= 30 and certificate_finding is None:
            _add_finding(findings, "CERTIFICATE_EXPIRING_SOON", "The TLS certificate is expiring soon.", days_until_expiration=days_until_expiration)

    if tls.get("hostname_matches_san") is False:
        _add_finding(
            findings,
            "CERTIFICATE_HOSTNAME_MISMATCH",
            "The requested hostname does not match the certificate Subject Alternative Name.",
            certificate_common_name=tls.get("certificate_common_name"),
        )


def _analyze_starttls(evidence, findings):
    network = evidence.get("network") if isinstance(evidence.get("network"), dict) else evidence
    tls = _section(evidence, "tls")
    if tls is evidence and "starttls_supported" not in evidence:
        return
    if (
        tls.get("starttls_supported") is True
        and str(network.get("encryption", "")).lower() == "plaintext"
        and str(tls.get("tls_mode", "")).lower() not in {"implicit", "implicit_tls"}
    ):
        _add_finding(
            findings,
            "POTENTIAL_STARTTLS_DOWNGRADE",
            f"Plaintext {network.get('protocol', 'email')} communication was observed while the service supports STARTTLS. This may indicate a downgrade or configuration issue, but does not prove that an attacker performed a downgrade.",
            protocol=network.get("protocol"),
            port=network.get("port"),
            observed_encryption=network.get("encryption"),
            supports_starttls=True,
        )


def _analyze_email_auth(evidence, findings):
    spf_container = evidence.get("spf")
    if isinstance(spf_container, dict):
        spf = spf_container.get("spf", spf_container)
        if spf.get("record_found") is True:
            finding_type = spf.get("finding")
            if finding_type not in DEDUCTIONS and finding_type != "STRONG_SPF_POLICY":
                policy = str(spf.get("policy", "")).lower()
                finding_type = {
                    "-all": "STRONG_SPF_POLICY",
                    "~all": "SOFTFAIL_SPF_POLICY",
                    "?all": "NEUTRAL_SPF_POLICY",
                    "+all": "PERMISSIVE_SPF_POLICY",
                }.get(policy, "SPF_POLICY_NOT_SPECIFIED")
            _add_finding(findings, finding_type, f"The domain has an SPF record with policy: {spf.get('policy', 'not specified')}.", domain=evidence.get("domain") or spf_container.get("domain"))
        elif spf.get("finding") == "SPF_RECORD_MISSING":
            _add_finding(findings, "SPF_RECORD_MISSING", "No SPF record was found for this domain.", domain=evidence.get("domain") or spf_container.get("domain"))
        elif spf.get("finding") == "DNS_LOOKUP_FAILED":
            _add_finding(findings, "DNS_LOOKUP_FAILED", spf.get("error") or "The SPF DNS lookup failed.", domain=evidence.get("domain") or spf_container.get("domain"))

    for name, missing_type, found_type, message in (
        ("dkim", "DKIM_SELECTOR_NOT_FOUND", "DKIM_RECORD_FOUND", "DKIM record was found and is configured for this domain."),
        ("dmarc", "DMARC_RECORD_MISSING", None, "No DMARC record was found for this domain."),
    ):
        container = evidence.get(name)
        if not isinstance(container, dict):
            continue
        data = container.get(name, container)
        if data.get("record_found") is True:
            if name == "dkim":
                _add_finding(findings, found_type, message, domain=evidence.get("domain") or container.get("domain"))
            else:
                policy = str(data.get("policy", "")).lower()
                finding_type = {"reject": "STRONG_DMARC_POLICY", "quarantine": "MODERATE_DMARC_POLICY", "none": "MONITOR_ONLY_DMARC_POLICY"}.get(policy, "DMARC_POLICY_NOT_SPECIFIED")
                _add_finding(findings, finding_type, f"The domain DMARC policy is: {data.get('policy', 'not specified')}.", domain=evidence.get("domain") or container.get("domain"))
        elif data.get("finding") == missing_type:
            observation = (
                "No DKIM record was found using the tested selectors. "
                "This does not prove DKIM is absent."
                if name == "dkim" else message
            )
            _add_finding(findings, missing_type, observation, domain=evidence.get("domain") or container.get("domain"))
        elif data.get("finding") in {"DKIM_DNS_LOOKUP_FAILED", "DNS_LOOKUP_FAILED"}:
            finding_type = "DKIM_DNS_LOOKUP_FAILED" if name == "dkim" else "DMARC_DNS_LOOKUP_FAILED"
            _add_finding(findings, finding_type, data.get("error") or "The DNS lookup failed.", domain=evidence.get("domain") or container.get("domain"))


def analyze(evidence_path="evidence.json", output_path="analysis.json"):
    evidence = _load_evidence(evidence_path)
    network = evidence.get("network") if isinstance(evidence.get("network"), dict) else evidence
    protocol = network.get("protocol")
    port = network.get("port")
    encryption = network.get("encryption")
    print(f"Protocol: {protocol if protocol is not None else 'evidence unavailable'}")
    print(f"Port: {port if port is not None else 'evidence unavailable'}")
    print(f"Encryption: {encryption if encryption is not None else 'evidence unavailable'}")

    findings = []
    if isinstance(protocol, str) and protocol.upper() in {"SMTP", "IMAP", "POP3"} and str(encryption).lower() == "plaintext":
        _add_finding(findings, "PLAINTEXT_COMMUNICATION", "Plaintext communication detected.", protocol=protocol, port=port, encryption=encryption)
    _analyze_tls(evidence, findings)
    _analyze_starttls(evidence, findings)
    _analyze_email_auth(evidence, findings)

    score = max(0, 100 - sum(DEDUCTIONS.get(item["finding_type"], 0) for item in findings))
    risk_level = "LOW" if score >= 80 else "MEDIUM" if score >= 60 else "HIGH" if score >= 40 else "CRITICAL"
    result = {}
    result["network"] = {
        key: network[key]
        for key in ("stream_id", "protocol", "port", "server_hostname", "encryption")
        if key in network
    }
    result["findings"] = findings
    result["security_score"] = score
    result["risk_level"] = risk_level
    result["score_breakdown"] = [
        {"finding_type": item["finding_type"], "deduction": DEDUCTIONS[item["finding_type"]]}
        for item in findings if DEDUCTIONS.get(item["finding_type"], 0)
    ]
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2)
    print(f"Security Score: {score}/100")
    print(f"Risk Level: {risk_level}")
    print(f"Analysis saved to {output_path}")
    return result


if __name__ == "__main__":
    analyze()
