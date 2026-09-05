import json
from analyzer import analyze
from domain_utils import get_organizational_domain
from tls_scanner import scan_tls


NETWORK_FIELDS = {
    "stream_id", "protocol", "port", "client_ip", "server_ip",
    "server_hostname", "total_packets", "encryption", "extracted_emails",
}


def load_evidence(path="evidence.json"):
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
        raise ValueError("evidence.json must contain a JSON object")
    return evidence


def save_evidence(path, evidence):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=2)


def _network_section(evidence):
    if isinstance(evidence.get("network"), dict):
        network = evidence["network"]
    else:
        network = {key: evidence[key] for key in NETWORK_FIELDS if key in evidence}
        evidence["network"] = network
    for key in NETWORK_FIELDS:
        evidence.pop(key, None)
    return network


def _dns_failure(domain, section_name, error):
    return {
        "domain": domain,
        section_name: {
            "record_found": None,
            "finding": "DNS_LOOKUP_FAILED",
            "risk": "UNKNOWN",
            "error": str(error),
        },
    }


def run_pipeline(evidence_path="evidence.json"):
    evidence = load_evidence(evidence_path)
    network = _network_section(evidence)
    hostname = network.get("server_hostname")
    organizational_domain = evidence.get("organizational_domain") or evidence.get("domain")
    if not organizational_domain and hostname:
        organizational_domain = get_organizational_domain(hostname)

    print("================================")
    print("       SecureMailScope")
    print("================================")

    print("\n[1/5] Running TLS scan...")
    try:
        evidence["tls"] = scan_tls(evidence_path)
    except Exception as error:
        evidence["tls"] = {"server_hostname": hostname, "reachable": False, "error": str(error)}
        print(f"TLS scan failed: {error}")
    save_evidence(evidence_path, evidence)

    print("[2/5] Checking SPF...")
    try:
        from spf_checker import check_spf
        evidence["spf"] = check_spf(organizational_domain)["spf"]
        evidence["spf"]["domain"] = organizational_domain
    except Exception as error:
        evidence["spf"] = _dns_failure(organizational_domain, "spf", error)["spf"]
    save_evidence(evidence_path, evidence)

    print("[3/5] Checking DKIM...")
    try:
        from dkim_checker import check_dkim
        evidence["dkim"] = check_dkim(organizational_domain)["dkim"]
        evidence["dkim"]["domain"] = organizational_domain
    except Exception as error:
        evidence["dkim"] = _dns_failure(organizational_domain, "dkim", error)["dkim"]
        evidence["dkim"]["finding"] = "DKIM_DNS_LOOKUP_FAILED"
    save_evidence(evidence_path, evidence)

    print("[4/5] Checking DMARC...")
    try:
        from dmarc_checker import check_dmarc
        evidence["dmarc"] = check_dmarc(organizational_domain)["dmarc"]
        evidence["dmarc"]["domain"] = organizational_domain
    except Exception as error:
        evidence["dmarc"] = _dns_failure(organizational_domain, "dmarc", error)["dmarc"]
    save_evidence(evidence_path, evidence)

    print("[5/5] Analyzing security posture...")
    return analyze(evidence_path)


def main():
    try:
        run_pipeline()
    except (FileNotFoundError, ValueError) as error:
        print(f"Pipeline failed: {error}")


if __name__ == "__main__":
    main()
