import dns.resolver
import dns.exception


def check_spf(domain):
    spf_record = None
    error_message = None

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        resolver.timeout = 5
        resolver.lifetime = 5
        records = resolver.resolve(domain, "TXT")

        for record in records:
            txt = record.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_record = txt
                break
    except dns.exception.Timeout as error:
        error_message = str(error)
        print("DNS lookup failed:", error)
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception as error:
        error_message = str(error)
        print("DNS lookup failed:", error)

    if spf_record:
        if "-all" in spf_record:
            policy, finding, risk = "-all", "STRONG_SPF_POLICY", "LOW"
        elif "~all" in spf_record:
            policy, finding, risk = "~all", "SOFTFAIL_SPF_POLICY", "MEDIUM"
        elif "?all" in spf_record:
            policy, finding, risk = "?all", "NEUTRAL_SPF_POLICY", "HIGH"
        elif "+all" in spf_record:
            policy, finding, risk = "+all", "PERMISSIVE_SPF_POLICY", "CRITICAL"
        else:
            policy, finding, risk = "Not specified", "SPF_POLICY_NOT_SPECIFIED", "MEDIUM"

        spf_result = {
            "domain": domain,
            "spf": {
                "record_found": True,
                "record": spf_record,
                "policy": policy,
                "finding": finding,
                "risk": risk
            }
        }
    else:
        spf_result = {
            "domain": domain,
            "spf": {
                "record_found": False if not error_message else None,
                "record": None,
                "policy": None,
                "finding": "DNS_LOOKUP_FAILED" if error_message else "SPF_RECORD_MISSING",
                "risk": "UNKNOWN" if error_message else "HIGH",
                "error": error_message
            }
        }

    return spf_result


if __name__ == "__main__":
    print("Use main.py to run SPF checks without interactive input.")