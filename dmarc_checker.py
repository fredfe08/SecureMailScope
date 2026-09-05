import dns.resolver
import dns.exception


def check_dmarc(domain):
    dmarc_result = {
        "domain": domain,
        "dmarc": {
                "record_found": None,
            "record": None,
            "policy": None,
            "finding": "DMARC_RECORD_MISSING",
            "risk": "HIGH"
        }
    }

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        records = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in records:
            txt = record.to_text().strip('"')
            if "v=DMARC1" not in txt:
                continue
            dmarc_result["dmarc"]["record_found"] = True
            dmarc_result["dmarc"]["record"] = txt
            policy = None
            for tag in txt.split(";"):
                tag = tag.strip()
                if tag.startswith("p="):
                    policy = tag.split("=")[1].strip()
                    dmarc_result["dmarc"]["policy"] = policy
                    break
            if policy == "reject":
                dmarc_result["dmarc"]["finding"] = "STRONG_DMARC_POLICY"
                dmarc_result["dmarc"]["risk"] = "LOW"
            elif policy == "quarantine":
                dmarc_result["dmarc"]["finding"] = "MODERATE_DMARC_POLICY"
                dmarc_result["dmarc"]["risk"] = "MEDIUM"
            elif policy == "none":
                dmarc_result["dmarc"]["finding"] = "MONITOR_ONLY_DMARC_POLICY"
                dmarc_result["dmarc"]["risk"] = "MEDIUM"
            elif not policy:
                dmarc_result["dmarc"]["finding"] = "DMARC_POLICY_NOT_SPECIFIED"
                dmarc_result["dmarc"]["risk"] = "HIGH"
            break
        if dmarc_result["dmarc"]["finding"] == "DMARC_RECORD_MISSING":
            dmarc_result["dmarc"]["record_found"] = False
    except dns.exception.Timeout as error:
        dmarc_result["dmarc"]["finding"] = "DNS_LOOKUP_FAILED"
        dmarc_result["dmarc"]["risk"] = "UNKNOWN"
        dmarc_result["dmarc"]["error"] = str(error)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        dmarc_result["dmarc"]["record_found"] = False
        dmarc_result["dmarc"]["finding"] = "DMARC_RECORD_MISSING"
        dmarc_result["dmarc"]["risk"] = "HIGH"
    except dns.exception.DNSException as error:
        dmarc_result["dmarc"]["finding"] = "DNS_LOOKUP_FAILED"
        dmarc_result["dmarc"]["risk"] = "UNKNOWN"
        dmarc_result["dmarc"]["error"] = str(error)
    except Exception as error:
        dmarc_result["dmarc"]["finding"] = "DNS_LOOKUP_FAILED"
        dmarc_result["dmarc"]["risk"] = "UNKNOWN"
        dmarc_result["dmarc"]["error"] = str(error)

    return dmarc_result


if __name__ == "__main__":
    print("Use main.py to run DMARC checks without interactive input.")
