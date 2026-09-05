import dns.resolver
import dns.exception


def check_dkim(domain):
    selectors = ["google", "selector1", "selector2", "default", "dkim", "mail"]
    dkim_records = []
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8"]
    resolver.timeout = 5
    resolver.lifetime = 5

    last_error = None
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            records = resolver.resolve(dkim_domain, "TXT")
            for record in records:
                txt = record.to_text().strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    dkim_records.append({"selector": selector, "record": txt})
        except dns.exception.Timeout as error:
            last_error = str(error)
            continue
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.exception.DNSException as error:
            last_error = str(error)
            continue
        except Exception as error:
            last_error = str(error)
            continue

    if dkim_records:
        dkim_result = {
            "domain": domain,
            "dkim": {
                "record_found": True,
                "records": dkim_records,
                "status": "FOUND",
                "finding": "DKIM_RECORD_FOUND"
            }
        }
    elif last_error:
        dkim_result = {
            "domain": domain,
            "dkim": {
                    "record_found": None,
                "records": [],
                "status": "DKIM_DNS_LOOKUP_FAILED",
                "finding": "DKIM_DNS_LOOKUP_FAILED",
                "note": "The DKIM lookup could not be completed.",
                "error": last_error
            }
        }
    else:
        dkim_result = {
            "domain": domain,
            "dkim": {
                "record_found": False,
                "records": [],
                "status": "DKIM_SELECTOR_NOT_FOUND",
                "finding": "DKIM_SELECTOR_NOT_FOUND",
                "note": "No DKIM record was found using the tested selectors. This does not prove DKIM is absent."
            }
        }

    return dkim_result


if __name__ == "__main__":
    print("Use main.py to run DKIM checks without interactive input.")