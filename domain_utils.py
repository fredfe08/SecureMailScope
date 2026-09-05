import re


_COMMON_MULTI_PART_SUFFIXES = {
    "ac.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.uk", "com.au",
    "com.br", "com.mx", "gov.uk", "net.au", "org.uk", "us.com"
}


def _normalize_hostname(hostname):
    if not hostname:
        return ""

    value = hostname.strip().lower().strip(".")
    value = value.split("/")[-1]
    if value.startswith("[") and "]" in value:
        value = value.replace("[", "").replace("]", "")
    if ":" in value and value.rsplit(":", 1)[-1].isdigit():
        value = value.rsplit(":", 1)[0]
    if not re.fullmatch(r"[a-z0-9.-]+", value):
        return ""
    return value


def _fallback_organizational_domain(hostname):
    if not hostname:
        return ""

    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname if len(labels) == 2 else ""

    for idx in range(len(labels) - 1, 0, -1):
        suffix = ".".join(labels[idx:])
        if suffix in _COMMON_MULTI_PART_SUFFIXES and idx > 0:
            return ".".join(labels[idx - 1:])

    return ".".join(labels[-2:])


def get_organizational_domain(hostname):
    """Derive the registrable organizational domain for a mail-server hostname.

    Prefer public-suffix aware libraries when available, but gracefully fall back to a
    conservative heuristic that handles common multi-label public suffixes like
    example.co.uk and example.co.in.
    """
    normalized = _normalize_hostname(hostname)
    if not normalized:
        return ""

    try:
        import tldextract  # type: ignore
        extracted = tldextract.extract(normalized)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except ImportError:
        pass

    try:
        import publicsuffix2  # type: ignore
        value = publicsuffix2.get_sld(normalized)
        if value:
            return value
    except ImportError:
        pass

    return _fallback_organizational_domain(normalized)
