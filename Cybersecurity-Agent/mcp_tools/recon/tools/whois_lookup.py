import whois


def _to_str(value):
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(value) if value else None


def whois_lookup(domain: str) -> dict:
    """
    Fetch WHOIS information.
    """
    try:
        data = whois.whois(domain)

        return {
            "status": "success",
            "data": {
                "domain": domain,
                "registrar": data.registrar,
                "creation_date": _to_str(data.creation_date),
                "expiration_date": _to_str(data.expiration_date),
                "name_servers": data.name_servers
            },
            "error": None
        }

    except Exception as e:
        return {
            "status": "failed",
            "data": None,
            "error": str(e)
        }