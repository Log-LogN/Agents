import whois


def whois_lookup(domain: str) -> dict:
    """
    Fetch WHOIS information for a domain.
    """
    try:
        data = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date),
            "name_servers": data.name_servers,
            "status": "success"
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": str(e),
            "status": "failed"
        }