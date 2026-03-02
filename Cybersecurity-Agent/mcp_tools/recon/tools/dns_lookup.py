import dns.resolver


def dns_lookup(domain: str) -> dict:
    """
    Resolve A records for a domain.
    """
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [rdata.to_text() for rdata in answers]

        return {
            "status": "success",
            "data": {
                "domain": domain,
                "ips": ips,
                "count": len(ips)
            },
            "error": None
        }

    except Exception as e:
        return {
            "status": "failed",
            "data": None,
            "error": str(e)
        }