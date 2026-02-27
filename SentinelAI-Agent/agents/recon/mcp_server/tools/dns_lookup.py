import dns.resolver


def dns_lookup(domain: str) -> dict:
    """
    Resolve A records for a domain.
    """
    try:
        answers = dns.resolver.resolve(domain, "A")
        ips = [rdata.to_text() for rdata in answers]

        return {
            "domain": domain,
            "ips": ips,
            "status": "success"
        }

    except Exception as e:
        return {
            "domain": domain,
            "error": str(e),
            "status": "failed"
        }