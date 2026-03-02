from __future__ import annotations

import socket
import ssl
import time
from typing import Any


def _parse_notafter(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        # Example: 'Jun  1 12:00:00 2026 GMT'
        t = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        return int(time.mktime(t))
    except Exception:
        return None


def ssl_info(host: str, port: int = 443) -> dict[str, Any]:
    """
    Lightweight TLS certificate inspection (no external dependencies).
    """
    host = (host or "").strip()
    if not host:
        return {"status": "error", "data": None, "error": "host is required"}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()

        not_after = cert.get("notAfter")
        not_after_ts = _parse_notafter(not_after)
        days_to_expiry = None
        if not_after_ts:
            days_to_expiry = int((not_after_ts - int(time.time())) / 86400)

        return {
            "status": "success",
            "data": {
                "host": host,
                "port": port,
                "tls_version": proto,
                "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
                "subject": cert.get("subject"),
                "issuer": cert.get("issuer"),
                "subject_alt_names": [x[1] for x in cert.get("subjectAltName", []) if len(x) > 1],
                "not_after": not_after,
                "days_to_expiry": days_to_expiry,
            },
            "error": None,
        }
    except Exception as e:
        return {"status": "error", "data": None, "error": str(e)}

