import socket
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    3306, 3389, 8080
]


def _check_port(ip: str, port: int, timeout: float = 1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None


def port_scan(host: str) -> dict:
    """
    Safe limited port scan (common ports only).
    """
    try:
        ip = socket.gethostbyname(host)

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda p: _check_port(ip, p), COMMON_PORTS)

        open_ports = [p for p in results if p]

        return {
            "status": "success",
            "data": {
                "host": host,
                "ip": ip,
                "open_ports": open_ports,
                "open_count": len(open_ports),
                "scanned_ports": COMMON_PORTS
            },
            "error": None
        }

    except Exception as e:
        return {
            "status": "failed",
            "data": None,
            "error": str(e)
        }