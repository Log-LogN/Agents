import socket
from concurrent.futures import ThreadPoolExecutor


# Common ports for safe security assessment
COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    3306, 3389, 8080
]


def _check_port(host: str, port: int, timeout: float = 1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None


def port_scan(host: str) -> dict:
    """
    Perform a limited safe port scan on common ports.
    """
    open_ports = []

    try:
        # Resolve host to IP
        ip = socket.gethostbyname(host)

        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(lambda p: _check_port(ip, p), COMMON_PORTS)

        open_ports = [port for port in results if port]

        return {
            "host": host,
            "ip": ip,
            "open_ports": open_ports,
            "scanned_ports": COMMON_PORTS,
            "status": "success",
            "note": "Safe limited scan of common ports only"
        }

    except Exception as e:
        return {
            "host": host,
            "error": str(e),
            "status": "failed"
        }