import threading
from collections import defaultdict

_metrics = defaultdict(int)
_lock = threading.Lock()


def incr(metric_name: str, value: int = 1) -> None:
    with _lock:
        _metrics[metric_name] += value


def snapshot() -> dict[str, int]:
    with _lock:
        return dict(_metrics)
