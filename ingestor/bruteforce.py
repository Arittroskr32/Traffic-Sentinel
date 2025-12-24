from typing import Any, Dict, List, Tuple
import time


def detect_bruteforce(
    events: List[Dict[str, Any]],
    endpoints: Tuple[str, ...],
    threshold_per_minute: int,
    fail_statuses: Tuple[int, ...] = (401, 403),
) -> Dict[str, int]:
    """
    Per-minute bruteforce:
    Count requests to auth endpoints per IP.
    If status codes exist, count only failures (401/403).
    """
    # window is "the batch"; assume you read continuously. For simplicity, treat each loop as ~minute-ish.
    counts: Dict[str, int] = {}

    for e in events:
        ip = e.get("ip") or ""
        uri = (e.get("uri") or "").lower()
        status = int(e.get("status") or 0)

        if not ip:
            continue
        if not any(ep in uri for ep in endpoints):
            continue

        # If status is known: count failures only; otherwise count all hits.
        if status != 0:
            if status in fail_statuses:
                counts[ip] = counts.get(ip, 0) + 1
        else:
            counts[ip] = counts.get(ip, 0) + 1

    return {ip: 1 for ip, c in counts.items() if c >= threshold_per_minute}
