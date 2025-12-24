import json
import subprocess
from typing import Any, Dict, List, Tuple


def _first(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, list) and value:
        return _first(value[0], default)
    if isinstance(value, dict):
        for k in ("show", "showname", "value", "raw", "text"):
            if k in value:
                return _first(value[k], default)
        if len(value) == 1:
            return _first(next(iter(value.values())), default)
    return default


def analyze_pcap_metadata(
    tshark_bin: str,
    pcap_file: str,
    portscan_threshold_ports: int,
    syn_threshold: int,
    portscan_score: int = 1,
    syn_score: int = 1,
) -> List[Dict[str, Any]]:
    """
    Metadata analysis:
    - Portscan: unique dst ports per src_ip
    - SYN flood: SYN count per src_ip
    """
    # We want TCP packets only to compute portscan/syn.
    cmd = [
        tshark_bin,
        "-r", pcap_file,
        "-Y", "tcp",
        "-T", "json",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, check=True, timeout=120)
        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        if not stdout:
            return []
        packets = json.loads(stdout)
    except Exception:
        return []

    unique_ports: Dict[str, set] = {}
    syn_counts: Dict[str, int] = {}

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {}) or {}

        src = _first(layers.get("ip.src")) or _first(layers.get("ipv6.src"))
        if not src:
            continue

        dport_s = _first(layers.get("tcp.dstport"))
        try:
            dport = int(dport_s) if dport_s else None
        except Exception:
            dport = None

        if dport is not None:
            unique_ports.setdefault(src, set()).add(dport)

        # SYN detection: tshark often exposes tcp.flags.syn as "1"
        syn_flag = _first(layers.get("tcp.flags.syn"))
        if syn_flag == "1":
            syn_counts[src] = syn_counts.get(src, 0) + 1

    results: List[Dict[str, Any]] = []

    for ip, ports in unique_ports.items():
        if len(ports) >= portscan_threshold_ports:
            results.append({
                "ip": ip,
                "score_total": portscan_score,
                "categories": ["portscan"],
                "hits": [{
                    "category": "portscan",
                    "id": "meta-portscan",
                    "target": "tcp.dstport",
                    "matched": f"unique_ports>={portscan_threshold_ports}",
                    "snippet": f"unique_ports={len(ports)}",
                }],
                "scoring_mode": "metadata",
            })

    for ip, cnt in syn_counts.items():
        if cnt >= syn_threshold:
            results.append({
                "ip": ip,
                "score_total": syn_score,
                "categories": ["synflood"],
                "hits": [{
                    "category": "synflood",
                    "id": "meta-synflood",
                    "target": "tcp.flags.syn",
                    "matched": f"syn_packets>={syn_threshold}",
                    "snippet": f"syn_packets={cnt}",
                }],
                "scoring_mode": "metadata",
            })

    return results
