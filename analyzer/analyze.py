import subprocess
import json
import os
import yaml
from typing import Any, Dict, List

from analyzer.detector import scan_request, get_rules_once
from analyzer.metadata import analyze_pcap_metadata


def _load_config() -> Dict[str, Any]:
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    cfg_path = os.path.join(base, "config", "config.yml")
    with open(cfg_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _first(value: Any, default: str = "") -> str:
    """
    Robust extraction for tshark JSON values across versions.
    Supports: str, [..], dict with show/value/raw/text, nested dicts.
    """
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


def extract_requests_from_pcap(pcap_file: str) -> List[Dict[str, Any]]:
    """
    Extract plaintext HTTP requests from a PCAP using tshark JSON output.

    NOTE:
    - Works for HTTP (unencrypted).
    - Does NOT work for HTTPS request content (TLS encrypted).
    """
    cfg = _load_config()
    tshark_bin = cfg.get("capture", {}).get("tshark_path", "tshark")

    cmd = [
        tshark_bin,
        "-r", pcap_file,
        "-Y", "http.request",
        "-T", "json",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, check=True, timeout=120)
        stdout = result.stdout.decode("utf-8", errors="ignore").strip()
        if not stdout:
            return []
        packets = json.loads(stdout)
    except Exception as e:
        print(f"[analyze] tshark http.request failed: {e}")
        return []

    requests: List[Dict[str, Any]] = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {}) or {}

        # IPv4 or IPv6
        ip = _first(layers.get("ip.src")) or _first(layers.get("ipv6.src"))
        if not ip:
            continue

        # Prefer full uri then uri
        uri = _first(layers.get("http.request.full_uri")) or _first(layers.get("http.request.uri"))

        # fallback: parse request line
        req_line = _first(layers.get("http.request.line"))
        if not uri and req_line:
            parts = req_line.split()
            if len(parts) >= 2:
                uri = parts[1]

        host = _first(layers.get("http.host"))
        ua = _first(layers.get("http.user_agent"))
        cookie = _first(layers.get("http.cookie"))

        headers: Dict[str, str] = {}
        if host:
            headers["host"] = host
        if ua:
            headers["user_agent"] = ua
        if cookie:
            headers["cookie"] = cookie
        if req_line:
            headers["request_line"] = req_line

        # body is only available sometimes
        body = _first(layers.get("http.file_data"))

        requests.append({
            "ip": ip,
            "uri": uri or "",
            "headers": headers,
            "body": body or "",
        })

    return requests


def _bruteforce_scores(cfg: Dict[str, Any], reqs: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Per-PCAP-slice bruteforce heuristic:
    - Count hits to auth endpoints per IP in this slice (assumed ~1 minute)
    - If count >= threshold => +1 bruteforce score
    """
    bf_cfg = cfg.get("bruteforce", {}) or {}
    if not bf_cfg.get("enabled", True):
        return {}

    threshold = int(bf_cfg.get("threshold_per_minute", 10))
    endpoints = tuple((bf_cfg.get("endpoints") or []) or [
        "/login", "/signin", "/auth", "/api/auth", "/wp-login.php", "/admin", "/administrator"
    ])

    counts: Dict[str, int] = {}
    for r in reqs:
        ip = r.get("ip") or ""
        if not ip:
            continue
        uri = (r.get("uri") or "").lower()
        if any(ep in uri for ep in endpoints):
            counts[ip] = counts.get(ip, 0) + 1

    return {ip: 1 for ip, c in counts.items() if c >= threshold}


def analyze_pcap(pcap_file: str) -> List[Dict[str, Any]]:
    """
    Main PCAP analysis entry:
    - HTTP content detection (if available)
    - bruteforce heuristic (HTTP URIs)
    - PCAP metadata detections: portscan + synflood (works for HTTPS too)
    """
    cfg = _load_config()
    rules = get_rules_once()

    results: List[Dict[str, Any]] = []

    # 1) HTTP content extraction + rule scan
    reqs = extract_requests_from_pcap(pcap_file)
    for req in reqs:
        results.append(
            scan_request(
                req["ip"],
                req["uri"],
                req["headers"],
                req["body"],
                rules=rules
            )
        )

    # 2) bruteforce heuristic from URIs in plaintext HTTP
    bf = _bruteforce_scores(cfg, reqs)
    for ip, score in bf.items():
        results.append({
            "ip": ip,
            "score_total": score,
            "categories": ["bruteforce"],
            "hits": [{
                "category": "bruteforce",
                "id": "bf-heuristic",
                "target": "uri",
                "matched": "endpoint-rate",
                "snippet": f"high-rate auth endpoint hits in slice (>= threshold)",
            }],
            "scoring_mode": "heuristic",
        })

    # 3) PCAP metadata detection (HTTPS-friendly)
    meta_cfg = cfg.get("pcap_metadata", {}) or {}
    if bool(meta_cfg.get("enabled", True)):
        tshark_bin = cfg.get("capture", {}).get("tshark_path", "tshark")

        ps = meta_cfg.get("portscan", {}) or {}
        sf = meta_cfg.get("synflood", {}) or {}

        meta_results = analyze_pcap_metadata(
            tshark_bin=tshark_bin,
            pcap_file=pcap_file,
            portscan_threshold_ports=int(ps.get("threshold_unique_ports", 20)),
            syn_threshold=int(sf.get("threshold_syn_packets", 200)),
            portscan_score=int(ps.get("score", 1)),
            syn_score=int(sf.get("score", 1)),
        )
        results.extend(meta_results)

    return results
