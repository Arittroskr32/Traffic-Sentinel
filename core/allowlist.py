import ipaddress
import os
import yaml
from typing import Any, Dict, List, Optional

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")

_CACHE: Optional[List[ipaddress._BaseNetwork]] = None


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _parse_entries(entries: List[str]) -> List[ipaddress._BaseNetwork]:
    """Parse allowlist entries into ipaddress networks.

    Accepts:
      - Single IP: "1.2.3.4"  -> treated as /32
      - CIDR: "1.2.3.0/24"
      - IPv6 single: "::1" -> treated as /128

    Invalid entries are ignored (no crash).
    """
    nets: List[ipaddress._BaseNetwork] = []
    for item in entries or []:
        s = str(item).strip()
        if not s:
            continue
        try:
            if "/" not in s:
                ip = ipaddress.ip_address(s)
                s = f"{ip}/{32 if ip.version == 4 else 128}"
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            continue
    return nets


def load_allowlist_networks(force_reload: bool = False) -> List[ipaddress._BaseNetwork]:
    """Load allowlist networks from config/config.yml.

    Supports:
      1) allowlist: [ "127.0.0.1", "203.0.113.5", "10.0.0.0/8" ]  (legacy list)

      2) allowlist:
           enabled: true
           ips: [ ... ]                     (older alternative / your current config)

      3) allowlist:
           enabled: true
           static: [ ... ]
           trusted_testers: [ ... ]
           never_ban: [ ... ]               (alias; same as static)
    """
    global _CACHE
    if _CACHE is not None and not force_reload:
        return _CACHE

    cfg = _load_config()
    al = cfg.get("allowlist", {}) or {}

    static_entries: List[str] = []
    trusted_entries: List[str] = []
    never_ban_entries: List[str] = []

    # Legacy: allowlist can be a list
    if isinstance(al, list):
        enabled = True
        static_entries = [str(x) for x in al]
    elif isinstance(al, dict):
        enabled = bool(al.get("enabled", True))

        # Accept BOTH "ips" and "static"
        if "static" in al:
            static_entries = [str(x) for x in (al.get("static") or [])]
        elif "ips" in al:
            static_entries = [str(x) for x in (al.get("ips") or [])]

        trusted_entries = [str(x) for x in (al.get("trusted_testers") or [])]
        never_ban_entries = [str(x) for x in (al.get("never_ban") or [])]
    else:
        enabled = True

    if not enabled:
        _CACHE = []
        return _CACHE

    _CACHE = (
        _parse_entries(static_entries)
        + _parse_entries(trusted_entries)
        + _parse_entries(never_ban_entries)
    )
    return _CACHE


def is_allowlisted(ip: str) -> bool:
    """Return True if the IP belongs to any allowlisted network."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for net in load_allowlist_networks():
        if addr in net:
            return True
    return False
