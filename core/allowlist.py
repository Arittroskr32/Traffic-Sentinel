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
    nets: List[ipaddress._BaseNetwork] = []
    for item in entries or []:
        s = str(item).strip()
        if not s:
            continue
        try:
            # If it's an IP, convert to /32 (or /128)
            if "/" not in s:
                ip = ipaddress.ip_address(s)
                s = f"{ip}/{32 if ip.version == 4 else 128}"
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            # Ignore invalid entries rather than crashing
            continue
    return nets


def load_allowlist_networks(force_reload: bool = False) -> List[ipaddress._BaseNetwork]:
    global _CACHE
    if _CACHE is not None and not force_reload:
        return _CACHE

    cfg = _load_config()
    al = cfg.get("allowlist", {}) or {}

    # Backward compatible: allowlist can be a list
    static_entries: List[str] = []
    trusted_entries: List[str] = []

    if isinstance(al, list):
        static_entries = [str(x) for x in al]
    else:
        static_entries = [str(x) for x in (al.get("static", []) or [])]
        trusted_entries = [str(x) for x in (al.get("trusted_testers", []) or [])]

    _CACHE = _parse_entries(static_entries) + _parse_entries(trusted_entries)
    return _CACHE


def is_allowlisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for net in load_allowlist_networks():
        if addr in net:
            return True
    return False
