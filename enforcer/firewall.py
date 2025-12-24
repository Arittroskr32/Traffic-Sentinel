import os
import subprocess
import yaml
from typing import Dict, Any, Optional

from core.allowlist import is_allowlisted

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")

_ENFORCE_CACHE: Optional[Dict[str, Any]] = None
DEFAULT_TS_CHAIN = "TS_BLOCK"


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get_enforcement(force_reload: bool = False) -> Dict[str, str]:
    global _ENFORCE_CACHE
    if _ENFORCE_CACHE is not None and not force_reload:
        return _ENFORCE_CACHE

    cfg = _load_config()
    enf = cfg.get("enforcement", {}) or {}
    _ENFORCE_CACHE = {
        "mode": str(enf.get("mode", "iptables")).strip(),
        "chain": str(enf.get("chain", "INPUT")).strip(),
        "ts_chain": str(enf.get("ts_chain", DEFAULT_TS_CHAIN)).strip(),
    }
    return _ENFORCE_CACHE


def _run(cmd: list) -> subprocess.CompletedProcess:
    # text=True gives readable stderr/stdout
    return subprocess.run(cmd, capture_output=True, text=True)


def ensure_chain() -> None:
    enf = get_enforcement()
    if enf["mode"] != "iptables":
        raise NotImplementedError("Only iptables mode implemented right now.")

    base_chain = enf["chain"]
    ts_chain = enf["ts_chain"]

    # Create TS chain if missing
    if _run(["iptables", "-nL", ts_chain]).returncode != 0:
        r = _run(["iptables", "-N", ts_chain])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "Failed to create TS chain")

    # Ensure base chain jumps to TS chain (once)
    if _run(["iptables", "-C", base_chain, "-j", ts_chain]).returncode != 0:
        r = _run(["iptables", "-I", base_chain, "1", "-j", ts_chain])
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "Failed to insert jump rule")


def is_banned(ip: str) -> bool:
    # Allowlisted IPs are never considered banned by TrafficSentinel
    if is_allowlisted(ip):
        return False

    ensure_chain()
    ts_chain = get_enforcement()["ts_chain"]
    return _run(["iptables", "-C", ts_chain, "-s", ip, "-j", "DROP"]).returncode == 0


def ban_ip(ip: str) -> None:
    # Never ban allowlisted (static or trusted tester) IPs / CIDRs
    if is_allowlisted(ip):
        return

    ensure_chain()
    ts_chain = get_enforcement()["ts_chain"]

    # Avoid duplicates
    if is_banned(ip):
        return

    r = _run(["iptables", "-A", ts_chain, "-s", ip, "-j", "DROP"])
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or f"Failed to ban IP: {ip}")


def unban_ip(ip: str) -> None:
    # Don’t touch allowlisted IPs (should never be present anyway)
    if is_allowlisted(ip):
        return

    ensure_chain()
    ts_chain = get_enforcement()["ts_chain"]

    # Remove all duplicates if any exist
    while _run(["iptables", "-D", ts_chain, "-s", ip, "-j", "DROP"]).returncode == 0:
        pass
