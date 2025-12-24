import json
import os
import time
import yaml
from typing import Dict, Any, Optional

from core.allowlist import is_allowlisted

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATE_PATH = os.path.join(BASE_DIR, "state", "reputation.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _settings() -> Dict[str, int]:
    cfg = _load_config()
    rep = cfg.get("reputation", {}) or {}
    return {
        "ban_threshold": int(rep.get("ban_threshold", 7)),
        "ban_seconds": int(rep.get("ban_seconds", 3600)),
        "ban_limit": int(rep.get("ban_limit", 3)),
        "decay_seconds": int(rep.get("decay_seconds", 3600)),
    }


def load_state(path: str = STATE_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Backward compatibility fields
    for _, entry in data.items():
        entry.setdefault("penalty", 0)
        entry.setdefault("last_seen", 0)
        entry.setdefault("ban_until", 0)
        entry.setdefault("ban_count", 0)
        entry.setdefault("permanent", False)

    return data


def save_state(state: Dict[str, Any], path: str = STATE_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_path, path)


def update_ip_state(state: Dict[str, Any], ip: str, score: int, now: Optional[int] = None) -> Dict[str, Any]:
    """
    Apply score (already computed from detector), update decay,
    and set bans/permanent bans based on config.

    Note: allowlisted IPs (including CIDRs / trusted_testers) are NEVER penalized.
    """
    s = _settings()
    ban_threshold = s["ban_threshold"]
    ban_seconds = s["ban_seconds"]
    ban_limit = s["ban_limit"]
    decay_seconds = s["decay_seconds"]

    now = now or int(time.time())

    # ✅ Allowlisted IPs: never penalize, never ban
    if is_allowlisted(ip):
        entry = state.setdefault(ip, {
            "penalty": 0,
            "last_seen": 0,
            "ban_until": 0,
            "ban_count": 0,
            "permanent": False
        })
        entry["last_seen"] = now
        entry["penalty"] = 0
        entry["ban_until"] = 0
        entry["permanent"] = False
        return entry

    entry = state.setdefault(ip, {
        "penalty": 0,
        "last_seen": 0,
        "ban_until": 0,
        "ban_count": 0,
        "permanent": False
    })

    # Decay if inactive
    if entry["last_seen"] and (now - entry["last_seen"] >= decay_seconds):
        entry["penalty"] = 0

    entry["last_seen"] = now

    # Expire temp ban if time passed (state-side)
    if entry["ban_until"] > 0 and now >= entry["ban_until"] and not entry["permanent"]:
        entry["ban_until"] = 0

    # If permanently banned, keep state but don't modify penalties
    if entry.get("permanent", False):
        return entry

    # Add penalty
    if score > 0:
        entry["penalty"] += int(score)

    # Ban logic
    if entry["penalty"] >= ban_threshold:
        entry["ban_until"] = now + ban_seconds
        entry["ban_count"] += 1
        entry["penalty"] = 0  # reset after ban

        if entry["ban_count"] >= ban_limit:
            entry["permanent"] = True
            entry["ban_until"] = 0  # permanent ban doesn't need expiry

    return entry


def is_banned(entry: Dict[str, Any], now: Optional[int] = None) -> bool:
    now = now or int(time.time())
    if entry.get("permanent", False):
        return True
    if entry.get("ban_until", 0) > now:
        return True
    return False
