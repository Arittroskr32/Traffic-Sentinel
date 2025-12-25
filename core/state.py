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
        # Threshold used for BOTH ban and mark workflows
        "ban_threshold": int(rep.get("ban_threshold", 7)),
        "ban_seconds": int(rep.get("ban_seconds", 3600)),
        "ban_limit": int(rep.get("ban_limit", 3)),
        "decay_seconds": int(rep.get("decay_seconds", 3600)),
    }


def _enforcement_action() -> str:
    """Returns 'ban' (legacy default), 'mark', or 'off'."""
    cfg = _load_config()
    enf = cfg.get("enforcement", {}) or {}
    action = str(enf.get("action", "ban")).strip().lower()
    if action not in ("ban", "mark", "off"):
        return "ban"
    return action


def load_state(path: str = STATE_PATH) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Backward compatibility defaults
    for _, entry in data.items():
        entry.setdefault("penalty", 0)
        entry.setdefault("last_seen", 0)
        entry.setdefault("ban_until", 0)
        entry.setdefault("ban_count", 0)
        entry.setdefault("permanent", False)

        # Mark/review workflow fields
        entry.setdefault("flagged", False)
        entry.setdefault("flagged_at", 0)
        entry.setdefault("flag_count", 0)
        entry.setdefault("max_penalty", 0)

    return data


def save_state(state: Dict[str, Any], path: str = STATE_PATH) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_path, path)


def update_ip_state(state: Dict[str, Any], ip: str, score: int, now: Optional[int] = None) -> Dict[str, Any]:
    """
    Apply score (already computed from detector), update decay, and then:

    - enforcement.action == 'ban': sets ban_until/permanent using reputation settings
    - enforcement.action == 'mark': NEVER bans; only sets flagged=True when threshold is reached
    - enforcement.action == 'off' : tracks penalty/last_seen only (no ban, no flag)

    Note: allowlisted IPs (including CIDRs / trusted_testers) are NEVER penalized, flagged, or banned.
    """
    s = _settings()
    ban_threshold = s["ban_threshold"]
    ban_seconds = s["ban_seconds"]
    ban_limit = s["ban_limit"]
    decay_seconds = s["decay_seconds"]

    action = _enforcement_action()
    now = now or int(time.time())

    # ✅ Allowlisted IPs: never penalize, never ban/flag
    if is_allowlisted(ip):
        entry = state.setdefault(
            ip,
            {
                "penalty": 0,
                "last_seen": 0,
                "ban_until": 0,
                "ban_count": 0,
                "permanent": False,
                "flagged": False,
                "flagged_at": 0,
                "flag_count": 0,
                "max_penalty": 0,
            },
        )
        entry["last_seen"] = now
        entry["penalty"] = 0
        entry["ban_until"] = 0
        entry["permanent"] = False
        entry["flagged"] = False
        entry["flagged_at"] = 0
        return entry

    entry = state.setdefault(
        ip,
        {
            "penalty": 0,
            "last_seen": 0,
            "ban_until": 0,
            "ban_count": 0,
            "permanent": False,
            "flagged": False,
            "flagged_at": 0,
            "flag_count": 0,
            "max_penalty": 0,
        },
    )

    # Decay if inactive
    if entry["last_seen"] and (now - entry["last_seen"] >= decay_seconds):
        entry["penalty"] = 0

    entry["last_seen"] = now

    # Expire temp ban if time passed (state-side)
    if entry.get("ban_until", 0) > 0 and now >= entry["ban_until"] and not entry.get("permanent", False):
        entry["ban_until"] = 0

    # If permanently banned, keep state but don't modify penalties
    if entry.get("permanent", False):
        return entry

    # Add penalty
    if score > 0:
        entry["penalty"] += int(score)
        entry["max_penalty"] = max(int(entry.get("max_penalty", 0)), int(entry["penalty"]))

    # --- Off: track only ---
    if action == "off":
        return entry

    # --- Mark: flag for review (no firewall bans) ---
    if action == "mark":
        if entry["penalty"] >= ban_threshold and not entry.get("flagged", False):
            entry["flagged"] = True
            entry["flagged_at"] = now
            entry["flag_count"] = int(entry.get("flag_count", 0)) + 1
            entry["max_penalty"] = max(int(entry.get("max_penalty", 0)), int(entry["penalty"]))
            entry["penalty"] = 0
        return entry

    # --- Ban: legacy behavior ---
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


def is_flagged(entry: Dict[str, Any]) -> bool:
    return bool(entry.get("flagged", False))
