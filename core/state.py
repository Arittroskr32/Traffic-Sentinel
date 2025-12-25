import json
import os
import time
import yaml
from typing import Dict, Any, Optional, List

from core.allowlist import is_allowlisted

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATE_PATH = os.path.join(BASE_DIR, "state", "reputation.json")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def _load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _settings() -> Dict[str, Any]:
    cfg = _load_config()
    rep = cfg.get("reputation", {}) or {}
    enf = cfg.get("enforcement", {}) or {}
    action = str(enf.get("action", "ban")).strip().lower()

    return {
        "action": action,
        "ban_threshold": int(rep.get("ban_threshold", 7)),
        "ban_seconds": int(rep.get("ban_seconds", 3600)),
        "ban_limit": int(rep.get("ban_limit", 3)),
        "decay_seconds": int(rep.get("decay_seconds", 3600)),
    }


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_PATH)


def _trim_recent(items: List[Any], max_items: int = 30) -> List[Any]:
    if not items:
        return []
    if len(items) <= max_items:
        return items
    return items[-max_items:]


def update_ip_state(
    state: Dict[str, Any],
    ip: str,
    score: int,
    now: Optional[int] = None,
    *,
    reasons: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Apply score, update decay, and update ban/flag state.

    Also stores *why* the IP gained penalty via `recent_reasons` so `cli.py show <ip>` can display it.

    reasons: list[dict] like:
      {
        "ts": 123,
        "category": "xss",
        "target": "body",
        "pattern": "(?i)<script",
        "method": "GET",
        "uri": "/path",
      }

    Note: allowlisted IPs are NEVER penalized/flagged/banned.
    """
    now = now or int(time.time())

    # Allowlist bypass
    if is_allowlisted(ip):
        return state.get(ip, {})

    s = _settings()
    action = s["action"]
    ban_threshold = s["ban_threshold"]
    ban_seconds = s["ban_seconds"]
    ban_limit = s["ban_limit"]
    decay_seconds = s["decay_seconds"]

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
            # New: store why penalty happened
            "recent_reasons": [],
        },
    )

    # Backward compatibility for old state files
    if "recent_reasons" not in entry or not isinstance(entry.get("recent_reasons"), list):
        entry["recent_reasons"] = []

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

    # Save reasons when score>0
    if score > 0 and reasons:
        for r in reasons[:10]:
            if not isinstance(r, dict):
                continue
            rr = {
                "ts": int(r.get("ts", now) or now),
                "category": str(r.get("category", "")),
                "target": str(r.get("target", "")),
                "pattern": str(r.get("pattern", ""))[:300],
                "method": str(r.get("method", ""))[:12],
                "uri": str(r.get("uri", ""))[:300],
            }
            entry["recent_reasons"].append(rr)
        entry["recent_reasons"] = _trim_recent(entry["recent_reasons"], max_items=40)

    # Add penalty
    if score > 0:
        entry["penalty"] += int(score)
        entry["max_penalty"] = max(int(entry.get("max_penalty", 0)), int(entry["penalty"]))

    # --- Off: track only ---
    if action == "off":
        return entry

    # --- Mark: never ban, only flag ---
    if action == "mark":
        if entry["penalty"] >= ban_threshold:
            if not entry.get("flagged", False):
                entry["flagged"] = True
                entry["flagged_at"] = now
                entry["flag_count"] = int(entry.get("flag_count", 0)) + 1
            entry["penalty"] = 0
        return entry

    # --- Ban: legacy behavior ---
    if entry["penalty"] >= ban_threshold:
        entry["ban_until"] = now + ban_seconds
        entry["ban_count"] = int(entry.get("ban_count", 0)) + 1
        entry["penalty"] = 0

        if entry["ban_count"] >= ban_limit:
            entry["permanent"] = True
            entry["ban_until"] = 0

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
