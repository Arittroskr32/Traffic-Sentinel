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


def _trim_recent(items: List[Any], max_items: int = 50) -> List[Any]:
    if not items:
        return []
    if len(items) <= max_items:
        return items
    return items[-max_items:]


def _migrate_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    If old key recent_reasons exists, convert into recent_events so CLI can show details.
    """
    if not isinstance(entry, dict):
        return {}

    # Ensure recent_events list exists
    revents = entry.get("recent_events")
    if not isinstance(revents, list):
        entry["recent_events"] = []
        revents = entry["recent_events"]

    # Migrate legacy recent_reasons if present and recent_events empty
    legacy = entry.get("recent_reasons")
    if isinstance(legacy, list) and legacy and not revents:
        for rr in legacy[-50:]:
            if not isinstance(rr, dict):
                continue
            ts = int(rr.get("ts", 0) or 0)
            cat = str(rr.get("category", "") or "")
            target = str(rr.get("target", "") or "")
            pat = str(rr.get("pattern", "") or "")
            method = str(rr.get("method", "") or "")
            uri = str(rr.get("uri", "") or "")

            entry["recent_events"].append(
                {
                    "ts": ts,
                    "delta_score": 1,
                    "penalty_before": 0,
                    "penalty_after": 0,
                    "method": method[:12],
                    "uri": uri[:300],
                    "rule": {
                        "category": cat[:32],
                        "target": target[:32],
                        "pattern": pat[:200],
                    },
                    "migrated": True,
                }
            )

        entry["recent_events"] = _trim_recent(entry["recent_events"], 50)

    return entry


def load_state() -> Dict[str, Any]:
    if not os.path.exists(STATE_PATH):
        return {}
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            st = json.load(f) or {}
        if not isinstance(st, dict):
            return {}
        # migrate all entries
        for ip, entry in list(st.items()):
            if isinstance(entry, dict):
                st[ip] = _migrate_entry(entry)
        return st
    except Exception:
        return {}


def save_state(state: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, STATE_PATH)


def update_ip_state(
    state: Dict[str, Any],
    ip: str,
    score: int,
    now: Optional[int] = None,
    *,
    reasons: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    now = now or int(time.time())

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
            "recent_events": [],
        },
    )

    entry = _migrate_entry(entry)

    if entry["last_seen"] and (now - int(entry["last_seen"])) >= decay_seconds:
        entry["penalty"] = 0

    entry["last_seen"] = now

    if entry.get("ban_until", 0) > 0 and now >= int(entry["ban_until"]) and not entry.get("permanent", False):
        entry["ban_until"] = 0

    if entry.get("permanent", False):
        return entry

    if score > 0:
        penalty_before = int(entry.get("penalty", 0) or 0)

        rule = {}
        method = ""
        uri = ""
        if reasons and isinstance(reasons, list) and reasons and isinstance(reasons[0], dict):
            r = reasons[0]
            rule = {
                "category": str(r.get("category", "") or "")[:32],
                "target": str(r.get("target", "") or "")[:32],
                "pattern": str(r.get("pattern", "") or "")[:200],
            }
            method = str(r.get("method", "") or "")[:12]
            uri = str(r.get("uri", "") or "")[:300]

        event = {
            "ts": now,
            "delta_score": int(score),
            "penalty_before": penalty_before,
            "penalty_after": penalty_before + int(score),
            "method": method,
            "uri": uri,
            "rule": rule,
        }

        entry["recent_events"].append(event)
        entry["recent_events"] = _trim_recent(entry["recent_events"], max_items=50)

        entry["penalty"] = penalty_before + int(score)
        entry["max_penalty"] = max(int(entry.get("max_penalty", 0)), int(entry["penalty"]))

    if action == "off":
        return entry

    if action == "mark":
        if int(entry["penalty"]) >= ban_threshold:
            if not entry.get("flagged", False):
                entry["flagged"] = True
                entry["flagged_at"] = now
                entry["flag_count"] = int(entry.get("flag_count", 0)) + 1
            entry["penalty"] = 0
        return entry

    # ban mode
    if int(entry["penalty"]) >= ban_threshold:
        entry["ban_until"] = now + ban_seconds
        entry["ban_count"] = int(entry.get("ban_count", 0)) + 1
        entry["penalty"] = 0

        if int(entry["ban_count"]) >= ban_limit:
            entry["permanent"] = True
            entry["ban_until"] = 0

    return entry


def is_banned(entry: Dict[str, Any], now: Optional[int] = None) -> bool:
    now = now or int(time.time())
    if entry.get("permanent", False):
        return True
    if int(entry.get("ban_until", 0) or 0) > now:
        return True
    return False
