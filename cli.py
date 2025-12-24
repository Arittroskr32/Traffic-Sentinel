import argparse
import os
import time
from typing import Any, Dict, Tuple

import yaml

from core.state import load_state, save_state
from enforcer.firewall import unban_ip, is_banned as fw_is_banned

from core.allowlist import load_allowlist_networks


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def _sort_key(item: Tuple[str, Dict[str, Any]]):
    ip, e = item
    # Higher priority: permanent, then ban_count, then penalty
    return (int(e.get("permanent", False)), int(e.get("ban_count", 0)), int(e.get("penalty", 0)))


# -----------------------
# Existing admin commands
# -----------------------

def cmd_top(args):
    state = load_state()
    items = list(state.items())
    items.sort(key=_sort_key, reverse=True)

    n = args.n
    now = int(time.time())

    print(f"{'IP':<18} {'penalty':<7} {'ban_count':<9} {'banned':<6} {'ban_until':<12} {'permanent'}")
    print("-" * 70)
    for ip, e in items[:n]:
        penalty = e.get("penalty", 0)
        ban_count = e.get("ban_count", 0)
        permanent = bool(e.get("permanent", False))
        ban_until = int(e.get("ban_until", 0) or 0)
        banned = permanent or ban_until > now
        print(f"{ip:<18} {penalty:<7} {ban_count:<9} {str(banned):<6} {ban_until:<12} {permanent}")


def cmd_show(args):
    state = load_state()
    ip = args.ip
    e = state.get(ip)
    if not e:
        print("No record for IP.")
        return
    print(f"IP: {ip}")
    for k in ["penalty", "last_seen", "ban_until", "ban_count", "permanent"]:
        print(f"  {k}: {e.get(k)}")
    print(f"Firewall blocked: {fw_is_banned(ip)}")


def cmd_clear(args):
    state = load_state()
    ip = args.ip
    e = state.get(ip)
    if not e:
        print("No record for IP.")
        return
    e["penalty"] = 0
    save_state(state)
    print(f"Cleared penalty for {ip}")


def cmd_unban(args):
    state = load_state()
    ip = args.ip
    e = state.get(ip)
    if not e:
        print("No record for IP.")
        return

    # Clear state ban fields (but do NOT remove permanent unless user forces)
    if e.get("permanent") and not args.force:
        print("IP is permanently banned in state. Use --force to clear permanent flag.")
        return

    e["ban_until"] = 0
    if args.force:
        e["permanent"] = False

    save_state(state)

    # Remove firewall drop rule(s)
    if fw_is_banned(ip):
        unban_ip(ip)

    print(f"Unbanned {ip} (state+firewall). Permanent cleared: {bool(args.force)}")


# -----------------------
# Allowlist management
# -----------------------

def _load_cfg() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _save_cfg(cfg: Dict[str, Any]) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)


def _ensure_allowlist_struct(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Supports:
      allowlist: [ ... ]     (old)
      allowlist:
        static: [...]
        trusted_testers: [...]
    If old format is detected, migrates it to new format (static list).
    """
    al = cfg.get("allowlist", {})

    if isinstance(al, list):
        cfg["allowlist"] = {
            "static": [str(x) for x in al],
            "trusted_testers": [],
        }
        return cfg

    if not isinstance(al, dict):
        cfg["allowlist"] = {"static": [], "trusted_testers": []}
        return cfg

    al.setdefault("static", [])
    al.setdefault("trusted_testers", [])
    cfg["allowlist"] = al
    return cfg


def cmd_allowlist_list(_args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    al = cfg["allowlist"]

    print("allowlist.static:")
    for x in al.get("static", []) or []:
        print(f"  - {x}")

    print("\nallowlist.trusted_testers:")
    for x in al.get("trusted_testers", []) or []:
        print(f"  - {x}")

    # Reload cache (so user sees consistent behavior after edits)
    load_allowlist_networks(force_reload=True)


def cmd_allowlist_add(args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    testers = cfg["allowlist"]["trusted_testers"]

    entry = str(args.entry).strip()
    if not entry:
        print("Invalid entry.")
        return

    if entry in testers:
        print("Already present:", entry)
        return

    testers.append(entry)
    _save_cfg(cfg)
    load_allowlist_networks(force_reload=True)
    print("Added trusted tester:", entry)


def cmd_allowlist_remove(args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    testers = cfg["allowlist"]["trusted_testers"]

    entry = str(args.entry).strip()
    if entry in testers:
        testers.remove(entry)
        _save_cfg(cfg)
        load_allowlist_networks(force_reload=True)
        print("Removed trusted tester:", entry)
    else:
        print("Not found in trusted_testers:", entry)


def main():
    p = argparse.ArgumentParser(description="TrafficSentinel admin CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Existing commands
    p_top = sub.add_parser("top", help="Show top attackers")
    p_top.add_argument("-n", type=int, default=20)
    p_top.set_defaults(func=cmd_top)

    p_show = sub.add_parser("show", help="Show one IP record")
    p_show.add_argument("ip")
    p_show.set_defaults(func=cmd_show)

    p_clear = sub.add_parser("clear", help="Clear penalty for an IP")
    p_clear.add_argument("ip")
    p_clear.set_defaults(func=cmd_clear)

    p_unban = sub.add_parser("unban", help="Unban an IP (state + firewall)")
    p_unban.add_argument("ip")
    p_unban.add_argument("--force", action="store_true", help="Also clear permanent ban flag")
    p_unban.set_defaults(func=cmd_unban)

    # New allowlist commands
    p_al = sub.add_parser("allowlist", help="Manage allowlist (trusted testers)")
    al_sub = p_al.add_subparsers(dest="action", required=True)

    p_al_list = al_sub.add_parser("list", help="List allowlist entries")
    p_al_list.set_defaults(func=cmd_allowlist_list)

    p_al_add = al_sub.add_parser("add", help="Add trusted tester IP or CIDR")
    p_al_add.add_argument("entry", help="IP or CIDR, e.g. 203.0.113.10 or 203.0.113.0/24")
    p_al_add.set_defaults(func=cmd_allowlist_add)

    p_al_rm = al_sub.add_parser("remove", help="Remove trusted tester IP or CIDR")
    p_al_rm.add_argument("entry", help="IP or CIDR")
    p_al_rm.set_defaults(func=cmd_allowlist_remove)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
