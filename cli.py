#!/usr/bin/env python3
"""
TrafficSentinel CLI (Log-Ingestion Edition)

This CLI is designed to be friendly for newcomers:
- clear commands
- sensible defaults
- helpful examples

Typical usage (host install or inside container):

  # 1) Check configuration and paths
  python3 cli.py status

  # 2) Run the live monitor (log tail -> detect -> ban)
  python3 cli.py run

  # 3) See the "worst" IPs right now
  python3 cli.py top --n 20

  # 4) Inspect one IP
  python3 cli.py show 203.0.113.10

  # 5) Manually ban/unban (emergency admin actions)
  python3 cli.py ban 203.0.113.10 --seconds 7200 --reason "manual"
  python3 cli.py unban 203.0.113.10

  # 6) Tail logs
  python3 cli.py tail events --lines 50
  python3 cli.py tail actions --lines 50

  # 7) Test detector locally against a URL/body/header snippet
  python3 cli.py test --ip 1.2.3.4 --uri "/?q=<script>alert(1)</script>"
  python3 cli.py test --ip 1.2.3.4 --body "1' OR 1=1--"
"""

import argparse
import os
import sys
import time
from typing import Any, Dict, List, Tuple

import yaml

from core.state import load_state, save_state, is_banned as state_is_banned
from core.allowlist import load_allowlist_networks, is_allowlisted
from enforcer.firewall import (
    ensure_chain,
    ban_ip,
    unban_ip,
    is_banned as fw_is_banned,
)
from analyzer.detector import get_rules_once, scan_request


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


# -----------------------
# Helpers
# -----------------------
def _load_cfg() -> Dict[str, Any]:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _save_cfg(cfg: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(cfg, f, sort_keys=False, default_flow_style=False)


def _ensure_allowlist_struct(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    allowlist supports:
      allowlist:
        static: [ "127.0.0.1", "10.0.0.0/8" ]
        trusted_testers: [ "203.0.113.10" ]
    Also accepts legacy formats:
      allowlist: [ "127.0.0.1", ... ]   (list)
      allowlist:
        ips: [ ... ]                    (older alternative)
    """
    al = cfg.get("allowlist")
    if al is None:
        cfg["allowlist"] = {"enabled": True, "static": ["127.0.0.1", "::1"], "trusted_testers": []}
        return cfg

    # If allowlist is a plain list, convert to struct
    if isinstance(al, list):
        cfg["allowlist"] = {"enabled": True, "static": [str(x) for x in al], "trusted_testers": []}
        return cfg

    if not isinstance(al, dict):
        cfg["allowlist"] = {"enabled": True, "static": ["127.0.0.1", "::1"], "trusted_testers": []}
        return cfg

    # Legacy "ips" -> "static"
    if "ips" in al and "static" not in al:
        al["static"] = [str(x) for x in (al.get("ips") or [])]
        al.pop("ips", None)

    al.setdefault("enabled", True)
    al.setdefault("static", ["127.0.0.1", "::1"])
    al.setdefault("trusted_testers", [])
    cfg["allowlist"] = al
    return cfg


def _sort_key(item: Tuple[str, Dict[str, Any]]):
    ip, e = item
    # Higher priority: permanent, then ban_count, then penalty
    return (int(e.get("permanent", False)), int(e.get("ban_count", 0)), int(e.get("penalty", 0)))


def _read_tail(path: str, lines: int = 50) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
        # Simple tail without external deps
        f.seek(0, os.SEEK_END)
        size = f.tell()
        block = 4096
        data = b""
        while size > 0 and data.count(b"\n") <= lines:
            step = block if size >= block else size
            size -= step
            f.seek(size)
            data = f.read(step) + data
        return data.decode("utf-8", errors="replace").splitlines()[-lines:]


# -----------------------
# Commands
# -----------------------
def cmd_status(_args):
    cfg = _load_cfg()
    ingestion = (cfg.get("ingestion") or {})
    logging = (cfg.get("logging") or {})
    rules_cfg = (cfg.get("rules") or {})

    mode = str(ingestion.get("mode", "log")).lower().strip()
    log_path = ingestion.get("log_path")
    log_source = ingestion.get("log_source", "jsonl")
    offset_file = ingestion.get("offset_file", "./state/log_offset.json")

    events_log = logging.get("events_log", "./state/events.log")
    actions_log = logging.get("actions_log", "./state/actions.log")
    error_log = logging.get("error_log", "./state/error.log")

    print("TrafficSentinel Status")
    print("-" * 72)
    print(f"Config:        {CONFIG_PATH}")
    print(f"Ingestion:     mode={mode} (this build expects 'log')")
    print(f"Log source:    {log_source}")
    print(f"Log path:      {log_path}")
    print(f"Offset file:   {offset_file}")
    print()
    print(f"events.log:    {events_log}")
    print(f"actions.log:   {actions_log}")
    print(f"error.log:     {error_log}")
    print()
    print(f"Rules compiled:{rules_cfg.get('compiled_rules_path')}")
    print(f"Rules custom:  {rules_cfg.get('custom_rules_path')}")
    print()

    # Allowlist
    cfg = _ensure_allowlist_struct(cfg)
    al = cfg.get("allowlist") or {}
    print("Allowlist")
    print(f"  enabled: {bool(al.get('enabled', True))}")
    print(f"  static: {len(al.get('static') or [])} entries")
    print(f"  trusted_testers: {len(al.get('trusted_testers') or [])} entries")

    # Firewall chain
    try:
        ensure_chain()
        print("\nFirewall:      chain OK (iptables)")
    except Exception as e:
        print("\nFirewall:      ERROR creating/checking chain:", repr(e))
        print("               If running in Docker, ensure NET_ADMIN + host networking/privileged.")
    print("-" * 72)


def cmd_run(_args):
    # Run the same loop as main.py without requiring docker
    from main import main_loop

    print("Starting TrafficSentinel monitor (log ingestion)...")
    main_loop()


def cmd_top(args):
    state = load_state()
    items = list(state.items())
    items.sort(key=_sort_key, reverse=True)

    n = int(args.n)
    now = int(time.time())

    print(f"{'IP':<18} {'penalty':<7} {'ban_count':<9} {'banned':<6} {'ban_until':<12} {'permanent'}")
    print("-" * 80)
    for ip, e in items[:n]:
        penalty = e.get("penalty", 0)
        ban_count = e.get("ban_count", 0)
        banned = "yes" if state_is_banned(e, now=now) else "no"
        ban_until = e.get("ban_until", 0)
        permanent = "yes" if e.get("permanent", False) else "no"
        print(f"{ip:<18} {penalty:<7} {ban_count:<9} {banned:<6} {ban_until:<12} {permanent}")


def cmd_show(args):
    state = load_state()
    ip = args.ip
    e = state.get(ip)
    if not e:
        print("No record for IP in state.")
        print("Tip: use `top` to see known IPs.")
        return

    now = int(time.time())
    print(f"IP: {ip}")
    for k in ["penalty", "last_seen", "ban_until", "ban_count", "permanent"]:
        print(f"  {k}: {e.get(k)}")

    print(f"State banned:     {state_is_banned(e, now=now)}")
    try:
        ensure_chain()
        print(f"Firewall blocked: {fw_is_banned(ip)}")
    except Exception as ex:
        print(f"Firewall blocked: (could not check) {repr(ex)}")

    print(f"Allowlisted:      {is_allowlisted(ip)}")


def cmd_clear(args):
    if not args.yes:
        print("Refusing to clear state without --yes (safety).")
        print("Run: python3 cli.py clear --yes")
        return

    save_state({})
    print("Cleared reputation state. (Firewall bans are NOT automatically removed.)")
    print("Tip: unban manually if needed: python3 cli.py unban <ip>")


def cmd_ban(args):
    ip = args.ip.strip()
    seconds = int(args.seconds) if args.seconds is not None else None
    permanent = bool(args.permanent)

    if is_allowlisted(ip):
        print("Refusing to ban: IP is allowlisted:", ip)
        return

    ensure_chain()

    # Ban in firewall immediately
    ban_ip(ip)

    # Optionally update state (so UI/CLI reflects it)
    state = load_state()
    now = int(time.time())
    entry = state.get(ip) or {}
    entry.setdefault("ban_count", 0)
    entry["ban_count"] = int(entry.get("ban_count", 0)) + 1
    entry["last_seen"] = now
    entry["permanent"] = permanent
    if permanent:
        entry["ban_until"] = 0
    else:
        if seconds is None:
            seconds = 3600
        entry["ban_until"] = now + seconds
    # Keep penalty high so it appears in top lists
    entry["penalty"] = max(int(entry.get("penalty", 0)), 999)
    state[ip] = entry
    save_state(state)

    reason = args.reason or "manual"
    print(f"BANNED {ip} ({'permanent' if permanent else str(seconds)+'s'}) reason={reason}")


def cmd_unban(args):
    ip = args.ip.strip()
    ensure_chain()

    if fw_is_banned(ip):
        unban_ip(ip)
        print("Unbanned (firewall):", ip)
    else:
        print("Not currently banned in firewall:", ip)

    # Also relax state record so it doesn't instantly re-ban on next loop.
    state = load_state()
    if ip in state:
        state[ip]["ban_until"] = 0
        state[ip]["permanent"] = False
        save_state(state)
        print("Updated state: ban cleared for", ip)


def cmd_tail(args):
    cfg = _load_cfg()
    logging = (cfg.get("logging") or {})
    which = args.which.lower().strip()

    if which == "events":
        path = logging.get("events_log", "./state/events.log")
    elif which == "actions":
        path = logging.get("actions_log", "./state/actions.log")
    elif which == "error":
        path = logging.get("error_log", "./state/error.log")
    else:
        print("Unknown log type:", which)
        return

    lines = _read_tail(path, lines=int(args.lines))
    if not lines:
        print("(no lines / file missing)", path)
        return

    print(f"==> {path} <==")
    for l in lines:
        print(l)


def cmd_test(args):
    """
    Local detector test: run scan_request() for a simulated request.
    This does NOT ban; it just prints the detection result.
    """
    ip = args.ip
    uri = args.uri or "/"
    body = args.body or ""
    headers: Dict[str, str] = {}

    # Simple header parsing: "K: V" lines
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    rules = get_rules_once()
    result = scan_request(ip=ip, uri=uri, headers=headers, body=body, rules=rules)

    print("Detector Result")
    print("-" * 72)
    print(f"ip:     {result.get('ip')}")
    print(f"score:  {result.get('score_total')}")
    print(f"cats:   {', '.join(result.get('categories') or [])}")
    print(f"hits:   {len(result.get('hits') or [])}")
    print("-" * 72)

    for h in (result.get("hits") or [])[:50]:
        print(f"- [{h.get('category')}] id={h.get('id')} target={h.get('target')} matched={h.get('matched')}")
        snip = (h.get("snippet") or "").strip()
        if snip:
            print(f"  snippet: {snip[:200]}")
    if (result.get("hits") or []) and len(result["hits"]) > 50:
        print("... (hits truncated)")

    print("-" * 72)
    print("Tip: to generate real detections, send requests to your site and watch events.log.")


def cmd_allowlist_list(_args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    al = cfg.get("allowlist", {}) or {}
    print("Allowlist entries")
    print("-" * 72)
    print("static:")
    for x in (al.get("static") or []):
        print("  -", x)
    print("trusted_testers:")
    for x in (al.get("trusted_testers") or []):
        print("  -", x)
    print("-" * 72)


def cmd_allowlist_add(args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    al = cfg.get("allowlist", {}) or {}
    group = args.group

    entry = str(args.entry).strip()
    if not entry:
        print("Invalid entry.")
        return

    lst = al.get(group) or []
    if entry in lst:
        print("Already present:", entry)
        return

    lst.append(entry)
    al[group] = lst
    cfg["allowlist"] = al
    _save_cfg(cfg)
    load_allowlist_networks(force_reload=True)
    print(f"Added to allowlist.{group}:", entry)


def cmd_allowlist_remove(args):
    cfg = _ensure_allowlist_struct(_load_cfg())
    al = cfg.get("allowlist", {}) or {}
    group = args.group

    entry = str(args.entry).strip()
    lst = al.get(group) or []
    if entry not in lst:
        print("Not found:", entry)
        return

    lst.remove(entry)
    al[group] = lst
    cfg["allowlist"] = al
    _save_cfg(cfg)
    load_allowlist_networks(force_reload=True)
    print(f"Removed from allowlist.{group}:", entry)


# -----------------------
# Main
# -----------------------
def build_parser() -> argparse.ArgumentParser:
    epilog = """
Examples:
  python3 cli.py status
  python3 cli.py run
  python3 cli.py top --n 20
  python3 cli.py show 203.0.113.10
  python3 cli.py ban 203.0.113.10 --seconds 3600 --reason "manual"
  python3 cli.py unban 203.0.113.10
  python3 cli.py tail events --lines 50
  python3 cli.py test --ip 1.2.3.4 --uri "/?q=<script>alert(1)</script>"
"""
    p = argparse.ArgumentParser(
        description="TrafficSentinel CLI (log ingestion + auto-ban)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog.strip(),
    )
    sub = p.add_subparsers(dest="cmd")

    # status
    sp = sub.add_parser("status", help="Show config paths, log paths, allowlist, firewall status")
    sp.set_defaults(func=cmd_status)

    # run
    sp = sub.add_parser("run", help="Start the live log monitor (same as running main.py)")
    sp.set_defaults(func=cmd_run)

    # top
    sp = sub.add_parser("top", help="Show top IPs by severity (penalty/ban_count)")
    sp.add_argument("--n", type=int, default=15, help="How many IPs to show (default: 15)")
    sp.set_defaults(func=cmd_top)

    # show
    sp = sub.add_parser("show", help="Show details for a single IP from state + firewall")
    sp.add_argument("ip", help="IP to inspect")
    sp.set_defaults(func=cmd_show)

    # clear
    sp = sub.add_parser("clear", help="Clear reputation state (does not remove firewall bans)")
    sp.add_argument("--yes", action="store_true", help="Confirm you really want to clear state")
    sp.set_defaults(func=cmd_clear)

    # ban
    sp = sub.add_parser("ban", help="Manually ban an IP (immediate firewall ban + state record)")
    sp.add_argument("ip", help="IP to ban")
    sp.add_argument("--seconds", type=int, default=None, help="Ban duration in seconds (default 3600)")
    sp.add_argument("--permanent", action="store_true", help="Permanent ban (no expiry)")
    sp.add_argument("--reason", default="manual", help="Reason string for your own notes")
    sp.set_defaults(func=cmd_ban)

    # unban
    sp = sub.add_parser("unban", help="Manually unban an IP (firewall + state)")
    sp.add_argument("ip", help="IP to unban")
    sp.set_defaults(func=cmd_unban)

    # tail
    sp = sub.add_parser("tail", help="Tail a TrafficSentinel log file")
    sp.add_argument("which", choices=["events", "actions", "error"], help="Which log to view")
    sp.add_argument("--lines", type=int, default=50, help="How many lines to show (default: 50)")
    sp.set_defaults(func=cmd_tail)

    # test
    sp = sub.add_parser("test", help="Test detector on a simulated request (no bans)")
    sp.add_argument("--ip", default="1.2.3.4", help="Source IP (default: 1.2.3.4)")
    sp.add_argument("--uri", default="/", help="Request URI (default: /)")
    sp.add_argument("--body", default="", help="Request body text (default: empty)")
    sp.add_argument(
        "--header",
        action="append",
        help='Header line like "User-Agent: curl/8.0" (can repeat)',
    )
    sp.set_defaults(func=cmd_test)

    # allowlist
    al = sub.add_parser("allowlist", help="Manage allowlist entries in config/config.yml")
    al_sub = al.add_subparsers(dest="allow_cmd")

    p_list = al_sub.add_parser("list", help="Show allowlist entries")
    p_list.set_defaults(func=cmd_allowlist_list)

    p_add = al_sub.add_parser("add", help="Add an allowlist entry")
    p_add.add_argument("entry", help="IP or CIDR, e.g. 203.0.113.10 or 203.0.113.0/24")
    p_add.add_argument("--group", choices=["static", "trusted_testers"], default="trusted_testers")
    p_add.set_defaults(func=cmd_allowlist_add)

    p_rm = al_sub.add_parser("remove", help="Remove an allowlist entry")
    p_rm.add_argument("entry", help="IP or CIDR")
    p_rm.add_argument("--group", choices=["static", "trusted_testers"], default="trusted_testers")
    p_rm.set_defaults(func=cmd_allowlist_remove)

    return p


def main():
    p = build_parser()
    args = p.parse_args()

    # No command provided
    if not getattr(args, "cmd", None):
        p.print_help()
        print("\nTip: start with `python3 cli.py status` then `python3 cli.py run`.")
        sys.exit(2)

    # allowlist subcommand missing
    if args.cmd == "allowlist" and not getattr(args, "allow_cmd", None):
        # print allowlist help
        for a in p._subparsers._actions:
            if isinstance(a, argparse._SubParsersAction):
                allow_parser = a.choices.get("allowlist")
                if allow_parser:
                    allow_parser.print_help()
        sys.exit(2)

    args.func(args)


if __name__ == "__main__":
    main()
