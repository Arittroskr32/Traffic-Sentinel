#!/usr/bin/env python3
import argparse
import os
import sys
import time
from typing import Any, Dict, List, Tuple

import yaml

from core.state import load_state, save_state, is_banned as state_is_banned
from core.allowlist import load_allowlist_networks, is_allowlisted
from enforcer.firewall import ensure_chain, ban_ip, unban_ip, is_banned as fw_is_banned
from analyzer.detector import get_rules_once, scan_request


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


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
    al = cfg.get("allowlist")
    if al is None:
        cfg["allowlist"] = {"enabled": True, "static": ["127.0.0.1", "::1"], "trusted_testers": []}
        return cfg

    if isinstance(al, list):
        cfg["allowlist"] = {"enabled": True, "static": [str(x) for x in al], "trusted_testers": []}
        return cfg

    if not isinstance(al, dict):
        cfg["allowlist"] = {"enabled": True, "static": ["127.0.0.1", "::1"], "trusted_testers": []}
        return cfg

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
    return (int(e.get("permanent", False)), int(e.get("ban_count", 0)), int(e.get("penalty", 0)))


def _read_tail(path: str, lines: int = 50) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "rb") as f:
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


def cmd_show(args):
    state = load_state()
    ip = args.ip
    e = state.get(ip)
    if not e:
        print("No record for IP in state.")
        return

    now = int(time.time())
    print(f"IP: {ip}")
    for k in ["penalty", "last_seen", "ban_until", "ban_count", "permanent", "flagged", "flagged_at", "flag_count", "max_penalty"]:
        if k in e:
            print(f"  {k}: {e.get(k)}")

    # ✅ New preferred clean output
    events = e.get("recent_events") or []
    if isinstance(events, list) and events:
        print("  recent_events (latest first):")
        for ev in reversed(events[-10:]):
            if not isinstance(ev, dict):
                continue
            ts = int(ev.get("ts", 0) or 0)
            delta = int(ev.get("delta_score", 0) or 0)
            p_after = int(ev.get("penalty_after", 0) or 0)
            method = str(ev.get("method", "") or "")
            uri = str(ev.get("uri", "") or "")
            req = (f"{method} {uri}").strip()
            print(f"    - +{delta} => penalty={p_after}  ts={ts}  request: {req}")

            rule = ev.get("rule") or {}
            if isinstance(rule, dict) and rule:
                cat = str(rule.get("category", "") or "")
                target = str(rule.get("target", "") or "")
                pat = str(rule.get("pattern", "") or "")[:200]
                print(f"      rule: {cat} on {target}: {pat}")

    # ✅ Legacy compatibility (so you can still see something if old state exists)
    legacy = e.get("recent_reasons") or []
    if (not events) and isinstance(legacy, list) and legacy:
        print("  recent_reasons (legacy; upgrade state.py to migrate):")
        for rr in reversed(legacy[-10:]):
            if not isinstance(rr, dict):
                continue
            ts = int(rr.get("ts", 0) or 0)
            cat = str(rr.get("category", "") or "")
            target = str(rr.get("target", "") or "")
            pat = str(rr.get("pattern", "") or "")[:200]
            method = str(rr.get("method", "") or "")
            uri = str(rr.get("uri", "") or "")
            print(f"    - ts={ts}  request: {method} {uri}".strip())
            print(f"      rule: {cat} on {target}: {pat}")

    print(f"State banned:     {state_is_banned(e, now=now)}")
    try:
        ensure_chain()
        print(f"Firewall blocked: {fw_is_banned(ip)}")
    except Exception as ex:
        print(f"Firewall blocked: (could not check) {repr(ex)}")

    print(f"Allowlisted:      {is_allowlisted(ip)}")


# (All other commands unchanged from your current cli.py)
# ---- Keep the rest as-is ----

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
    print(f"Ingestion:     mode={mode}")
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

    cfg = _ensure_allowlist_struct(cfg)
    al = cfg.get("allowlist") or {}
    print("Allowlist")
    print(f"  enabled: {bool(al.get('enabled', True))}")
    print(f"  static: {len(al.get('static') or [])} entries")
    print(f"  trusted_testers: {len(al.get('trusted_testers') or [])} entries")

    try:
        ensure_chain()
        print("\nFirewall:      chain OK (iptables)")
    except Exception as e:
        print("\nFirewall:      ERROR creating/checking chain:", repr(e))
    print("-" * 72)


def cmd_run(_args):
    from main import main_loop
    print("Starting TrafficSentinel monitor (log ingestion)...")
    try:
        main_loop()
    except KeyboardInterrupt:
        print("Stopped.")


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


def cmd_clear(args):
    if not args.yes:
        print("Refusing to clear state without --yes.")
        return
    save_state({})
    print("Cleared reputation state.")


def cmd_ban(args):
    ip = args.ip.strip()
    seconds = int(args.seconds) if args.seconds is not None else None
    permanent = bool(args.permanent)

    if is_allowlisted(ip):
        print("Refusing to ban: IP is allowlisted:", ip)
        return

    ensure_chain()
    ban_ip(ip)

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

    state = load_state()
    if ip in state:
        state[ip]["ban_until"] = 0
        state[ip]["permanent"] = False
        save_state(state)
        print("Updated state: ban cleared for", ip)


def cmd_penalty_clear(args):
    ip = args.ip.strip()
    state = load_state()
    if ip not in state:
        print("No record for IP in state:", ip)
        return
    before = int(state.get(ip, {}).get("penalty", 0) or 0)
    state[ip]["penalty"] = 0
    save_state(state)
    print(f"Penalty cleared for {ip}: {before} -> 0")


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
    ip = args.ip
    uri = args.uri or "/"
    body = args.body or ""
    headers: Dict[str, str] = {}

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

    hits = result.get("hits") or []
    for h in hits[:1]:
        print(f"- [{h.get('category')}] id={h.get('id')} target={h.get('target')} matched={h.get('matched')}")
    print("-" * 72)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="TrafficSentinel CLI")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("status"); sp.set_defaults(func=cmd_status)
    sp = sub.add_parser("run"); sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("top"); sp.add_argument("--n", type=int, default=15); sp.set_defaults(func=cmd_top)
    sp = sub.add_parser("show"); sp.add_argument("ip"); sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("clear"); sp.add_argument("--yes", action="store_true"); sp.set_defaults(func=cmd_clear)

    sp = sub.add_parser("ban")
    sp.add_argument("ip"); sp.add_argument("--seconds", type=int, default=None)
    sp.add_argument("--permanent", action="store_true"); sp.add_argument("--reason", default="manual")
    sp.set_defaults(func=cmd_ban)

    sp = sub.add_parser("unban"); sp.add_argument("ip"); sp.set_defaults(func=cmd_unban)

    sp = sub.add_parser("penalty-clear"); sp.add_argument("ip"); sp.set_defaults(func=cmd_penalty_clear)

    sp = sub.add_parser("tail")
    sp.add_argument("which", choices=["events", "actions", "error"])
    sp.add_argument("--lines", type=int, default=50)
    sp.set_defaults(func=cmd_tail)

    sp = sub.add_parser("test")
    sp.add_argument("--ip", default="1.2.3.4"); sp.add_argument("--uri", default="/")
    sp.add_argument("--body", default=""); sp.add_argument("--header", action="append")
    sp.set_defaults(func=cmd_test)

    return p


def main():
    p = build_parser()
    args = p.parse_args()
    if not getattr(args, "cmd", None):
        p.print_help()
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
