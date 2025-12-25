import os
import time
import signal
import yaml
from typing import Dict, Any

from analyzer.detector import scan_request, get_rules_once

# Firewall (used only in action=ban)
from enforcer.firewall import ban_ip, unban_ip, is_banned as fw_is_banned, ensure_chain

# State (mark/ban logic lives here)
from core.state import load_state, save_state, update_ip_state, is_banned as state_is_banned

# Optional: is_flagged() exists in your "mark" patch; keep compatibility if not present
try:
    from core.state import is_flagged  # type: ignore
except Exception:
    def is_flagged(entry: Dict[str, Any]) -> bool:  # fallback
        return bool(entry.get("flagged", False))

from ingestor.log_reader import tail_lines
from ingestor.parsers import parse_lines
from ingestor.bruteforce import detect_bruteforce

# Optional Telegram sender (only if you created core/telegram_alert.py)
try:
    from core.telegram_alert import send_telegram_message  # type: ignore
except Exception:
    send_telegram_message = None  # Telegram disabled if module missing


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def load_config() -> Dict[str, Any]:
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def append_log(path: str, line: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")


def evidence_categories(result: dict) -> str:
    cats = result.get("categories") or []
    return ",".join(cats)


def enforcement_action(cfg: Dict[str, Any]) -> str:
    """
    'ban'  = iptables enforcement (legacy)
    'mark' = review-only flagging (no iptables)
    'off'  = log-only (no ban, no flag; still logs events)
    """
    enf = cfg.get("enforcement", {}) or {}
    action = str(enf.get("action", "ban")).strip().lower()
    if action not in ("ban", "mark", "off"):
        return "ban"
    return action


def enforce_state_firewall(state: dict, now: int):
    """Make firewall match current state file (only used when action='ban')."""
    for ip, entry in state.items():
        banned_by_state = state_is_banned(entry, now=now)
        if banned_by_state:
            if not fw_is_banned(ip):
                ban_ip(ip)
        else:
            if fw_is_banned(ip):
                unban_ip(ip)


def _format_telegram_flag_message(ip: str, result: dict, now: int) -> str:
    method = (result.get("method") or "").strip()
    uri = (result.get("uri") or "").strip()
    cats = evidence_categories(result) or "unknown"
    score = int(result.get("score_total", 0))

    hits = result.get("hits") or []
    evidence_lines = []
    # Show up to 2 evidence lines (avoid spam)
    for h in hits[:2]:
        if isinstance(h, dict):
            cat = str(h.get("category", ""))
            target = str(h.get("target", ""))
            matched = str(h.get("matched", ""))[:90]
            evidence_lines.append(f"- {cat} on {target}: {matched}")
        else:
            evidence_lines.append(f"- {str(h)[:120]}")

    msg = [
        "🚩 TrafficSentinel FLAG",
        f"IP: {ip}",
        f"Score: {score}",
        f"Categories: {cats}",
    ]
    if method or uri:
        msg.append(f"Request: {method} {uri}".strip())
    if evidence_lines:
        msg.append("Evidence:")
        msg.extend(evidence_lines)
    msg.append(f"Time: {now}")
    return "\n".join(msg)


def process_results(
    results,
    state,
    logs,
    now: int,
    action: str,
    cfg: Dict[str, Any],
    alert_cache: Dict[str, int],
):
    """
    ✅ events.log: only suspicious (score > 0)
    ✅ all_requests_log (optional): logs everything (score can be 0)

    ✅ actions.log:
      - action='ban'  -> logs ban/unban transitions
      - action='mark' -> logs flag transitions
      - action='off'  -> no actions are written

    ✅ telegram:
      - action='mark' -> sends message only when IP becomes flagged
    """
    events_log = logs.get("events_log", "./state/events.log")
    actions_log = logs.get("actions_log", "./state/actions.log")
    all_log = logs.get("all_requests_log")  # optional

    tg = cfg.get("telegram", {}) or {}
    tg_enabled = bool(tg.get("enabled", False))
    tg_token = str(tg.get("bot_token", "") or "").strip()
    tg_chat_id = str(tg.get("chat_id", "") or "").strip()
    tg_cooldown = int(tg.get("cooldown_seconds", 60) or 60)
    tg_include_evidence = bool(tg.get("include_evidence", True))

    for result in results:
        if not result:
            continue

        ip = result.get("ip", "")
        score = int(result.get("score_total", 0))
        hits = result.get("hits", [])
        cats = evidence_categories(result)

        ua_only = bool(result.get("ua_only_suppressed", False))

        if not ip:
            continue

        entry_before = state.get(ip, {}).copy()
        entry_after = update_ip_state(state, ip, score, now=now)

        # Optional full telemetry (score may be 0)
        if all_log:
            append_log(
                all_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        # Only log suspicious events
        if score > 0:
            append_log(
                events_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        # OFF: do not record actions
        if action == "off":
            continue

        # BAN: legacy ban/unban transitions
        if action == "ban":
            was_banned = state_is_banned(entry_before, now=now) if entry_before else False
            is_now_banned = state_is_banned(entry_after, now=now)

            if not was_banned and is_now_banned:
                append_log(
                    actions_log,
                    f"{now} action=ban ip={ip} permanent={entry_after.get('permanent', False)} reason=cats:{cats}",
                )
            elif was_banned and not is_now_banned:
                append_log(actions_log, f"{now} action=unban ip={ip} reason=expired")

        # MARK: flag transitions + optional telegram
        elif action == "mark":
            was_flagged = is_flagged(entry_before) if entry_before else False
            is_now_flagged = is_flagged(entry_after)

            if (not was_flagged) and is_now_flagged:
                append_log(
                    actions_log,
                    f"{now} action=flag ip={ip} flagged_at={entry_after.get('flagged_at', 0)} reason=cats:{cats}",
                )

                # Telegram alert only on NEW flag
                if (
                    tg_enabled
                    and send_telegram_message is not None
                    and tg_token
                    and tg_chat_id
                ):
                    last = int(alert_cache.get(ip, 0))
                    if now - last >= tg_cooldown:
                        alert_cache[ip] = now
                        if tg_include_evidence:
                            text = _format_telegram_flag_message(ip, result, now)
                        else:
                            text = f"🚩 TrafficSentinel FLAG\nIP: {ip}\nCategories: {cats}\nScore: {score}\nTime: {now}"
                        send_telegram_message(tg_token, tg_chat_id, text)


def main_loop():
    cfg = load_config()
    logs = cfg.get("logging", {}) or {}
    error_log = logs.get("error_log", "./state/error.log")

    action = enforcement_action(cfg)

    # Only ensure iptables chain when we actually ban
    if action == "ban":
        ensure_chain()

    # Load detection rules once
    rules = get_rules_once()

    # Load reputation state
    state = load_state()

    ingestion = cfg.get("ingestion", {}) or {}
    mode = str(ingestion.get("mode", "log")).strip().lower()

    # This build runs LOG INGESTION ONLY. If config asks for pcap, override safely.
    if mode != "log":
        append_log(error_log, f"{int(time.time())} config_forced mode_was={mode} mode_now=log reason=pcap_disabled")
        mode = "log"

    running = True

    def _request_stop(_sig=None, _frame=None):
        """Request a fast, graceful stop.

        Notes:
        - We keep it "graceful" (state gets saved at end of loop), but we also
          try to stop quickly by checking `running` inside heavy loops.
        - We handle SIGTERM as well so systemd/docker stop works cleanly.
        """
        nonlocal running
        if running:
            print("Exiting gracefully...")
        running = False

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    # Telegram cooldown cache (in-memory)
    alert_cache: Dict[str, int] = {}

    while running:
        now = int(time.time())

        try:
            log_path = ingestion.get("log_path", "./logs/access.log")
            offset_file = ingestion.get("offset_file", "./state/log_offset.json")
            batch_lines = int(ingestion.get("batch_lines", 2000))
            log_source = str(ingestion.get("log_source", "access")).strip().lower()

            lines = tail_lines(log_path, offset_file, max_lines=batch_lines)
            if not lines:
                time.sleep(1)
                continue

            events = parse_lines(lines, source=log_source)

            # Build detector results
            results = []
            for e in events:
                if not running:
                    break
                res = scan_request(
                    ip=e.get("ip", ""),
                    uri=e.get("uri", ""),
                    headers=e.get("headers", {}),
                    body=e.get("body", ""),
                    rules=rules,
                )
                if res:
                    # enrich for telegram
                    res["method"] = e.get("method", "")
                    res["uri"] = e.get("uri", "")
                    results.append(res)

            # Bruteforce heuristic from logs (optional)
            bf_cfg = (ingestion.get("bruteforce") or {})
            bf_enabled = bool(bf_cfg.get("enabled", True))

            if bf_enabled:
                endpoints = tuple(bf_cfg.get("endpoints") or [])
                threshold = int(bf_cfg.get("threshold_per_minute", 10))
                fail_statuses = tuple(int(x) for x in (bf_cfg.get("fail_statuses") or [401, 403]))

                # ✅ FIXED: detect_bruteforce() does NOT accept now=...
                if endpoints and threshold > 0:
                    bf = detect_bruteforce(
                        events,
                        endpoints=endpoints,
                        threshold_per_minute=threshold,
                        fail_statuses=fail_statuses,
                    )
                    for ip, score in bf.items():
                        results.append(
                            {
                                "ip": ip,
                                "score_total": int(score),
                                "categories": ["bruteforce"],
                                "hits": [
                                    {
                                        "category": "bruteforce",
                                        "id": "bf-log-heuristic",
                                        "target": "uri",
                                        "matched": "endpoint+failrate",
                                        "snippet": f">={threshold}/min auth failures",
                                    }
                                ],
                                "scoring_mode": "heuristic",
                                "method": "",
                                "uri": "",
                            }
                        )

            if results and running:
                process_results(results, state, logs, now, action, cfg, alert_cache)
                save_state(state)
            elif running:
                # Still persist last_seen / ban decay timers even if no hits
                save_state(state)

            # Only enforce firewall rules when action='ban'
            if action == "ban" and running:
                enforce_state_firewall(state, now)

        except Exception as e:
            append_log(error_log, f"{int(time.time())} loop_failed mode={mode} err={repr(e)}")

        # If a stop was requested, don't linger in sleep.
        if not running:
            break
        time.sleep(1)

    # Ensure the caller (cli.py) returns to the shell promptly.
    try:
        print("Stopped.")
    except Exception:
        pass

    # Final newline so the shell prompt returns cleanly.
    return


if __name__ == "__main__":
    main_loop()
