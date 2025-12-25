import os
import time
import signal
import yaml
from typing import Dict, Any

from analyzer.detector import scan_request, get_rules_once
from enforcer.firewall import ban_ip, unban_ip, is_banned as fw_is_banned, ensure_chain
from core.state import load_state, save_state, update_ip_state, is_banned as state_is_banned, is_flagged
from core.telegram_alert import send_telegram_message

from ingestor.log_reader import tail_lines
from ingestor.parsers import parse_lines
from ingestor.bruteforce import detect_bruteforce


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
    """'ban' (default/legacy), 'mark' (review-only), or 'off' (logging only)."""
    enf = cfg.get("enforcement", {}) or {}
    action = str(enf.get("action", "ban")).strip().lower()
    if action not in ("ban", "mark", "off"):
        return "ban"
    return action


def enforce_state(state: dict, now: int, action: str):
    """Make firewall match the current state file (only in action='ban')."""
    if action != "ban":
        return

    for ip, entry in state.items():
        banned_by_state = state_is_banned(entry, now=now)
        if banned_by_state:
            if not fw_is_banned(ip):
                ban_ip(ip)
        else:
            if fw_is_banned(ip):
                unban_ip(ip)


def _format_telegram_flag_message(ip: str, result: dict, now: int) -> str:
    # Keep it short and readable on mobile
    method = (result.get("method") or "").strip()
    uri = (result.get("uri") or "").strip()
    cats = evidence_categories(result) or "unknown"
    score = int(result.get("score_total", 0))

    hits = result.get("hits") or []
    # Show up to 2 evidence lines (avoid spam)
    evidence_lines = []
    for h in hits[:2]:
        cat = h.get("category", "")
        target = h.get("target", "")
        matched = str(h.get("matched", ""))[:80]
        evidence_lines.append(f"- {cat} on {target}: {matched}")

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


def process_results(results, state, logs, now: int, action: str, cfg: Dict[str, Any], alert_cache: Dict[str, int]):
    """
    ✅ events.log: only suspicious (score > 0)
    ✅ all_requests_log (optional): logs everything (score can be 0)

    ✅ actions.log:
      - action='ban'  -> logs ban/unban transitions
      - action='mark' -> logs flag/unflag transitions (review-only; no firewall bans)
      - action='off'  -> no actions are written (events still logged)

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
        ip = result.get("ip", "")
        score = int(result.get("score_total", 0))
        cats = evidence_categories(result)

        ua_only = bool(result.get("ua_only_suppressed", False))

        if not ip:
            continue

        entry_before = state.get(ip, {}).copy()
        entry_after = update_ip_state(state, ip, score, now=now)

        # Optional full telemetry log (includes score=0)
        if all_log:
            append_log(
                all_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(result.get('hits', []))} ua_only={int(ua_only)}",
            )

        # Only log suspicious/malicious events
        if score > 0:
            append_log(
                events_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(result.get('hits', []))} ua_only={int(ua_only)}",
            )

        # State transitions -> actions.log
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

        elif action == "mark":
            was_flagged = is_flagged(entry_before) if entry_before else False
            is_now_flagged = is_flagged(entry_after)

            if not was_flagged and is_now_flagged:
                append_log(
                    actions_log,
                    f"{now} action=flag ip={ip} flagged_at={entry_after.get('flagged_at', 0)} reason=cats:{cats}",
                )

                # ✅ Telegram alert on new flag (with cooldown per IP)
                if tg_enabled and tg_token and tg_chat_id:
                    last = int(alert_cache.get(ip, 0))
                    if now - last >= tg_cooldown:
                        alert_cache[ip] = now
                        if tg_include_evidence:
                            text = _format_telegram_flag_message(ip, result, now)
                        else:
                            text = f"🚩 TrafficSentinel FLAG\nIP: {ip}\nCategories: {cats}\nScore: {score}\nTime: {now}"
                        send_telegram_message(tg_token, tg_chat_id, text)

            elif was_flagged and not is_now_flagged:
                append_log(actions_log, f"{now} action=unflag ip={ip} reason=cleared")

        # action == "off": do nothing in actions.log


def main_loop():
    cfg = load_config()
    logs = cfg.get("logging", {}) or {}
    error_log = logs.get("error_log", "./state/error.log")

    action = enforcement_action(cfg)

    # Only create firewall chain when we actually enforce bans
    if action == "ban":
        ensure_chain()

    # Load detection rules once
    rules = get_rules_once()

    # Load reputation state
    state = load_state()

    ingestion = cfg.get("ingestion", {}) or {}
    mode = str(ingestion.get("mode", "log")).strip().lower()

    # This build runs LOG INGESTION ONLY. If config asks for pcap, we override safely.
    if mode != "log":
        append_log(error_log, f"{int(time.time())} config_forced mode_was={mode} mode_now=log reason=pcap_disabled")
        mode = "log"

    running = True

    def sigint_handler(sig, frame):
        nonlocal running
        print("Exiting gracefully...")
        running = False

    signal.signal(signal.SIGINT, sigint_handler)

    # Telegram cooldown cache (in-memory)
    alert_cache: Dict[str, int] = {}

    while running:
        now = int(time.time())

        try:
            log_path = ingestion.get("log_path", "/var/log/nginx/access.log")
            offset_file = ingestion.get("offset_file", "./state/log_offset.json")
            batch_lines = int(ingestion.get("batch_lines", 2000))

            raw_lines = tail_lines(log_path, offset_file, max_lines=batch_lines)
            reqs = parse_lines(raw_lines, source=str(ingestion.get("log_source", "jsonl")).strip().lower())

            # Detect brute-force based on auth endpoints/statuses
            bf_cfg = (ingestion.get("bruteforce", {}) or {})
            bf_hits = detect_bruteforce(reqs, bf_cfg, now=now)

            results = []
            for req in reqs:
                ip = req.get("ip", "")
                uri = req.get("uri", "")
                headers = req.get("headers", {}) or {}
                body = req.get("body", "") or ""
                result = scan_request(ip=ip, uri=uri, headers=headers, body=body, rules=rules)
                if result:
                    # enrich for logging/telegram
                    result["uri"] = uri
                    result["method"] = req.get("method", "")
                    result["ts"] = req.get("ts", "")
                    results.append(result)

            # Add bruteforce results as score-bearing events
            for ip, bf_score in bf_hits.items():
                results.append(
                    {
                        "ip": ip,
                        "score_total": int(bf_score),
                        "categories": ["bruteforce"],
                        "hits": ["bruteforce"],
                        "ua_only_suppressed": False,
                        "uri": "",
                        "method": "",
                        "ts": "",
                    }
                )

            process_results(results, state, logs, now, action, cfg, alert_cache)
            save_state(state)
            enforce_state(state, now, action)

        except Exception as e:
            append_log(error_log, f"{int(time.time())} loop_failed mode={mode} err={repr(e)}")

        time.sleep(1)


if __name__ == "__main__":
    main_loop()
