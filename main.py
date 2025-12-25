import os
import time
import signal
import yaml
from typing import Dict, Any, List

from analyzer.detector import scan_request, get_rules_once

# Firewall (used only when action='ban')
from enforcer.firewall import ban_ip, unban_ip, is_banned as fw_is_banned, ensure_chain

# State
from core.state import load_state, save_state, update_ip_state, is_banned as state_is_banned

try:
    from core.state import is_flagged  # type: ignore
except Exception:
    def is_flagged(entry: Dict[str, Any]) -> bool:
        return bool(entry.get("flagged", False))

from ingestor.log_reader import tail_lines
from ingestor.parsers import parse_lines
from ingestor.bruteforce import detect_bruteforce

from core.telegram_alert import send_telegram_message


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
    enf = cfg.get("enforcement", {}) or {}
    action = str(enf.get("action", "ban")).strip().lower()
    if action not in ("ban", "mark", "off"):
        return "ban"
    return action


def ban_threshold(cfg: Dict[str, Any]) -> int:
    rep = cfg.get("reputation", {}) or {}
    return int(rep.get("ban_threshold", 7) or 7)


def enforce_state_firewall(state: dict, now: int):
    for ip, entry in state.items():
        banned_by_state = state_is_banned(entry, now=now)
        if banned_by_state:
            if not fw_is_banned(ip):
                ban_ip(ip)
        else:
            if fw_is_banned(ip):
                unban_ip(ip)


# -------------------------
# Telegram helpers
# -------------------------
def _tg_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    tg = cfg.get("telegram", {}) or {}
    return {
        "enabled": bool(tg.get("enabled", False)),
        "token": str(tg.get("bot_token", "") or "").strip(),
        "chat_id": str(tg.get("chat_id", "") or "").strip(),
        "cooldown": int(tg.get("cooldown_seconds", 60) or 60),
        "include_evidence": bool(tg.get("include_evidence", True)),
        "penalty_threshold": int(tg.get("penalty_alert_threshold", 10) or 10),
    }


def _tg_ready(tgconf: Dict[str, Any]) -> bool:
    return bool(tgconf["enabled"] and tgconf["token"] and tgconf["chat_id"])


def _hit_line(h: Dict[str, Any]) -> str:
    cat = str(h.get("category", ""))
    target = str(h.get("target", ""))
    pat = str(h.get("pattern", ""))[:180]
    if not pat:
        pat = "<no pattern>"
    return f"- {cat} on {target}: {pat}"


def _format_msg(title: str, ip: str, result: Dict[str, Any], now: int, extra: List[str] = None) -> str:
    method = (result.get("method") or "").strip()
    uri = (result.get("uri") or "").strip()
    cats = evidence_categories(result) or "unknown"
    score = int(result.get("score_total", 0))

    msg = [title, f"IP: {ip}", f"Score: {score}", f"Categories: {cats}"]
    if method or uri:
        msg.append(f"Request: {method} {uri}".strip())
    if extra:
        msg.extend(extra)

    hits = result.get("hits") or []
    if hits:
        msg.append("Evidence:")
        for h in hits[:2]:
            if isinstance(h, dict):
                msg.append(_hit_line(h))
            else:
                msg.append(f"- {str(h)[:180]}")

    msg.append(f"Time: {now}")
    return "\n".join(msg)


def _send_tg(tgconf: Dict[str, Any], text: str):
    if not _tg_ready(tgconf):
        return
    send_telegram_message(tgconf["token"], tgconf["chat_id"], text)


def _reasons_from_result(result: Dict[str, Any], now: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    method = str(result.get("method", "") or "")
    uri = str(result.get("uri", "") or "")

    for h in (result.get("hits") or [])[:10]:
        if not isinstance(h, dict):
            continue
        out.append(
            {
                "ts": now,
                "category": str(h.get("category", "")),
                "target": str(h.get("target", "")),
                "pattern": str(h.get("pattern", "")),
                "method": method,
                "uri": uri,
            }
        )
    return out


def _cooldown_ok(alert_cache: Dict[str, int], key: str, now: int, cooldown: int) -> bool:
    last = int(alert_cache.get(key, 0) or 0)
    return (now - last) >= cooldown


# -------------------------
# Core processing
# -------------------------
def process_results(
    results,
    state,
    logs,
    now: int,
    action: str,
    cfg: Dict[str, Any],
    alert_cache: Dict[str, int],
):
    events_log = logs.get("events_log", "./state/events.log")
    actions_log = logs.get("actions_log", "./state/actions.log")
    all_log = logs.get("all_requests_log")  # optional

    tgconf = _tg_cfg(cfg)
    penalty_threshold = int(tgconf["penalty_threshold"])
    mark_threshold = ban_threshold(cfg)

    for result in results:
        if not result:
            continue

        ip = str(result.get("ip", "") or "")
        if not ip:
            continue

        score = int(result.get("score_total", 0))
        cats = evidence_categories(result)
        hits = result.get("hits", []) or []
        ua_only = bool(result.get("ua_only_suppressed", False))

        entry_before = state.get(ip, {}).copy()
        penalty_before = int(entry_before.get("penalty", 0) or 0)

        # -------------------------------------------------------------------
        # ✅ NEW: MARK-THRESHOLD alert (send BEFORE penalty resets to 0)
        # -------------------------------------------------------------------
        if action == "mark" and score > 0 and _tg_ready(tgconf):
            projected = penalty_before + score
            if penalty_before < mark_threshold and projected >= mark_threshold:
                # Send once per cooldown
                if _cooldown_ok(alert_cache, f"markreset:{ip}", now, tgconf["cooldown"]):
                    alert_cache[f"markreset:{ip}"] = now
                    extra = [f"Penalty about to reset: {projected} (mark_threshold: {mark_threshold})"]
                    _send_tg(
                        tgconf,
                        _format_msg("🚩 TrafficSentinel MARK THRESHOLD REACHED", ip, result, now, extra),
                    )

        # Store reasons into state
        reasons = _reasons_from_result(result, now) if score > 0 else None

        # Apply state update (this can reset penalty to 0 in mark mode)
        entry_after = update_ip_state(state, ip, score, now=now, reasons=reasons)

        # Optional telemetry log (includes score=0)
        if all_log:
            append_log(
                all_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        # Only suspicious events
        if score > 0:
            append_log(
                events_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        # -------------------------------------------------------------------
        # Telegram case #2: penalty threshold crossing (normal penalty alert)
        # NOTE: In mark-mode, penalty might reset to 0 at mark_threshold,
        # so this is mostly useful when penalty_threshold <= mark_threshold
        # or in ban-mode/off-mode.
        # -------------------------------------------------------------------
        if _tg_ready(tgconf) and penalty_threshold > 0:
            penalty_after = int(entry_after.get("penalty", 0) or 0)
            crossed = (penalty_before < penalty_threshold) and (penalty_after >= penalty_threshold)

            if crossed and _cooldown_ok(alert_cache, f"penalty:{ip}", now, tgconf["cooldown"]):
                alert_cache[f"penalty:{ip}"] = now
                extra = [f"Penalty: {penalty_after} (threshold: {penalty_threshold})"]
                _send_tg(tgconf, _format_msg("⚠️ TrafficSentinel PENALTY THRESHOLD", ip, result, now, extra))

        # OFF -> no actions log
        if action == "off":
            continue

        # BAN transitions + Telegram case #1
        if action == "ban":
            was_banned = state_is_banned(entry_before, now=now) if entry_before else False
            is_now_banned = state_is_banned(entry_after, now=now)

            if not was_banned and is_now_banned:
                append_log(
                    actions_log,
                    f"{now} action=ban ip={ip} permanent={entry_after.get('permanent', False)} reason=cats:{cats}",
                )

                if _tg_ready(tgconf) and _cooldown_ok(alert_cache, f"ban:{ip}", now, tgconf["cooldown"]):
                    alert_cache[f"ban:{ip}"] = now
                    extra = []
                    if entry_after.get("permanent", False):
                        extra.append("Ban: PERMANENT")
                    else:
                        extra.append(f"Ban until: {entry_after.get('ban_until', 0)}")
                    _send_tg(tgconf, _format_msg("⛔ TrafficSentinel BANNED", ip, result, now, extra))

            elif was_banned and not is_now_banned:
                append_log(actions_log, f"{now} action=unban ip={ip} reason=expired")

        # MARK transitions (no extra telegram here; mark-reset alert already covered above)
        elif action == "mark":
            was_flagged = is_flagged(entry_before) if entry_before else False
            is_now_flagged = is_flagged(entry_after)

            if (not was_flagged) and is_now_flagged:
                append_log(
                    actions_log,
                    f"{now} action=flag ip={ip} flagged_at={entry_after.get('flagged_at', 0)} reason=cats:{cats}",
                )


def main_loop():
    cfg = load_config()
    logs = cfg.get("logging", {}) or {}
    error_log = logs.get("error_log", "./state/error.log")

    action = enforcement_action(cfg)

    if action == "ban":
        ensure_chain()

    rules = get_rules_once()
    state = load_state()

    ingestion = cfg.get("ingestion", {}) or {}
    mode = str(ingestion.get("mode", "log")).strip().lower()

    if mode != "log":
        append_log(error_log, f"{int(time.time())} config_forced mode_was={mode} mode_now=log reason=pcap_disabled")
        mode = "log"

    running = True

    def _request_stop(_sig=None, _frame=None):
        nonlocal running
        if running:
            print("Exiting gracefully...")
        running = False

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)

    alert_cache: Dict[str, int] = {}

    while running:
        now = int(time.time())

        try:
            log_path = ingestion.get("log_path", "./logs/access.log")
            offset_file = ingestion.get("offset_file", "./state/log_offset.json")
            batch_lines = int(ingestion.get("batch_lines", 300))
            log_source = str(ingestion.get("log_source", "access")).strip().lower()

            lines = tail_lines(log_path, offset_file, max_lines=batch_lines)
            if not lines:
                time.sleep(1)
                continue

            events = parse_lines(lines, source=log_source)

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
                    res["method"] = e.get("method", "")
                    res["uri"] = e.get("uri", "")
                    results.append(res)

            # Bruteforce heuristic
            bf_cfg = (ingestion.get("bruteforce") or {})
            if bool(bf_cfg.get("enabled", True)):
                endpoints = tuple(bf_cfg.get("endpoints") or [])
                threshold = int(bf_cfg.get("threshold_per_minute", 10))
                fail_statuses = tuple(int(x) for x in (bf_cfg.get("fail_statuses") or [401, 403]))

                if endpoints and threshold > 0:
                    bf = detect_bruteforce(
                        events,
                        endpoints=endpoints,
                        threshold_per_minute=threshold,
                        fail_statuses=fail_statuses,
                    )
                    for ip, sc in bf.items():
                        results.append(
                            {
                                "ip": ip,
                                "score_total": int(sc),
                                "categories": ["bruteforce"],
                                "hits": [{"category": "bruteforce", "target": "uri", "pattern": "bf-log-heuristic"}],
                                "scoring_mode": "heuristic",
                                "method": "",
                                "uri": "",
                            }
                        )

            if results and running:
                process_results(results, state, logs, now, action, cfg, alert_cache)
                save_state(state)
            elif running:
                save_state(state)

            if action == "ban" and running:
                enforce_state_firewall(state, now)

        except Exception as e:
            append_log(error_log, f"{int(time.time())} loop_failed mode={mode} err={repr(e)}")

        if not running:
            break
        time.sleep(1)

    print("Stopped.")


if __name__ == "__main__":
    main_loop()
