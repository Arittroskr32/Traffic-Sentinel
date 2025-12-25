import os
import time
import signal
import yaml

from analyzer.detector import scan_request, get_rules_once
from enforcer.firewall import ban_ip, unban_ip, is_banned as fw_is_banned, ensure_chain
from core.state import load_state, save_state, update_ip_state, is_banned as state_is_banned

from ingestor.log_reader import tail_lines
from ingestor.parsers import parse_lines
from ingestor.bruteforce import detect_bruteforce


BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def append_log(path: str, line: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(line.rstrip() + "\n")


def evidence_categories(result: dict) -> str:
    cats = result.get("categories") or []
    return ",".join(cats)


def enforce_state(state: dict, now: int):
    """Make firewall match the current state file."""
    for ip, entry in state.items():
        banned_by_state = state_is_banned(entry, now=now)
        if banned_by_state:
            if not fw_is_banned(ip):
                ban_ip(ip)
        else:
            if fw_is_banned(ip):
                unban_ip(ip)


def process_results(results, state, logs, now: int):
    """
    ✅ events.log: only suspicious (score > 0)
    ✅ all_requests_log (optional): logs everything (score can be 0)
    ✅ actions.log: ban/unban transitions
    """
    events_log = logs.get("events_log", "./state/events.log")
    actions_log = logs.get("actions_log", "./state/actions.log")
    all_log = logs.get("all_requests_log")  # optional

    for result in results:
        ip = result.get("ip", "")
        score = int(result.get("score_total", 0))
        hits = result.get("hits", [])
        cats = evidence_categories(result)

        # Track UA-only suppression if detector provides it
        ua_only = bool(result.get("ua_only_suppressed", False))

        if not ip:
            continue

        entry_before = state.get(ip, {}).copy()
        entry_after = update_ip_state(state, ip, score, now=now)

        # Optional full telemetry log (includes score=0)
        if all_log:
            append_log(
                all_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        # Only log suspicious/malicious events
        if score > 0:
            append_log(
                events_log,
                f"{now} ip={ip} score={score} cats={cats} hits={len(hits)} ua_only={int(ua_only)}",
            )

        was_banned = state_is_banned(entry_before, now=now) if entry_before else False
        is_now_banned = state_is_banned(entry_after, now=now)

        if not was_banned and is_now_banned:
            append_log(
                actions_log,
                f"{now} action=ban ip={ip} permanent={entry_after.get('permanent', False)} reason=cats:{cats}",
            )
        elif was_banned and not is_now_banned:
            append_log(actions_log, f"{now} action=unban ip={ip} reason=expired")


def main_loop():
    cfg = load_config()
    logs = cfg.get("logging", {}) or {}
    error_log = logs.get("error_log", "./state/error.log")

    # Ensure host firewall chain exists (iptables)
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

            results = []
            for e in events:
                results.append(
                    scan_request(
                        ip=e["ip"],
                        uri=e.get("uri", ""),
                        headers=e.get("headers", {}),
                        body=e.get("body", ""),
                        rules=rules,
                    )
                )

            # Bruteforce heuristic from logs (optional)
            bf_cfg = (ingestion.get("bruteforce") or {})
            if bf_cfg.get("enabled", True):
                endpoints = tuple(bf_cfg.get("endpoints") or [])
                threshold = int(bf_cfg.get("threshold_per_minute", 10))
                fail_statuses = tuple(int(x) for x in (bf_cfg.get("fail_statuses") or [401, 403]))

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
                            "score_total": score,
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
                        }
                    )

            process_results(results, state, logs, now)
            save_state(state)
            enforce_state(state, now)

        except Exception as e:
            append_log(error_log, f"{int(time.time())} loop_failed mode={mode} err={repr(e)}")

        time.sleep(1)


if __name__ == "__main__":
    main_loop()
