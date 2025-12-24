import argparse
import os
import time
import signal
import yaml

from agent.capture import capture_traffic
from analyzer.analyze import analyze_pcap
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


def capture_only():
    pcap_file = capture_traffic()
    print(f"Captured: {pcap_file}")


def analyze_only(pcap_file: str):
    results = analyze_pcap(pcap_file)
    for result in results:
        print(result)


def evidence_categories(result: dict) -> str:
    cats = result.get("categories") or []
    return ",".join(cats)


def enforce_state(state: dict, now: int):
    for ip, entry in state.items():
        banned_by_state = state_is_banned(entry, now=now)
        if banned_by_state:
            if not fw_is_banned(ip):
                ban_ip(ip)
        else:
            if fw_is_banned(ip):
                unban_ip(ip)


def process_results(results, state, logs, now):
    events_log = logs.get("events_log", "./state/events.log")
    actions_log = logs.get("actions_log", "./state/actions.log")

    for result in results:
        ip = result.get("ip", "")
        score = int(result.get("score_total", 0))
        hits = result.get("hits", [])
        cats = evidence_categories(result)

        if not ip:
            continue

        entry_before = state.get(ip, {}).copy()
        entry_after = update_ip_state(state, ip, score, now=now)

        append_log(events_log, f"{now} ip={ip} score={score} cats={cats} hits={len(hits)}")

        was_banned = state_is_banned(entry_before, now=now) if entry_before else False
        is_now_banned = state_is_banned(entry_after, now=now)

        if not was_banned and is_now_banned:
            append_log(actions_log, f"{now} action=ban ip={ip} permanent={entry_after.get('permanent', False)} reason=cats:{cats}")
        elif was_banned and not is_now_banned:
            append_log(actions_log, f"{now} action=unban ip={ip} reason=expired")


def main_loop():
    cfg = load_config()
    logs = cfg.get("logging", {}) or {}
    error_log = logs.get("error_log", "./state/error.log")

    ensure_chain()
    rules = get_rules_once()  # ✅ loaded once for both modes
    state = load_state()

    ingestion = cfg.get("ingestion", {}) or {}
    mode = str(ingestion.get("mode", "pcap")).strip().lower()

    running = True

    def sigint_handler(sig, frame):
        nonlocal running
        print("Exiting gracefully...")
        running = False

    signal.signal(signal.SIGINT, sigint_handler)

    while running:
        now = int(time.time())

        try:
            if mode == "log":
                log_path = ingestion.get("log_path", "./logs/access.log")
                offset_file = ingestion.get("offset_file", "./state/log_offset.json")
                batch_lines = int(ingestion.get("batch_lines", 2000))
                log_source = str(ingestion.get("log_source", "access")).strip().lower()

                lines = tail_lines(log_path, offset_file, max_lines=batch_lines)
                if not lines:
                    time.sleep(1)
                    continue

                events = parse_lines(lines, source=log_source)

                # Scan each log event using the same detector => works for HTTPS
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

                # Bruteforce from logs (more accurate)
                bf_cfg = (ingestion.get("bruteforce") or {})
                if bf_cfg.get("enabled", True):
                    endpoints = tuple(bf_cfg.get("endpoints") or [])
                    threshold = int(bf_cfg.get("threshold_per_minute", 10))
                    fail_statuses = tuple(int(x) for x in (bf_cfg.get("fail_statuses") or [401, 403]))

                    bf = detect_bruteforce(events, endpoints=endpoints, threshold_per_minute=threshold, fail_statuses=fail_statuses)
                    for ip, score in bf.items():
                        results.append({
                            "ip": ip,
                            "score_total": score,
                            "categories": ["bruteforce"],
                            "hits": [{
                                "category": "bruteforce",
                                "id": "bf-log-heuristic",
                                "target": "uri",
                                "matched": "endpoint+failrate",
                                "snippet": f">={threshold}/min auth failures",
                            }],
                            "scoring_mode": "heuristic",
                        })

                process_results(results, state, logs, now)
                save_state(state)
                enforce_state(state, now)

            else:
                # PCAP mode (plaintext HTTP only)
                pcap_file = capture_traffic()
                if not pcap_file:
                    append_log(error_log, f"{now} capture_failed")
                    time.sleep(1)
                    continue

                analyzed_ok = False
                try:
                    results = analyze_pcap(pcap_file)
                    analyzed_ok = True

                    process_results(results, state, logs, now)
                    save_state(state)
                    enforce_state(state, now)

                finally:
                    if analyzed_ok:
                        try:
                            if os.path.exists(pcap_file):
                                os.remove(pcap_file)
                        except Exception as e:
                            append_log(error_log, f"{int(time.time())} pcap_delete_failed file={pcap_file} err={repr(e)}")

        except Exception as e:
            append_log(error_log, f"{int(time.time())} loop_failed mode={mode} err={repr(e)}")

        time.sleep(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrafficSentinel orchestrator")
    parser.add_argument("--capture-only", action="store_true", help="Only capture one PCAP slice")
    parser.add_argument("--analyze-only", type=str, help="Analyze a given PCAP file")
    args = parser.parse_args()

    if args.capture_only:
        capture_only()
    elif args.analyze_only:
        analyze_only(args.analyze_only)
    else:
        main_loop()
