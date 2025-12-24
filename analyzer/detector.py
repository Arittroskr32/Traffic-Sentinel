import os
import re
import yaml
from typing import Any, Dict, List, Optional, Set

from analyzer.normalizer import build_target_map
from analyzer.rules_loader import load_all_rules, Rule

MAX_HITS_PER_REQUEST = 50

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_COMPILED = os.path.join(BASE_DIR, "config", "rules_compiled.yml")
DEFAULT_CUSTOM = os.path.join(BASE_DIR, "config", "rules_custom.yml")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")

VENDOR_RULES_DIR = os.path.join(BASE_DIR, "vendor", "crs", "rules")
UNIX_DATA = os.path.join(VENDOR_RULES_DIR, "unix-shell.data")
WIN_DATA = os.path.join(VENDOR_RULES_DIR, "windows-powershell-commands.data")

_UNIX_CMDS: Optional[set] = None
_WIN_CMDS: Optional[set] = None

_RULES_CACHE: Optional[List[Rule]] = None


def _load_config() -> Dict[str, Any]:
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _scoring_mode() -> str:
    cfg = _load_config()
    scoring = cfg.get("scoring", {}) or {}
    mode = str(scoring.get("mode", "per_category")).strip().lower()
    if mode not in ("per_category", "per_request"):
        mode = "per_category"
    return mode


def get_rules_once() -> List[Rule]:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = load_all_rules(DEFAULT_COMPILED, DEFAULT_CUSTOM)
    return _RULES_CACHE


def _load_command_words_once() -> None:
    global _UNIX_CMDS, _WIN_CMDS
    if _UNIX_CMDS is not None and _WIN_CMDS is not None:
        return

    def load_data(path: str) -> set:
        out = set()
        if not os.path.exists(path):
            return out
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.add(s.lower())
        return out

    _UNIX_CMDS = load_data(UNIX_DATA)
    _WIN_CMDS = load_data(WIN_DATA)


def _expand_targets(rule_targets: List[str]) -> List[str]:
    """
    Expand rule targets automatically so you don't need to edit rule YAML.

    - If rule targets 'headers', also scan headers_kv + user_agent + cookies + cookies_params
    - If rule targets 'uri', also scan path + query + query_params
    - Always include 'combined' as a catch-all
    """
    if not rule_targets:
        rule_targets = ["uri", "headers", "body"]

    out = list(rule_targets)

    if "headers" in out:
        if "headers_kv" not in out:
            out.append("headers_kv")
        # Always scan User-Agent separately so it can be down-weighted / ignored
        # for bans when it's the only evidence.
        if "user_agent" not in out:
            out.append("user_agent")
        if "cookies" not in out:
            out.append("cookies")
        if "cookies_params" not in out:
            out.append("cookies_params")

    if "uri" in out:
        if "path" not in out:
            out.append("path")
        if "query" not in out:
            out.append("query")
        if "query_params" not in out:
            out.append("query_params")

    if "combined" not in out:
        out.append("combined")

    return out


def scan_request(
    ip: str,
    uri: str,
    headers: Any,
    body: str,
    rules: Optional[List[Rule]] = None
) -> Dict[str, Any]:
    if rules is None:
        rules = get_rules_once()

    mode = _scoring_mode()
    target_map = build_target_map(uri=uri, headers=headers, body=body)

    hits: List[Dict[str, Any]] = []
    # Track evidence separately so User-Agent-only matches don't ban real users.
    seen_categories_non_ua: Set[str] = set()
    seen_categories_ua: Set[str] = set()

    hit_count = 0
    for rule in rules:
        targets = _expand_targets(rule.targets)

        for target in targets:
            text = target_map.get(target, "")
            if not text:
                continue

            for pat in rule.patterns:
                if pat.search(text):
                    hits.append({
                        "category": rule.category,
                        "id": rule.id,
                        "target": target,
                        "matched": getattr(pat, "pattern", str(pat)),
                        "snippet": text[:160],
                    })
                    if target == "user_agent":
                        seen_categories_ua.add(rule.category)
                    else:
                        seen_categories_non_ua.add(rule.category)
                    hit_count += 1
                    if hit_count >= MAX_HITS_PER_REQUEST:
                        break
            if hit_count >= MAX_HITS_PER_REQUEST:
                break
        if hit_count >= MAX_HITS_PER_REQUEST:
            break

    # CMDi heuristic (uses combined, which excludes UA now)
    _load_command_words_once()
    unix_cmds = _UNIX_CMDS or set()
    win_cmds = _WIN_CMDS or set()

    combined = target_map.get("combined", "")
    separators = ["&&", "||", ";", "|", "$(", "`", "\n", "\r"]
    sep_found = any(sep in combined for sep in separators)

    tokens = set(re.findall(r"[a-z0-9_\-\.]{2,}", combined))
    cmd_hit = None

    for cmd in unix_cmds:
        if cmd in tokens:
            cmd_hit = cmd
            break
    if cmd_hit is None:
        for cmd in win_cmds:
            if cmd in tokens:
                cmd_hit = cmd
                break

    if sep_found and cmd_hit:
        hits.append({
            "category": "cmdi",
            "id": "cmdi-heuristic",
            "target": "combined",
            "matched": "separator+cmdword",
            "snippet": cmd_hit,
        })
        seen_categories_non_ua.add("cmdi")

    # --- False-positive guard: UA-only evidence should NOT penalize/ban ---
    # If *all* matches came from the User-Agent bucket, we keep the hits for
    # visibility but return score_total=0 and categories=[].
    ua_only_suppressed = bool(seen_categories_ua) and not bool(seen_categories_non_ua)

    effective_categories = set() if ua_only_suppressed else set(seen_categories_non_ua)

    if mode == "per_request":
        score_total = 1 if effective_categories else 0
    else:
        score_total = len(effective_categories)

    return {
        "ip": ip,
        "score_total": score_total,
        "categories": sorted(effective_categories),
        "hits": hits,
        "scoring_mode": mode,
        "ua_only_suppressed": ua_only_suppressed,
        "ua_categories": sorted(seen_categories_ua),
    }
