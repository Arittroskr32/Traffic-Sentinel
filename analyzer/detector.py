import os
import re
import yaml
from typing import Any, Dict, List, Optional, Set

from analyzer.normalizer import normalize
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

# ✅ cache compiled rules so we don't reload every scan
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
    """Load rules one time and reuse."""
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


def scan_request(
    ip: str,
    uri: str,
    headers: Any,
    body: str,
    rules: Optional[List[Rule]] = None
) -> Dict[str, Any]:
    if rules is None:
        rules = get_rules_once()

    mode = _scoring_mode()  # "per_category" or "per_request"

    header_text = ""
    if isinstance(headers, dict):
        header_text = " ".join(str(v) for v in headers.values())
    elif isinstance(headers, str):
        header_text = headers

    norm_uri = normalize(uri)["normalized"]
    norm_body = normalize(body)["normalized"]
    norm_headers = normalize(header_text)["normalized"]

    target_map = {
        "uri": norm_uri,
        "body": norm_body,
        "headers": norm_headers,
    }

    hits: List[Dict[str, Any]] = []
    seen_categories: Set[str] = set()

    hit_count = 0
    for rule in rules:
        for target in rule.targets:
            target_text = target_map.get(target, "")
            if not target_text:
                continue

            for pat in rule.patterns:
                if pat.search(target_text):
                    hits.append({
                        "category": rule.category,
                        "id": rule.id,
                        "target": target,
                        "matched": pat.pattern,
                        "snippet": target_text[:160],
                    })

                    seen_categories.add(rule.category)

                    hit_count += 1
                    if hit_count >= MAX_HITS_PER_REQUEST:
                        break
            if hit_count >= MAX_HITS_PER_REQUEST:
                break
        if hit_count >= MAX_HITS_PER_REQUEST:
            break

    # CMDi heuristic (adds category "cmdi" if triggered)
    _load_command_words_once()
    unix_cmds = _UNIX_CMDS or set()
    win_cmds = _WIN_CMDS or set()

    combined = f"{norm_uri} {norm_headers} {norm_body}"
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
        seen_categories.add("cmdi")

    # ✅ Final score computation (toggle)
    if mode == "per_request":
        score_total = 1 if len(seen_categories) > 0 else 0
    else:
        score_total = len(seen_categories)

    return {
        "ip": ip,
        "score_total": score_total,
        "categories": sorted(seen_categories),
        "hits": hits,
        "scoring_mode": mode,
    }
