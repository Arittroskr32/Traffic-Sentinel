import os
import re
import yaml
from typing import Any, Dict, List, Optional, Set

from analyzer.normalizer import build_target_map
from analyzer.rules_loader import load_all_rules, Rule

MAX_HITS_PER_REQUEST = 50

# Skip scanning for static assets (unless query string or body present).
# This prevents false positives on requests like /static/app.js or /static/background.png.
STATIC_EXT_RE = re.compile(
    r"\.(?:png|jpg|jpeg|gif|webp|svg|ico|css|js|map|woff2?|ttf|eot)$",
    re.IGNORECASE,
)


def _is_static_asset_uri(uri: str) -> bool:
    if not uri:
        return False
    base = uri.split("?", 1)[0]
    return bool(STATIC_EXT_RE.search(base))


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_COMPILED = os.path.join(BASE_DIR, "config", "rules_compiled.yml")
DEFAULT_CUSTOM = os.path.join(BASE_DIR, "config", "rules_custom.yml")
CONFIG_PATH = os.path.join(BASE_DIR, "config", "config.yml")

VENDOR_RULES_DIR = os.path.join(BASE_DIR, "vendor", "crs", "rules")

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
    if mode not in ("per_request", "per_category"):
        mode = "per_category"
    return mode


def _expand_targets(targets: Any) -> List[str]:
    if targets is None:
        return []
    if isinstance(targets, str):
        return [targets]
    if isinstance(targets, list):
        out: List[str] = []
        for t in targets:
            if isinstance(t, str):
                out.append(t)
        return out
    return []


def _compile_patterns(patterns: Any) -> List[re.Pattern]:
    out: List[re.Pattern] = []
    if patterns is None:
        return out
    if isinstance(patterns, str):
        patterns = [patterns]
    if not isinstance(patterns, list):
        return out

    for p in patterns:
        if not isinstance(p, str) or not p.strip():
            continue
        try:
            out.append(re.compile(p))
        except re.error:
            # ignore bad regex instead of crashing
            continue
    return out


def get_rules_once(
    compiled_path: str = DEFAULT_COMPILED,
    custom_path: str = DEFAULT_CUSTOM
) -> List[Rule]:
    global _RULES_CACHE
    if _RULES_CACHE is not None:
        return _RULES_CACHE

    rules = load_all_rules(compiled_path=compiled_path, custom_path=custom_path)

    # Defensive: ensure patterns are compiled
    for r in rules:
        if getattr(r, "patterns", None) is None:
            r.patterns = _compile_patterns(getattr(r, "pattern", None))
        # Ensure targets present
        if getattr(r, "targets", None) is None:
            r.targets = []

    _RULES_CACHE = rules
    return rules


# -------- CMDi heuristic keyword lists (optional) --------
_UNIX_CMDS: Optional[Set[str]] = None
_WIN_CMDS: Optional[Set[str]] = None


def _load_wordlist(path: str) -> Set[str]:
    out: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                out.add(s.lower())
    except Exception:
        pass
    return out


def _load_command_words_once() -> None:
    global _UNIX_CMDS, _WIN_CMDS
    if _UNIX_CMDS is not None and _WIN_CMDS is not None:
        return

    unix_path = os.path.join(VENDOR_RULES_DIR, "unix-shell.data")
    win_path = os.path.join(VENDOR_RULES_DIR, "windows-powershell-commands.data")

    _UNIX_CMDS = _load_wordlist(unix_path) if os.path.exists(unix_path) else set()
    _WIN_CMDS = _load_wordlist(win_path) if os.path.exists(win_path) else set()


def _contains_command_word(text: str, words: Set[str]) -> bool:
    if not text or not words:
        return False
    # cheap tokenization: split on non-alphanum, keep '-' and '_' as part of tokens
    tokens = re.split(r"[^a-zA-Z0-9_\-]+", text.lower())
    for t in tokens:
        if t and t in words:
            return True
    return False


def scan_request(
    ip: str,
    uri: str,
    headers: Any,
    body: str,
    rules: Optional[List[Rule]] = None
) -> Dict[str, Any]:
    if rules is None:
        rules = get_rules_once()

    # ✅ Fast-path: ignore plain static asset fetches (no query/body).
    # This stops noisy alerts for normal asset loads like /static/*.png, .css, .js, etc.
    uri_s = (uri or "").strip()
    body_s = (body or "").strip()
    if _is_static_asset_uri(uri_s) and ("?" not in uri_s) and (not body_s):
        mode = _scoring_mode()
        return {
            "ip": ip,
            "score_total": 0,
            "categories": [],
            "hits": [],
            "scoring_mode": mode,
            "ua_only_suppressed": True,
            "ua_categories": [],
        }

    mode = _scoring_mode()
    target_map = build_target_map(uri=uri, headers=headers, body=body)

    hits: List[Dict[str, Any]] = []
    # Track evidence separately so User-Agent-only matches don't ban real users.
    seen_categories_non_ua: Set[str] = set()
    seen_categories_ua: Set[str] = set()
    ua_only_suppressed = False

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
                        "target": target,
                        "pattern": pat.pattern,
                    })

                    if target == "ua":
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
    if combined:
        # Require operator hints to reduce false positives
        if re.search(r"(?:;|\|\||&&|`|\$\()", combined):
            if _contains_command_word(combined, unix_cmds) or _contains_command_word(combined, win_cmds):
                hits.append({
                    "category": "cmdi",
                    "target": "combined",
                    "pattern": "cmdi_heuristic(operator+wordlist)",
                })
                seen_categories_non_ua.add("cmdi")

    # If we only matched UA rules, suppress enforcement categories (but keep UA categories available)
    if not seen_categories_non_ua and seen_categories_ua:
        ua_only_suppressed = True

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
