import os
import re
import yaml
from typing import List, Dict, Any, Optional

# Prefer the "regex" module for PCRE-like compatibility (CRS patterns)
try:
    import regex as rx  # pip install regex
except Exception:
    rx = None

# ---- Known bad CRS artifacts / overbroad patterns ----
# These are patterns that match almost any normal string and create massive false positives.
BAD_RULE_IDS = {
    # Known offenders in some CRS dumps
    "932205",
    "932207",
}

BAD_PATTERNS_EXACT = {
    "^[^#]+",
    "#.*",
}

BAD_PATTERNS_SUBSTR = {
    # This family contains tokens for HTTP verbs and ends up matching normal requests/bodies
    "(?:GE|POS)T",
    "(?:GET|POST|HEAD)",
}


def _compile(pat: str, is_regex: bool):
    if not isinstance(pat, str) or not pat:
        return None
    if is_regex:
        if rx is not None:
            try:
                return rx.compile(pat, rx.IGNORECASE)
            except Exception:
                pass
        try:
            return re.compile(pat, re.IGNORECASE)
        except Exception:
            return None
    try:
        return re.compile(re.escape(pat), re.IGNORECASE)
    except Exception:
        return None


def _is_too_broad_pattern(rule_id: Optional[str], pat: str, is_regex: bool) -> bool:
    """Return True if a pattern is clearly too broad / unsafe for log-based detection."""
    if not isinstance(pat, str) or not pat.strip():
        return True

    rid = str(rule_id) if rule_id is not None else ""
    p = pat.strip()

    if rid in BAD_RULE_IDS:
        return True
    if p in BAD_PATTERNS_EXACT:
        return True
    for sub in BAD_PATTERNS_SUBSTR:
        if sub in p:
            return True

    # Only attempt broadness test for regex patterns
    if not is_regex:
        return False

    c = _compile(p, is_regex=True)
    if c is None:
        return True

    # If it matches many benign samples, it's too broad.
    benign_samples = [
        "/", "/friends", "/post/7", "/register", "/api/login",
        "hello", "abc123",
        "GET", "POST", "HEAD",
        "GET / HTTP/1.1", "POST /register HTTP/1.1",
    ]
    hits = sum(1 for s in benign_samples if c.search(s))

    # Allow patterns that include obvious attack operators/tokens
    allow_tokens = [
        ";", "&&", "||", "`", "$(", "../",
        "<script", "union", "select", "sleep", "pg_sleep",
        "wget", "curl", "cmd", "powershell",
    ]
    if any(tok in p for tok in allow_tokens):
        return False

    if hits >= 6:
        return True

    return False


class Rule:
    def __init__(
        self,
        category: str,
        rule_id: Optional[str],
        targets: List[str],
        patterns: List[str],
        is_regex: bool,
    ):
        self.category = category
        self.id = rule_id
        self.targets = targets or ["uri", "headers", "body"]

        # Enforce your global rule: each match contributes score=1
        self.score = 1

        self.is_regex = is_regex
        self.patterns = []  # compiled patterns

        for pat in patterns:
            if _is_too_broad_pattern(rule_id, pat, is_regex):
                continue
            compiled = _compile(pat, is_regex)
            if compiled is not None:
                self.patterns.append(compiled)


def load_yaml_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    out: List[Rule] = []
    bad_rules = 0
    bad_patterns = 0
    skipped_broad = 0

    for rule in data.get("rules", []):
        if "category" not in rule or "patterns" not in rule:
            bad_rules += 1
            continue

        category = str(rule.get("category", "unknown"))
        rule_id = rule.get("id")
        targets = rule.get("targets") or ["uri", "headers", "body"]
        patterns = rule.get("patterns") or []
        is_regex = bool(rule.get("regex", False))

        # Count broad skips (for visibility)
        if isinstance(patterns, list):
            for p in patterns:
                if isinstance(p, str) and _is_too_broad_pattern(rule_id, p, is_regex):
                    skipped_broad += 1

        r = Rule(
            category=category,
            rule_id=str(rule_id) if rule_id is not None else None,
            targets=targets,
            patterns=patterns,
            is_regex=is_regex,
        )

        if not r.patterns:
            bad_patterns += len(patterns)
            continue

        out.append(r)

    if bad_rules or bad_patterns or skipped_broad:
        print(f"[rules_loader] skipped invalid rules={bad_rules}, failed patterns≈{bad_patterns}, skipped_too_broad≈{skipped_broad}")

    return out


def load_all_rules(compiled_path: str, custom_path: str, enabled_categories: Optional[List[str]] = None) -> List[Rule]:
    compiled = load_yaml_rules(compiled_path)
    custom = load_yaml_rules(custom_path)
    all_rules = compiled + custom

    if enabled_categories:
        enabled = set(enabled_categories)
        all_rules = [r for r in all_rules if r.category in enabled]

    # summary
    cat_count: Dict[str, int] = {}
    total_patterns = 0
    for r in all_rules:
        cat_count[r.category] = cat_count.get(r.category, 0) + 1
        total_patterns += len(r.patterns)

    print("[rules_loader] Loaded rules per category:")
    for k in sorted(cat_count.keys()):
        print(f"  {k}: {cat_count[k]}")
    print(f"[rules_loader] Total compiled patterns: {total_patterns}")

    return all_rules


if __name__ == "__main__":
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    compiled_path = os.path.join(base, "config", "rules_compiled.yml")
    custom_path = os.path.join(base, "config", "rules_custom.yml")
    rules = load_all_rules(compiled_path, custom_path)
    print(f"Total loaded rules: {len(rules)}")
