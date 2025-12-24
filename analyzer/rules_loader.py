import os
import re
import yaml
from typing import List, Dict, Any, Optional

# Prefer the "regex" module for PCRE-like compatibility (CRS patterns)
try:
    import regex as rx  # pip install regex
except Exception:
    rx = None


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

        # Enforce your global rule: every vuln score = 1
        self.score = 1

        self.is_regex = is_regex
        self.patterns = []  # compiled patterns

        for pat in patterns:
            compiled = self._compile_pattern(pat, is_regex)
            if compiled is not None:
                self.patterns.append(compiled)

    @staticmethod
    def _compile_pattern(pat: str, is_regex: bool):
        """
        Returns a compiled pattern object or None (if compile fails).
        """
        if not isinstance(pat, str) or not pat:
            return None

        # If this is CRS regex, use `regex` module if available.
        if is_regex:
            if rx is not None:
                try:
                    return rx.compile(pat, rx.IGNORECASE)
                except Exception:
                    # If regex module still can't compile it, fall back to python re
                    pass
            try:
                # Try python re as last resort
                return re.compile(pat, re.IGNORECASE)
            except Exception:
                return None

        # Non-regex patterns are treated as literal tokens
        try:
            return re.compile(re.escape(pat), re.IGNORECASE)
        except Exception:
            return None


def load_yaml_rules(path: str) -> List[Rule]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    out: List[Rule] = []
    bad_rules = 0
    bad_patterns = 0

    for rule in data.get("rules", []):
        if "category" not in rule or "patterns" not in rule:
            bad_rules += 1
            continue

        category = str(rule.get("category", "unknown"))
        rule_id = rule.get("id")
        targets = rule.get("targets") or ["uri", "headers", "body"]
        patterns = rule.get("patterns") or []
        is_regex = bool(rule.get("regex", False))

        r = Rule(
            category=category,
            rule_id=str(rule_id) if rule_id is not None else None,
            targets=targets,
            patterns=patterns,
            is_regex=is_regex,
        )

        if not r.patterns:
            # rule exists but no patterns compiled successfully
            bad_patterns += len(patterns)
            continue

        out.append(r)

    if bad_rules or bad_patterns:
        print(f"[rules_loader] skipped invalid rules={bad_rules}, failed patterns≈{bad_patterns}")

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
