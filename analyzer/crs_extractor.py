import re
from typing import List, Tuple, Dict, Optional


SEC_RULE_START = re.compile(r'^\s*SecRule\b')
ID_RE = re.compile(r'\bid\s*:\s*(\d+)\b')
RX_RE = re.compile(r'@rx\s+(.+?)(?:"\s|"\s*$)', re.IGNORECASE)


def extract_sec_rules(conf_lines: List[str]) -> List[str]:
    """
    Joins multi-line SecRule blocks into a single string per rule.
    CRS rules often span multiple lines until the final quote closes.
    """
    rules: List[str] = []
    buf: List[str] = []
    in_rule = False

    for line in conf_lines:
        # Remove trailing newline, keep content
        s = line.rstrip("\n")

        if not in_rule and SEC_RULE_START.search(s):
            in_rule = True
            buf = [s.strip()]
            # If it ends with a quote, it's likely a one-liner
            if s.strip().endswith('"'):
                rules.append(" ".join(buf))
                buf = []
                in_rule = False
            continue

        if in_rule:
            buf.append(s.strip())
            if s.strip().endswith('"'):
                rules.append(" ".join(buf))
                buf = []
                in_rule = False

    return rules


def parse_rule(rule_str: str) -> Optional[Dict[str, str]]:
    """
    Extract only rules that have both id:<num> and @rx <pattern>.
    """
    id_match = ID_RE.search(rule_str)
    rx_match = RX_RE.search(rule_str)

    if not id_match or not rx_match:
        return None

    rule_id = id_match.group(1).strip()
    pattern = rx_match.group(1).strip()

    if not pattern:
        return None

    return {"id": rule_id, "pattern": pattern}


def extract_rules_from_conf(conf_path: str) -> Tuple[List[Dict[str, str]], int]:
    with open(conf_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    sec_rules = extract_sec_rules(lines)

    extracted: List[Dict[str, str]] = []
    skipped = 0
    for rule in sec_rules:
        parsed = parse_rule(rule)
        if parsed:
            extracted.append(parsed)
        else:
            skipped += 1

    return extracted, skipped


if __name__ == "__main__":
    # Mini sanity test
    test_lines = [
        'SecRule REQUEST_HEADERS "@rx attack" "id:1234,phase:2,deny"',
        'SecRule REQUEST_BODY "@rx ssti" "id:5678,phase:2,deny"',
        'SecRule REQUEST_URI "@rx sql" "id:9999,phase:2,deny"',
        'SecRule REQUEST_HEADERS "@rx " "id:0000,phase:2,deny"',
        'SecRule REQUEST_HEADERS "no regex here" "id:1111,phase:2,deny"',
    ]
    rules = extract_sec_rules(test_lines)
    out = []
    sk = 0
    for r in rules:
        p = parse_rule(r)
        if p:
            out.append(p)
        else:
            sk += 1
    print("Extracted:", out)
    print("Skipped:", sk)
