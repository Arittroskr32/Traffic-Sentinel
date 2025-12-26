import os
import re
import yaml
from typing import Any, Dict, List, Optional, Tuple


BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_COMPILED = os.path.join(BASE_DIR, "config", "rules_compiled.yml")
DEFAULT_CUSTOM = os.path.join(BASE_DIR, "config", "rules_custom.yml")
CONFIG_YML = os.path.join(BASE_DIR, "config", "config.yml")


TARGET_MAP = {
    "uri": "uri",
    "path": "uri",
    "query": "args",
    "query_params": "args",
    "headers": "headers",
    "headers_kv": "headers",
    "cookies": "cookies",
    "cookies_params": "cookies",
    "user_agent": "ua",
    "ua": "ua",
    "body": "body",
    "combined": "combined",
}


def _read_yaml_abs(path: str) -> Any:
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _get_paths_from_config() -> Tuple[str, str]:
    """
    config/config.yml supports:
      rules:
        compiled_rules_path: "config/rules_compiled.yml"  (or "" to disable)
        custom_rules_path: "config/rules_custom.yml"
    """
    doc = _read_yaml_abs(CONFIG_YML)
    if not isinstance(doc, dict):
        return ("", "")
    rules = doc.get("rules") or {}
    if not isinstance(rules, dict):
        return ("", "")

    compiled = str(rules.get("compiled_rules_path", "") or "")
    custom = str(rules.get("custom_rules_path", "") or "")
    return (compiled.strip(), custom.strip())


def _compile_regex(pat: str) -> Optional[re.Pattern]:
    try:
        return re.compile(pat)
    except re.error:
        return None


def _expand_custom_schema(doc: Any) -> List[Dict[str, Any]]:
    """
    Custom schema:
      rules:
        - id, category, regex, targets[], patterns[]
    Expands to flat rules:
      {id, category, target, pattern, score, _re}
    """
    if not isinstance(doc, dict):
        return []
    items = doc.get("rules")
    if not isinstance(items, list):
        return []

    out: List[Dict[str, Any]] = []
    for r in items:
        if not isinstance(r, dict):
            continue

        rid = str(r.get("id", "rule") or "rule").strip()
        cat = str(r.get("category", "unknown") or "unknown").strip().lower()
        is_regex = bool(r.get("regex", True))

        targets = r.get("targets") or []
        patterns = r.get("patterns") or []
        if not isinstance(targets, list) or not isinstance(patterns, list):
            continue

        for t in targets:
            t0 = str(t or "").strip().lower()
            mapped_target = TARGET_MAP.get(t0)
            if not mapped_target:
                continue

            for p in patterns:
                p0 = str(p or "").strip()
                if not p0:
                    continue

                pat = p0 if is_regex else re.escape(p0)
                cre = _compile_regex(pat)
                if not cre:
                    continue

                out.append(
                    {
                        "id": rid,
                        "category": cat,
                        "target": mapped_target,
                        "pattern": pat,
                        "score": 1,
                        "_re": cre,
                    }
                )

    return out


def _normalize_flat_schema(doc: Any) -> List[Dict[str, Any]]:
    """
    Flat schema accepted:
      - list of {id, category, target, pattern, score}
      - {"rules":[...]}
      - {category: [ ...rules... ]}
    """
    if not doc:
        return []

    rules_list: List[Dict[str, Any]] = []

    if isinstance(doc, list):
        rules_list = [x for x in doc if isinstance(x, dict)]
    elif isinstance(doc, dict):
        if isinstance(doc.get("rules"), list):
            rules_list = [x for x in doc["rules"] if isinstance(x, dict)]
        else:
            for k, v in doc.items():
                if isinstance(v, list):
                    for x in v:
                        if isinstance(x, dict):
                            rr = dict(x)
                            rr.setdefault("category", k)
                            rules_list.append(rr)

    out: List[Dict[str, Any]] = []
    for r in rules_list:
        pat = str(r.get("pattern", "") or "").strip()
        if not pat:
            continue
        cre = _compile_regex(pat)
        if not cre:
            continue

        out.append(
            {
                "id": str(r.get("id", r.get("name", "rule")) or "rule").strip(),
                "category": str(r.get("category", "unknown") or "unknown").strip().lower(),
                "target": str(r.get("target", "uri") or "uri").strip(),
                "pattern": pat,
                "score": int(r.get("score", 1) or 1),
                "_re": cre,
            }
        )

    return out


def load_rules(compiled_path: Optional[str] = None, custom_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    IMPORTANT behavior:
      - compiled_path is None  => use config/default
      - compiled_path == ""    => DISABLE compiled rules
      - custom_path is None    => use config/default
      - custom_path == ""      => DISABLE custom rules
    """
    cfg_compiled, cfg_custom = _get_paths_from_config()

    # compiled
    if compiled_path is None:
        compiled_path = cfg_compiled if cfg_compiled != "" else DEFAULT_COMPILED
    # if compiled_path == "" => disabled

    # custom
    if custom_path is None:
        custom_path = cfg_custom if cfg_custom != "" else DEFAULT_CUSTOM
    # if custom_path == "" => disabled

    compiled_rules: List[Dict[str, Any]] = []
    custom_rules: List[Dict[str, Any]] = []

    if compiled_path != "":
        compiled_doc = _read_yaml_abs(compiled_path)
        compiled_rules = _normalize_flat_schema(compiled_doc)

    if custom_path != "":
        custom_doc = _read_yaml_abs(custom_path)
        custom_rules = _expand_custom_schema(custom_doc)

    return compiled_rules + custom_rules
