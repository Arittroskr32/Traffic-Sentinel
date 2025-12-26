from typing import Dict, List, Optional, Tuple
from analyzer.rules_loader import load_rules

_RULES_CACHE: Optional[List[Dict[str, object]]] = None

# Priority: if multiple match, choose ONE strongest category
CATEGORY_PRIORITY = [
    "rce",
    "cmdi",
    "ssrf",
    "xxe",
    "ssti",
    "sqli",
    "lfi",
    "php",
    "xss",
    "scan",
    "bruteforce",
    "unknown",
]


def get_rules_once() -> List[Dict[str, object]]:
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = load_rules()
    return _RULES_CACHE


def _cat_rank(cat: str) -> int:
    cat = (cat or "unknown").strip().lower()
    try:
        return CATEGORY_PRIORITY.index(cat)
    except ValueError:
        return CATEGORY_PRIORITY.index("unknown")


def _pick_best_hit(hits: List[Dict[str, object]]) -> Optional[Dict[str, object]]:
    if not hits:
        return None

    best = None
    best_key: Tuple[int, int] = (10_000, -1)  # (rank, -score)
    for h in hits:
        cat = str(h.get("category", "unknown")).lower()
        rank = _cat_rank(cat)
        score = int(h.get("score", 1) or 1)
        key = (rank, -score)
        if best is None or key < best_key:
            best = h
            best_key = key
    return best


def _combined_text(uri: str, headers: Dict[str, str], body: str) -> str:
    # keep it bounded to avoid huge regex runtime
    hvals = " ".join([str(v) for v in (headers or {}).values()])
    txt = f"{uri}\n{hvals}\n{body}"
    if len(txt) > 8000:
        txt = txt[:8000]
    return txt


def _target_value(target: str, uri: str, headers: Dict[str, str], body: str) -> str:
    t = (target or "").strip().lower()

    if t in ("uri", "path"):
        return uri or ""

    if t in ("args", "query", "query_params"):
        if "?" in (uri or ""):
            return uri.split("?", 1)[1]
        return uri or ""

    if t in ("body",):
        return body or ""

    if t in ("ua", "user-agent", "user_agent"):
        return headers.get("User-Agent", "") or headers.get("user-agent", "") or ""

    if t in ("headers", "cookies"):
        # allow these to still work by searching combined
        return _combined_text(uri, headers, body)

    if t == "combined":
        return _combined_text(uri, headers, body)

    return uri or ""


def scan_request(ip: str, uri: str, headers: Dict[str, str], body: str, rules: List[Dict[str, object]]) -> Dict[str, object]:
    ip = str(ip or "").strip()
    uri = str(uri or "")
    headers = headers or {}
    body = body or ""

    hits: List[Dict[str, object]] = []

    for r in rules:
        cre = r.get("_re")
        if cre is None:
            continue

        cat = str(r.get("category", "unknown") or "unknown").strip().lower()
        target = str(r.get("target", "uri") or "uri").strip()
        score = int(r.get("score", 1) or 1)
        rid = str(r.get("id", "rule") or "rule")

        text = _target_value(target, uri, headers, body)
        if not text:
            continue

        m = cre.search(text)  # type: ignore[attr-defined]
        if not m:
            continue

        matched = m.group(0) or ""
        if len(matched) > 180:
            matched = matched[:180]

        hits.append(
            {
                "id": rid,
                "category": cat,
                "target": target,
                "pattern": str(r.get("pattern", ""))[:240],
                "matched": matched,
                "score": score,
            }
        )

    best = _pick_best_hit(hits)
    if not best:
        return {"ip": ip, "score_total": 0, "categories": [], "hits": []}

    return {
        "ip": ip,
        "score_total": int(best.get("score", 1) or 1),
        "categories": [str(best.get("category", "unknown") or "unknown")],
        "hits": [best],  # ✅ ONE hit only
    }
