import urllib.parse
import re
from typing import Dict, Any, List

_WS_RE = re.compile(r"\s+")
_NULL_RE = re.compile(r"[\x00\0]+")


def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    return str(x)


def normalize(text: Any, querystring_mode: bool = False) -> Dict[str, str]:
    """
    - stringify
    - URL decode twice
    - lowercase
    - remove null bytes
    - collapse whitespace
    """
    raw = _safe_str(text)
    s = raw

    try:
        s = urllib.parse.unquote_plus(s)
        s = urllib.parse.unquote_plus(s)
    except Exception:
        pass

    s = s.lower()
    s = _NULL_RE.sub("", s)
    s = _WS_RE.sub(" ", s).strip()

    if querystring_mode:
        s = s.replace("+", " ")

    return {"raw": raw, "normalized": s}


def _query_pairs(query: str) -> str:
    if not query:
        return ""
    out: List[str] = []
    try:
        for k, v in urllib.parse.parse_qsl(query, keep_blank_values=True):
            kn = normalize(k, querystring_mode=True)["normalized"]
            vn = normalize(v, querystring_mode=True)["normalized"]
            if kn or vn:
                out.append(f"{kn}={vn}")
    except Exception:
        return normalize(query, querystring_mode=True)["normalized"]
    return "\n".join(out).strip()


def _parse_uri(uri: str) -> Dict[str, str]:
    uri_raw = _safe_str(uri)

    path = ""
    query = ""
    try:
        sp = urllib.parse.urlsplit(uri_raw)
        path = sp.path or ""
        query = sp.query or ""
    except Exception:
        path = uri_raw
        query = ""

    return {
        "uri": normalize(uri_raw)["normalized"],
        "path": normalize(path)["normalized"],
        "query": normalize(query, querystring_mode=True)["normalized"],
        "query_params": _query_pairs(query),
    }


def _cookie_pairs(cookie_header: str) -> str:
    cookie_header = _safe_str(cookie_header)
    if not cookie_header:
        return ""
    out: List[str] = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            kn = normalize(k, querystring_mode=True)["normalized"]
            vn = normalize(v, querystring_mode=True)["normalized"]
            out.append(f"{kn}={vn}")
        else:
            out.append(normalize(part, querystring_mode=True)["normalized"])
    return "\n".join([x for x in out if x]).strip()


def _headers_targets(headers: Any) -> Dict[str, str]:
    """
    Returns:
      - headers_values: just values joined
      - headers_kv: "key: value" lines (includes header names)
      - cookies_raw: cookie header normalized (if present)
      - cookies_params: parsed cookie pairs
    """
    values: List[str] = []
    kv: List[str] = []
    cookie_raw = ""

    if isinstance(headers, dict):
        for k, v in headers.items():
            ks = normalize(k)["normalized"]
            vs = normalize(v)["normalized"]

            if vs:
                values.append(vs)
            if ks or vs:
                kv.append(f"{ks}: {vs}")

            if ks in ("cookie", "cookies") and not cookie_raw:
                cookie_raw = _safe_str(v)

    elif isinstance(headers, str):
        s = normalize(headers)["normalized"]
        if s:
            values.append(s)
            kv.append(s)

    return {
        "headers_values": " ".join(values).strip(),
        "headers_kv": "\n".join(kv).strip(),
        "cookies_raw": normalize(cookie_raw, querystring_mode=True)["normalized"],
        "cookies_params": _cookie_pairs(cookie_raw),
    }


def build_target_map(uri: str, headers: Any, body: Any) -> Dict[str, str]:
    """
    Unified scan buckets.
    These keys are what detector can scan: uri, path, query, query_params,
    headers, headers_kv, cookies, cookies_params, body, combined
    """
    up = _parse_uri(uri)
    hp = _headers_targets(headers)
    bp = normalize(body)["normalized"]

    combined = " ".join([
        up["uri"],
        up["path"],
        up["query"],
        up["query_params"],
        hp["headers_kv"],
        hp["cookies_raw"],
        hp["cookies_params"],
        bp,
    ]).strip()

    return {
        # URI
        "uri": up["uri"],
        "path": up["path"],
        "query": up["query"],
        "query_params": up["query_params"],

        # Headers: keep old key "headers" as VALUES ONLY (backward compatible)
        "headers": hp["headers_values"],

        # New: includes header NAMES too
        "headers_kv": hp["headers_kv"],

        # Cookies
        "cookies": hp["cookies_raw"],
        "cookies_params": hp["cookies_params"],

        # Body + catch-all
        "body": bp,
        "combined": combined,
    }
