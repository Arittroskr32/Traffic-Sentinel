import json
import re
from typing import Any, Dict, List, Optional


# Default nginx combined-ish:
# ip - - [time] "METHOD URI HTTP/x" status bytes "ref" "ua"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s*'
    r'(?:"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _as_headers(h: Any) -> Dict[str, str]:
    if not h:
        return {}
    if isinstance(h, dict):
        out: Dict[str, str] = {}
        for k, v in h.items():
            if k is None:
                continue
            kk = str(k)
            if isinstance(v, (list, tuple)):
                vv = ",".join(str(x) for x in v if x is not None)
            else:
                vv = "" if v is None else str(v)
            out[kk] = vv
        return out
    return {}


def _safe_body(x: Any, limit: int = 2048) -> str:
    if x is None:
        return ""
    if isinstance(x, (dict, list)):
        try:
            s = json.dumps(x, ensure_ascii=False)
        except Exception:
            s = str(x)
    else:
        s = str(x)
    if len(s) > limit:
        s = s[:limit]
    return s


def _combine_uri_args(uri: str, args: str) -> str:
    uri = (uri or "").strip()
    args = (args or "").strip()
    if not uri:
        return ""
    if not args:
        return uri
    if "?" in uri:
        return uri
    return f"{uri}?{args}"


def parse_jsonl_line(line: str) -> Optional[Dict[str, Any]]:
    """
    JSONL event format (flexible). Supports your nginx JSONL keys:
      ts, remote_addr, xff, host, server_addr, request, method, uri, args,
      status, bytes, ref, ua, body

    Returns:
      {ip, uri, args, method, status, headers, body, ts}
    """
    try:
        obj = json.loads(line)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None

    ip = (
        obj.get("ip")
        or obj.get("client_ip")
        or obj.get("remote_addr")
        or obj.get("remoteAddress")
        or obj.get("src_ip")
        or ""
    )

    uri = (
        obj.get("uri")
        or obj.get("path")
        or obj.get("url")
        or obj.get("full_path")
        or obj.get("request_uri")
        or obj.get("originalUrl")
        or ""
    )

    # nginx JSONL often has args separately
    args = obj.get("args") or obj.get("query") or obj.get("query_string") or ""
    if args is None:
        args = ""
    args = str(args)

    # fallback: parse from full request line: "GET /path?x=1 HTTP/1.1"
    req = str(obj.get("request") or "")
    if (not uri) and req:
        parts = req.split()
        if len(parts) >= 2:
            uri = parts[1]

    full_uri = _combine_uri_args(str(uri), args)

    method = obj.get("method") or ""
    if not method and req:
        parts = req.split()
        if parts:
            method = parts[0]

    status = obj.get("status") or obj.get("status_code") or 0

    headers = _as_headers(obj.get("headers") or obj.get("request_headers") or obj.get("hdrs") or {})

    # Map nginx flat UA/XFF fields into headers so UA/header rules work
    ua = obj.get("ua") or obj.get("user_agent") or ""
    if ua and "User-Agent" not in headers:
        headers["User-Agent"] = str(ua)

    xff = obj.get("xff") or obj.get("x_forwarded_for") or obj.get("X-Forwarded-For") or ""
    if xff and "X-Forwarded-For" not in headers:
        headers["X-Forwarded-For"] = str(xff)

    body = _safe_body(obj.get("body") or obj.get("request_body") or obj.get("data") or "")

    ts = obj.get("ts") or obj.get("time") or obj.get("timestamp") or ""
    content_type = obj.get("content_type") or obj.get("contentType") or ""

    if not ip or not full_uri:
        return None

    try:
        status = int(status)
    except Exception:
        status = 0

    return {
        "ip": str(ip),
        "uri": full_uri,   # IMPORTANT: includes ?args
        "args": args,
        "method": str(method),
        "status": status,
        "headers": headers,
        "body": body,
        "ts": str(ts),
        "content_type": str(content_type),
    }


def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
    m = ACCESS_RE.match(line.strip())
    if not m:
        return None

    ip = m.group("ip")
    uri = m.group("uri")
    method = m.group("method")
    status = m.group("status") or "0"
    ua = m.group("ua") or ""

    try:
        status_i = int(status)
    except Exception:
        status_i = 0

    headers: Dict[str, str] = {}
    if ua:
        headers["User-Agent"] = ua

    return {
        "ip": ip,
        "uri": uri,   # already includes query string in classic access logs
        "args": "",
        "method": method,
        "status": status_i,
        "headers": headers,
        "body": "",
        "ts": "",
        "content_type": "",
    }


def parse_lines(lines: List[str], source: str = "access") -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    source = (source or "access").lower().strip()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        ev: Optional[Dict[str, Any]] = None
        if source == "jsonl":
            ev = parse_jsonl_line(line)
        else:
            ev = parse_access_line(line)

        if ev:
            out.append(ev)

    return out
