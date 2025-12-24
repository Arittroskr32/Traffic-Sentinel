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

# Safety limit for body logging/processing
MAX_BODY = 8192


def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Access logs typically do NOT include request body.
    This parser is still used when log_source=access.
    """
    m = ACCESS_RE.match(line)
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d.get("ip", ""),
        "uri": d.get("uri", "") or "",
        "method": d.get("method", "") or "",
        "status": int(d.get("status") or 0),
        "headers": {
            "user-agent": d.get("ua") or "",
            "referer": d.get("ref") or "",
        },
        "body": "",
        "ts": d.get("time", ""),
        "raw": line,
        "content_type": "",
    }


def _as_headers(obj: Any) -> Dict[str, Any]:
    """
    Normalize headers into a dict.
    Accepts dict or list of pairs or raw string.
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        # could be [["k","v"], ...] or [{"k":"..","v":".."}]
        out: Dict[str, Any] = {}
        for item in obj:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                out[str(item[0])] = item[1]
            elif isinstance(item, dict):
                # common patterns
                k = item.get("key") or item.get("name") or item.get("k")
                v = item.get("value") or item.get("v")
                if k is not None:
                    out[str(k)] = v
        return out
    # fallback: store as one header blob
    return {"headers": str(obj)}


def _safe_body(body: Any) -> str:
    """
    Convert body to string, cap length, avoid crashes.
    """
    if body is None:
        return ""
    if isinstance(body, (dict, list)):
        try:
            body = json.dumps(body, ensure_ascii=False)
        except Exception:
            body = str(body)
    else:
        body = str(body)

    if len(body) > MAX_BODY:
        body = body[:MAX_BODY] + "...(truncated)"
    return body


def parse_jsonl_line(line: str) -> Optional[Dict[str, Any]]:
    """
    JSONL event format (flexible). Examples of accepted keys:

    IP:
      ip, client_ip, remote_addr, remoteAddress, src_ip
    URI:
      uri, path, url, full_path, request_uri, originalUrl
    Method:
      method
    Status:
      status, status_code
    Headers:
      headers
    Body:
      body, request_body
    Timestamp:
      ts, time, timestamp
    Content-Type:
      content_type, contentType
    """
    try:
        obj = json.loads(line)
    except Exception:
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

    method = obj.get("method") or ""
    status = obj.get("status") or obj.get("status_code") or 0
    headers = _as_headers(obj.get("headers") or obj.get("request_headers") or obj.get("hdrs") or {})
    body = _safe_body(obj.get("body") or obj.get("request_body") or obj.get("data") or "")
    ts = obj.get("ts") or obj.get("time") or obj.get("timestamp") or ""
    content_type = obj.get("content_type") or obj.get("contentType") or ""

    if not ip or not uri:
        return None

    try:
        status = int(status)
    except Exception:
        status = 0

    return {
        "ip": str(ip),
        "uri": str(uri),
        "method": str(method),
        "status": status,
        "headers": headers,
        "body": body,
        "ts": str(ts),
        "raw": line,
        "content_type": str(content_type),
    }


def parse_lines(lines: List[str], source: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        if not line or not line.strip():
            continue
        if source == "jsonl":
            e = parse_jsonl_line(line)
        else:
            e = parse_access_line(line)
        if e:
            out.append(e)
    return out
