import json
import re
from typing import Any, Dict, List, Optional


# A pragmatic “combined-ish” parser:
# ip - - [time] "METHOD URI HTTP/x" status bytes "ref" "ua"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s*'
    r'(?:"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_access_line(line: str) -> Optional[Dict[str, Any]]:
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
            "user_agent": d.get("ua") or "",
            "referer": d.get("ref") or "",
        },
        "body": "",  # access logs usually don't include body
        "ts": d.get("time", ""),
        "raw": line,
    }


def parse_jsonl_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        obj = json.loads(line)
    except Exception:
        return None

    # expected fields (flexible)
    ip = obj.get("ip") or obj.get("client_ip") or obj.get("remote_addr") or ""
    uri = obj.get("uri") or obj.get("path") or obj.get("url") or ""
    method = obj.get("method") or ""
    status = obj.get("status") or obj.get("status_code") or 0
    headers = obj.get("headers") or {}
    body = obj.get("body") or obj.get("request_body") or ""
    ts = obj.get("ts") or obj.get("time") or obj.get("timestamp") or ""

    if not ip or not uri:
        return None

    if not isinstance(headers, dict):
        headers = {"headers": str(headers)}

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
        "body": str(body),
        "ts": str(ts),
        "raw": line,
    }


def parse_lines(lines: List[str], source: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        if source == "jsonl":
            e = parse_jsonl_line(line)
        else:
            e = parse_access_line(line)
        if e:
            out.append(e)
    return out
