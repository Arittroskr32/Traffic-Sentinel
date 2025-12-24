import json
import os
from typing import Dict, Any, List, Optional


def _load_offset(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"pos": 0}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {"pos": 0}
    except Exception:
        return {"pos": 0}


def _save_offset(path: str, pos: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"pos": pos}, f)
    os.replace(tmp, path)


def tail_lines(path: str, offset_file: str, max_lines: int = 2000) -> List[str]:
    """
    Stateful tail: reads new lines since last position stored in offset_file.
    Works for local files. If log is rotated, it resets safely.
    """
    os.makedirs(os.path.dirname(offset_file), exist_ok=True)

    if not os.path.exists(path):
        return []

    off = _load_offset(offset_file)
    pos = int(off.get("pos", 0))

    # handle rotation/truncation
    size = os.path.getsize(path)
    if pos > size:
        pos = 0

    lines: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(pos)
        for _ in range(max_lines):
            line = f.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
        new_pos = f.tell()

    _save_offset(offset_file, new_pos)
    return lines
