import urllib.parse
import re
from typing import Dict, Any


def normalize(text: Any, querystring_mode: bool = False) -> Dict[str, str]:
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    raw = text

    # URL decode twice (good for double-encoding)
    try:
        # unquote_plus turns + into space, useful for query strings
        text = urllib.parse.unquote_plus(text)
        text = urllib.parse.unquote_plus(text)
    except Exception:
        pass

    text = text.lower()
    text = text.replace("\x00", "").replace("\0", "")
    text = re.sub(r"\s+", " ", text).strip()

    if querystring_mode:
        text = text.replace("+", " ")

    return {"raw": raw, "normalized": text}


if __name__ == "__main__":
    sample = "%7B%7B%20__class__%20%7D%7D+%00%00"
    result = normalize(sample, querystring_mode=True)
    print(result)
