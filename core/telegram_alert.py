import json
import urllib.parse
import urllib.request


def send_telegram_message(bot_token: str, chat_id: str, text: str, *, disable_web_page_preview: bool = True) -> bool:
    """Send a Telegram message via Bot API. Returns True on success."""
    bot_token = (bot_token or "").strip()
    chat_id = str(chat_id or "").strip()
    if not bot_token or not chat_id:
        return False

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": bool(disable_web_page_preview),
    }

    data = urllib.parse.urlencode(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            obj = json.loads(body)
            return bool(obj.get("ok", False))
    except Exception:
        return False
