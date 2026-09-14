from __future__ import annotations

import os
import requests
from .database import get_setting, setting_enabled


def send_telegram_alert(message: str) -> str:
    if not setting_enabled("telegram_enabled", os.getenv("TELEGRAM_ENABLED", "false")):
        return "Disabled"
    token = str(get_setting("telegram_bot_token", os.getenv("TELEGRAM_BOT_TOKEN", ""))).strip()
    chat_id = str(get_setting("telegram_chat_id", os.getenv("TELEGRAM_CHAT_ID", ""))).strip()
    if not token or not chat_id:
        return "Not Configured"
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        response = requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"}, timeout=8)
        response.raise_for_status()
        return "Delivered"
    except Exception as exc:
        return f"Failed: {exc.__class__.__name__}"
