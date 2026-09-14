from __future__ import annotations

import os
import requests
from .database import execute, fetch_all, fetch_one, setting_enabled


def check_target(target_id: int) -> dict:
    if not setting_enabled("monitoring_enabled", "true"):
        raise RuntimeError("Live target monitoring is disabled in system settings")
    target = fetch_one("SELECT * FROM monitored_targets WHERE id=?", (target_id,))
    if not target:
        raise ValueError("Target not found")
    timeout = int(os.getenv("HTTP_TIMEOUT_SECONDS", "5"))
    try:
        res = requests.get(target["url"], timeout=timeout)
        status = "Online" if res.status_code < 500 else "Warning"
        risk_score = 10 if status == "Online" else 55
        error = None
        status_code = res.status_code
    except Exception as exc:
        status = "Offline"
        risk_score = 80
        error = f"{exc.__class__.__name__}: {exc}"
        status_code = None
    execute(
        """
        UPDATE monitored_targets
        SET status=?, risk_score=?, last_status_code=?, last_error=?, last_checked=datetime('now')
        WHERE id=?
        """,
        (status, risk_score, status_code, error, target_id),
    )
    execute("INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('System','Target Monitor',?,?,datetime('now'))", (f"Target {target['name']} checked: {status}", "Info" if status == "Online" else "Medium"))
    return fetch_one("SELECT * FROM monitored_targets WHERE id=?", (target_id,)) or {}


def check_all_targets() -> list[dict]:
    return [check_target(t["id"]) for t in fetch_all("SELECT id FROM monitored_targets ORDER BY id")]
