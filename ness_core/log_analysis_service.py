from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from .database import execute, fetch_all, fetch_one, next_code

LEVEL_WEIGHT = {"Info": 0, "Low": 1, "Medium": 2, "Warning": 2, "High": 4, "Critical": 6, "Error": 4}
SUSPICIOUS_TERMS = ("failed", "denied", "rate-limit", "attack", "detected", "critical", "brute", "injection", "traversal", "xss", "unauthorized")


def _level_score(level: str) -> int:
    return LEVEL_WEIGHT.get(str(level or "").title(), 1)


def analyze_security_logs(hours: int = 24, category: str | None = None, level: str | None = None, generated_by: int | None = None) -> dict[str, Any]:
    hours = max(1, min(int(hours or 24), 24 * 30))
    sql = "SELECT * FROM system_logs WHERE created_at >= datetime('now', ?)"
    params: list[Any] = [f"-{hours} hours"]
    if category:
        sql += " AND category=?"; params.append(category)
    if level:
        sql += " AND level=?"; params.append(level)
    sql += " ORDER BY id DESC LIMIT 5000"
    logs = fetch_all(sql, tuple(params))

    levels = Counter(str(x.get("level") or "Info") for x in logs)
    categories = Counter(str(x.get("category") or "Unknown") for x in logs)
    actors = Counter(str(x.get("actor") or "Unknown") for x in logs)
    suspicious = [x for x in logs if any(term in str(x.get("event") or "").lower() for term in SUSPICIOUS_TERMS)]
    incident_refs = sorted(set(re.findall(r"NESS-\d{4}-\d{4}", "\n".join(str(x.get("event") or "") for x in logs))))

    weighted = sum(_level_score(x.get("level", "Info")) for x in logs)
    high_critical = sum(levels.get(k, 0) for k in ("High", "Critical", "Error"))
    risk_score = min(100, round(weighted * 2.2 + high_critical * 4 + len(suspicious) * 1.5)) if logs else 0

    findings: list[str] = []
    if not logs:
        findings.append("No system log records were present in the selected time window.")
    if high_critical:
        findings.append(f"{high_critical} high/critical/error log entries require review.")
    if suspicious:
        findings.append(f"{len(suspicious)} entries contain security-sensitive or failure indicators.")
    repeated = [(a, c) for a, c in actors.most_common(5) if c >= 8]
    for actor, count in repeated:
        findings.append(f"Actor '{actor}' generated {count} events in the selected window.")
    if incident_refs:
        findings.append(f"Logs reference {len(incident_refs)} tracked NESS incident(s): {', '.join(incident_refs[:8])}.")
    if not findings:
        findings.append("No significant concentration or high-severity pattern was identified in the selected window.")

    dominant_category = categories.most_common(1)[0][0] if categories else "None"
    dominant_actor = actors.most_common(1)[0][0] if actors else "None"
    summary = (
        f"Analyzed {len(logs)} real system log entries from the last {hours} hour(s). "
        f"Risk score: {risk_score}/100. Dominant category: {dominant_category}. "
        f"Most active actor: {dominant_actor}. High/Critical/Error entries: {high_critical}."
    )

    recommendations = []
    if high_critical:
        recommendations.append("Review all High, Critical, and Error events and correlate them with incident/evidence records.")
    if suspicious:
        recommendations.append("Correlate repeated failure/detection messages by actor and timestamp to identify attack sequences or operational failures.")
    if incident_refs:
        recommendations.append("Open the referenced INTS records and verify incident status, assignment, evidence, and resolution history.")
    if risk_score >= 60:
        recommendations.append("Escalate this log window for analyst review and preserve an exported copy for the investigation record.")
    recommendations.append("Continue monitoring new WebSocket alerts and re-run log analysis after meaningful security events or configuration changes.")

    code = next_code("LOGA", "log_analysis", "analysis_code")
    analysis_id = execute(
        """
        INSERT INTO log_analysis(analysis_code,time_window_hours,category_filter,level_filter,log_count,anomaly_count,risk_score,summary,findings,recommendations,model_name,confidence,generated_by,generated_at,source)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),'NESS Local Log Analyzer')
        """,
        (
            code, hours, category or "", level or "", len(logs), len(suspicious), risk_score, summary,
            json.dumps(findings, ensure_ascii=False), "\n".join(f"{i+1}. {r}" for i, r in enumerate(recommendations)),
            "NESS Statistical & Rule Log Analyzer", min(0.98, 0.70 + min(len(logs), 100) / 500), generated_by,
        ),
    )
    return get_log_analysis(analysis_id) or {}


def get_log_analysis(identifier: int | str) -> dict[str, Any] | None:
    if str(identifier).isdigit():
        row = fetch_one("SELECT a.*, COALESCE(u.name,'NESS') generated_by_name FROM log_analysis a LEFT JOIN users u ON u.id=a.generated_by WHERE a.id=?", (int(identifier),))
    else:
        row = fetch_one("SELECT a.*, COALESCE(u.name,'NESS') generated_by_name FROM log_analysis a LEFT JOIN users u ON u.id=a.generated_by WHERE a.analysis_code=?", (str(identifier),))
    if row:
        try: row["findings"] = json.loads(row.get("findings") or "[]")
        except Exception: row["findings"] = [row.get("findings") or ""]
    return row


def list_log_analyses(limit: int = 100) -> list[dict[str, Any]]:
    rows = fetch_all("SELECT a.*, COALESCE(u.name,'NESS') generated_by_name FROM log_analysis a LEFT JOIN users u ON u.id=a.generated_by ORDER BY a.id DESC LIMIT ?", (max(1, min(int(limit), 500)),))
    for row in rows:
        try: row["findings"] = json.loads(row.get("findings") or "[]")
        except Exception: row["findings"] = []
    return rows
