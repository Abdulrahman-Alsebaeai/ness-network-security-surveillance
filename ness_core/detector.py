from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict, deque
from typing import Any
from urllib.parse import unquote_plus

from .database import execute, fetch_one, next_code, setting_enabled, get_setting

_REQUEST_TIMES: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=400))
_AUTH_REQUEST_TIMES: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=120))
_LAB_RUN_INCIDENTS: dict[tuple[str, str, str, str], int] = {}

SQLI_PATTERNS = [
    r"(?i)(\bUNION\b\s+\bSELECT\b)",
    r"(?i)(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
    r"(?i)(\bAND\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
    r"(?i)(\bDROP\b\s+\bTABLE\b)",
    r"(?i)(\bSELECT\b.+\bFROM\b)",
    r"(?i)(--|/\*|\*/|;\s*shutdown|benchmark\s*\(|sleep\s*\()",
]

XSS_PATTERNS = [
    r"(?i)<\s*script[^>]*>",
    r"(?i)javascript\s*:",
    r"(?i)on(error|load|click|mouseover)\s*=",
    r"(?i)document\.cookie",
    r"(?i)<\s*img[^>]+src\s*=",
]

TRAVERSAL_PATTERNS = [
    r"(\.\./|\.\.\\)",
    r"(?i)(/etc/passwd|boot\.ini|win\.ini)",
]

BRUTE_FORCE_PATHS = ["/login", "/admin", "/wp-login", "/api/auth/login"]


def _match_any(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        if re.search(pattern, text or ""):
            return pattern
    return None


def _decoded_variants(text: str) -> list[str]:
    values = [text or ""]
    try:
        once = unquote_plus(text or "")
        if once not in values:
            values.append(once)
        twice = unquote_plus(once)
        if twice not in values:
            values.append(twice)
    except Exception:
        pass
    return values


def _header(headers: dict[str, str], name: str, default: str = "") -> str:
    wanted = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == wanted:
            return str(value or default)
    return default


def analyze_http_request(method: str, path: str, query_string: str, headers: dict[str, str], body: str, source_ip: str) -> dict[str, Any] | None:
    """Passive defensive detector: analyzes received HTTP requests when monitoring is enabled."""
    if not setting_enabled("monitoring_enabled", "true"):
        return None

    combined = "\n".join(_decoded_variants(path) + _decoded_variants(query_string) + _decoded_variants(body))
    now = time.time()
    q = _REQUEST_TIMES[source_ip]
    q.append(now)
    recent = [t for t in q if now - t <= 60]
    auth_key = f"{source_ip}:{path.lower()}"
    auth_recent: list[float] = []
    if method.upper() == "POST" and any(p in path.lower() for p in BRUTE_FORCE_PATHS):
        aq = _AUTH_REQUEST_TIMES[auth_key]
        aq.append(now)
        auth_recent = [t for t in aq if now - t <= 60]

    try:
        high_rate_threshold = max(40, min(1000, int(str(get_setting("high_request_rate_threshold", "120")))))
    except Exception:
        high_rate_threshold = 120

    detection: dict[str, Any] | None = None
    if setting_enabled("detect_sqli", "true") and (match := _match_any(SQLI_PATTERNS, combined)):
        detection = {
            "attack_type": "SQL Injection",
            "severity": "Critical",
            "rule": match,
            "description": "SQL injection pattern detected in HTTP request data.",
        }
    elif setting_enabled("detect_xss", "true") and (match := _match_any(XSS_PATTERNS, combined)):
        detection = {
            "attack_type": "XSS Attempt",
            "severity": "High",
            "rule": match,
            "description": "Cross-site scripting pattern detected in HTTP request data.",
        }
    elif setting_enabled("detect_traversal", "true") and (match := _match_any(TRAVERSAL_PATTERNS, combined)):
        detection = {
            "attack_type": "Directory Traversal",
            "severity": "High",
            "rule": match,
            "description": "Directory traversal pattern detected in requested path or payload.",
        }
    elif setting_enabled("detect_rate", "true") and method.upper() == "POST" and any(p in path.lower() for p in BRUTE_FORCE_PATHS) and len(auth_recent) >= 8:
        detection = {
            "attack_type": "Brute Force Attempt",
            "severity": "High",
            "rule": "auth-rate-threshold:8-posts-per-minute",
            "description": "Repeated authentication-related POST requests from the same source.",
        }
    elif setting_enabled("detect_rate", "true") and len(recent) >= high_rate_threshold:
        detection = {
            "attack_type": "High Request Rate",
            "severity": "Medium",
            "rule": f"rate-threshold:{high_rate_threshold}-requests-per-minute",
            "description": "Abnormally high request rate from the same source IP within a short time window.",
        }

    if not detection:
        return None

    return create_incident_from_detection(detection, method, path, query_string, headers, body, source_ip)


def create_incident_from_detection(detection: dict[str, Any], method: str, path: str, query_string: str, headers: dict[str, str], body: str, source_ip: str) -> dict[str, Any]:
    payload = body or query_string or path
    lab_run_id = _header(headers, "X-NESS-Lab-Run-ID")
    lab_scenario = _header(headers, "X-NESS-Lab-Scenario")
    lab_key = (lab_run_id, detection["attack_type"], source_ip, path) if lab_run_id else None
    if lab_key and lab_key in _LAB_RUN_INCIDENTS:
        previous = fetch_one("SELECT * FROM incidents WHERE id=?", (_LAB_RUN_INCIDENTS[lab_key],))
        if previous:
            return previous
        _LAB_RUN_INCIDENTS.pop(lab_key, None)
    # Production-style traffic is de-duplicated. In the isolated Cyber Range,
    # each explicit scenario run is a distinct observation so every Run button
    # press produces a traceable incident/evidence/alert/AI chain.
    existing = None
    if not lab_run_id:
        if detection["attack_type"] in {"High Request Rate", "Brute Force Attempt"}:
            existing = fetch_one(
                """SELECT * FROM incidents WHERE attack_type=? AND source_ip=? AND path=?
                   AND created_at >= datetime('now','-3 minutes') ORDER BY id DESC LIMIT 1""",
                (detection["attack_type"], source_ip, path),
            )
        else:
            existing = fetch_one(
                """SELECT * FROM incidents WHERE attack_type=? AND source_ip=? AND path=? AND payload=?
                   AND created_at >= datetime('now','-3 minutes') ORDER BY id DESC LIMIT 1""",
                (detection["attack_type"], source_ip, path, payload),
            )
    if existing:
        return existing

    incident_code = next_code("NESS", "incidents", "incident_code")
    user_agent = _header(headers, "User-Agent", "Unknown")
    target = _header(headers, "X-NESS-Lab-Destination-IP") or _header(headers, "Host") or path
    incident_id = execute(
        """
        INSERT INTO incidents(
            incident_code, attack_type, severity, status, source_ip, source_country, source_city,
            target, method, path, query_string, payload, user_agent, description,
            created_at, updated_at, assigned_to, created_by
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),NULL,NULL)
        """,
        (
            incident_code,
            detection["attack_type"],
            detection["severity"],
            "New",
            source_ip,
            None,
            None,
            target,
            method,
            path,
            query_string,
            payload,
            user_agent,
            f"{detection['description']} Matched rule: {detection['rule']}" + (f" Lab run #{lab_run_id} ({lab_scenario or 'scenario'})." if lab_run_id else ""),
        ),
    )
    if lab_key:
        _LAB_RUN_INCIDENTS[lab_key] = int(incident_id)
        # Keep the tiny in-memory demo cache bounded across long-running sessions.
        if len(_LAB_RUN_INCIDENTS) > 2000:
            for old_key in list(_LAB_RUN_INCIDENTS)[:500]:
                _LAB_RUN_INCIDENTS.pop(old_key, None)

    raw = json.dumps(
        {
            "method": method,
            "path": path,
            "query_string": query_string,
            "decoded_query_string": unquote_plus(query_string or ""),
            "headers": headers,
            "body": body,
            "decoded_body": unquote_plus(body or ""),
            "source_ip": source_ip,
            "lab_run_id": lab_run_id or None,
            "lab_scenario": lab_scenario or None,
            "detection": detection,
        },
        ensure_ascii=False,
        indent=2,
    )
    hash_value = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    evidence_code = next_code("EV", "digital_evidence", "evidence_code")
    execute(
        """
        INSERT INTO digital_evidence(evidence_code,incident_id,evidence_type,file_path,hash_value,raw_data,notes,captured_at,captured_by)
        VALUES(?,?,?,?,?,?,?,datetime('now'),NULL)
        """,
        (evidence_code, incident_id, "HTTP Request Evidence", None, hash_value, raw, "Captured automatically by NESS passive detector."),
    )
    execute(
        """
        INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at)
        VALUES(?,NULL,NULL,'New','Incident created automatically by detection engine.',datetime('now'))
        """,
        (incident_id,),
    )
    execute(
        """
        INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at)
        VALUES(?,?,?,?,?,NULL,datetime('now'))
        """,
        (incident_id, incident_code, "Created", "New", "Incident created automatically by detection engine."),
    )
    execute(
        """
        INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at)
        VALUES(?,?,?,?,?,NULL,datetime('now'))
        """,
        (incident_id, incident_code, "Evidence Preserved", "New", f"Digital evidence {evidence_code} captured and SHA-256 integrity hash stored."),
    )
    execute(
        "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Security','Detection Engine',?,?,datetime('now'))",
        (f"{detection['attack_type']} detected for {incident_code} from {source_ip}", detection["severity"]),
    )
    return fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,)) or {}
