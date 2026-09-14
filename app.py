from __future__ import annotations

import os
import time
import hashlib
import secrets
import json
import threading
from datetime import datetime, timedelta
from pathlib import Path
from functools import wraps
from flask import Flask, jsonify, request, session, send_from_directory, redirect, send_file
from flask_sock import Sock
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

from ness_core.database import DB_PATH, init_db, execute, fetch_all, fetch_one, get_setting, setting_enabled
from ness_core.detector import analyze_http_request
from ness_core.telegram_service import send_telegram_alert
from ness_core.arduino_service import trigger_arduino_alert, get_arduino_status, test_arduino_alarm, reset_arduino_connection
from ness_core.ai_service import analyze_incident
from ness_core.log_analysis_service import analyze_security_logs, get_log_analysis, list_log_analyses
from ness_core.report_service import generate_incident_report
from ness_core.realtime_engine import start_realtime_engine, enqueue_incident_for_auto_analysis, get_realtime_status
from ness_core.cyber_lab_service import (
    get_cyber_lab_status, start_cyber_lab, stop_cyber_lab, reset_cyber_lab,
    get_cyber_lab_topology, run_cyber_lab_scenario, list_cyber_lab_scenarios,
    list_cyber_lab_runs, check_cyber_lab_backend
)

FRONTEND_DIR = BASE_DIR / "frontend"
AUTH_PAGES = {
    "login.html", "forgot-password.html", "reset-password.html", "two-factor.html", "lock-screen.html",
    "index.html", "404.html", "500.html", "access-denied.html", "empty-state.html", "loading.html"
}
PUBLIC_API_PREFIXES = ("/api/auth/login", "/api/auth/logout", "/api/setup/", "/api/auth/forgot-password", "/api/auth/reset-password", "/api/auth/verify-2fa")
PUBLIC_PATH_PREFIXES = ("/assets/", "/watched/", "/favicon.ico")

ROLE_PAGE_ACCESS = {
    "Administrator": "*",
    "Security Operator": {
        "dashboard.html", "incidents.html", "incident-details.html", "alerts.html", "evidence.html", "evidence-details.html",
        "reports.html", "generate-report.html", "report-preview.html", "network-topology.html", "network-devices.html", "network-traffic.html",
        "profile.html", "user-profile.html", "change-password.html", "logs.html", "ints-tracking.html", "access-denied.html",
    },
    "Security Analyst": {
        "dashboard.html", "incidents.html", "incident-details.html", "evidence.html", "evidence-details.html",
        "ai-analysis.html", "logs.html", "ints-tracking.html", "reports.html", "report-preview.html", "network-topology.html", "network-devices.html", "network-traffic.html",
        "profile.html", "user-profile.html", "change-password.html", "alerts.html", "access-denied.html",
    },
}

ROLE_API_ACCESS = {
    "Administrator": "*",
    "Security Operator": {
        "read", "incident_status", "incident_assign", "alert_review", "report_generate", "report_download", "network_manage",
        "profile_update", "password_change", "settings_read"
    },
    "Security Analyst": {
        "read", "ai_analyze", "log_analyze", "report_generate", "report_download", "profile_update", "password_change", "settings_read", "network_manage"
    },
}

PERMISSION_DEFINITIONS = [
    {"key": "read", "label": "View dashboard, incidents, alerts, evidence, logs, and details"},
    {"key": "incident_status", "label": "Update incident status and investigation notes"},
    {"key": "incident_assign", "label": "Assign incidents to users"},
    {"key": "alert_review", "label": "Review and acknowledge alerts"},
    {"key": "report_generate", "label": "Generate incident PDF reports"},
    {"key": "report_download", "label": "Download incident PDF reports"},
    {"key": "ai_analyze", "label": "Run AI analysis and view recommendations"},
    {"key": "log_analyze", "label": "Analyze real security logs and save analysis results"},
    {"key": "network_manage", "label": "Start, stop, reset, and run approved scenarios in the isolated cyber range"},
    {"key": "user_manage", "label": "Create, update, activate, and deactivate users"},
    {"key": "permissions_manage", "label": "Assign roles and per-user permissions"},
    {"key": "settings_read", "label": "View system settings"},
    {"key": "settings_write", "label": "Save system settings"},
    {"key": "profile_update", "label": "Update own profile"},
    {"key": "password_change", "label": "Change own password"},
]

PAGE_PERMISSION_MAP = {
    "dashboard.html": "read",
    "incidents.html": "read",
    "incident-details.html": "read",
    "alerts.html": "read",
    "evidence.html": "read",
    "evidence-details.html": "read",
    "logs.html": "read",
    "ints-tracking.html": "read",
    "reports.html": "read",
    "report-preview.html": "read",
    "generate-report.html": "report_generate",
    "ai-analysis.html": "ai_analyze",
    "network-topology.html": "read",
    "network-devices.html": "read",
    "network-traffic.html": "read",
    "users.html": "user_manage",
    "user-profile.html": "profile_update",
    "profile.html": "profile_update",
    "roles-permissions.html": "permissions_manage",
    "settings.html": "settings_read",
    "change-password.html": "password_change",
}

LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_WINDOW_SECONDS = 5 * 60
LOGIN_MAX_ATTEMPTS = 5

app = Flask(__name__)
sock = Sock()
WS_CLIENTS: set = set()
WS_LOCK = threading.RLock()
configured_secret = os.getenv("FLASK_SECRET_KEY", "").strip()
app.secret_key = configured_secret if configured_secret and configured_secret != "change-this-secret-key" else os.urandom(32).hex()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"},
)
app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 25, "max_message_size": 65536}
sock.init_app(app)



def emit_realtime(event_type: str, payload: dict | None = None) -> None:
    message = json.dumps({"type": event_type, "payload": payload or {}, "time": datetime.utcnow().isoformat(timespec="seconds") + "Z"}, default=str)
    with WS_LOCK:
        clients = list(WS_CLIENTS)
    dead = []
    for ws in clients:
        try:
            ws.send(message)
        except Exception:
            dead.append(ws)
    if dead:
        with WS_LOCK:
            for ws in dead:
                WS_CLIENTS.discard(ws)


@sock.route('/ws/alerts')
def websocket_alerts(ws):
    user = current_user()
    if not user or user.get('status') != 'Active':
        try: ws.close(reason=1008, message='Authentication required')
        except Exception: pass
        return
    with WS_LOCK:
        WS_CLIENTS.add(ws)
    try:
        ws.send(json.dumps({"type": "connected", "payload": {"transport": "WebSocket", "user": user.get("name")}}))
        while True:
            message = ws.receive()
            if message is None:
                break
            if str(message).strip().lower() in {"ping", "{\"type\":\"ping\"}"}:
                ws.send(json.dumps({"type": "pong", "payload": {}}))
    except Exception:
        pass
    finally:
        with WS_LOCK:
            WS_CLIENTS.discard(ws)

def current_user() -> dict | None:
    uid = session.get("user_id")
    return fetch_one("SELECT id,name,email,username,role,status,last_login FROM users WHERE id=?", (uid,)) if uid else None


def role_default_permissions(role: str) -> set[str] | str:
    return ROLE_API_ACCESS.get(role, set())


def custom_user_permissions(user_id: int) -> set[str] | None:
    rows = fetch_all("SELECT permission_key, enabled FROM user_permissions WHERE user_id=?", (user_id,))
    if not rows:
        return None
    return {r["permission_key"] for r in rows if int(r.get("enabled") or 0) == 1 and r["permission_key"] != "__custom__"}


def effective_permissions(user: dict) -> set[str] | str:
    if user.get("role") == "Administrator":
        return "*"
    custom = custom_user_permissions(int(user["id"]))
    if custom is not None:
        return custom
    return role_default_permissions(user.get("role"))


def user_can(permission: str, user: dict | None = None) -> bool:
    user = user or current_user()
    if not user:
        return False
    allowed = effective_permissions(user)
    return allowed == "*" or permission in allowed


def page_allowed(filename: str, user: dict | None) -> bool:
    if filename in AUTH_PAGES:
        return True
    if not user:
        return False
    if user.get("role") == "Administrator":
        return True
    required = PAGE_PERMISSION_MAP.get(filename)
    if required:
        return user_can(required, user)
    allowed = ROLE_PAGE_ACCESS.get(user.get("role"), set())
    return allowed == "*" or filename in allowed



def client_ip() -> str:
    remote = (request.remote_addr or "unknown").strip()
    if os.getenv("TRUST_PROXY_HEADERS", "false").lower() in {"1", "true", "yes", "on"}:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return remote


def login_key(login: str) -> str:
    return f"{client_ip()}:{login.lower()}"


def is_rate_limited(login: str) -> bool:
    key = login_key(login)
    now = time.time()
    attempts = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def record_failed_login(login: str) -> None:
    key = login_key(login)
    now = time.time()
    LOGIN_ATTEMPTS[key] = [t for t in LOGIN_ATTEMPTS.get(key, []) if now - t < LOGIN_WINDOW_SECONDS] + [now]


def clear_failed_logins(login: str) -> None:
    LOGIN_ATTEMPTS.pop(login_key(login), None)


def api_required(permission: str = "read"):
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"ok": False, "error": "Authentication required"}), 401
            if user.get("status") != "Active":
                return jsonify({"ok": False, "error": "Account is not active"}), 403
            if not user_can(permission, user):
                return jsonify({"ok": False, "error": "Access denied for this role"}), 403
            return func(*args, **kwargs)
        return wrapper
    return deco


def log_event(category: str, actor: str, event: str, level: str = "Info") -> None:
    log_id = execute(
        "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES(?,?,?,?,datetime('now'))",
        (category, actor, event, level),
    )
    row = fetch_one("SELECT * FROM system_logs WHERE id=?", (log_id,))
    if row:
        emit_realtime("log.created", map_log(row) if "map_log" in globals() else row)


def record_ints_event(incident_id: int, tracking_code: str, event_type: str, status: str | None = None, notes: str | None = None, created_by: int | None = None) -> None:
    execute(
        """
        INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at)
        VALUES(?,?,?,?,?,?,datetime('now'))
        """,
        (incident_id, tracking_code, event_type, status, notes, created_by),
    )


def should_monitor_http_request(path: str) -> bool:
    if not setting_enabled("monitoring_enabled", "true"):
        return False
    if not setting_enabled("monitor_all_http_requests", "true") and not path.startswith("/watched"):
        return False
    # Static assets and the WebSocket transport itself are not security payloads.
    if path.startswith("/assets/") or path.startswith("/ws/") or path == "/favicon.ico":
        return False
    return True


@app.before_request
def protect_and_monitor():
    path = request.path

    # Fully automatic passive monitoring: every non-static HTTP request received
    # by NESS is inspected in real time. The body is cached so downstream Flask
    # handlers can still read JSON/form data normally.
    if should_monitor_http_request(path):
        headers = {k: v for k, v in request.headers.items()}
        body = request.get_data(as_text=True, cache=True) or ""
        incident = analyze_http_request(
            request.method,
            request.path,
            request.query_string.decode("utf-8", errors="ignore"),
            headers,
            body,
            client_ip(),
        )
        if incident:
            create_alert_for_incident(incident)
            enqueue_incident_for_auto_analysis(int(incident["id"]), reason="real-time-http-detection")

    if path.startswith(PUBLIC_PATH_PREFIXES):
        return None
    if any(path.startswith(p) for p in PUBLIC_API_PREFIXES):
        return None
    if path.startswith("/reports/download"):
        if not current_user():
            return redirect("/login.html")
        return None

    # Protect all API endpoints by default.
    if path.startswith("/api/"):
        if not current_user():
            return jsonify({"ok": False, "error": "Authentication required"}), 401
        return None

    # Protect all application pages.
    if path == "/":
        return None
    if path.endswith(".html") or path.count("/") <= 1:
        filename = path.strip("/") or "login.html"
        if filename not in AUTH_PAGES and not current_user():
            return redirect("/login.html")
        if filename not in AUTH_PAGES and not page_allowed(filename, current_user()):
            return redirect("/access-denied.html")
    return None


def create_alert_for_incident(incident: dict) -> None:
    existing = fetch_one("SELECT id FROM alerts WHERE incident_id=? LIMIT 1", (incident["id"],))
    if existing:
        return
    message = (
        f"🚨 NESS Security Alert\n"
        f"Incident: {incident['incident_code']}\n"
        f"Type: {incident['attack_type']}\n"
        f"Severity: {incident['severity']}\n"
        f"Source IP: {incident['source_ip']}\n"
        f"Path: {incident.get('path') or '-'}\n"
        f"Time: {incident['created_at']}"
    )
    telegram_status = send_telegram_alert(message)
    arduino_status = trigger_arduino_alert(incident.get("severity", "Medium"))
    channels = ["Dashboard/WebSocket"]
    if telegram_status not in {"Disabled", "Not Configured"}:
        channels.append("Telegram")
    if arduino_status not in {"Disabled", "Not Configured", "Skipped by Policy"}:
        channels.append("Arduino")
    delivery_status = "Delivered" if telegram_status == "Delivered" else "Stored"
    alert_id = execute(
        """
        INSERT INTO alerts(incident_id,alert_channel,alert_priority,alert_message,sent_at,delivery_status,arduino_status,reviewed)
        VALUES(?,?,?,?,datetime('now'),?,?,0)
        """,
        (incident["id"], " + ".join(channels), incident["severity"], message, delivery_status, arduino_status),
    )
    record_ints_event(incident["id"], incident["incident_code"], "Alert Generated", incident.get("status"), f"Real-time alert created. Arduino: {arduino_status}; Telegram: {telegram_status}", None)
    alert = fetch_one("SELECT a.*, i.incident_code, i.attack_type FROM alerts a JOIN incidents i ON i.id=a.incident_id WHERE a.id=?", (alert_id,))
    if alert:
        emit_realtime("alert.created", map_alert(alert) if "map_alert" in globals() else alert)
    emit_realtime("incident.created", {"id": incident.get("id"), "incident_code": incident.get("incident_code"), "severity": incident.get("severity"), "attack_type": incident.get("attack_type")})


def handle_network_incident(incident: dict) -> None:
    """Connect integrated cyber-lab detections to the existing NESS response pipeline."""
    if not incident or not incident.get("id"):
        return
    create_alert_for_incident(incident)
    enqueue_incident_for_auto_analysis(int(incident["id"]), reason="cyber-range-detection")


def users_exist() -> bool:
    row = fetch_one("SELECT COUNT(*) AS c FROM users")
    return bool(row and int(row.get("c") or 0) > 0)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@app.route("/api/setup/status")
def api_setup_status():
    return jsonify({"ok": True, "needsSetup": not users_exist()})


@app.route("/api/setup/initial-admin", methods=["POST"])
def api_initial_admin_setup():
    if users_exist():
        return jsonify({"ok": False, "error": "Initial setup has already been completed"}), 409
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not name or not email or not username or len(password) < 8:
        return jsonify({"ok": False, "error": "Name, email, username, and a password of at least 8 characters are required"}), 400
    try:
        user_id = execute(
            """
            INSERT INTO users(name,email,username,password_hash,role,status,created_at,last_login)
            VALUES(?,?,?,?,?,?,datetime('now'),datetime('now'))
            """,
            (name, email, username, generate_password_hash(password), "Administrator", "Active"),
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Could not create initial Administrator: {exc}"}), 400
    session.clear()
    session["user_id"] = user_id
    log_event("Setup", name, "Initial Administrator account created", "Info")
    return jsonify({"ok": True, "user": current_user()})


@app.route("/api/auth/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    user = fetch_one("SELECT id,name,email FROM users WHERE email=? AND status='Active'", (email,)) if email else None
    # Always return ok so account enumeration is not possible.
    if user:
        token = secrets.token_urlsafe(32)
        expires = (datetime.utcnow() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        execute(
            "INSERT INTO password_reset_tokens(user_id,token_hash,created_at,expires_at,used_at) VALUES(?,?,datetime('now'),?,NULL)",
            (user["id"], hash_token(token), expires),
        )
        log_event("Audit", "Password Recovery", f"Password reset token generated for user ID {user['id']}", "Info")
        return jsonify({"ok": True, "message": "If the account exists, a reset token has been generated.", "resetToken": token, "resetUrl": f"/reset-password.html?token={token}"})
    return jsonify({"ok": True, "message": "If the account exists, a reset token has been generated."})


@app.route("/api/auth/reset-password", methods=["POST"])
def api_reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get("token") or ""
    password = data.get("password") or ""
    if len(password) < 8:
        return jsonify({"ok": False, "error": "New password must be at least 8 characters"}), 400
    row = fetch_one(
        """
        SELECT t.*, u.id AS uid FROM password_reset_tokens t JOIN users u ON u.id=t.user_id
        WHERE t.token_hash=? AND t.used_at IS NULL AND t.expires_at > datetime('now') AND u.status='Active'
        """,
        (hash_token(token),),
    )
    if not row:
        return jsonify({"ok": False, "error": "Invalid or expired reset token"}), 400
    execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(password), row["uid"]))
    execute("UPDATE password_reset_tokens SET used_at=datetime('now') WHERE id=?", (row["id"],))
    log_event("Audit", "Password Recovery", f"Password reset completed for user ID {row['uid']}", "Info")
    return jsonify({"ok": True})


@app.route("/api/auth/verify-2fa", methods=["POST"])
def api_verify_2fa():
    data = request.get_json(silent=True) or {}
    code = "".join(str(x) for x in (data.get("code") or "")).strip()
    pending_user_id = session.get("pending_2fa_user_id")
    pending_code = session.get("pending_2fa_code")
    if not pending_user_id or not pending_code:
        return jsonify({"ok": False, "error": "No two-factor verification is pending"}), 400
    if code != pending_code:
        return jsonify({"ok": False, "error": "Invalid verification code"}), 400
    session.pop("pending_2fa_user_id", None)
    session.pop("pending_2fa_code", None)
    session["user_id"] = pending_user_id
    execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (pending_user_id,))
    return jsonify({"ok": True, "user": current_user()})


@app.route("/api/auth/unlock", methods=["POST"])
def api_unlock_session():
    user = current_user()
    if not user:
        return jsonify({"ok": False, "error": "Authentication required"}), 401
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    full = fetch_one("SELECT * FROM users WHERE id=?", (user["id"],))
    if not full or not check_password_hash(full["password_hash"], password):
        return jsonify({"ok": False, "error": "Password is incorrect"}), 400
    return jsonify({"ok": True})


@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or request.form.to_dict()
    login = (data.get("email") or data.get("username") or "").strip()
    password = data.get("password") or ""
    if is_rate_limited(login):
        log_event("Audit", "Anonymous", f"Rate-limited login attempt for {login}", "High")
        return jsonify({"ok": False, "error": "Too many failed login attempts. Please try again later."}), 429
    user = fetch_one("SELECT * FROM users WHERE email=? OR username=?", (login, login))
    if not user or not check_password_hash(user["password_hash"], password):
        record_failed_login(login)
        log_event("Audit", "Anonymous", f"Failed login attempt for {login}", "Medium")
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    clear_failed_logins(login)
    if user["status"] != "Active":
        return jsonify({"ok": False, "error": "Account is not active"}), 403
    session.clear()
    if setting_enabled("two_factor_enabled", "false"):
        code = f"{secrets.randbelow(1000000):06d}"
        session["pending_2fa_user_id"] = user["id"]
        session["pending_2fa_code"] = code
        log_event("Audit", user["name"], "Two-factor verification code generated", "Info")
        # Returned only for local academic deployment/testing; external delivery can be added through Telegram/email settings.
        return jsonify({"ok": True, "requires2FA": True, "verificationCode": code})
    session["user_id"] = user["id"]
    execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
    log_event("Audit", user["name"], "User logged in successfully", "Info")
    return jsonify({"ok": True, "user": current_user()})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
@api_required("read")
def api_me():
    user = current_user()
    perms = effective_permissions(user)
    return jsonify({"ok": True, "user": user, "permissions": sorted(perms) if perms != "*" else ["*"]})


@app.route("/api/dashboard/summary")
@api_required("read")
def api_dashboard_summary():
    total = fetch_one("SELECT COUNT(*) AS c FROM incidents")["c"]
    today = fetch_one("SELECT COUNT(*) AS c FROM incidents WHERE date(created_at)=date('now')")["c"]
    critical = fetch_one("SELECT COUNT(*) AS c FROM incidents WHERE severity='Critical' AND status!='Resolved'")["c"]
    alerts = fetch_one("SELECT COUNT(*) AS c FROM alerts WHERE reviewed=0")["c"]
    devices_online = fetch_one("SELECT COUNT(*) AS c FROM network_devices WHERE status='Online'")["c"]
    flows_24h = fetch_one("SELECT COUNT(*) AS c FROM network_flows WHERE last_seen >= datetime('now','-24 hours')")["c"]
    network_threats = fetch_one("SELECT COUNT(*) AS c FROM incidents WHERE (user_agent='NESS Cyber Range Sensor' OR source_ip LIKE '10.10.%') AND created_at >= datetime('now','-24 hours')")["c"]
    realtime = get_realtime_status()
    network = realtime.get("network") or get_cyber_lab_status()
    return jsonify({
        "ok": True,
        "summary": {
            "totalIncidents": total,
            "todaysAttacks": today,
            "criticalAlerts": critical,
            "cyberRangeNodes": devices_online,
            "unreviewedAlerts": alerts,
            "networkDevicesOnline": devices_online,
            "networkFlows24h": flows_24h,
            "networkThreats24h": network_threats,
            "networkSensor": network.get("sensorState", "Unknown"),
            "networkDiscovery": "Cyber Range Running" if network.get("running") else ("Setup Required" if not network.get("backendReady") else "Cyber Range Stopped"),
            "networkInterface": network.get("resolvedInterface") or "NESS Gateway",
            "networkCidr": network.get("resolvedCidr") or "10.10.0.0/16 (segmented)",
            "telegramStatus": "Configured" if setting_enabled("telegram_enabled", os.getenv("TELEGRAM_ENABLED", "false")) and get_setting("telegram_bot_token", os.getenv("TELEGRAM_BOT_TOKEN", "")) and get_setting("telegram_chat_id", os.getenv("TELEGRAM_CHAT_ID", "")) else ("Enabled" if setting_enabled("telegram_enabled", os.getenv("TELEGRAM_ENABLED", "false")) else "Disabled"),
            "arduinoStatus": get_arduino_status(connect=True).get("state", "Unknown"),
            "aiStatus": "Automatic AI + Ollama" if setting_enabled("ollama_enabled", os.getenv("OLLAMA_ENABLED", "false")) else "Automatic Hybrid AI",
            "automationStatus": "Running" if realtime.get("started") else "Stopped",
            "automaticAI": "Running" if realtime.get("started") and realtime.get("automaticAIEnabled") else "Disabled",
            "automaticLogAnalysis": "Running" if realtime.get("started") and realtime.get("automaticLogAnalysisEnabled") else "Disabled",
            "systemHealth": "Operational / Automatic",
            "liveTransport": "WebSocket",
        },
    })


@app.route("/api/dashboard/charts")
@api_required("read")
def api_dashboard_charts():
    attack_rows = fetch_all("SELECT attack_type AS label, COUNT(*) AS value FROM incidents GROUP BY attack_type ORDER BY value DESC")
    severity_rows = fetch_all("SELECT severity AS label, COUNT(*) AS value FROM incidents GROUP BY severity")
    trend_rows = fetch_all("SELECT strftime('%H:00', created_at) AS label, COUNT(*) AS value FROM incidents WHERE created_at >= datetime('now','-24 hours') GROUP BY strftime('%H', created_at) ORDER BY label")
    return jsonify({"ok": True, "attackTypes": attack_rows, "severities": severity_rows, "trend": trend_rows})


def map_incident(i: dict) -> dict:
    return {
        "id": i["incident_code"], "dbId": i["id"], "time": i["created_at"], "type": i["attack_type"],
        "target": i.get("target") or i.get("path") or "local", "source": i["source_ip"], "severity": i["severity"],
        "status": i["status"], "owner": i.get("owner") or "Unassigned", "path": i.get("path") or "", "method": i.get("method") or "",
    }


def map_alert(a: dict) -> dict:
    return {"id": a["id"], "incidentId": a["incident_id"], "incident": a.get("incident_code"), "time": a["sent_at"], "event": a["alert_message"].replace("\n", " ")[:140], "channel": a["alert_channel"], "delivery": a["delivery_status"], "arduino": a["arduino_status"], "severity": a["alert_priority"], "reviewed": bool(a.get("reviewed"))}


def map_evidence(e: dict) -> dict:
    return {"id": e["evidence_code"], "dbId": e["id"], "incident": e.get("incident_code"), "type": e["evidence_type"], "hash": "SHA256-" + e["hash_value"][:12], "fullHash": e["hash_value"], "collected": e["captured_at"], "custodian": "NESS Engine", "status": "Preserved"}


def map_log(l: dict) -> dict:
    return {"id": l["id"], "time": l["created_at"], "category": l["category"], "actor": l["actor"], "message": l["event"], "level": l["level"]}


def map_target(t: dict) -> dict:
    return {"id": t["id"], "name": t["name"], "url": t["url"], "type": t["target_type"], "ip": t.get("host") or t["url"], "status": t["status"], "health": f"{100 - int(t.get('risk_score') or 0)}%", "riskScore": t.get("risk_score") or 0, "lastScan": t.get("last_checked") or "Never", "lastStatusCode": t.get("last_status_code"), "lastError": t.get("last_error")}


def map_network_device(d: dict) -> dict:
    meta = {}
    try:
        meta = json.loads(d.get("notes") or "{}") if isinstance(d.get("notes"), str) else {}
    except Exception:
        meta = {}
    return {
        "id": d["id"], "ip": d["ip_address"], "mac": d.get("mac_address") or "—", "hostname": d.get("hostname") or "Unknown",
        "type": d.get("device_type") or "Unknown", "interface": d.get("interface") or "NESS Cyber Range", "network": d.get("network_cidr") or "—",
        "status": d.get("status") or "Unknown", "firstSeen": d.get("first_seen"), "lastSeen": d.get("last_seen"),
        "method": d.get("discovery_method") or "NESS Cyber Range", "packets": int(d.get("packets_seen") or 0), "bytes": int(d.get("bytes_seen") or 0),
        "riskScore": int(d.get("risk_score") or 0), "role": meta.get("role") or d.get("device_type") or "Unknown",
        "namespace": meta.get("namespace") or "—", "services": meta.get("services") or [], "addresses": meta.get("addresses") or [d["ip_address"]],
    }


def map_network_flow(f: dict) -> dict:
    return {
        "id": f["id"], "source": f["source_ip"], "destination": f["destination_ip"], "sourcePort": f.get("source_port"),
        "destinationPort": f.get("destination_port"), "protocol": f.get("protocol"), "flags": f.get("tcp_flags") or "",
        "packets": int(f.get("packets") or 0), "bytes": int(f.get("bytes") or 0), "firstSeen": f.get("first_seen"), "lastSeen": f.get("last_seen"),
        "classification": f.get("classification") or "Normal", "riskScore": int(f.get("risk_score") or 0), "incidentId": f.get("incident_id"),
        "incidentCode": f.get("incident_code"),
    }


def map_report(r: dict) -> dict:
    return {"id": r["report_code"], "dbId": r["id"], "incidentId": r["incident_id"], "incident": r.get("incident_code"), "title": f"{r.get('attack_type','Incident')} Report", "period": r["generated_at"], "author": r.get("generated_by_name") or "NESS", "status": r["status"], "downloadUrl": f"/reports/download/{r['id']}"}


def map_user(u: dict) -> dict:
    return {"id": u["id"], "name": u["name"], "email": u["email"], "username": u.get("username") or "", "role": u["role"], "status": u["status"], "last": u.get("last_login") or "Never"}


def map_analysis(a: dict) -> dict:
    probability = a.get("threat_probability")
    return {
        "id": a["id"],
        "incidentId": a["incident_id"],
        "incident": a["incident_code"],
        "model": a["model_name"],
        "confidence": f"{float(a['confidence']) * 100:.1f}%",
        "classification": a.get("classification") or a.get("attack_type") or "Security Event",
        "riskScore": int(a.get("risk_score") or 0),
        "predictedSeverity": a.get("predicted_severity") or "Medium",
        "threatProbability": f"{float(probability or 0) * 100:.1f}%",
        "prediction": a.get("prediction") or "",
        "automatic": bool(a.get("automatic")),
        "source": a.get("source") or "local",
        "result": a["analysis_summary"][:90] + ("..." if len(a["analysis_summary"]) > 90 else ""),
        "summary": a["analysis_summary"],
        "recommendations": a["recommendations"],
        "time": a["generated_at"],
    }


@app.route("/api/ui-revision")
@api_required("read")
def api_ui_revision():
    """Cheap cross-page change detector used as a WebSocket fallback.

    It intentionally includes counters that change for benign traffic as well
    as security records, so every Cyber Range scenario is reflected across open
    NESS pages even when a browser/proxy drops the WebSocket connection.
    """
    tables = {}
    for name in ("incidents", "alerts", "digital_evidence", "ai_analysis", "ints_tracking", "system_logs", "network_flows", "lab_scenario_runs"):
        row = fetch_one(f"SELECT COUNT(*) AS c, COALESCE(MAX(id),0) AS m FROM {name}") or {"c": 0, "m": 0}
        tables[name] = {"count": int(row.get("c") or 0), "maxId": int(row.get("m") or 0)}
    dev = fetch_one("SELECT COUNT(*) AS c, COALESCE(SUM(packets_seen),0) AS p, COALESCE(SUM(bytes_seen),0) AS b, COALESCE(MAX(last_seen),'') AS last FROM network_devices WHERE discovery_method='NESS Cyber Range'") or {}
    lab = get_cyber_lab_status()
    parts = []
    for name in sorted(tables):
        parts.append(f"{name}:{tables[name]['count']}:{tables[name]['maxId']}")
    parts.append(f"devices:{int(dev.get('c') or 0)}:{int(dev.get('p') or 0)}:{int(dev.get('b') or 0)}:{dev.get('last') or ''}")
    parts.append(f"lab:{int(bool(lab.get('running')))}:{int(lab.get('packetsCaptured') or 0)}:{int(lab.get('bytesCaptured') or 0)}:{int(lab.get('scenarioRuns') or 0)}:{lab.get('lastScenarioAt') or ''}")
    revision = hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()
    return jsonify({"ok": True, "revision": revision, "tables": tables, "devices": dev, "lab": lab})


@app.route("/api/ui-data")
@api_required("read")
def api_ui_data():
    incidents = fetch_all("""
        SELECT i.*, COALESCE(u.name,'Unassigned') AS owner
        FROM incidents i LEFT JOIN users u ON u.id=i.assigned_to
        ORDER BY i.id DESC
    """)
    alerts = fetch_all("""
        SELECT a.*, i.incident_code, i.attack_type
        FROM alerts a JOIN incidents i ON i.id=a.incident_id
        ORDER BY a.id DESC
    """)
    evidence = fetch_all("""
        SELECT e.*, i.incident_code
        FROM digital_evidence e JOIN incidents i ON i.id=e.incident_id
        ORDER BY e.id DESC
    """)
    logs = fetch_all("SELECT * FROM system_logs ORDER BY id DESC LIMIT 300")
    network_devices = fetch_all("SELECT * FROM network_devices WHERE discovery_method='NESS Cyber Range' ORDER BY CASE status WHEN 'Online' THEN 0 ELSE 1 END, last_seen DESC LIMIT 500")
    network_flows = fetch_all("""SELECT f.*, i.incident_code FROM network_flows f LEFT JOIN incidents i ON i.id=f.incident_id ORDER BY f.id DESC LIMIT 300""")
    reports = fetch_all("""
        SELECT r.*, i.incident_code, i.attack_type, COALESCE(u.name,'NESS') AS generated_by_name
        FROM incident_reports r JOIN incidents i ON i.id=r.incident_id LEFT JOIN users u ON u.id=r.generated_by
        ORDER BY r.id DESC
    """)
    users = fetch_all("SELECT id,name,email,username,role,status,last_login FROM users ORDER BY id")
    analysis = fetch_all("SELECT a.*, i.incident_code FROM ai_analysis a JOIN incidents i ON i.id=a.incident_id ORDER BY a.id DESC LIMIT 100")
    return jsonify({
        "ok": True,
        "incidents": [map_incident(i) for i in incidents],
        "alerts": [map_alert(a) for a in alerts],
        "evidence": [map_evidence(e) for e in evidence],
        "logs": [map_log(l) for l in logs],
        "networkDevices": [map_network_device(d) for d in network_devices],
        "networkFlows": [map_network_flow(f) for f in network_flows],
        "reports": [map_report(r) for r in reports],
        "users": [map_user(u) for u in users],
        "analysisHistory": [map_analysis(a) for a in analysis],
    })


@app.route("/api/incidents", methods=["GET", "POST"])
@api_required("read")
def api_incidents():
    if request.method == "POST":
        if not user_can("incident_status"):
            return jsonify({"ok": False, "error": "Access denied for this role"}), 403
        data = request.get_json(silent=True) or {}
        required = ["attack_type", "severity", "source_ip", "target", "method", "path", "description"]
        missing = [k for k in required if not str(data.get(k) or "").strip()]
        if missing:
            return jsonify({"ok": False, "error": "Missing required incident fields: " + ", ".join(missing)}), 400
        code = next_incident_code()
        incident_id = execute("""
            INSERT INTO incidents(incident_code,attack_type,severity,status,source_ip,source_country,source_city,target,method,path,query_string,payload,user_agent,description,created_at,updated_at,assigned_to,created_by)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),?,?)
        """, (
            code, data.get("attack_type"), data.get("severity"), data.get("status", "New"),
            data.get("source_ip"), data.get("source_country"), data.get("source_city"),
            data.get("target"), data.get("method"), data.get("path"), data.get("query_string", ""), data.get("payload", ""),
            data.get("user_agent", request.headers.get("User-Agent", "")), data.get("description"), data.get("assigned_to"), session.get("user_id")
        ))
        execute("INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at) VALUES(?,?,NULL,'New','Manual incident created.',datetime('now'))", (incident_id, session.get("user_id")))
        record_ints_event(incident_id, code, "Created", "New", "Manual incident created.", session.get("user_id"))
        log_event("Security", current_user()["name"], f"Manual incident {code} created", "Info")
        emit_realtime("incident.created", {"id": incident_id, "incident_code": code, "severity": data.get("severity"), "attack_type": data.get("attack_type")})
        enqueue_incident_for_auto_analysis(int(incident_id), reason="incident-created")
        return jsonify({"ok": True, "incident": fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,))})

    status = request.args.get("status")
    severity = request.args.get("severity")
    q = request.args.get("q")
    sql = "SELECT i.*, COALESCE(u.name,'Unassigned') AS owner FROM incidents i LEFT JOIN users u ON u.id=i.assigned_to WHERE 1=1"
    params = []
    if status:
        sql += " AND i.status=?"; params.append(status)
    if severity:
        sql += " AND i.severity=?"; params.append(severity)
    if q:
        sql += " AND (i.incident_code LIKE ? OR i.attack_type LIKE ? OR i.source_ip LIKE ? OR i.target LIKE ?)"; params += [f"%{q}%"]*4
    sql += " ORDER BY i.id DESC"
    return jsonify({"ok": True, "incidents": [map_incident(i) for i in fetch_all(sql, tuple(params))]})


def next_incident_code() -> str:
    from ness_core.database import next_code
    return next_code("NESS", "incidents", "incident_code")


@app.route("/api/incidents/<identifier>")
@api_required("read")
def api_incident_details(identifier):
    if identifier == "latest":
        incident = fetch_one("SELECT * FROM incidents ORDER BY id DESC LIMIT 1")
    elif str(identifier).isdigit():
        incident = fetch_one("SELECT * FROM incidents WHERE id=?", (int(identifier),))
    else:
        incident = fetch_one("SELECT * FROM incidents WHERE incident_code=?", (identifier,))
    if not incident:
        return jsonify({"ok": False, "error": "Incident not found"}), 404
    evidence = fetch_all("SELECT * FROM digital_evidence WHERE incident_id=? ORDER BY id DESC", (incident["id"],))
    analysis = fetch_one("SELECT * FROM ai_analysis WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident["id"],))
    history = fetch_all("""
        SELECT h.*, COALESCE(u.name,'NESS Engine') AS changed_by_name
        FROM incident_status_history h LEFT JOIN users u ON u.id=h.changed_by
        WHERE incident_id=? ORDER BY h.id
    """, (incident["id"],))
    ints = fetch_all("""
        SELECT t.*, COALESCE(u.name,'NESS Engine') AS created_by_name
        FROM ints_tracking t LEFT JOIN users u ON u.id=t.created_by
        WHERE t.incident_id=? ORDER BY t.id
    """, (incident["id"],))
    owner = fetch_one("SELECT id,name,email,role FROM users WHERE id=?", (incident.get("assigned_to"),)) if incident.get("assigned_to") else None
    return jsonify({"ok": True, "incident": incident, "evidence": evidence, "analysis": analysis, "history": history, "ints": ints, "owner": owner})


@app.route("/api/ints")
@api_required("read")
def api_ints_tracking():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    sql = """SELECT t.*, i.incident_code, i.attack_type, i.severity, i.source_ip, COALESCE(u.name,'NESS Engine') AS created_by_name FROM ints_tracking t JOIN incidents i ON i.id=t.incident_id LEFT JOIN users u ON u.id=t.created_by WHERE 1=1"""
    params = []
    if q:
        sql += " AND (t.tracking_code LIKE ? OR i.incident_code LIKE ? OR i.attack_type LIKE ? OR t.event_type LIKE ? OR t.notes LIKE ?)"
        params += [f"%{q}%"] * 5
    if status:
        sql += " AND COALESCE(t.status,'')=?"; params.append(status)
    sql += " ORDER BY t.id DESC LIMIT 2000"
    rows = fetch_all(sql, tuple(params))
    return jsonify({"ok": True, "tracking": rows})


@app.route("/api/incidents/<int:incident_id>/ints")
@api_required("read")
def api_incident_ints_tracking(incident_id):
    rows = fetch_all("""SELECT t.*, COALESCE(u.name,'NESS Engine') AS created_by_name FROM ints_tracking t LEFT JOIN users u ON u.id=t.created_by WHERE t.incident_id=? ORDER BY t.id""", (incident_id,))
    return jsonify({"ok": True, "tracking": rows})


@app.route("/api/incidents/<int:incident_id>/status", methods=["POST"])
@api_required("incident_status")
def api_update_incident_status(incident_id):
    data = request.get_json(silent=True) or {}
    new_status = data.get("status", "Under Investigation")
    remarks = data.get("remarks", "Status updated from NESS console")
    old = fetch_one("SELECT status,incident_code FROM incidents WHERE id=?", (incident_id,))
    if not old:
        return jsonify({"ok": False, "error": "Incident not found"}), 404
    execute("UPDATE incidents SET status=?, updated_at=datetime('now') WHERE id=?", (new_status, incident_id))
    execute("""
        INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at)
        VALUES(?,?,?,?,?,datetime('now'))
    """, (incident_id, session.get("user_id"), old["status"], new_status, remarks))
    record_ints_event(incident_id, old["incident_code"], "Status Updated", new_status, remarks, session.get("user_id"))
    log_event("Security", current_user()["name"], f"Incident {old['incident_code']} status updated to {new_status}", "Info")
    emit_realtime("incident.updated", {"incident_id": incident_id, "incident_code": old["incident_code"], "status": new_status})
    return jsonify({"ok": True})


@app.route("/api/incidents/<int:incident_id>/assign", methods=["POST"])
@api_required("incident_assign")
def api_assign_incident(incident_id):
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    if not fetch_one("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        return jsonify({"ok": False, "error": "Incident not found"}), 404
    if user_id and not fetch_one("SELECT id FROM users WHERE id=? AND status='Active'", (int(user_id),)):
        return jsonify({"ok": False, "error": "Assigned user not found or inactive"}), 404
    execute("UPDATE incidents SET assigned_to=?, updated_at=datetime('now') WHERE id=?", (user_id, incident_id))
    code_row = fetch_one("SELECT incident_code FROM incidents WHERE id=?", (incident_id,))
    record_ints_event(incident_id, code_row["incident_code"] if code_row else str(incident_id), "Assigned", "Assigned", f"Incident assigned to user ID {user_id}", session.get("user_id"))
    execute("INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at) VALUES(?,?,NULL,'Assigned',?,datetime('now'))", (incident_id, session.get("user_id"), f"Incident assigned to user ID {user_id}"))
    emit_realtime("incident.updated", {"incident_id": incident_id, "event": "Assigned", "user_id": user_id})
    return jsonify({"ok": True})


@app.route("/api/incidents/<int:incident_id>/notes", methods=["POST"])
@api_required("incident_status")
def api_save_incident_notes(incident_id):
    data = request.get_json(silent=True) or {}
    notes = data.get("notes", "")
    if not fetch_one("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        return jsonify({"ok": False, "error": "Incident not found"}), 404
    execute("UPDATE incidents SET description=?, updated_at=datetime('now') WHERE id=?", (notes, incident_id))
    code_row = fetch_one("SELECT incident_code FROM incidents WHERE id=?", (incident_id,))
    record_ints_event(incident_id, code_row["incident_code"] if code_row else str(incident_id), "Notes Updated", "Notes Updated", "Analyst/operator notes updated.", session.get("user_id"))
    execute("INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at) VALUES(?,?,NULL,'Notes Updated',?,datetime('now'))", (incident_id, session.get("user_id"), "Analyst/operator notes updated."))
    emit_realtime("incident.updated", {"incident_id": incident_id, "event": "Notes Updated"})
    return jsonify({"ok": True})


@app.route("/api/alerts")
@api_required("read")
def api_alerts():
    rows = fetch_all("SELECT a.*, i.incident_code, i.attack_type FROM alerts a JOIN incidents i ON i.id=a.incident_id ORDER BY a.id DESC")
    return jsonify({"ok": True, "alerts": [map_alert(a) for a in rows]})


@app.route("/api/alerts/<int:alert_id>/review", methods=["POST"])
@api_required("alert_review")
def api_review_alert(alert_id):
    alert = fetch_one("SELECT a.*, i.incident_code FROM alerts a JOIN incidents i ON i.id=a.incident_id WHERE a.id=?", (alert_id,))
    if not alert:
        return jsonify({"ok": False, "error": "Alert not found"}), 404
    execute("UPDATE alerts SET reviewed=1, delivery_status='Reviewed' WHERE id=?", (alert_id,))
    record_ints_event(alert["incident_id"], alert["incident_code"], "Alert Reviewed", None, f"Alert {alert_id} reviewed by {current_user()['name']}", session.get("user_id"))
    log_event("Audit", current_user()["name"], f"Alert {alert_id} marked as reviewed", "Info")
    emit_realtime("alert.reviewed", {"alert_id": alert_id, "incident_id": alert["incident_id"]})
    return jsonify({"ok": True})


@app.route("/api/evidence")
@api_required("read")
def api_evidence():
    rows = fetch_all("SELECT e.*, i.incident_code FROM digital_evidence e JOIN incidents i ON i.id=e.incident_id ORDER BY e.id DESC")
    return jsonify({"ok": True, "evidence": [map_evidence(e) for e in rows]})


@app.route("/api/evidence/<identifier>")
@api_required("read")
def api_evidence_details(identifier):
    if str(identifier).isdigit():
        ev = fetch_one("SELECT e.*, i.incident_code, i.attack_type, i.source_ip, i.target FROM digital_evidence e JOIN incidents i ON i.id=e.incident_id WHERE e.id=?", (int(identifier),))
    else:
        ev = fetch_one("SELECT e.*, i.incident_code, i.attack_type, i.source_ip, i.target FROM digital_evidence e JOIN incidents i ON i.id=e.incident_id WHERE e.evidence_code=?", (identifier,))
    if not ev:
        return jsonify({"ok": False, "error": "Evidence not found"}), 404
    return jsonify({"ok": True, "evidence": ev})


@app.route("/api/ai/analyze", methods=["POST"])
@api_required("ai_analyze")
def api_ai_analyze():
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    if not incident_id:
        row = fetch_one("SELECT id FROM incidents ORDER BY id DESC LIMIT 1")
        if not row:
            return jsonify({"ok": False, "error": "No incidents available for analysis"}), 404
        incident_id = row["id"]
    try:
        analysis = analyze_incident(int(incident_id), automatic=False, force=True)
        code_row = fetch_one("SELECT incident_code,status FROM incidents WHERE id=?", (int(incident_id),))
        if code_row:
            record_ints_event(int(incident_id), code_row["incident_code"], "Manual AI Reanalysis", code_row.get("status"), f"Analysis {analysis.get('id')} generated using {analysis.get('model_name')}", session.get("user_id"))
        log_event("AI", current_user()["name"], f"Manual AI reanalysis generated for incident ID {incident_id}", "Info")
        emit_realtime("analysis.created", {"incident_id": int(incident_id), "analysis_id": analysis.get("id")})
        return jsonify({"ok": True, "analysis": analysis})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400



@app.route("/api/log-analysis", methods=["GET", "POST"])
@api_required("read")
def api_log_analysis():
    if request.method == "GET":
        return jsonify({"ok": True, "analyses": list_log_analyses(100)})
    if not user_can("log_analyze"):
        return jsonify({"ok": False, "error": "Security log analysis permission is required"}), 403
    data = request.get_json(silent=True) or {}
    try:
        analysis = analyze_security_logs(
            hours=int(data.get("hours") or 24),
            category=(data.get("category") or "").strip() or None,
            level=(data.get("level") or "").strip() or None,
            generated_by=session.get("user_id"),
        )
        log_event("AI", current_user()["name"], f"Security log analysis {analysis.get('analysis_code')} generated", "Info")
        emit_realtime("log_analysis.created", {"analysis_id": analysis.get("id"), "analysis_code": analysis.get("analysis_code"), "risk_score": analysis.get("risk_score")})
        return jsonify({"ok": True, "analysis": analysis})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/log-analysis/<identifier>")
@api_required("read")
def api_log_analysis_details(identifier):
    analysis = get_log_analysis(identifier)
    if not analysis:
        return jsonify({"ok": False, "error": "Log analysis not found"}), 404
    return jsonify({"ok": True, "analysis": analysis})


@app.route("/api/realtime/status")
@api_required("read")
def api_realtime_status():
    latest = fetch_one(
        """SELECT a.*, i.incident_code FROM ai_analysis a JOIN incidents i ON i.id=a.incident_id ORDER BY a.id DESC LIMIT 1"""
    )
    return jsonify({
        "ok": True,
        "engine": get_realtime_status(),
        "latestAnalysis": map_analysis(latest) if latest else None,
    })


@app.route("/api/network/status")
@api_required("read")
def api_network_status():
    return jsonify({"ok": True, "network": get_cyber_lab_status()})


@app.route("/api/lab/status")
@api_required("read")
def api_lab_status():
    return jsonify({"ok": True, "lab": get_cyber_lab_status(), "backend": check_cyber_lab_backend()})


@app.route("/api/lab/topology")
@api_required("read")
def api_lab_topology():
    topo = get_cyber_lab_topology()
    return jsonify({"ok": bool(topo.get("ok", True)), "topology": topo, "lab": get_cyber_lab_status()})


@app.route("/api/lab/start", methods=["POST"])
@api_required("network_manage")
def api_lab_start():
    try:
        status = start_cyber_lab()
        log_event("Cyber Range", current_user()["name"], "Integrated cyber lab started", "Info")
        emit_realtime("lab.status", status)
        return jsonify({"ok": True, "lab": status})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/lab/stop", methods=["POST"])
@api_required("network_manage")
def api_lab_stop():
    try:
        status = stop_cyber_lab()
        log_event("Cyber Range", current_user()["name"], "Cyber range stopped", "Info")
        emit_realtime("lab.status", status)
        return jsonify({"ok": True, "lab": status})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/lab/reset", methods=["POST"])
@api_required("network_manage")
def api_lab_reset():
    try:
        status = reset_cyber_lab()
        log_event("Cyber Range", current_user()["name"], "Cyber range reset to a clean state", "Info")
        emit_realtime("lab.status", status)
        return jsonify({"ok": True, "lab": status})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/lab/scenarios")
@api_required("read")
def api_lab_scenarios():
    return jsonify({"ok": True, "scenarios": list_cyber_lab_scenarios(), "runs": list_cyber_lab_runs(50)})


@app.route("/api/lab/scenario/<key>", methods=["POST"])
@api_required("network_manage")
def api_lab_run_scenario(key: str):
    try:
        result = run_cyber_lab_scenario(key)
        emit_realtime("data.changed", {
            "reason": "cyber-range-scenario",
            "scenario": key,
            "run_id": result.get("runId"),
            "category": (result.get("meta") or {}).get("category"),
            "integration": result.get("integration") or {},
        })
        return jsonify({"ok": True, "result": result})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/api/network/devices")
@api_required("read")
def api_network_devices():
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "").strip()
    sql = "SELECT * FROM network_devices WHERE discovery_method='NESS Cyber Range'"
    params = []
    if q:
        sql += " AND (ip_address LIKE ? OR mac_address LIKE ? OR hostname LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if status:
        sql += " AND status=?"; params.append(status)
    sql += " ORDER BY CASE status WHEN 'Online' THEN 0 ELSE 1 END, last_seen DESC LIMIT 1000"
    return jsonify({"ok": True, "devices": [map_network_device(d) for d in fetch_all(sql, tuple(params))]})


@app.route("/api/network/traffic")
@api_required("read")
def api_network_traffic():
    try:
        limit = max(1, min(1000, int(request.args.get("limit") or 300)))
    except Exception:
        limit = 300
    protocol = (request.args.get("protocol") or "").strip().upper()
    q = (request.args.get("q") or "").strip()
    sql = "SELECT f.*, i.incident_code FROM network_flows f LEFT JOIN incidents i ON i.id=f.incident_id WHERE 1=1"
    params = []
    if protocol:
        sql += " AND f.protocol=?"; params.append(protocol)
    if q:
        sql += " AND (f.source_ip LIKE ? OR f.destination_ip LIKE ? OR f.classification LIKE ?)"; params.extend([f"%{q}%"]*3)
    sql += " ORDER BY f.id DESC LIMIT ?"; params.append(limit)
    flows = fetch_all(sql, tuple(params))
    return jsonify({"ok": True, "flows": [map_network_flow(f) for f in flows]})


@app.route("/api/network/traffic/summary")
@api_required("read")
def api_network_traffic_summary():
    totals = fetch_one("SELECT COUNT(*) AS flows, COALESCE(SUM(packets),0) AS packets, COALESCE(SUM(bytes),0) AS bytes FROM network_flows WHERE last_seen >= datetime('now','-24 hours')") or {}
    protocols = fetch_all("SELECT protocol, COUNT(*) AS flows, COALESCE(SUM(packets),0) AS packets, COALESCE(SUM(bytes),0) AS bytes FROM network_flows WHERE last_seen >= datetime('now','-24 hours') GROUP BY protocol ORDER BY bytes DESC")
    top_sources = fetch_all("SELECT source_ip, COALESCE(SUM(bytes),0) AS bytes, COALESCE(SUM(packets),0) AS packets FROM network_flows WHERE last_seen >= datetime('now','-24 hours') GROUP BY source_ip ORDER BY bytes DESC LIMIT 10")
    threats = fetch_one("SELECT COUNT(*) AS c FROM network_flows WHERE classification!='Normal' AND last_seen >= datetime('now','-24 hours')") or {"c": 0}
    return jsonify({"ok": True, "summary": {"flows": int(totals.get('flows') or 0), "packets": int(totals.get('packets') or 0), "bytes": int(totals.get('bytes') or 0), "suspiciousFlows": int(threats.get('c') or 0), "protocols": protocols, "topSources": top_sources}})


@app.route("/api/arduino/status")
@api_required("settings_read")
def api_arduino_status():
    return jsonify({"ok": True, "arduino": get_arduino_status(connect=True)})


@app.route("/api/arduino/test", methods=["POST"])
@api_required("settings_write")
def api_arduino_test():
    result = test_arduino_alarm()
    log_event("System", current_user()["name"], f"Arduino alarm test: {result.get('status')}", "Info" if result.get("ok") else "Warning")
    emit_realtime("arduino.status", result)
    return jsonify({"ok": bool(result.get("ok")), "arduino": result, **({} if result.get("ok") else {"error": result.get("message", "Arduino unavailable")})}), (200 if result.get("ok") else 503)

@app.route("/api/reports")
@api_required("read")
def api_reports():
    rows = fetch_all("""
        SELECT r.*, i.incident_code, i.attack_type, COALESCE(u.name,'NESS') AS generated_by_name
        FROM incident_reports r JOIN incidents i ON i.id=r.incident_id LEFT JOIN users u ON u.id=r.generated_by
        ORDER BY r.id DESC
    """)
    return jsonify({"ok": True, "reports": [map_report(r) for r in rows]})


@app.route("/api/reports/<identifier>")
@api_required("read")
def api_report_details(identifier):
    if identifier == "latest":
        report = fetch_one("SELECT * FROM incident_reports ORDER BY id DESC LIMIT 1")
    elif str(identifier).isdigit():
        report = fetch_one("SELECT * FROM incident_reports WHERE id=?", (int(identifier),))
    else:
        report = fetch_one("SELECT * FROM incident_reports WHERE report_code=?", (identifier,))
    if not report:
        return jsonify({"ok": False, "error": "Report not found"}), 404
    incident = fetch_one("SELECT * FROM incidents WHERE id=?", (report["incident_id"],))
    evidence = fetch_all("SELECT * FROM digital_evidence WHERE incident_id=? ORDER BY id", (report["incident_id"],))
    analysis = fetch_one("SELECT * FROM ai_analysis WHERE incident_id=? ORDER BY id DESC LIMIT 1", (report["incident_id"],))
    history = fetch_all("SELECT * FROM incident_status_history WHERE incident_id=? ORDER BY id", (report["incident_id"],))
    return jsonify({"ok": True, "report": report, "incident": incident, "evidence": evidence, "analysis": analysis, "history": history, "downloadUrl": f"/reports/download/{report['id']}"})


@app.route("/api/reports/generate", methods=["POST"])
@api_required("report_generate")
def api_generate_report():
    data = request.get_json(silent=True) or {}
    incident_id = data.get("incident_id")
    if not incident_id:
        row = fetch_one("SELECT id FROM incidents ORDER BY id DESC LIMIT 1")
        if not row:
            return jsonify({"ok": False, "error": "No incidents available for report generation"}), 404
        incident_id = row["id"]
    try:
        report = generate_incident_report(int(incident_id), session.get("user_id"))
        code_row = fetch_one("SELECT incident_code FROM incidents WHERE id=?", (int(incident_id),))
        if code_row:
            record_ints_event(int(incident_id), code_row["incident_code"], "Report Generated", None, f"Generated report {report.get('report_code')}", session.get("user_id"))
        log_event("Report", current_user()["name"], f"Generated report {report.get('report_code')}", "Info")
        emit_realtime("report.created", {"incident_id": int(incident_id), "report_id": report.get("id"), "report_code": report.get("report_code")})
        return jsonify({"ok": True, "report": report, "downloadUrl": f"/reports/download/{report['id']}"})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.route("/reports/download/<int:report_id>")
def download_report(report_id):
    user = current_user()
    if not user:
        return redirect("/login.html")
    if not user_can("report_download", user):
        return redirect("/access-denied.html")
    report = fetch_one("SELECT * FROM incident_reports WHERE id=?", (report_id,))
    if not report:
        return "Report not found", 404
    report_path = Path(report["report_path"])
    if not report_path.exists() or not report_path.is_file():
        return "Report file is missing. Please regenerate the report.", 404
    return send_file(str(report_path), as_attachment=True)


@app.route("/api/users", methods=["GET", "POST"])
@api_required("read")
def api_users():
    if not user_can("user_manage"):
        return jsonify({"ok": False, "error": "Only users with user management permission can manage user accounts"}), 403
    if request.method == "GET":
        return jsonify({"ok": True, "users": [map_user(u) for u in fetch_all("SELECT id,name,email,username,role,status,last_login FROM users ORDER BY id")]})
    data = request.get_json(silent=True) or {}
    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    username = str(data.get("username") or "").strip()
    password = data.get("password") or ""
    if not name or not email or not username or len(password) < 8:
        return jsonify({"ok": False, "error": "Name, email, username, and a password of at least 8 characters are required"}), 400
    configured_default_role = str(get_setting("default_role", "Security Operator"))
    role = data.get("role") if data.get("role") in {"Administrator", "Security Operator", "Security Analyst"} else configured_default_role
    if role not in {"Administrator", "Security Operator", "Security Analyst"}:
        role = "Security Operator"
    status = data.get("status") if data.get("status") in {"Active", "Inactive"} else "Active"
    try:
        user_id = execute("""
            INSERT INTO users(name,email,username,password_hash,role,status,created_at,last_login)
            VALUES(?,?,?,?,?,?,datetime('now'),NULL)
        """, (name, email, username, generate_password_hash(password), role, status))
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Could not create user: {exc}"}), 400
    log_event("Audit", current_user()["name"], f"Created user {email} with role {role}", "Info")
    return jsonify({"ok": True, "user": map_user(fetch_one("SELECT id,name,email,username,role,status,last_login FROM users WHERE id=?", (user_id,)))})


@app.route("/api/users/<int:user_id>", methods=["GET", "PUT", "PATCH"])
@api_required("read")
def api_user_details(user_id):
    if not user_can("user_manage") and current_user().get("id") != user_id:
        return jsonify({"ok": False, "error": "Access denied for this user profile"}), 403
    if request.method == "GET":
        user = fetch_one("SELECT id,name,email,username,role,status,last_login FROM users WHERE id=?", (user_id,))
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        assigned = fetch_all("SELECT incident_code,attack_type,severity,status,created_at FROM incidents WHERE assigned_to=? ORDER BY id DESC", (user_id,))
        return jsonify({"ok": True, "user": map_user(user), "assignedIncidents": assigned})
    if not user_can("user_manage"):
        return jsonify({"ok": False, "error": "Only users with user management permission can update users"}), 403
    data = request.get_json(silent=True) or {}
    user = fetch_one("SELECT * FROM users WHERE id=?", (user_id,))
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    role = data.get("role", user["role"])
    if role not in {"Administrator", "Security Operator", "Security Analyst"}:
        role = user["role"]
    status = data.get("status", user["status"])
    if status not in {"Active", "Inactive"}:
        status = user["status"]
    execute("UPDATE users SET name=?,email=?,username=?,role=?,status=? WHERE id=?", (data.get("name", user["name"]), data.get("email", user["email"]), data.get("username", user["username"]), role, status, user_id))
    if data.get("password"):
        execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(data["password"]), user_id))
    log_event("Audit", current_user()["name"], f"Updated user ID {user_id}", "Info")
    return jsonify({"ok": True, "user": map_user(fetch_one("SELECT id,name,email,username,role,status,last_login FROM users WHERE id=?", (user_id,)))})


@app.route("/api/users/<int:user_id>/status", methods=["POST"])
@api_required("read")
def api_user_status(user_id):
    if not user_can("user_manage"):
        return jsonify({"ok": False, "error": "Only users with user management permission can change account status"}), 403
    data = request.get_json(silent=True) or {}
    status = data.get("status")
    if status not in {"Active", "Inactive"}:
        return jsonify({"ok": False, "error": "Invalid status"}), 400
    execute("UPDATE users SET status=? WHERE id=?", (status, user_id))
    return jsonify({"ok": True})


@app.route("/api/profile", methods=["GET", "PUT", "PATCH"])
@api_required("profile_update")
def api_profile():
    user = current_user()
    if request.method == "GET":
        assigned = fetch_all("SELECT incident_code,attack_type,severity,status,created_at FROM incidents WHERE assigned_to=? ORDER BY id DESC", (user["id"],))
        return jsonify({"ok": True, "user": map_user(user), "assignedIncidents": assigned})
    data = request.get_json(silent=True) or {}
    execute("UPDATE users SET name=?,email=? WHERE id=?", (data.get("name", user["name"]), data.get("email", user["email"]), user["id"]))
    return jsonify({"ok": True, "user": map_user(fetch_one("SELECT id,name,email,username,role,status,last_login FROM users WHERE id=?", (user["id"],)))})


@app.route("/api/profile/password", methods=["POST"])
@api_required("password_change")
def api_change_password():
    user_id = session.get("user_id")
    data = request.get_json(silent=True) or {}
    current = data.get("current_password") or ""
    new = data.get("new_password") or ""
    user = fetch_one("SELECT * FROM users WHERE id=?", (user_id,))
    if not user or not check_password_hash(user["password_hash"], current):
        return jsonify({"ok": False, "error": "Current password is incorrect"}), 400
    if len(new) < 8:
        return jsonify({"ok": False, "error": "New password must be at least 8 characters"}), 400
    execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user_id))
    return jsonify({"ok": True})


@app.route("/api/permissions", methods=["GET"])
@api_required("permissions_manage")
def api_permissions():
    users = fetch_all("SELECT id,name,email,username,role,status,last_login FROM users ORDER BY id")
    user_permission_rows = fetch_all("SELECT user_id,permission_key,enabled FROM user_permissions ORDER BY user_id, permission_key")
    user_permissions: dict[int, list[str]] = {}
    for row in user_permission_rows:
        uid = int(row["user_id"])
        user_permissions.setdefault(uid, [])
        if int(row.get("enabled") or 0) == 1 and row["permission_key"] != "__custom__":
            user_permissions[uid].append(row["permission_key"])
    role_defaults = {}
    for role, permissions in ROLE_API_ACCESS.items():
        role_defaults[role] = ["*"] if permissions == "*" else sorted(permissions)
    return jsonify({
        "ok": True,
        "permissions": PERMISSION_DEFINITIONS,
        "roleDefaults": role_defaults,
        "users": [map_user(u) for u in users],
        "userPermissions": {str(k): v for k, v in user_permissions.items()},
    })


@app.route("/api/permissions/users/<int:user_id>", methods=["POST"])
@api_required("permissions_manage")
def api_save_user_permissions(user_id):
    if not fetch_one("SELECT id FROM users WHERE id=?", (user_id,)):
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = request.get_json(silent=True) or {}
    requested = data.get("permissions") or []
    valid = {p["key"] for p in PERMISSION_DEFINITIONS}
    selected_set = {str(p) for p in requested if str(p) in valid}
    if selected_set & {"incident_status", "incident_assign", "alert_review", "report_generate", "report_download", "ai_analyze", "log_analyze", "network_manage", "user_manage", "permissions_manage", "settings_read", "settings_write"}:
        selected_set.add("read")
    if "settings_write" in selected_set:
        selected_set.add("settings_read")
    selected = sorted(selected_set)
    execute("DELETE FROM user_permissions WHERE user_id=?", (user_id,))
    execute(
        "INSERT INTO user_permissions(user_id,permission_key,enabled,updated_at) VALUES(?,?,0,datetime('now'))",
        (user_id, "__custom__"),
    )
    for permission in selected:
        execute(
            "INSERT INTO user_permissions(user_id,permission_key,enabled,updated_at) VALUES(?,?,1,datetime('now'))",
            (user_id, permission),
        )
    log_event("Audit", current_user()["name"], f"Updated custom permissions for user ID {user_id}", "Info")
    return jsonify({"ok": True, "permissions": selected})


@app.route("/api/permissions/users/<int:user_id>/reset", methods=["POST"])
@api_required("permissions_manage")
def api_reset_user_permissions(user_id):
    execute("DELETE FROM user_permissions WHERE user_id=?", (user_id,))
    log_event("Audit", current_user()["name"], f"Reset permissions for user ID {user_id} to role defaults", "Info")
    return jsonify({"ok": True})


@app.route("/api/settings", methods=["GET", "POST"])
@api_required("settings_read")
def api_settings():
    if request.method == "GET":
        rows = fetch_all("SELECT setting_key,setting_value FROM settings ORDER BY setting_key")
        return jsonify({"ok": True, "settings": {r["setting_key"]: r["setting_value"] for r in rows}})
    if not user_can("settings_write"):
        return jsonify({"ok": False, "error": "Only users with settings permission can save system settings"}), 403
    data = request.get_json(silent=True) or {}
    for k, v in data.items():
        if fetch_one("SELECT id FROM settings WHERE setting_key=?", (k,)):
            execute("UPDATE settings SET setting_value=?, updated_at=datetime('now') WHERE setting_key=?", (str(v), k))
        else:
            execute("INSERT INTO settings(setting_key,setting_value,updated_at) VALUES(?,?,datetime('now'))", (k, str(v)))
    if any(k.startswith("arduino_") for k in data):
        reset_arduino_connection()
    # Cyber-range lifecycle is controlled explicitly from Network Topology.
    # Saving settings never touches a physical LAN or starts the removed legacy sensor.
    if str(data.get("auto_ai_enabled", "")).strip().lower() in {"1","true","yes","on"}:
        for row in fetch_all("""SELECT i.id FROM incidents i LEFT JOIN ai_analysis a ON a.incident_id=i.id AND a.automatic=1 WHERE a.id IS NULL ORDER BY i.id"""):
            enqueue_incident_for_auto_analysis(int(row["id"]), reason="auto-ai-enabled")
    log_event("System", current_user()["name"], "System settings updated", "Info")
    emit_realtime("settings.updated", {"keys": sorted(data.keys())})
    return jsonify({"ok": True})


@app.route("/watched/search")
def watched_search():
    return jsonify({"ok": True, "message": "NESS monitored endpoint received the request.", "query": request.args.to_dict()})


@app.route("/watched/login", methods=["GET", "POST"])
def watched_login_target():
    return jsonify({"ok": True, "message": "NESS monitored login endpoint received the request.", "method": request.method})


@app.route("/watched/file")
def watched_file_target():
    return jsonify({"ok": True, "message": "NESS monitored file endpoint received the request.", "path": request.args.get("path")})


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(FRONTEND_DIR / "assets", filename)


@app.route("/")
def root():
    return redirect("/dashboard.html" if current_user() else "/login.html")


@app.route("/<path:filename>")
def serve_frontend(filename):
    safe = filename if filename else "login.html"
    if (FRONTEND_DIR / safe).exists() and (FRONTEND_DIR / safe).is_file():
        return send_from_directory(FRONTEND_DIR, safe)
    return send_from_directory(FRONTEND_DIR, "404.html"), 404


if __name__ == "__main__":
    init_db(seed=True)
    start_realtime_engine(emit_realtime, handle_network_incident)
    debug_enabled = os.getenv("FLASK_DEBUG", "false").lower() in {"1", "true", "yes", "on"}
    app.run(host="0.0.0.0", port=5000, debug=debug_enabled, use_reloader=False, threaded=True)
