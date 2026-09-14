from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / ".env")
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

DB_PATH = Path(os.getenv("NESS_DB_PATH", DATA_DIR / "ness.sqlite3"))
if not DB_PATH.is_absolute():
    DB_PATH = BASE_DIR / DB_PATH


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def execute(sql: str, params: tuple[Any, ...] = ()) -> int:
    with get_db() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return int(cur.lastrowid or 0)


def fetch_one(sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with get_db() as conn:
        return row_to_dict(conn.execute(sql, params).fetchone())


def fetch_all(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_db() as conn:
        return rows_to_dicts(conn.execute(sql, params).fetchall())


def get_setting(key: str, default: Any = None) -> str | Any:
    row = fetch_one("SELECT setting_value FROM settings WHERE setting_key=?", (key,))
    if row is not None and row.get("setting_value") is not None:
        return row["setting_value"]
    env_key = key.upper()
    return os.getenv(env_key, default)


def setting_enabled(key: str, default: Any = "false") -> bool:
    value = str(get_setting(key, default)).strip().lower()
    return value in {"1", "true", "yes", "on", "enabled"}


def upsert_setting(key: str, value: Any) -> None:
    if fetch_one("SELECT id FROM settings WHERE setting_key=?", (key,)):
        execute("UPDATE settings SET setting_value=?, updated_at=datetime('now') WHERE setting_key=?", (str(value), key))
    else:
        execute("INSERT INTO settings(setting_key,setting_value,updated_at) VALUES(?,?,datetime('now'))", (key, str(value)))


def init_db(seed: bool = True) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    with get_db() as conn:
        conn.executescript(SCHEMA)
        # Forward-compatible migration for databases created by older NESS builds.
        existing_ai_cols = {row[1] for row in conn.execute("PRAGMA table_info(ai_analysis)").fetchall()}
        migrations = {
            "classification": "TEXT",
            "risk_score": "INTEGER NOT NULL DEFAULT 0",
            "predicted_severity": "TEXT",
            "threat_probability": "REAL",
            "prediction": "TEXT",
            "factors": "TEXT",
            "automatic": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in migrations.items():
            if column not in existing_ai_cols:
                conn.execute(f"ALTER TABLE ai_analysis ADD COLUMN {column} {definition}")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_analysis_incident ON ai_analysis(incident_id, id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_source_created ON incidents(source_ip, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_devices_ip ON network_devices(ip_address)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_devices_status ON network_devices(status,last_seen)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_flows_last_seen ON network_flows(last_seen DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_flows_src ON network_flows(source_ip,last_seen DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_flows_dst ON network_flows(destination_ip,last_seen DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_flows_incident ON network_flows(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_lab_scenario_runs_started ON lab_scenario_runs(started_at DESC)")
        conn.execute("UPDATE network_flows SET classification='Normal' WHERE classification='Observed'")
        conn.commit()
    if seed:
        seed_core_data()


def seed_core_data() -> None:
    """Insert configuration defaults only.

    The project is shipped without sample users, sample targets, incidents, alerts,
    reports, or evidence. The first Administrator account is created through
    the initial setup endpoint or by setting NESS_INITIAL_ADMIN_* environment
    variables before first run.
    """
    defaults = {
        "system_name": "NESS — Network Security & Surveillance System",
        "default_role": "Security Operator",
        "polling_interval": "WebSocket",
        "telegram_enabled": os.getenv("TELEGRAM_ENABLED", "false"),
        "telegram_bot_token": os.getenv("TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("TELEGRAM_CHAT_ID", ""),
        "arduino_enabled": os.getenv("ARDUINO_ENABLED", "true"),
        "arduino_port": os.getenv("ARDUINO_PORT", "AUTO"),
        "arduino_baudrate": os.getenv("ARDUINO_BAUDRATE", "9600"),
        "arduino_policy": "High and Critical",
        "ollama_enabled": os.getenv("OLLAMA_ENABLED", "false"),
        "ollama_model": os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
        "ollama_host": os.getenv("OLLAMA_HOST", "http://localhost:11434"),
        "ai_confidence_threshold": "85%",
        "monitoring_enabled": "true",
        "monitor_all_http_requests": os.getenv("MONITOR_ALL_HTTP_REQUESTS", "true"),
        "realtime_engine_enabled": os.getenv("REALTIME_ENGINE_ENABLED", "true"),
        "auto_ai_enabled": os.getenv("AUTO_AI_ENABLED", "true"),
        "auto_log_analysis_enabled": os.getenv("AUTO_LOG_ANALYSIS_ENABLED", "true"),
        "auto_log_analysis_interval_seconds": os.getenv("AUTO_LOG_ANALYSIS_INTERVAL_SECONDS", "60"),
        "lab_enabled": os.getenv("LAB_ENABLED", "true"),
        "lab_auto_start": os.getenv("LAB_AUTO_START", "true"),
                "lab_event_poll_ms": os.getenv("LAB_EVENT_POLL_MS", "900"),
        "lab_event_cursor": "0",
        "lab_port_scan_threshold": os.getenv("LAB_PORT_SCAN_THRESHOLD", "12"),
        "lab_host_sweep_threshold": os.getenv("LAB_HOST_SWEEP_THRESHOLD", "8"),
        "lab_syn_rate_threshold": os.getenv("LAB_SYN_RATE_THRESHOLD", "80"),
        "lab_icmp_rate_threshold": os.getenv("LAB_ICMP_RATE_THRESHOLD", "40"),
        "network_flow_retention_hours": os.getenv("NETWORK_FLOW_RETENTION_HOURS", "24"),
        "detect_sqli": "true",
        "detect_xss": "true",
        "detect_traversal": "true",
        "detect_rate": "true",
        "report_include_evidence": "true",
        "report_include_ai": "true",
        "report_format": "PDF",
        "two_factor_enabled": "false",
    }
    for key, value in defaults.items():
        if not fetch_one("SELECT id FROM settings WHERE setting_key=?", (key,)):
            execute(
                "INSERT INTO settings(setting_key,setting_value,updated_at) VALUES(?,?,datetime('now'))",
                (key, value),
            )

    # Migration marker for the self-contained integrated cyber-lab build.
    cyber_marker = fetch_one("SELECT setting_value FROM settings WHERE setting_key='cyber_range_schema_version'")
    try:
        cyber_version = int((cyber_marker or {}).get("setting_value") or 0)
    except Exception:
        cyber_version = 0
    if cyber_version < 5:
        if cyber_marker:
            execute("UPDATE settings SET setting_value='5',updated_at=datetime('now') WHERE setting_key='cyber_range_schema_version'")
        else:
            execute("INSERT INTO settings(setting_key,setting_value,updated_at) VALUES('cyber_range_schema_version','5',datetime('now'))")
        # Remove settings that belonged to retired physical-LAN/WSL/VM backends.
        legacy_keys = (
            'network_discovery_enabled','network_discovery_interval_seconds','network_discovery_max_hosts',
            'network_sensor_enabled','network_interface','network_cidr','network_port_scan_threshold',
            'network_host_sweep_threshold','network_syn_flood_threshold','network_icmp_rate_threshold',
            'auto_target_monitor_enabled','auto_target_interval_seconds','lab_wsl_distro','vmware_lab_host','vmware_ssh_user','vmware_ssh_port','vmware_ssh_key'
        )
        for key in legacy_keys:
            execute("DELETE FROM settings WHERE setting_key=?", (key,))
        # Network devices/flows are derived telemetry. Purge records from the retired
        # legacy external backends so the integrated cyber-lab UI starts cleanly.
        execute("DELETE FROM network_flows")
        execute("DELETE FROM network_devices")
        execute("DROP TABLE IF EXISTS monitored_targets")

    # Optional non-hardcoded first-run admin via environment variables.
    # If these values are absent, the database remains user-free and the setup
    # API/UI will create the first Administrator interactively.
    admin_username = os.getenv("NESS_INITIAL_ADMIN_USERNAME", "").strip()
    admin_email = os.getenv("NESS_INITIAL_ADMIN_EMAIL", "").strip()
    admin_password = os.getenv("NESS_INITIAL_ADMIN_PASSWORD", "")
    admin_name = os.getenv("NESS_INITIAL_ADMIN_NAME", "Initial Administrator").strip() or "Initial Administrator"
    if not fetch_one("SELECT id FROM users LIMIT 1") and admin_username and admin_email and len(admin_password) >= 8:
        execute(
            """
            INSERT INTO users(name,email,username,password_hash,role,status,created_at,last_login)
            VALUES(?,?,?,?,?,?,datetime('now'),NULL)
            """,
            (admin_name, admin_email, admin_username, generate_password_hash(admin_password), "Administrator", "Active"),
        )

def next_code(prefix: str, table: str, column: str) -> str:
    year = str(datetime.now().year)
    like = f"{prefix}-{year}-%"
    row = fetch_one(f"SELECT {column} AS code FROM {table} WHERE {column} LIKE ? ORDER BY id DESC LIMIT 1", (like,))
    if row and row.get("code"):
        try:
            n = int(str(row["code"]).split("-")[-1]) + 1
        except Exception:
            n = 1
    else:
        n = 1
    return f"{prefix}-{year}-{n:04d}"


SCHEMA = r"""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Administrator','Security Operator','Security Analyst')),
    status TEXT NOT NULL DEFAULT 'Active',
    created_at TEXT NOT NULL,
    last_login TEXT
);

CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    permission_key TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, permission_key),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code TEXT UNIQUE NOT NULL,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    source_ip TEXT NOT NULL,
    source_country TEXT,
    source_city TEXT,
    target TEXT,
    method TEXT,
    path TEXT,
    query_string TEXT,
    payload TEXT,
    user_agent TEXT,
    description TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT,
    assigned_to INTEGER,
    created_by INTEGER,
    FOREIGN KEY(assigned_to) REFERENCES users(id),
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS digital_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_code TEXT UNIQUE NOT NULL,
    incident_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    file_path TEXT,
    hash_value TEXT NOT NULL,
    raw_data TEXT NOT NULL,
    notes TEXT,
    captured_at TEXT NOT NULL,
    captured_by INTEGER,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(captured_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    alert_channel TEXT NOT NULL,
    alert_priority TEXT NOT NULL,
    alert_message TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    delivery_status TEXT NOT NULL,
    arduino_status TEXT NOT NULL DEFAULT 'Not Configured',
    reviewed INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    model_name TEXT NOT NULL,
    analysis_summary TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    confidence REAL NOT NULL,
    generated_at TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'local',
    classification TEXT,
    risk_score INTEGER NOT NULL DEFAULT 0,
    predicted_severity TEXT,
    threat_probability REAL,
    prediction TEXT,
    factors TEXT,
    automatic INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_code TEXT UNIQUE NOT NULL,
    incident_id INTEGER NOT NULL,
    generated_by INTEGER,
    report_path TEXT NOT NULL,
    report_format TEXT NOT NULL DEFAULT 'PDF',
    generated_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Ready',
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(generated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ints_tracking (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    tracking_code TEXT NOT NULL,
    event_type TEXT NOT NULL,
    status TEXT,
    notes TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS incident_status_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL,
    changed_by INTEGER,
    old_status TEXT,
    new_status TEXT NOT NULL,
    remarks TEXT,
    changed_at TEXT NOT NULL,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY(changed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'Info',
    created_at TEXT NOT NULL
);


CREATE TABLE IF NOT EXISTS log_analysis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_code TEXT UNIQUE NOT NULL,
    time_window_hours INTEGER NOT NULL,
    category_filter TEXT,
    level_filter TEXT,
    log_count INTEGER NOT NULL DEFAULT 0,
    anomaly_count INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    summary TEXT NOT NULL,
    findings TEXT NOT NULL,
    recommendations TEXT NOT NULL,
    model_name TEXT NOT NULL,
    confidence REAL NOT NULL,
    generated_by INTEGER,
    generated_at TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(generated_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS network_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    mac_address TEXT,
    hostname TEXT,
    vendor TEXT,
    device_type TEXT NOT NULL DEFAULT 'Unknown',
    interface TEXT,
    network_cidr TEXT,
    status TEXT NOT NULL DEFAULT 'Online',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    discovery_method TEXT,
    packets_seen INTEGER NOT NULL DEFAULT 0,
    bytes_seen INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS network_flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_key TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    destination_ip TEXT NOT NULL,
    source_port INTEGER,
    destination_port INTEGER,
    protocol TEXT NOT NULL,
    tcp_flags TEXT,
    packets INTEGER NOT NULL DEFAULT 0,
    bytes INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'Normal',
    risk_score INTEGER NOT NULL DEFAULT 0,
    incident_id INTEGER,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS lab_scenario_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_key TEXT NOT NULL,
    scenario_name TEXT NOT NULL,
    category TEXT NOT NULL,
    source_ip TEXT,
    target_ip TEXT,
    status TEXT NOT NULL DEFAULT 'Running',
    result_summary TEXT,
    incident_id INTEGER,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    updated_at TEXT NOT NULL
);
"""
