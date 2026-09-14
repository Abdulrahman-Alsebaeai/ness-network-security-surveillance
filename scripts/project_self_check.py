from __future__ import annotations

import importlib
from importlib import metadata
import sqlite3
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

print("NESS PROJECT SELF-CHECK — INTEGRATED CYBER LAB")
print("=" * 76)
required = ["flask", "flask_sock", "dotenv", "requests", "reportlab", "serial", "werkzeug"]
failed = False
dist_names = {
    "flask": "Flask",
    "flask_sock": "flask-sock",
    "dotenv": "python-dotenv",
    "requests": "requests",
    "reportlab": "reportlab",
    "serial": "pyserial",
    "werkzeug": "Werkzeug",
}
for module in required:
    try:
        importlib.import_module(module)
        try:
            version = metadata.version(dist_names.get(module, module))
        except metadata.PackageNotFoundError:
            version = ""
        print(f"[OK] Python dependency: {module}" + (f" {version}" if version else ""))
    except Exception as exc:
        failed = True
        print(f"[FAIL] Python dependency: {module} ({exc.__class__.__name__}: {exc})")

try:
    from ness_core.database import DB_PATH, init_db, fetch_one
    init_db(seed=True)
    con = sqlite3.connect(DB_PATH)
    integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    print(f"[{'OK' if integrity == 'ok' else 'FAIL'}] SQLite integrity: {integrity}")
    failed = failed or integrity != "ok"
    required_tables = [
        "users", "incidents", "digital_evidence", "alerts", "ai_analysis", "ints_tracking",
        "system_logs", "log_analysis", "settings", "network_devices", "network_flows", "lab_scenario_runs",
    ]
    for table in required_tables:
        exists = con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        print(f"[{'OK' if exists else 'FAIL'}] Table: {table}")
        failed = failed or not bool(exists)
    con.close()

    from ness_core.cyber_lab_service import check_cyber_lab_backend, list_cyber_lab_scenarios, get_cyber_lab_topology
    backend = check_cyber_lab_backend()
    print(f"[{'OK' if backend.get('ready') else 'FAIL'}] Integrated lab backend: {backend.get('mode')}")
    failed = failed or not bool(backend.get("ready"))
    scenarios = list_cyber_lab_scenarios()
    print(f"[OK] Approved local lab scenarios: {len(scenarios)}")
    topology = get_cyber_lab_topology()
    print(f"[OK] Topology definition: {len(topology.get('nodes') or [])} nodes / {len(topology.get('links') or [])} links")

    marker = fetch_one("SELECT setting_value FROM settings WHERE setting_key='cyber_range_schema_version'")
    print(f"[OK] Cyber range schema version: {(marker or {}).get('setting_value') or 'initialized'}")
except Exception as exc:
    failed = True
    print(f"[FAIL] Database/core check: {exc.__class__.__name__}: {exc}")

# Bilingual UI integrity checks
try:
    frontend = BASE / "frontend"
    html_files = sorted(frontend.glob("*.html"))
    missing_bootstrap = []
    missing_i18n = []
    options_without_value = []
    for page in html_files:
        text = page.read_text(encoding="utf-8")
        if 'assets/js/language-bootstrap.js' not in text:
            missing_bootstrap.append(page.name)
        if 'assets/js/i18n.js' not in text:
            missing_i18n.append(page.name)
        import re
        if re.search(r'<option(?![^>]*\bvalue\s*=)[^>]*>', text, flags=re.I):
            options_without_value.append(page.name)
    i18n_text = (frontend / "assets" / "js" / "i18n.js").read_text(encoding="utf-8")
    safe_guard = "current === state.rendered" in i18n_text and "queueScheduled" in i18n_text
    ar_entries = len(re.findall(r'^\s*"(?:\\.|[^"])*"\s*:', i18n_text, flags=re.M))
    print(f"[{'OK' if not missing_bootstrap else 'FAIL'}] Early language bootstrap on all pages")
    print(f"[{'OK' if not missing_i18n else 'FAIL'}] i18n runtime on all pages")
    print(f"[{'OK' if not options_without_value else 'FAIL'}] Stable option values for bilingual selects")
    print(f"[{'OK' if safe_guard else 'FAIL'}] Mutation-loop protection in i18n engine")
    print(f"[OK] Arabic translation entries: {ar_entries}")
    if missing_bootstrap: print("     Missing bootstrap:", ", ".join(missing_bootstrap))
    if missing_i18n: print("     Missing i18n:", ", ".join(missing_i18n))
    if options_without_value: print("     Options without value:", ", ".join(options_without_value))
    failed = failed or bool(missing_bootstrap or missing_i18n or options_without_value or not safe_guard)
except Exception as exc:
    failed = True
    print(f"[FAIL] Bilingual UI check: {exc.__class__.__name__}: {exc}")

print("=" * 76)
print("SELF-CHECK PASSED" if not failed else "SELF-CHECK FOUND A PROBLEM")
raise SystemExit(1 if failed else 0)
