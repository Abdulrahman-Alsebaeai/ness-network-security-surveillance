from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import socketserver
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

import requests

from .database import execute, fetch_all, fetch_one, get_setting, next_code, setting_enabled
from .detector import analyze_http_request
from .ai_service import analyze_incident
from .telegram_service import send_telegram_alert
from .arduino_service import trigger_arduino_alert

EmitCallback = Callable[[str, dict | None], None]
IncidentCallback = Callable[[dict], None]

LAB_CIDRS = (
    ipaddress.ip_network("10.10.10.0/24"),
    ipaddress.ip_network("10.10.20.0/24"),
    ipaddress.ip_network("10.10.30.0/24"),
)

SAFE_SCENARIOS = {
    "ping_web": {"name": "Client → Web Connectivity Test", "category": "Normal", "source": "10.10.10.11", "target": "10.10.20.20"},
    "normal_http": {"name": "Normal HTTP Request", "category": "Normal", "source": "10.10.10.11", "target": "10.10.20.20"},
    "send_message": {"name": "Client → Web → Database Message", "category": "Normal", "source": "10.10.10.11", "target": "10.10.20.20"},
    "sql_injection": {"name": "SQL Injection Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "xss": {"name": "Reflected XSS Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "traversal": {"name": "Directory Traversal Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "port_scan": {"name": "TCP Port Scan Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "auth_burst": {"name": "Authentication Burst Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "icmp_burst": {"name": "ICMP Burst Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.20"},
    "host_sweep": {"name": "DMZ Host Sweep Lab Test", "category": "Security", "source": "10.10.10.40", "target": "10.10.20.0/24"},
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_lab_ip(value: str | None) -> bool:
    try:
        addr = ipaddress.ip_address(value or "")
        return any(addr in n for n in LAB_CIDRS)
    except Exception:
        return False


def _int_setting(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(get_setting(key, default)).strip())
    except Exception:
        value = default
    return max(minimum, min(maximum, value))


class _ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _WebHandler(BaseHTTPRequestHandler):
    server_version = "NESS-Embedded-Web/1.0"
    manager: "CyberLabManager"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _source_ip(self) -> str:
        value = self.headers.get("X-NESS-Lab-Source-IP", "10.10.10.11").strip()
        return value if _is_lab_ip(value) else "10.10.10.11"

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except Exception:
            length = 0
        return self.rfile.read(min(length, 65536)) if length > 0 else b""

    def _reply(self, status: int, payload: dict[str, Any] | str, content_type: str = "application/json") -> None:
        if isinstance(payload, str):
            raw = payload.encode("utf-8")
        else:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record_http(self, body: bytes = b"") -> None:
        parsed = urlparse(self.path)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in {"authorization", "cookie"}}
        self.manager._record_http_event(
            source_ip=self._source_ip(),
            method=self.command,
            path=parsed.path or "/",
            query_string=parsed.query or "",
            headers=headers,
            body=body.decode("utf-8", errors="replace"),
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        self.manager._record_packet(self._source_ip(), "10.10.20.20", "TCP", 50000, 8080, "PA", max(64, len(self.path) + 80))
        self._record_http()
        if parsed.path == "/api/health":
            self._reply(200, {"ok": True, "service": "NESS Training Web", "logicalIp": "10.10.20.20", "status": "healthy"})
        elif parsed.path == "/echo":
            q = parse_qs(parsed.query).get("q", [""])[0]
            self._reply(200, f"<html><body>Echo: {q}</body></html>", "text/html")
        elif parsed.path == "/files":
            name = parse_qs(parsed.query).get("name", ["readme.txt"])[0]
            if ".." in name or "%2e%2e" in name.lower():
                self._reply(200, {"ok": True, "file": "training-secret.txt", "content": "NESS-LAB-SECRET=training-only"})
            else:
                self._reply(200, {"ok": True, "file": name, "content": "Disposable NESS lab file"})
        else:
            self._reply(200, {"ok": True, "message": "NESS integrated training web service", "path": parsed.path})
        self.manager._record_packet("10.10.20.20", self._source_ip(), "TCP", 8080, 50000, "PA", 180)

    def do_POST(self) -> None:
        body = self._read_body()
        parsed = urlparse(self.path)
        self.manager._record_packet(self._source_ip(), "10.10.20.20", "TCP", 50001, 8080, "PA", max(80, len(body) + 100))
        self._record_http(body)
        if parsed.path == "/login":
            text = body.decode("utf-8", errors="replace")
            lowered = text.lower()
            bypass = any(x in lowered for x in ("' or 1=1", "' or '1'='1", "union select", "--"))
            if bypass:
                self._reply(200, {"ok": True, "lab": True, "message": "Training login bypass simulated"})
            else:
                self._reply(401, {"ok": False, "message": "Invalid training credentials"})
        elif parsed.path == "/api/messages":
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                data = {}
            message = str(data.get("message") or "")[:500]
            db_result = self.manager._db_request("store_message", {"message": message, "client_ip": self._source_ip()})
            self._reply(200, {"ok": True, "stored": bool(db_result.get("ok")), "message": message})
        else:
            self._reply(200, {"ok": True, "path": parsed.path})
        self.manager._record_packet("10.10.20.20", self._source_ip(), "TCP", 8080, 50001, "PA", 190)


class _DBHandler(socketserver.StreamRequestHandler):
    manager: "CyberLabManager"

    def handle(self) -> None:
        raw = self.rfile.readline(65536)
        try:
            request_obj = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            request_obj = {}
        source_ip = str(request_obj.get("source_ip") or "10.10.20.20")
        operation = str(request_obj.get("operation") or "ping")
        payload = request_obj.get("data") if isinstance(request_obj.get("data"), dict) else {}
        result = self.manager._handle_db_operation(source_ip, operation, payload)
        self.wfile.write((json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8"))


class _UDPEchoHandler(socketserver.BaseRequestHandler):
    manager: "CyberLabManager"

    def handle(self) -> None:
        data, sock = self.request
        try:
            sock.sendto(data, self.client_address)
        except Exception:
            pass


class CyberLabManager:
    """Self-contained NESS training network.

    This build deliberately avoids WSL, VMware, VirtualBox, Docker, Npcap and
    administrator-only packet capture.  The topology is an integrated virtual
    network model inside NESS, while the Web/DB/echo services and scenario I/O
    use real localhost TCP/HTTP/UDP sockets.  Logical lab IPs are attached to
    each virtual device so the rest of the NESS incident/evidence/AI pipeline
    can operate exactly as it does for monitored network events.
    """

    DEVICE_DEFS = [
        {"id": "client", "name": "Client-PC", "hostname": "client.ness.lab", "role": "Employee Workstation", "type": "Workstation", "ip": "10.10.10.11", "mac": "02:42:0a:0a:0a:0b", "network": "10.10.10.0/24", "services": ["HTTP Client", "Messaging Client"]},
        {"id": "attacker", "name": "Security-Test", "hostname": "security-test.ness.lab", "role": "Controlled Security Test", "type": "Testing Host", "ip": "10.10.10.40", "mac": "02:42:0a:0a:0a:28", "network": "10.10.10.0/24", "services": ["Approved Lab Scenarios"]},
        {"id": "gateway", "name": "NESS-Gateway-Sensor", "hostname": "gateway.ness.lab", "role": "Gateway / IDS Sensor", "type": "Security Gateway", "ip": "10.10.10.1", "addresses": ["10.10.10.1", "10.10.20.1", "10.10.30.1"], "mac": "02:42:0a:0a:0a:01", "network": "All Lab Segments", "services": ["Virtual Routing", "Detection", "Flow Aggregation"]},
        {"id": "web", "name": "Web-Server", "hostname": "web.ness.lab", "role": "DMZ Web Server", "type": "Server", "ip": "10.10.20.20", "mac": "02:42:0a:0a:14:14", "network": "10.10.20.0/24", "services": ["HTTP :8080", "Training Web App"]},
        {"id": "db", "name": "Database-Server", "hostname": "db.ness.lab", "role": "Data Service", "type": "Server", "ip": "10.10.30.30", "mac": "02:42:0a:0a:1e:1e", "network": "10.10.30.0/24", "services": ["NESS DB Protocol :5432"]},
    ]

    def __init__(self) -> None:
        self._emit: EmitCallback | None = None
        self._incident_callback: IncidentCallback | None = None
        self._stop = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._lock = threading.RLock()
        self._start_lock = threading.Lock()
        self._flow_lock = threading.RLock()
        self._flows: dict[tuple, dict[str, Any]] = {}
        self._syn_events: dict[str, deque[tuple[float, str, int]]] = defaultdict(lambda: deque(maxlen=4000))
        self._icmp_events: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=4000))
        self._recent_detections: dict[tuple[str, str, str], float] = {}
        self._servers: list[tuple[Any, threading.Thread]] = []
        self._web_port: int | None = None
        self._db_port: int | None = None
        self._udp_port: int | None = None
        self._messages: list[dict[str, Any]] = []
        self._scenario_ctx = threading.local()
        self._state: dict[str, Any] = {
            "started": False,
            "backendReady": True,
            "running": False,
            "sensorState": "Stopped",
            "sensorMessage": "Integrated lab is ready. Press Start Lab.",
            "mode": "Integrated Windows/Python Cyber Lab — No VM, WSL or Docker",
            "packetsCaptured": 0,
            "bytesCaptured": 0,
            "flowsStored": 0,
            "devicesOnline": 0,
            "incidentsDetected": 0,
            "scenarioRuns": 0,
            "normalScenarioRuns": 0,
            "securityScenarioRuns": 0,
            "lastScenario": None,
            "lastScenarioAt": None,
            "lastPacketAt": None,
            "lastSyncAt": None,
            "lastError": None,
            "internetAccess": False,
        }

    # ------------------------ lifecycle / backend ------------------------
    def backend_check(self) -> dict[str, Any]:
        return {
            "ready": True,
            "installed": True,
            "running": bool(self._state.get("running")),
            "sensorRunning": bool(self._state.get("running")),
            "mode": self._state["mode"],
            "internetAccess": False,
            "requiresSetup": False,
            "externalDependencies": [],
        }

    def start(self, emit: EmitCallback | None = None, incident_callback: IncidentCallback | None = None) -> None:
        with self._lock:
            if self._state["started"]:
                if emit:
                    self._emit = emit
                if incident_callback:
                    self._incident_callback = incident_callback
                return
            self._emit = emit
            self._incident_callback = incident_callback
            self._stop.clear()
            self._state["started"] = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, name="NESS-IntegratedLab", daemon=True)
        self._monitor_thread.start()

    def stop_monitor(self) -> None:
        self._stop.set()
        try:
            self.stop_lab()
        except Exception:
            pass
        self._flush_flows(force=True)
        with self._lock:
            self._state["started"] = False

    def start_lab(self) -> dict[str, Any]:
        if not setting_enabled("lab_enabled", "true"):
            raise RuntimeError("Cyber range integration is disabled in Settings.")
        # Auto-start and the Start button can arrive at nearly the same time.
        # Serialize the full startup sequence so services/devices are created once.
        with self._start_lock:
            with self._lock:
                if self._state.get("running"):
                    return self.status()
            self._start_services()
            with self._lock:
                self._state.update({
                    "backendReady": True,
                    "running": True,
                    "sensorState": "Running",
                    "sensorMessage": "Integrated virtual network is running; local TCP/HTTP/UDP service traffic is monitored in real time.",
                    "devicesOnline": len(self.DEVICE_DEFS),
                    "lastError": None,
                    "lastSyncAt": _utc_now(),
                })
            self._sync_devices()
            self._emit_event("lab.started", self.status())
            self._emit_event("lab.status", self.status())
            return self.status()

    def stop_lab(self) -> dict[str, Any]:
        self._stop_services()
        self._flush_flows(force=True)
        with self._lock:
            self._state.update({
                "running": False,
                "sensorState": "Stopped",
                "sensorMessage": "Integrated cyber lab is stopped. Press Start Lab to start it again.",
                "devicesOnline": 0,
                "lastSyncAt": _utc_now(),
            })
        execute("UPDATE network_devices SET status='Offline' WHERE discovery_method='NESS Cyber Range'")
        self._emit_event("lab.stopped", self.status())
        self._emit_event("lab.status", self.status())
        return self.status()

    def reset_lab(self) -> dict[str, Any]:
        self._stop_services()
        with self._lock:
            self._state["running"] = False
            self._state["devicesOnline"] = 0
        with self._flow_lock:
            self._flows.clear()
        self._syn_events.clear()
        self._icmp_events.clear()
        self._recent_detections.clear()
        with self._lock:
            self._state.update({"packetsCaptured": 0, "bytesCaptured": 0, "flowsStored": 0, "lastPacketAt": None, "lastError": None})
        execute("DELETE FROM network_flows")
        execute("UPDATE network_devices SET packets_seen=0,bytes_seen=0,risk_score=0,status='Offline' WHERE discovery_method='NESS Cyber Range'")
        result = self.start_lab()
        self._emit_event("lab.reset", result)
        return result

    def _start_services(self) -> None:
        self._stop_services()
        manager = self

        class WebHandler(_WebHandler):
            pass
        WebHandler.manager = manager
        web = _ReusableHTTPServer(("127.0.0.1", 0), WebHandler)
        self._web_port = int(web.server_address[1])

        class DBHandler(_DBHandler):
            pass
        DBHandler.manager = manager
        db = _ReusableTCPServer(("127.0.0.1", 0), DBHandler)
        self._db_port = int(db.server_address[1])

        class UDPHandler(_UDPEchoHandler):
            pass
        UDPHandler.manager = manager
        udp = _ReusableUDPServer(("127.0.0.1", 0), UDPHandler)
        self._udp_port = int(udp.server_address[1])

        for server, name in ((web, "NESS-Lab-Web"), (db, "NESS-Lab-DB"), (udp, "NESS-Lab-Echo")):
            thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
            thread.start()
            self._servers.append((server, thread))

    def _stop_services(self) -> None:
        servers = list(self._servers)
        self._servers.clear()
        for server, _ in servers:
            try:
                server.shutdown()
            except Exception:
                pass
        for server, _ in servers:
            try:
                server.server_close()
            except Exception:
                pass
        self._web_port = self._db_port = self._udp_port = None

    # ------------------------ topology / devices -------------------------
    def devices(self) -> list[dict[str, Any]]:
        running = bool(self._state.get("running"))
        rows: list[dict[str, Any]] = []
        for item in self.DEVICE_DEFS:
            d = dict(item)
            d["status"] = "Online" if running else "Offline"
            d["namespace"] = "Integrated Device Agent"
            d["implementation"] = "NESS in-process virtual device + real localhost socket I/O"
            rows.append(d)
        return rows

    def topology(self) -> dict[str, Any]:
        running = bool(self._state.get("running"))
        status = "Online" if running else "Offline"
        nodes = [
            {"id": "client", "label": "Client-PC", "kind": "pc", "ip": "10.10.10.11", "x": 105, "y": 125, "status": status, "role": "Employee Workstation", "segment": "Users", "services": ["HTTP Client", "Messaging Client"]},
            {"id": "attacker", "label": "Security-Test", "kind": "attacker", "ip": "10.10.10.40", "x": 105, "y": 360, "status": status, "role": "Controlled Security Test", "segment": "Users", "services": ["Approved Lab Scenarios"]},
            {"id": "sw-users", "label": "Users Switch", "kind": "switch", "ip": "10.10.10.0/24", "x": 330, "y": 245, "status": status, "role": "Virtual L2 Switch", "segment": "Users"},
            {"id": "gateway", "label": "NESS Gateway", "kind": "shield", "ip": "10.10.10.1 / 20.1 / 30.1", "x": 585, "y": 245, "status": status, "role": "Virtual Router + IDS", "segment": "All Segments", "services": ["Routing Model", "Detection", "Flow Aggregation"]},
            {"id": "sw-dmz", "label": "DMZ Switch", "kind": "switch", "ip": "10.10.20.0/24", "x": 815, "y": 135, "status": status, "role": "Virtual L2 Switch", "segment": "DMZ"},
            {"id": "web", "label": "Web Server", "kind": "server", "ip": "10.10.20.20:8080", "x": 1060, "y": 135, "status": status, "role": "Training Web Server", "segment": "DMZ", "services": ["HTTP :8080", "Training Web App"], "runtime": f"127.0.0.1:{self._web_port}" if self._web_port else "Stopped"},
            {"id": "sw-data", "label": "Data Switch", "kind": "switch", "ip": "10.10.30.0/24", "x": 815, "y": 360, "status": status, "role": "Virtual L2 Switch", "segment": "Data"},
            {"id": "db", "label": "Database Server", "kind": "database", "ip": "10.10.30.30:5432", "x": 1060, "y": 360, "status": status, "role": "Training Data Service", "segment": "Data", "services": ["NESS DB Protocol :5432"], "runtime": f"127.0.0.1:{self._db_port}" if self._db_port else "Stopped"},
        ]
        links = [
            {"source": "client", "target": "sw-users", "label": "Virtual Link"},
            {"source": "attacker", "target": "sw-users", "label": "Virtual Link"},
            {"source": "sw-users", "target": "gateway", "label": "10.10.10.0/24"},
            {"source": "gateway", "target": "sw-dmz", "label": "10.10.20.0/24"},
            {"source": "sw-dmz", "target": "web", "label": "HTTP"},
            {"source": "gateway", "target": "sw-data", "label": "10.10.30.0/24"},
            {"source": "sw-data", "target": "db", "label": "DB TCP"},
        ]
        return {"ok": True, "running": running, "nodes": nodes, "links": links, "mode": self._state["mode"]}

    def _sync_devices(self) -> None:
        rows = self.devices()
        online = 0
        for d in rows:
            ip = str(d.get("ip") or "")
            status = d.get("status") or "Offline"
            if status == "Online":
                online += 1
            notes = json.dumps({
                "lab_id": d.get("id"), "role": d.get("role"), "namespace": d.get("namespace"),
                "services": d.get("services") or [], "addresses": d.get("addresses") or [ip],
                "implementation": d.get("implementation"),
            }, ensure_ascii=False)
            execute(
                """INSERT INTO network_devices(ip_address,mac_address,hostname,vendor,device_type,interface,network_cidr,status,first_seen,last_seen,discovery_method,packets_seen,bytes_seen,risk_score,notes)
                   VALUES(?,?,?,NULL,?,'NESS Integrated Lab',?,?,datetime('now'),datetime('now'),'NESS Cyber Range',0,0,0,?)
                   ON CONFLICT(ip_address) DO UPDATE SET
                     mac_address=excluded.mac_address, hostname=excluded.hostname, device_type=excluded.device_type,
                     interface='NESS Integrated Lab', network_cidr=excluded.network_cidr, status=excluded.status,
                     last_seen=datetime('now'), discovery_method='NESS Cyber Range', notes=excluded.notes""",
                (ip, d.get("mac"), d.get("hostname"), d.get("type") or "Unknown", d.get("network"), status, notes),
            )
        with self._lock:
            self._state["devicesOnline"] = online
            self._state["lastSyncAt"] = _utc_now()
        self._emit_event("lab.devices.updated", {"online": online, "devices": rows})

    # ------------------------ scenario execution -------------------------
    def run_scenario(self, key: str) -> dict[str, Any]:
        if key not in SAFE_SCENARIOS:
            raise ValueError("Unknown or disallowed lab scenario")
        if not self._state.get("running"):
            raise RuntimeError("Integrated lab is not running. Press Start Lab first.")
        meta = SAFE_SCENARIOS[key]
        run_id = execute(
            """INSERT INTO lab_scenario_runs(scenario_key,scenario_name,category,source_ip,target_ip,status,started_at)
               VALUES(?,?,?,?,?,'Running',datetime('now'))""",
            (key, meta["name"], meta["category"], meta["source"], meta["target"]),
        )
        self._scenario_ctx.run_id = int(run_id)
        self._scenario_ctx.key = key
        # Scenario runs are independent observations. Do not let rate/scan
        # windows from a previous demo scenario leak into the next one.
        self._syn_events[meta["source"]].clear()
        self._icmp_events[meta["source"]].clear()
        execute(
            "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Cyber Range','NESS Integrated Lab',?,'Info',datetime('now'))",
            (f"Scenario {meta['name']} started ({key}, run #{run_id})",),
        )
        self._emit_event("lab.scenario.started", {"id": run_id, "key": key, **meta})
        try:
            output = self._execute_scenario(key)
            self._flush_flows(force=True)
            linked = fetch_one(
                """SELECT id FROM incidents WHERE source_ip=? AND created_at >= (SELECT started_at FROM lab_scenario_runs WHERE id=?) ORDER BY id DESC LIMIT 1""",
                (meta["source"], run_id),
            )
            execute(
                "UPDATE lab_scenario_runs SET status='Completed',result_summary=?,incident_id=?,finished_at=datetime('now') WHERE id=?",
                (output[-4000:], (linked or {}).get("id"), run_id),
            )
            execute(
                "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Cyber Range','NESS Integrated Lab',?,'Info',datetime('now'))",
                (f"Scenario {meta['name']} completed",),
            )
            with self._lock:
                self._state["scenarioRuns"] = int(self._state.get("scenarioRuns") or 0) + 1
                bucket = "securityScenarioRuns" if meta["category"] == "Security" else "normalScenarioRuns"
                self._state[bucket] = int(self._state.get(bucket) or 0) + 1
                self._state["lastScenario"] = meta["name"]
                self._state["lastScenarioAt"] = _utc_now()
                self._state["lastSyncAt"] = _utc_now()
            integration = self._integration_snapshot(run_id)
            result = {"ok": True, "output": output, "mode": "Integrated Lab", "integration": integration}
            self._emit_event("lab.scenario.completed", {"id": run_id, "key": key, "name": meta["name"], "status": "Completed", "result": result, "integration": integration})
            self._emit_event("data.changed", {"reason": "lab-scenario-completed", "run_id": run_id, "scenario": key, "category": meta["category"], **integration})
            return {"runId": run_id, "meta": meta, **result}
        except Exception as exc:
            execute("UPDATE lab_scenario_runs SET status='Failed',result_summary=?,finished_at=datetime('now') WHERE id=?", (str(exc), run_id))
            self._emit_event("lab.scenario.completed", {"id": run_id, "key": key, "name": meta["name"], "status": "Failed", "error": str(exc)})
            self._emit_event("data.changed", {"reason": "lab-scenario-failed", "run_id": run_id, "scenario": key})
            raise
        finally:
            self._scenario_ctx.run_id = None
            self._scenario_ctx.key = None

    def _execute_scenario(self, key: str) -> str:
        if key == "ping_web":
            return self._scenario_connectivity()
        if key == "normal_http":
            response = self._http_request("10.10.10.11", "GET", "/api/health")
            return f"HTTP {response.status_code}: {response.text[:280]}"
        if key == "send_message":
            response = self._http_request("10.10.10.11", "POST", "/api/messages", json_body={"message": "Hello from NESS Client-PC"})
            return f"Message path Client → Web → DB completed. HTTP {response.status_code}: {response.text[:280]}"
        if key == "sql_injection":
            response = self._http_request("10.10.10.40", "POST", "/login", raw_body="username=admin' OR 1=1 --&password=x", content_type="application/x-www-form-urlencoded")
            return f"SQL injection training request completed. HTTP {response.status_code}: {response.text[:280]}"
        if key == "xss":
            response = self._http_request("10.10.10.40", "GET", "/echo?q=%3Cscript%3Ealert(1)%3C/script%3E")
            return f"Reflected XSS training request completed. HTTP {response.status_code}."
        if key == "traversal":
            response = self._http_request("10.10.10.40", "GET", "/files?name=../../training-secret.txt")
            return f"Traversal training request completed. HTTP {response.status_code}: {response.text[:280]}"
        if key == "port_scan":
            return self._scenario_port_scan()
        if key == "auth_burst":
            codes = []
            for i in range(9):
                r = self._http_request("10.10.10.40", "POST", "/login", raw_body=f"username=test&password=wrong{i}", content_type="application/x-www-form-urlencoded")
                codes.append(str(r.status_code))
                time.sleep(0.02)
            return "Authentication burst completed. Responses: " + ", ".join(codes)
        if key == "icmp_burst":
            return self._scenario_icmp_burst()
        if key == "host_sweep":
            return self._scenario_host_sweep()
        raise ValueError("Unknown scenario")

    def _scenario_connectivity(self) -> str:
        if not self._web_port:
            raise RuntimeError("Web service is not running")
        ok = 0
        for _ in range(4):
            with socket.create_connection(("127.0.0.1", self._web_port), timeout=2):
                ok += 1
            self._record_packet("10.10.10.11", "10.10.20.20", "ICMP", 0, 0, "", 64)
            self._record_packet("10.10.20.20", "10.10.10.11", "ICMP", 0, 0, "", 64)
            time.sleep(0.04)
        return f"Connectivity test passed: {ok}/4 logical echo checks; the underlying reachability used real localhost sockets."

    def _scenario_port_scan(self) -> str:
        if not self._web_port:
            raise RuntimeError("Web service is not running")
        logical_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3306, 5432, 8080, 8443]
        closed = self._find_closed_loopback_port()
        open_ports = []
        for port in logical_ports:
            actual = self._web_port if port == 8080 else closed
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.12)
            result = sock.connect_ex(("127.0.0.1", int(actual)))
            sock.close()
            if result == 0:
                open_ports.append(port)
            self._record_packet("10.10.10.40", "10.10.20.20", "TCP", 51000 + (port % 1000), port, "S", 60)
            time.sleep(0.015)
        return f"Bounded lab scan completed across {len(logical_ports)} logical ports. Open training ports: {open_ports or [8080]}."

    def _scenario_icmp_burst(self) -> str:
        if not self._udp_port:
            raise RuntimeError("Echo service is not running")
        count = max(_int_setting("lab_icmp_rate_threshold", 40, 10, 500) + 2, 42)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        for i in range(count):
            payload = f"NESS-ECHO-{i}".encode()
            try:
                sock.sendto(payload, ("127.0.0.1", self._udp_port))
            except Exception:
                pass
            self._record_packet("10.10.10.40", "10.10.20.20", "ICMP", 0, 0, "", 64)
        sock.close()
        return f"Bounded echo burst completed: {count} logical ICMP events backed by local UDP echo traffic."

    def _scenario_host_sweep(self) -> str:
        threshold = _int_setting("lab_host_sweep_threshold", 8, 4, 100)
        targets = [f"10.10.20.{i}" for i in range(20, 20 + threshold + 2)]
        closed = self._find_closed_loopback_port()
        for target in targets:
            actual = self._web_port if target == "10.10.20.20" else closed
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.08)
            sock.connect_ex(("127.0.0.1", int(actual)))
            sock.close()
            self._record_packet("10.10.10.40", target, "TCP", 52000, 8080, "S", 60)
            time.sleep(0.01)
        return f"Bounded DMZ host sweep completed across {len(targets)} logical addresses."

    def _find_closed_loopback_port(self) -> int:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
        s.close()
        return port

    def _http_request(self, source_ip: str, method: str, path: str, json_body: dict[str, Any] | None = None, raw_body: str | None = None, content_type: str | None = None) -> requests.Response:
        if not self._web_port:
            raise RuntimeError("Integrated web service is not running")
        url = f"http://127.0.0.1:{self._web_port}{path}"
        headers = {"X-NESS-Lab-Source-IP": source_ip, "X-NESS-Lab-Destination-IP": "10.10.20.20", "User-Agent": "NESS-Integrated-Lab/2.0"}
        run_id = getattr(self._scenario_ctx, "run_id", None)
        scenario_key = getattr(self._scenario_ctx, "key", None)
        if run_id:
            headers["X-NESS-Lab-Run-ID"] = str(run_id)
        if scenario_key:
            headers["X-NESS-Lab-Scenario"] = str(scenario_key)
        if content_type:
            headers["Content-Type"] = content_type
        return requests.request(method, url, json=json_body, data=raw_body, headers=headers, timeout=4)

    # ------------------------ real service I/O ---------------------------
    def _db_request(self, operation: str, data: dict[str, Any]) -> dict[str, Any]:
        if not self._db_port:
            raise RuntimeError("Integrated database service is not running")
        request_obj = {"source_ip": "10.10.20.20", "operation": operation, "data": data}
        raw = (json.dumps(request_obj, ensure_ascii=False) + "\n").encode("utf-8")
        self._record_packet("10.10.20.20", "10.10.30.30", "TCP", 53000, 5432, "PA", len(raw) + 60)
        with socket.create_connection(("127.0.0.1", self._db_port), timeout=3) as sock:
            sock.sendall(raw)
            response = b""
            while not response.endswith(b"\n") and len(response) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        self._record_packet("10.10.30.30", "10.10.20.20", "TCP", 5432, 53000, "PA", len(response) + 60)
        try:
            return json.loads(response.decode("utf-8") or "{}")
        except Exception:
            return {"ok": False, "error": "Invalid DB response"}

    def _handle_db_operation(self, source_ip: str, operation: str, data: dict[str, Any]) -> dict[str, Any]:
        if operation == "ping":
            result = {"ok": True, "service": "NESS Training DB", "logicalIp": "10.10.30.30"}
        elif operation == "store_message":
            item = {"id": len(self._messages) + 1, "message": str(data.get("message") or "")[:500], "client_ip": data.get("client_ip"), "stored_at": _utc_now()}
            self._messages.append(item)
            result = {"ok": True, "record": item}
        elif operation == "list_messages":
            result = {"ok": True, "messages": self._messages[-20:]}
        else:
            result = {"ok": False, "error": "Unknown training DB operation"}
        self._emit_event("lab.db.event", {"operation": operation, "source_ip": source_ip, "destination_ip": "10.10.30.30", "ok": bool(result.get("ok")), "time": _utc_now()})
        return result

    # ------------------------ event ingestion / detection ----------------
    def _record_http_event(self, source_ip: str, method: str, path: str, query_string: str, headers: dict[str, str], body: str) -> None:
        event = {
            "kind": "http", "ts": _utc_now(), "source_ip": source_ip, "destination_ip": "10.10.20.20",
            "method": method, "path": path, "query_string": query_string, "headers": headers, "body": body,
        }
        self._ingest_http(event)

    def _record_packet(self, src: str, dst: str, protocol: str, source_port: int, destination_port: int, flags: str, size: int) -> None:
        event = {
            "kind": "packet", "ts": _utc_now(), "source_ip": src, "destination_ip": dst,
            "protocol": protocol, "source_port": source_port or 0, "destination_port": destination_port or 0,
            "tcp_flags": flags, "bytes": max(0, int(size)),
            "lab_run_id": getattr(self._scenario_ctx, "run_id", None),
            "lab_scenario": getattr(self._scenario_ctx, "key", None),
        }
        self._ingest_packet(event)

    def _flow_key(self, event: dict[str, Any]) -> tuple:
        return (
            event.get("source_ip"), event.get("destination_ip"), event.get("protocol"),
            int(event.get("source_port") or 0), int(event.get("destination_port") or 0),
        )

    def _ingest_packet(self, event: dict[str, Any]) -> None:
        src = str(event.get("source_ip") or "")
        dst = str(event.get("destination_ip") or "")
        if not (_is_lab_ip(src) or _is_lab_ip(dst)):
            return
        proto = str(event.get("protocol") or "IP")
        sport = int(event.get("source_port") or 0) or None
        dport = int(event.get("destination_port") or 0) or None
        flags = str(event.get("tcp_flags") or "")
        size = max(0, int(event.get("bytes") or 0))
        now = time.time()
        now_text = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        key = self._flow_key(event)
        with self._flow_lock:
            flow = self._flows.get(key)
            if not flow:
                flow = {
                    "source_ip": src, "destination_ip": dst, "source_port": sport, "destination_port": dport,
                    "protocol": proto, "tcp_flags": flags, "packets": 0, "bytes": 0,
                    "first_seen": now_text, "last_seen": now_text, "started_monotonic": now, "last_update": now,
                    "classification": "Normal", "risk_score": 0, "incident_id": None,
                }
                self._flows[key] = flow
            flow["packets"] += 1
            flow["bytes"] += size
            flow["last_seen"] = now_text
            flow["last_update"] = now
            if flags:
                flow["tcp_flags"] = flags
        with self._lock:
            self._state["packetsCaptured"] += 1
            self._state["bytesCaptured"] += size
            self._state["lastPacketAt"] = event.get("ts") or _utc_now()
        if _is_lab_ip(src):
            execute("UPDATE network_devices SET status='Online',last_seen=datetime('now'),packets_seen=packets_seen+1,bytes_seen=bytes_seen+? WHERE ip_address=?", (size, src))
        detection = self._detect_packet_anomaly(src, dst, proto, dport, flags, now)
        if detection:
            incident = self._create_network_incident(detection, event)
            if incident:
                with self._flow_lock:
                    f = self._flows.get(key)
                    if f:
                        f["classification"] = detection["attack_type"]
                        f["risk_score"] = int(detection.get("risk_score") or 70)
                        f["incident_id"] = incident.get("id")
                with self._lock:
                    self._state["incidentsDetected"] += 1
                self._complete_security_pipeline(incident, "integrated-lab-packet-detection")
                self._notify_incident(incident, "integrated-lab-packet-detection")
                self._emit_event("lab.threat.detected", {
                    "incident_id": incident.get("id"), "incident_code": incident.get("incident_code"),
                    "attack_type": incident.get("attack_type"), "severity": incident.get("severity"),
                    "source_ip": src, "destination_ip": dst, "target": dst,
                })
        self._emit_event("lab.packet", {
            "source_ip": src, "destination_ip": dst, "protocol": proto, "source_port": sport,
            "destination_port": dport, "bytes": size, "tcp_flags": flags, "time": event.get("ts"),
        })

    def _ingest_http(self, event: dict[str, Any]) -> None:
        src = str(event.get("source_ip") or "")
        if not _is_lab_ip(src):
            return
        incident = analyze_http_request(
            str(event.get("method") or "GET"), str(event.get("path") or "/"), str(event.get("query_string") or ""),
            dict(event.get("headers") or {}), str(event.get("body") or ""), src,
        )
        if incident:
            self._mark_http_flow(incident, event)
            self._complete_security_pipeline(incident, "integrated-lab-http-detection")
            self._notify_incident(incident, "integrated-lab-http-detection")
            self._emit_event("lab.http.threat", {
                "incident_id": incident.get("id"), "incident_code": incident.get("incident_code"),
                "attack_type": incident.get("attack_type"), "severity": incident.get("severity"),
                "source_ip": src, "destination_ip": event.get("destination_ip") or "10.10.20.20", "path": event.get("path"),
            })
        else:
            self._emit_event("lab.http", event)

    def _mark_http_flow(self, incident: dict[str, Any], event: dict[str, Any]) -> None:
        src = str(event.get("source_ip") or "")
        dst = str(event.get("destination_ip") or "10.10.20.20")
        attack = str(incident.get("attack_type") or "HTTP Threat")
        severity = str(incident.get("severity") or "Medium")
        risk = {"Critical": 95, "High": 82, "Medium": 60, "Low": 30}.get(severity, 60)
        with self._flow_lock:
            for flow in self._flows.values():
                if flow.get("source_ip") == src and flow.get("destination_ip") == dst and int(flow.get("destination_port") or 0) == 8080:
                    flow["classification"] = attack
                    flow["risk_score"] = risk
                    flow["incident_id"] = incident.get("id")
        row = fetch_one(
            """SELECT id FROM network_flows WHERE source_ip=? AND destination_ip=? AND destination_port=8080
               AND last_seen >= datetime('now','-30 seconds') ORDER BY id DESC LIMIT 1""",
            (src, dst),
        )
        if row:
            execute("UPDATE network_flows SET classification=?,risk_score=?,incident_id=? WHERE id=?", (attack, risk, incident.get("id"), row["id"]))

    def _integration_snapshot(self, run_id: int | None = None) -> dict[str, Any]:
        run = fetch_one("SELECT * FROM lab_scenario_runs WHERE id=?", (int(run_id),)) if run_id else None
        return {
            "runId": int(run_id) if run_id else None,
            "incidentId": (run or {}).get("incident_id"),
            "incidents": int((fetch_one("SELECT COUNT(*) AS c FROM incidents") or {"c": 0})["c"]),
            "alerts": int((fetch_one("SELECT COUNT(*) AS c FROM alerts") or {"c": 0})["c"]),
            "evidence": int((fetch_one("SELECT COUNT(*) AS c FROM digital_evidence") or {"c": 0})["c"]),
            "aiAnalyses": int((fetch_one("SELECT COUNT(*) AS c FROM ai_analysis") or {"c": 0})["c"]),
            "intsEvents": int((fetch_one("SELECT COUNT(*) AS c FROM ints_tracking") or {"c": 0})["c"]),
            "logs": int((fetch_one("SELECT COUNT(*) AS c FROM system_logs") or {"c": 0})["c"]),
            "flows": int((fetch_one("SELECT COUNT(*) AS c FROM network_flows") or {"c": 0})["c"]),
            "devicePackets": int((fetch_one("SELECT COALESCE(SUM(packets_seen),0) AS c FROM network_devices WHERE discovery_method='NESS Cyber Range'") or {"c": 0})["c"]),
        }

    def _complete_security_pipeline(self, incident: dict[str, Any], reason: str) -> None:
        """Synchronously persist every downstream SOC artifact for a lab detection.

        The old build relied on a background callback for alerts and AI. If that
        worker was not running (or the page opened before it completed), Cyber
        Range looked active while the other pages stayed unchanged. Lab events
        now complete the response pipeline before the scenario request returns.
        """
        if not incident or not incident.get("id"):
            return
        incident_id = int(incident["id"])
        # Alert / physical-response record (idempotent per incident).
        alert = fetch_one("SELECT * FROM alerts WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident_id,))
        if not alert:
            message = (
                f"NESS Security Alert\nIncident: {incident.get('incident_code')}\n"
                f"Type: {incident.get('attack_type')}\nSeverity: {incident.get('severity')}\n"
                f"Source IP: {incident.get('source_ip')}\nTarget: {incident.get('target') or incident.get('path') or '-'}\n"
                f"Time: {incident.get('created_at')}"
            )
            try:
                telegram_status = send_telegram_alert(message)
            except Exception as exc:
                telegram_status = f"Error: {exc.__class__.__name__}"
            try:
                arduino_status = trigger_arduino_alert(incident.get("severity", "Medium"))
            except Exception as exc:
                arduino_status = f"Error: {exc.__class__.__name__}"
            channels = ["Dashboard/WebSocket"]
            if telegram_status not in {"Disabled", "Not Configured"}:
                channels.append("Telegram")
            if arduino_status not in {"Disabled", "Not Configured", "Skipped by Policy"}:
                channels.append("Arduino")
            delivery = "Delivered" if telegram_status == "Delivered" else "Stored"
            alert_id = execute(
                """INSERT INTO alerts(incident_id,alert_channel,alert_priority,alert_message,sent_at,delivery_status,arduino_status,reviewed)
                   VALUES(?,?,?,?,datetime('now'),?,?,0)""",
                (incident_id, " + ".join(channels), incident.get("severity") or "Medium", message, delivery, arduino_status),
            )
            execute(
                "INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))",
                (incident_id, incident.get("incident_code"), "Alert Generated", incident.get("status") or "New", f"Automatic lab alert generated. Arduino: {arduino_status}; Telegram: {telegram_status}"),
            )
            alert = fetch_one("SELECT * FROM alerts WHERE id=?", (alert_id,))
            self._emit_event("alert.created", {
                "id": alert_id, "incidentId": incident_id, "incident": incident.get("incident_code"),
                "severity": incident.get("severity"), "delivery": delivery, "arduino": arduino_status,
            })

        # Automatic AI is synchronous for Cyber Range so AI Analysis is updated
        # before the user changes pages. The realtime worker remains as fallback.
        analysis = fetch_one("SELECT * FROM ai_analysis WHERE incident_id=? AND automatic=1 ORDER BY id DESC LIMIT 1", (incident_id,))
        if not analysis:
            try:
                analysis = analyze_incident(incident_id, automatic=True, force=False)
                execute(
                    "INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))",
                    (incident_id, incident.get("incident_code"), "Automatic AI Analysis", incident.get("status") or "New", f"Automatic analysis completed. Risk {analysis.get('risk_score')}/100; predicted severity {analysis.get('predicted_severity')}."),
                )
                execute(
                    "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('AI','NESS Cyber Range',?,?,datetime('now'))",
                    (f"Automatic AI completed for {incident.get('incident_code')} ({analysis.get('classification')}; risk {analysis.get('risk_score')}/100)", analysis.get("predicted_severity") or "Info"),
                )
                self._emit_event("analysis.created", {
                    "incident_id": incident_id, "incident_code": incident.get("incident_code"),
                    "analysis_id": analysis.get("id"), "classification": analysis.get("classification"),
                    "risk_score": analysis.get("risk_score"), "predicted_severity": analysis.get("predicted_severity"),
                    "threat_probability": analysis.get("threat_probability"), "automatic": True, "reason": reason,
                })
            except Exception as exc:
                execute(
                    "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('AI','NESS Cyber Range',?,'High',datetime('now'))",
                    (f"Automatic AI failed for {incident.get('incident_code')}: {exc.__class__.__name__}: {exc}",),
                )
                self._emit_event("automation.error", {"error": f"Automatic AI failed: {exc}"})

        execute("UPDATE incidents SET updated_at=datetime('now') WHERE id=?", (incident_id,))
        self._emit_event("incident.created", {
            "id": incident_id, "incident_code": incident.get("incident_code"),
            "severity": incident.get("severity"), "attack_type": incident.get("attack_type"),
            "source_ip": incident.get("source_ip"), "reason": reason,
        })
        self._emit_event("data.changed", {"reason": reason, "incident_id": incident_id, **self._integration_snapshot()})

    def _notify_incident(self, incident: dict[str, Any], reason: str) -> None:
        cb = self._incident_callback
        if cb and incident and incident.get("id"):
            try:
                cb(incident)
            except Exception:
                pass

    def _trim(self, dq: deque, seconds: float, now: float) -> None:
        while dq and now - dq[0][0] > seconds:
            dq.popleft()

    def _detect_packet_anomaly(self, src: str, dst: str, proto: str, dport: int | None, flags: str, now: float) -> dict[str, Any] | None:
        if not _is_lab_ip(src):
            return None
        if proto == "TCP" and "S" in flags and "A" not in flags:
            events = self._syn_events[src]
            events.append((now, dst, int(dport or 0)))
            self._trim(events, 20.0, now)
            ports: dict[str, set[int]] = defaultdict(set)
            targets: set[str] = set()
            recent_10 = 0
            for ts, target, port in events:
                targets.add(target)
                ports[target].add(port)
                if now - ts <= 10:
                    recent_10 += 1
            port_threshold = _int_setting("lab_port_scan_threshold", 12, 6, 100)
            host_threshold = _int_setting("lab_host_sweep_threshold", 8, 4, 100)
            syn_threshold = _int_setting("lab_syn_rate_threshold", 80, 20, 2000)
            if len(ports.get(dst, set())) >= port_threshold:
                return {"attack_type": "Network Port Scan", "severity": "High", "risk_score": 78, "rule": f"{port_threshold}+ distinct destination ports in 20 seconds", "description": "The integrated lab sensor observed one logical source probing many TCP ports on the same training host."}
            if len(targets) >= host_threshold:
                return {"attack_type": "Host Sweep", "severity": "High", "risk_score": 76, "rule": f"{host_threshold}+ destination hosts in 20 seconds", "description": "The integrated lab sensor observed one logical source probing many training hosts."}
            if recent_10 >= syn_threshold:
                return {"attack_type": "TCP SYN Flood", "severity": "Critical", "risk_score": 92, "rule": f"{syn_threshold}+ SYN events in 10 seconds", "description": "The integrated lab sensor observed an abnormal TCP connection-attempt rate."}
        if proto == "ICMP":
            events = self._icmp_events[src]
            events.append((now, dst))
            self._trim(events, 10.0, now)
            threshold = _int_setting("lab_icmp_rate_threshold", 40, 10, 500)
            if len(events) >= threshold:
                return {"attack_type": "ICMP Flood / Sweep", "severity": "High", "risk_score": 80, "rule": f"{threshold}+ logical echo events in 10 seconds", "description": "The integrated lab observed an abnormal echo-traffic rate from one training source."}
        return None

    def _create_network_incident(self, detection: dict[str, Any], event: dict[str, Any]) -> dict[str, Any] | None:
        src = str(event.get("source_ip") or "")
        dst = str(event.get("destination_ip") or "")
        proto = str(event.get("protocol") or "IP")
        dport = int(event.get("destination_port") or 0) or None
        group_target = "MULTI-HOST" if detection["attack_type"] in {"Host Sweep", "ICMP Flood / Sweep", "TCP SYN Flood"} else dst
        run_id = event.get("lab_run_id") or getattr(self._scenario_ctx, "run_id", None)
        key = (detection["attack_type"], src, group_target, str(run_id or "live"))
        now = time.time()
        if now - self._recent_detections.get(key, 0) < 90:
            return None
        # In the controlled lab each scenario run is a separate observable occurrence.
        # Outside a scenario keep the normal 2-minute de-duplication window.
        if run_id:
            existing = None
        elif group_target == "MULTI-HOST":
            existing = fetch_one(
                """SELECT * FROM incidents WHERE attack_type=? AND source_ip=? AND created_at >= datetime('now','-2 minutes') ORDER BY id DESC LIMIT 1""",
                (detection["attack_type"], src),
            )
        else:
            existing = fetch_one(
                """SELECT * FROM incidents WHERE attack_type=? AND source_ip=? AND target=? AND created_at >= datetime('now','-2 minutes') ORDER BY id DESC LIMIT 1""",
                (detection["attack_type"], src, dst),
            )
        if existing:
            self._recent_detections[key] = now
            return None
        incident_code = next_code("NESS", "incidents", "incident_code")
        payload_obj = {"sensor": "NESS Integrated Lab Sensor", "event": event, "detection": detection, "lab": "Self-contained Python virtual network with localhost socket services", "lab_run_id": run_id, "lab_scenario": event.get("lab_scenario") or getattr(self._scenario_ctx, "key", None)}
        payload = json.dumps(payload_obj, ensure_ascii=False, sort_keys=True)
        incident_id = execute(
            """INSERT INTO incidents(incident_code,attack_type,severity,status,source_ip,source_country,source_city,target,method,path,query_string,payload,user_agent,description,created_at,updated_at,assigned_to,created_by)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),NULL,NULL)""",
            (incident_code, detection["attack_type"], detection["severity"], "New", src, None, None, dst, proto, f"{dst}:{dport}" if dport else dst, "", payload, "NESS Integrated Lab Sensor", f"{detection['description']} Matched rule: {detection['rule']}"),
        )
        raw = json.dumps({**payload_obj, "captured_at": _utc_now()}, ensure_ascii=False, indent=2, sort_keys=True)
        evidence_code = next_code("EV", "digital_evidence", "evidence_code")
        execute(
            """INSERT INTO digital_evidence(evidence_code,incident_id,evidence_type,file_path,hash_value,raw_data,notes,captured_at,captured_by)
               VALUES(?,?,?,?,?,?,?,datetime('now'),NULL)""",
            (evidence_code, incident_id, "Integrated Lab Network Evidence", None, hashlib.sha256(raw.encode()).hexdigest(), raw, "Captured automatically from NESS integrated training-lab telemetry and real local service I/O."),
        )
        execute("INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at) VALUES(?,NULL,NULL,'New','Incident created automatically by the integrated NESS lab detector.',datetime('now'))", (incident_id,))
        execute("INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))", (incident_id, incident_code, "Integrated Lab Threat Detected", "New", f"{detection['attack_type']} detected from controlled lab traffic."))
        execute("INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))", (incident_id, incident_code, "Evidence Preserved", "New", f"Evidence {evidence_code} stored with SHA-256 integrity hash."))
        execute("INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Cyber Range','NESS Integrated Lab',?,?,datetime('now'))", (f"{detection['attack_type']} detected: {src} -> {dst}", detection["severity"]))
        execute("UPDATE network_devices SET risk_score=MAX(risk_score,?),status='Online' WHERE ip_address=?", (int(detection.get("risk_score") or 70), src))
        self._recent_detections[key] = now
        return fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,))

    def _flush_flows(self, force: bool = False) -> None:
        now = time.time()
        ready: list[dict[str, Any]] = []
        with self._flow_lock:
            for key, flow in list(self._flows.items()):
                if force or now - float(flow.get("last_update") or now) >= 0.8 or now - float(flow.get("started_monotonic") or now) >= 4:
                    ready.append(dict(flow))
                    self._flows.pop(key, None)
        for flow in ready:
            flow_key = hashlib.sha1(f"integrated|{flow['source_ip']}|{flow['destination_ip']}|{flow['protocol']}|{flow.get('source_port')}|{flow.get('destination_port')}|{flow['first_seen']}".encode()).hexdigest()
            execute(
                """INSERT INTO network_flows(flow_key,source_ip,destination_ip,source_port,destination_port,protocol,tcp_flags,packets,bytes,first_seen,last_seen,classification,risk_score,incident_id)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (flow_key, flow["source_ip"], flow["destination_ip"], flow.get("source_port"), flow.get("destination_port"), flow["protocol"], flow.get("tcp_flags") or "", int(flow.get("packets") or 0), int(flow.get("bytes") or 0), flow["first_seen"], flow["last_seen"], flow.get("classification") or "Normal", int(flow.get("risk_score") or 0), flow.get("incident_id")),
            )
            with self._lock:
                self._state["flowsStored"] += 1
            self._emit_event("lab.flow", {k: flow.get(k) for k in ("source_ip", "destination_ip", "source_port", "destination_port", "protocol", "packets", "bytes", "classification", "risk_score", "incident_id", "last_seen")})

    # ------------------------ background / state -------------------------
    def _monitor_loop(self) -> None:
        auto_start_attempted = False
        last_devices = 0.0
        last_retention = 0.0
        while not self._stop.is_set():
            try:
                if setting_enabled("lab_enabled", "true") and setting_enabled("lab_auto_start", "true") and not self._state.get("running") and not auto_start_attempted:
                    auto_start_attempted = True
                    self.start_lab()
                if self._state.get("running"):
                    auto_start_attempted = False
                    now = time.time()
                    if now - last_devices >= 5:
                        self._sync_devices()
                        last_devices = now
                    self._flush_flows(force=False)
                    if now - last_retention >= 600:
                        hours = _int_setting("network_flow_retention_hours", 24, 1, 720)
                        execute("DELETE FROM network_flows WHERE last_seen < datetime('now', ?)", (f"-{hours} hours",))
                        last_retention = now
            except Exception as exc:
                with self._lock:
                    self._state["lastError"] = f"Integrated lab monitor: {exc.__class__.__name__}: {exc}"
                    self._state["sensorState"] = "Degraded"
                    self._state["sensorMessage"] = self._state["lastError"]
                self._emit_event("lab.error", {"error": self._state["lastError"]})
            self._stop.wait(0.35)

    def scenario_runs(self, limit: int = 40) -> list[dict[str, Any]]:
        limit = max(1, min(200, int(limit)))
        return fetch_all(
            """SELECT r.*, i.incident_code, i.attack_type, i.severity
               FROM lab_scenario_runs r LEFT JOIN incidents i ON i.id=r.incident_id
               ORDER BY r.id DESC LIMIT ?""",
            (limit,),
        )

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
        state.update({
            "labEnabled": setting_enabled("lab_enabled", "true"),
            "labAutoStart": setting_enabled("lab_auto_start", "true"),
            "eventPollMilliseconds": _int_setting("lab_event_poll_ms", 900, 300, 5000),
            "flowRetentionHours": _int_setting("network_flow_retention_hours", 24, 1, 720),
            "usersCidr": "10.10.10.0/24", "dmzCidr": "10.10.20.0/24", "dataCidr": "10.10.30.0/24",
            "captureScope": "NESS integrated training-network events and real local TCP/HTTP/UDP service I/O",
            "resolvedInterface": "Integrated Virtual Fabric",
            "resolvedCidr": "10.10.10.0/24 + 10.10.20.0/24 + 10.10.30.0/24",
            "webRuntime": f"127.0.0.1:{self._web_port}" if self._web_port else None,
            "dbRuntime": f"127.0.0.1:{self._db_port}" if self._db_port else None,
            "requiresExternalSetup": False,
        })
        return state

    def _emit_event(self, event_type: str, payload: dict | None = None) -> None:
        cb = self._emit
        if cb:
            try:
                cb(event_type, payload or {})
            except Exception:
                pass


_MANAGER = CyberLabManager()


def start_cyber_lab_monitor(emit: EmitCallback | None = None, incident_callback: IncidentCallback | None = None) -> None:
    _MANAGER.start(emit, incident_callback)


def stop_cyber_lab_monitor() -> None:
    _MANAGER.stop_monitor()


def get_cyber_lab_status() -> dict[str, Any]:
    return _MANAGER.status()


def start_cyber_lab() -> dict[str, Any]:
    return _MANAGER.start_lab()


def stop_cyber_lab() -> dict[str, Any]:
    return _MANAGER.stop_lab()


def reset_cyber_lab() -> dict[str, Any]:
    return _MANAGER.reset_lab()


def get_cyber_lab_topology() -> dict[str, Any]:
    return _MANAGER.topology()


def run_cyber_lab_scenario(key: str) -> dict[str, Any]:
    return _MANAGER.run_scenario(key)


def list_cyber_lab_scenarios() -> list[dict[str, Any]]:
    return [{"key": k, **v} for k, v in SAFE_SCENARIOS.items()]


def list_cyber_lab_runs(limit: int = 40) -> list[dict[str, Any]]:
    return _MANAGER.scenario_runs(limit)


def check_cyber_lab_backend() -> dict[str, Any]:
    return _MANAGER.backend_check()
