from __future__ import annotations

import atexit
import queue
import threading
import time
from datetime import datetime
from typing import Callable, Any

from .ai_service import analyze_incident
from .database import execute, fetch_all, fetch_one, get_setting, setting_enabled
from .log_analysis_service import analyze_security_logs
from .cyber_lab_service import start_cyber_lab_monitor, stop_cyber_lab_monitor, get_cyber_lab_status

EmitCallback = Callable[[str, dict | None], None]


def _utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _int_setting(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(get_setting(key, default)).strip())
    except Exception:
        value = default
    return max(minimum, min(maximum, value))


class RealtimeEngine:
    """Background automation engine for NESS.

    It automatically:
    - processes every new incident with the AI/risk engine,
    - classifies and predicts its risk,
    - analyzes new security logs on a schedule,
    - emits all results over the existing WebSocket channel.

    The engine is intentionally defensive. The cyber range is an isolated, disposable
    self-contained integrated training lab. NESS observes the lab
    service traffic and logical network events and automatically sends detections into the
    incident/evidence/AI/alert pipeline.
    """

    def __init__(self) -> None:
        self._emit: EmitCallback | None = None
        self._incident_callback: Callable[[dict], None] | None = None
        self._queue: queue.Queue[tuple[int, str]] = queue.Queue(maxsize=2000)
        self._queued: set[int] = set()
        self._queued_lock = threading.RLock()
        self._stop = threading.Event()
        self._started = False
        self._threads: list[threading.Thread] = []
        self._state_lock = threading.RLock()
        self._state: dict[str, Any] = {
            "started": False,
            "startedAt": None,
            "aiProcessed": 0,
            "aiFailed": 0,
            "lastAiAt": None,
            "lastAiIncidentId": None,
            "logAnalyses": 0,
            "lastLogAnalysisAt": None,
            "lastLogAnalysisCode": None,
            "lastError": None,
        }

    def start(self, emit_callback: EmitCallback | None = None, incident_callback: Callable[[dict], None] | None = None) -> None:
        if self._started:
            if emit_callback:
                self._emit = emit_callback
            if incident_callback:
                self._incident_callback = incident_callback
            return
        if not setting_enabled("realtime_engine_enabled", "true"):
            with self._state_lock:
                self._state["started"] = False
                self._state["lastError"] = "Realtime automation is disabled in settings."
            return

        self._emit = emit_callback
        self._incident_callback = incident_callback
        self._stop.clear()
        self._started = True
        with self._state_lock:
            self._state["started"] = True
            self._state["startedAt"] = _utc_now()
            self._state["lastError"] = None

        self._threads = [
            threading.Thread(target=self._ai_worker, name="NESS-AutoAI", daemon=True),
            threading.Thread(target=self._log_worker, name="NESS-LogAnalyzer", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

        # Start the self-contained cyber-range monitor. No WSL, VM, Docker or packet driver is required.
        try:
            start_cyber_lab_monitor(self._emit, self._incident_callback)
        except Exception as exc:
            self._set_error(f"Cyber range monitor failed to start: {exc.__class__.__name__}: {exc}")

        # Pick up incidents created before this process started or before the
        # automatic engine was introduced.
        for row in fetch_all(
            """
            SELECT i.id
            FROM incidents i
            LEFT JOIN ai_analysis a ON a.incident_id=i.id
            WHERE a.id IS NULL
            ORDER BY i.id ASC
            LIMIT 1000
            """
        ):
            self.enqueue_incident(int(row["id"]), reason="startup-backlog")

        self._emit_event("automation.started", self.status())

    def stop(self) -> None:
        if not self._started:
            return
        self._stop.set()
        try:
            stop_cyber_lab_monitor()
        except Exception:
            pass
        self._started = False
        with self._state_lock:
            self._state["started"] = False
        self._emit_event("automation.stopped", self.status())

    def enqueue_incident(self, incident_id: int, reason: str = "detected") -> bool:
        if not incident_id:
            return False
        # Even if the engine has not started yet, keep the item queued; it will
        # be consumed as soon as app.py starts the engine.
        with self._queued_lock:
            if incident_id in self._queued:
                return False
            # Do not generate duplicate automatic analyses.
            if fetch_one("SELECT id FROM ai_analysis WHERE incident_id=? AND automatic=1 LIMIT 1", (incident_id,)):
                return False
            self._queued.add(incident_id)
        try:
            self._queue.put_nowait((int(incident_id), reason))
            self._emit_event("analysis.queued", {"incident_id": int(incident_id), "reason": reason, "queue_size": self._queue.qsize()})
            return True
        except queue.Full:
            with self._queued_lock:
                self._queued.discard(incident_id)
            self._set_error("Automatic AI queue is full")
            return False

    def status(self) -> dict[str, Any]:
        with self._state_lock:
            state = dict(self._state)
        network = get_cyber_lab_status()
        state.update(
            {
                "queueSize": self._queue.qsize(),
                "realtimeEngineEnabled": setting_enabled("realtime_engine_enabled", "true"),
                "automaticAIEnabled": setting_enabled("auto_ai_enabled", "true"),
                "automaticLogAnalysisEnabled": setting_enabled("auto_log_analysis_enabled", "true"),
                "monitorAllHttpRequests": setting_enabled("monitor_all_http_requests", "true"),
                "logAnalysisIntervalSeconds": _int_setting("auto_log_analysis_interval_seconds", 60, 15, 3600),
                "network": network,
                "cyberRangeEnabled": network.get("labEnabled"),
                "cyberRangeRunning": network.get("running"),
                "networkSensorState": network.get("sensorState"),
                "networkInterface": network.get("resolvedInterface"),
                "networkCidr": network.get("resolvedCidr"),
                "mode": "Fully Automatic / Real-Time + Integrated Cyber Lab",
            }
        )
        return state

    def _emit_event(self, event_type: str, payload: dict | None = None) -> None:
        callback = self._emit
        if not callback:
            return
        try:
            callback(event_type, payload or {})
        except Exception:
            pass

    def _set_error(self, text: str) -> None:
        with self._state_lock:
            self._state["lastError"] = text
        self._emit_event("automation.error", {"error": text})

    def _ai_worker(self) -> None:
        while not self._stop.is_set():
            try:
                incident_id, reason = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                if not setting_enabled("auto_ai_enabled", "true"):
                    continue
                incident = fetch_one("SELECT incident_code,status FROM incidents WHERE id=?", (incident_id,))
                if not incident:
                    continue
                existing = fetch_one("SELECT * FROM ai_analysis WHERE incident_id=? AND automatic=1 ORDER BY id DESC LIMIT 1", (incident_id,))
                analysis = existing or analyze_incident(incident_id, automatic=True, force=False)
                if not existing:
                    execute(
                        """
                        INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at)
                        VALUES(?,?,?,?,?,NULL,datetime('now'))
                        """,
                        (
                            incident_id,
                            incident["incident_code"],
                            "Automatic AI Analysis",
                            incident.get("status"),
                            f"NESS automatically classified and predicted risk using {analysis.get('model_name')}. Risk {analysis.get('risk_score')}/100; predicted severity {analysis.get('predicted_severity')}.",
                        ),
                    )
                    execute(
                        "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('AI','NESS Realtime Engine',?,?,datetime('now'))",
                        (
                            f"Automatic AI analysis completed for {incident['incident_code']} ({analysis.get('classification')}; risk {analysis.get('risk_score')}/100)",
                            analysis.get("predicted_severity") or "Info",
                        ),
                    )
                with self._state_lock:
                    self._state["aiProcessed"] = int(self._state.get("aiProcessed") or 0) + (0 if existing else 1)
                    self._state["lastAiAt"] = _utc_now()
                    self._state["lastAiIncidentId"] = incident_id
                    self._state["lastError"] = None
                self._emit_event(
                    "analysis.created",
                    {
                        "incident_id": incident_id,
                        "incident_code": incident.get("incident_code"),
                        "analysis_id": analysis.get("id"),
                        "classification": analysis.get("classification"),
                        "risk_score": analysis.get("risk_score"),
                        "predicted_severity": analysis.get("predicted_severity"),
                        "threat_probability": analysis.get("threat_probability"),
                        "prediction": analysis.get("prediction"),
                        "automatic": True,
                        "reason": reason,
                    },
                )
            except Exception as exc:
                with self._state_lock:
                    self._state["aiFailed"] = int(self._state.get("aiFailed") or 0) + 1
                self._set_error(f"Automatic AI failed for incident {incident_id}: {exc.__class__.__name__}: {exc}")
            finally:
                with self._queued_lock:
                    self._queued.discard(incident_id)
                self._queue.task_done()

    def _log_worker(self) -> None:
        if self._stop.wait(4.0):
            return
        last_seen_log_id = 0
        while not self._stop.is_set():
            interval = _int_setting("auto_log_analysis_interval_seconds", 60, 15, 3600)
            if setting_enabled("auto_log_analysis_enabled", "true"):
                try:
                    row = fetch_one("SELECT MAX(id) AS max_id FROM system_logs") or {"max_id": 0}
                    max_id = int(row.get("max_id") or 0)
                    # Generate a new analysis only when new logs arrived. This
                    # keeps the database useful instead of producing empty repeats.
                    if max_id > last_seen_log_id:
                        analysis = analyze_security_logs(hours=24, generated_by=None)
                        last_seen_log_id = max_id
                        with self._state_lock:
                            self._state["logAnalyses"] = int(self._state.get("logAnalyses") or 0) + 1
                            self._state["lastLogAnalysisAt"] = _utc_now()
                            self._state["lastLogAnalysisCode"] = analysis.get("analysis_code")
                        self._emit_event(
                            "log_analysis.created",
                            {
                                "analysis_id": analysis.get("id"),
                                "analysis_code": analysis.get("analysis_code"),
                                "risk_score": analysis.get("risk_score"),
                                "automatic": True,
                            },
                        )
                except Exception as exc:
                    self._set_error(f"Automatic log analysis failed: {exc.__class__.__name__}: {exc}")
            if self._stop.wait(interval):
                break


_ENGINE = RealtimeEngine()


def start_realtime_engine(emit_callback: EmitCallback | None = None, incident_callback: Callable[[dict], None] | None = None) -> None:
    _ENGINE.start(emit_callback, incident_callback)


def stop_realtime_engine() -> None:
    _ENGINE.stop()


def enqueue_incident_for_auto_analysis(incident_id: int, reason: str = "detected") -> bool:
    return _ENGINE.enqueue_incident(incident_id, reason)


def get_realtime_status() -> dict[str, Any]:
    return _ENGINE.status()


atexit.register(stop_realtime_engine)
