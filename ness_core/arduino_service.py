from __future__ import annotations

import os
import threading
import time
from typing import Any

from .database import get_setting, setting_enabled

PROTOCOL_ID = "NESS_ALARM_V1"


class ArduinoAlarmController:
    """Persistent, reconnecting serial controller for the NESS physical alarm.

    The configured port may be AUTO. In that mode the controller scans serial
    ports and only accepts a device that responds to the NESS protocol handshake.
    This prevents NESS from sending alarm commands to an unrelated serial device.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._serial: Any | None = None
        self._port: str | None = None
        self._last_error = ""
        self._last_seen = 0.0

    def _enabled(self) -> bool:
        return setting_enabled("arduino_enabled", os.getenv("ARDUINO_ENABLED", "true"))

    def _baudrate(self) -> int:
        try:
            return int(str(get_setting("arduino_baudrate", os.getenv("ARDUINO_BAUDRATE", "9600"))))
        except (TypeError, ValueError):
            return 9600

    def _configured_port(self) -> str:
        return str(get_setting("arduino_port", os.getenv("ARDUINO_PORT", "AUTO")) or "AUTO").strip() or "AUTO"

    def _close_unlocked(self) -> None:
        if self._serial is not None:
            try:
                self._serial.close()
            except Exception:
                pass
        self._serial = None
        self._port = None

    def disconnect(self) -> None:
        with self._lock:
            self._close_unlocked()

    def _candidate_ports(self) -> list[str]:
        configured = self._configured_port()
        if configured.upper() != "AUTO":
            return [configured]
        try:
            from serial.tools import list_ports  # type: ignore
            ports = list(list_ports.comports())
        except Exception as exc:
            self._last_error = f"Serial discovery failed: {exc.__class__.__name__}"
            return []

        preferred, others = [], []
        keywords = ("arduino", "ch340", "ch341", "cp210", "usb serial", "wch", "ftdi")
        for p in ports:
            text = f"{getattr(p, 'description', '')} {getattr(p, 'manufacturer', '')}".lower()
            (preferred if any(k in text for k in keywords) else others).append(p.device)
        return preferred + others

    @staticmethod
    def _read_lines(ser: Any, seconds: float = 1.6) -> list[str]:
        deadline = time.monotonic() + seconds
        lines: list[str] = []
        while time.monotonic() < deadline:
            try:
                raw = ser.readline()
            except Exception:
                break
            if raw:
                text = raw.decode("utf-8", errors="ignore").strip()
                if text:
                    lines.append(text)
            else:
                time.sleep(0.03)
        return lines

    def _handshake(self, ser: Any) -> bool:
        # UNO/Nano boards normally reset when a host opens the serial port.
        time.sleep(1.8)
        try:
            ser.reset_input_buffer()
            ser.write(b"PING\n")
            ser.flush()
        except Exception:
            return False
        lines = self._read_lines(ser, 1.4)
        return any(PROTOCOL_ID in line for line in lines)

    def ensure_connected(self) -> bool:
        if not self._enabled():
            self.disconnect()
            self._last_error = "Arduino integration is disabled"
            return False
        with self._lock:
            if self._serial is not None:
                try:
                    if self._serial.is_open:
                        return True
                except Exception:
                    self._close_unlocked()

            try:
                import serial  # type: ignore
            except Exception as exc:
                self._last_error = f"pyserial unavailable: {exc.__class__.__name__}"
                return False

            candidates = self._candidate_ports()
            if not candidates:
                self._last_error = "Waiting for NESS Arduino (no serial ports detected)"
                return False

            for port in candidates:
                ser = None
                try:
                    ser = serial.Serial(port=port, baudrate=self._baudrate(), timeout=0.25, write_timeout=1)
                    if not self._handshake(ser):
                        ser.close()
                        continue
                    self._serial = ser
                    self._port = port
                    self._last_seen = time.time()
                    self._last_error = ""
                    return True
                except Exception as exc:
                    self._last_error = f"{port}: {exc.__class__.__name__}"
                    try:
                        if ser is not None:
                            ser.close()
                    except Exception:
                        pass
            if self._configured_port().upper() == "AUTO":
                self._last_error = "Serial devices found, but no NESS alarm handshake was received"
            return False

    def _command(self, command: str) -> tuple[bool, str]:
        with self._lock:
            if not self.ensure_connected() or self._serial is None:
                return False, self._last_error or "Arduino unavailable"
            try:
                self._serial.reset_input_buffer()
                self._serial.write((command.strip().upper() + "\n").encode("ascii"))
                self._serial.flush()
                lines = self._read_lines(self._serial, 0.9)
                expected = f"ACK:{command.strip().upper()}"
                if any(expected in line for line in lines):
                    self._last_seen = time.time()
                    return True, "Acknowledged"
                self._last_error = "Command sent, but acknowledgement was not received"
                return False, self._last_error
            except Exception as exc:
                self._last_error = f"Serial communication failed: {exc.__class__.__name__}"
                self._close_unlocked()
                return False, self._last_error

    def trigger(self, severity: str) -> str:
        if not self._enabled():
            return "Disabled"
        policy = str(get_setting("arduino_policy", "High and Critical"))
        sev = (severity or "Medium").strip().lower()
        if policy == "Critical only" and sev != "critical":
            return "Skipped by Policy"
        if policy == "High and Critical" and sev not in {"high", "critical"}:
            return "Skipped by Policy"
        command = "CRITICAL" if sev == "critical" else "ALERT"
        ok, detail = self._command(command)
        return "Triggered" if ok else f"Waiting/Error: {detail}"

    def test(self) -> dict[str, Any]:
        if not self._enabled():
            return {"ok": False, "status": "Disabled", "message": "Enable Arduino integration first."}
        ok, detail = self._command("TEST")
        return {"ok": ok, "status": "Triggered" if ok else "Unavailable", "message": detail, "port": self._port}

    def status(self, connect: bool = True) -> dict[str, Any]:
        if not self._enabled():
            return {"enabled": False, "connected": False, "state": "Disabled", "port": None, "configuredPort": self._configured_port(), "message": "Arduino integration disabled"}
        connected = self.ensure_connected() if connect else bool(self._serial is not None and getattr(self._serial, "is_open", False))
        if connected:
            return {"enabled": True, "connected": True, "state": "Connected", "port": self._port, "configuredPort": self._configured_port(), "message": f"NESS alarm connected on {self._port}", "lastSeen": self._last_seen}
        return {"enabled": True, "connected": False, "state": "Waiting for Arduino", "port": None, "configuredPort": self._configured_port(), "message": self._last_error or "Connect the programmed NESS Arduino by USB"}


_controller = ArduinoAlarmController()


def trigger_arduino_alert(severity: str) -> str:
    return _controller.trigger(severity)


def get_arduino_status(connect: bool = True) -> dict[str, Any]:
    return _controller.status(connect=connect)


def test_arduino_alarm() -> dict[str, Any]:
    return _controller.test()


def reset_arduino_connection() -> None:
    _controller.disconnect()
