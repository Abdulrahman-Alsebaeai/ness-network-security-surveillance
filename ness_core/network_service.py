from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Any, Callable

from .database import execute, fetch_all, fetch_one, get_setting, next_code, setting_enabled

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover - optional runtime fallback
    psutil = None

try:
    from scapy.all import ARP, Ether, IP, TCP, UDP, ICMP, AsyncSniffer, conf, srp  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - optional runtime fallback
    ARP = Ether = IP = TCP = UDP = ICMP = AsyncSniffer = conf = srp = None
    SCAPY_AVAILABLE = False

EmitCallback = Callable[[str, dict | None], None]
IncidentCallback = Callable[[dict], None]


def _utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _int_setting(key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(str(get_setting(key, default)).strip())
    except Exception:
        value = default
    return max(minimum, min(maximum, value))


def _private_lab_network(cidr: str) -> ipaddress.IPv4Network:
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("NESS network discovery currently supports IPv4 lab networks only")
    # Keep automatic discovery defensive and bounded to local/private ranges.
    if not (network.is_private or network.is_link_local or network.is_loopback):
        raise ValueError("Automatic discovery is restricted to private/local lab networks")
    max_hosts = _int_setting("network_discovery_max_hosts", 256, 8, 1024)
    if max(0, network.num_addresses - 2) > max_hosts:
        raise ValueError(f"Configured network contains more than {max_hosts} hosts; narrow NETWORK_CIDR for safe lab discovery")
    return network


def list_network_interfaces() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if psutil is None:
        try:
            host = socket.gethostname()
            ip = socket.gethostbyname(host)
            if ip and ip != "127.0.0.1":
                rows.append({"name": "AUTO", "ip": ip, "netmask": None, "cidr": None, "is_up": True, "mac": None})
        except Exception:
            pass
        return rows

    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        ipv4 = None
        mac = None
        for addr in addrs:
            family_name = getattr(addr.family, "name", str(addr.family))
            if addr.family == socket.AF_INET and addr.address and not addr.address.startswith("127."):
                ipv4 = addr
            elif "LINK" in family_name or "PACKET" in family_name or str(addr.family) in {"17", "-1"}:
                if addr.address and addr.address != "00:00:00:00:00:00":
                    mac = addr.address
        if not ipv4:
            continue
        cidr = None
        try:
            if ipv4.netmask:
                cidr = str(ipaddress.ip_network(f"{ipv4.address}/{ipv4.netmask}", strict=False))
        except Exception:
            pass
        rows.append(
            {
                "name": name,
                "ip": ipv4.address,
                "netmask": ipv4.netmask,
                "cidr": cidr,
                "is_up": bool(stats.get(name).isup) if stats.get(name) else True,
                "mac": mac,
            }
        )
    # Stable preference: active private interfaces first, loopback excluded above.
    def score(row: dict[str, Any]) -> tuple[int, int, str]:
        try:
            private = 1 if ipaddress.ip_address(row.get("ip") or "0.0.0.0").is_private else 0
        except Exception:
            private = 0
        return (1 if row.get("is_up") else 0, private, str(row.get("name") or ""))

    return sorted(rows, key=score, reverse=True)


def resolve_network_configuration() -> dict[str, Any]:
    configured_iface = str(get_setting("network_interface", os.getenv("NETWORK_INTERFACE", "AUTO")) or "AUTO").strip()
    configured_cidr = str(get_setting("network_cidr", os.getenv("NETWORK_CIDR", "192.168.56.0/24")) or "192.168.56.0/24").strip()
    interfaces = list_network_interfaces()

    explicit_network: ipaddress.IPv4Network | None = None
    config_error: str | None = None
    if configured_cidr and configured_cidr.upper() != "AUTO":
        try:
            explicit_network = _private_lab_network(configured_cidr)
        except Exception as exc:
            config_error = str(exc)

    selected = None
    if configured_iface and configured_iface.upper() != "AUTO":
        selected = next((x for x in interfaces if x["name"] == configured_iface), None)
        if selected is None and not config_error:
            config_error = f"Configured network interface '{configured_iface}' is not active or has no IPv4 address"
    elif explicit_network is not None:
        # When a lab CIDR is configured, AUTO must select the adapter that actually
        # belongs to that subnet. This prevents silently capturing/scanning Wi-Fi or
        # another unrelated private network.
        for row in interfaces:
            try:
                if row.get("is_up") and ipaddress.ip_address(row.get("ip") or "0.0.0.0") in explicit_network:
                    selected = row
                    break
            except Exception:
                continue
        if selected is None and not config_error:
            config_error = f"No active IPv4 interface belongs to configured lab network {explicit_network}"
    else:
        # AUTO/AUTO is allowed only when a likely virtual-lab adapter is present.
        virtual_hints = ("virtualbox", "vbox", "vmware", "hyper-v", "vethernet", "host-only", "virbr")
        for row in interfaces:
            name = str(row.get("name") or "").lower()
            if row.get("is_up") and row.get("cidr") and any(hint in name for hint in virtual_hints):
                try:
                    _private_lab_network(str(row["cidr"]))
                    selected = row
                    break
                except Exception:
                    continue
        if selected is None and not config_error:
            config_error = "AUTO could not identify a virtual lab adapter. Set Network CIDR (recommended: 192.168.56.0/24) or choose the lab interface explicitly."

    cidr = configured_cidr
    if not cidr or cidr.upper() == "AUTO":
        cidr = (selected or {}).get("cidr") or ""

    result = {
        "interface": (selected or {}).get("name") or (configured_iface if configured_iface.upper() != "AUTO" else None),
        "ip": (selected or {}).get("ip"),
        "mac": (selected or {}).get("mac"),
        "cidr": cidr or None,
        "configuredInterface": configured_iface,
        "configuredCidr": configured_cidr,
        "interfaces": interfaces,
    }
    if result["cidr"]:
        try:
            validated = _private_lab_network(str(result["cidr"]))
            result["cidr"] = str(validated)
            if selected and selected.get("ip"):
                try:
                    if ipaddress.ip_address(str(selected["ip"])) not in validated and not config_error:
                        config_error = f"Selected interface {selected.get('name')} ({selected.get('ip')}) is outside configured lab network {validated}"
                except Exception:
                    pass
        except Exception as exc:
            config_error = str(exc)
    elif not interfaces and not config_error:
        config_error = "No active IPv4 interface was found"
    elif not config_error:
        config_error = "Could not determine a lab subnet; set Network CIDR in Settings"
    if config_error:
        result["error"] = config_error
    return result


def _ping_once(ip: str, timeout_ms: int = 500) -> bool:
    system = platform.system().lower()
    if system.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        timeout_sec = max(1, int(round(timeout_ms / 1000)))
        cmd = ["ping", "-c", "1", "-W", str(timeout_sec), ip]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=max(2, timeout_ms / 1000 + 1))
        return proc.returncode == 0
    except Exception:
        return False


def _arp_table() -> dict[str, str]:
    table: dict[str, str] = {}
    commands = [["arp", "-a"]]
    if platform.system().lower() != "windows":
        commands.insert(0, ["ip", "neigh"])
    text = ""
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
            if proc.returncode == 0 and proc.stdout:
                text += "\n" + proc.stdout
        except Exception:
            continue
    ip_mac = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).{0,60}?(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})")
    for match in ip_mac.finditer(text):
        table[match.group("ip")] = match.group("mac").replace("-", ":").lower()
    return table


def _reverse_hostname(ip: str) -> str | None:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _scapy_interface(interface_name: str | None, interface_ip: str | None) -> Any:
    """Resolve a Scapy interface reliably across Windows/Linux/macOS.

    psutil and Scapy can expose different names on Windows. Matching by the
    selected lab IPv4 first avoids accidentally falling back to another adapter.
    """
    if not SCAPY_AVAILABLE:
        return interface_name
    try:
        candidates = list(conf.ifaces.values())
        if interface_ip:
            for candidate in candidates:
                if str(getattr(candidate, "ip", "") or "") == str(interface_ip):
                    return candidate
        if interface_name:
            wanted = str(interface_name).strip().lower()
            for candidate in candidates:
                labels = {
                    str(getattr(candidate, "name", "") or "").strip().lower(),
                    str(getattr(candidate, "description", "") or "").strip().lower(),
                    str(getattr(candidate, "network_name", "") or "").strip().lower(),
                }
                if wanted in labels:
                    return candidate
    except Exception:
        pass
    return interface_name


def _upsert_device(ip: str, mac: str | None, hostname: str | None, interface: str | None, cidr: str | None, method: str, packets: int = 0, bytes_seen: int = 0) -> dict:
    existing = fetch_one("SELECT * FROM network_devices WHERE ip_address=?", (ip,))
    if existing:
        execute(
            """
            UPDATE network_devices
            SET mac_address=COALESCE(NULLIF(?,''),mac_address), hostname=COALESCE(NULLIF(?,''),hostname),
                interface=COALESCE(NULLIF(?,''),interface), network_cidr=COALESCE(NULLIF(?,''),network_cidr),
                status='Online', last_seen=datetime('now'), discovery_method=?,
                packets_seen=packets_seen+?, bytes_seen=bytes_seen+?
            WHERE id=?
            """,
            (mac or "", hostname or "", interface or "", cidr or "", method, packets, bytes_seen, existing["id"]),
        )
    else:
        execute(
            """
            INSERT INTO network_devices(ip_address,mac_address,hostname,vendor,device_type,interface,network_cidr,status,
                                        first_seen,last_seen,discovery_method,packets_seen,bytes_seen,risk_score,notes)
            VALUES(?,?,?,NULL,'Unknown',?,?, 'Online',datetime('now'),datetime('now'),?,?,?,0,NULL)
            """,
            (ip, mac, hostname, interface, cidr, method, packets, bytes_seen),
        )
    return fetch_one("SELECT * FROM network_devices WHERE ip_address=?", (ip,)) or {}


def discover_network_devices(emit: EmitCallback | None = None) -> dict[str, Any]:
    config = resolve_network_configuration()
    if config.get("error"):
        raise RuntimeError(config["error"])
    network = _private_lab_network(str(config["cidr"]))
    interface = config.get("interface")
    found: dict[str, dict[str, Any]] = {}
    method = "Ping/ARP"

    if SCAPY_AVAILABLE:
        try:
            scapy_iface = _scapy_interface(interface, config.get("ip"))
            request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            answered, _ = srp(request, timeout=1.2, retry=0, verbose=False, iface=scapy_iface)
            for _, response in answered:
                found[str(response.psrc)] = {"ip": str(response.psrc), "mac": str(response.hwsrc).lower()}
            method = "ARP"
        except Exception:
            # Scapy may be unavailable at privilege/driver level; safe ping fallback remains usable.
            found = {}

    if not found:
        hosts = [str(ip) for ip in network.hosts()]
        # Keep sweep bounded by the validated network size and low concurrency.
        workers = min(48, max(4, len(hosts)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_ping_once, ip): ip for ip in hosts}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    if future.result():
                        found[ip] = {"ip": ip, "mac": None}
                except Exception:
                    pass
        arp = _arp_table()
        for ip, item in found.items():
            item["mac"] = item.get("mac") or arp.get(ip)
        method = "Ping/ARP"

    # Ensure the local NESS interface is represented even if ICMP/ARP behavior differs.
    if config.get("ip") and ipaddress.ip_address(config["ip"]) in network:
        found.setdefault(str(config["ip"]), {"ip": str(config["ip"]), "mac": config.get("mac")})

    hostnames: dict[str, str | None] = {}
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(found)))) as pool:
        hostname_futures = {pool.submit(_reverse_hostname, ip): ip for ip in found}
        for future in as_completed(hostname_futures):
            ip = hostname_futures[future]
            try:
                hostnames[ip] = future.result()
            except Exception:
                hostnames[ip] = None

    devices = []
    for ip in sorted(found, key=lambda x: tuple(int(p) for p in x.split("."))):
        item = found[ip]
        row = _upsert_device(ip, item.get("mac"), hostnames.get(ip), interface, str(network), method)
        devices.append(row)
        if emit:
            emit("network.device.seen", {"id": row.get("id"), "ip": ip, "mac": row.get("mac_address"), "hostname": row.get("hostname"), "status": "Online"})

    # Mark devices from this subnet that were not rediscovered as offline; never delete history.
    online_ips = set(found)
    for old in fetch_all("SELECT id,ip_address,status FROM network_devices WHERE network_cidr=?", (str(network),)):
        if old["ip_address"] not in online_ips and old.get("status") != "Offline":
            execute("UPDATE network_devices SET status='Offline' WHERE id=?", (old["id"],))
            if emit:
                emit("network.device.status", {"id": old["id"], "ip": old["ip_address"], "status": "Offline"})

    execute(
        "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Network','NESS Discovery',?,?,datetime('now'))",
        (f"Automatic network discovery completed on {network}: {len(devices)} online device(s)", "Info"),
    )
    return {
        "configuration": config,
        "network": str(network),
        "interface": interface,
        "method": method,
        "online": len(devices),
        "devices": devices,
        "completedAt": _utc_now(),
    }


class NetworkMonitor:
    """Passive lab-network sensor plus safe automatic device discovery.

    NESS only observes packets available to the selected interface. To monitor traffic
    between other VMs in a switched lab, place NESS on the traffic path (gateway/sensor)
    or configure the hypervisor/switch to mirror/allow promiscuous traffic.
    """

    def __init__(self) -> None:
        self._emit: EmitCallback | None = None
        self._incident_callback: IncidentCallback | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._sniffer = None
        self._capture_network: ipaddress.IPv4Network | None = None
        self._lock = threading.RLock()
        self._flow_lock = threading.RLock()
        self._flows: dict[tuple, dict[str, Any]] = {}
        self._last_device_touch: dict[str, float] = {}
        self._syn_events: dict[str, deque[tuple[float, str, int]]] = defaultdict(lambda: deque(maxlen=4000))
        self._icmp_events: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=2000))
        self._recent_detections: dict[tuple[str, str, str], float] = {}
        self._state: dict[str, Any] = {
            "started": False,
            "sensorState": "Stopped",
            "sensorMessage": "Network monitor has not started",
            "interface": None,
            "cidr": None,
            "packetsCaptured": 0,
            "bytesCaptured": 0,
            "flowsStored": 0,
            "devicesDiscovered": 0,
            "discoveryRuns": 0,
            "incidentsDetected": 0,
            "lastPacketAt": None,
            "lastDiscoveryAt": None,
            "lastError": None,
            "scapyAvailable": SCAPY_AVAILABLE,
        }

    def start(self, emit: EmitCallback | None = None, incident_callback: IncidentCallback | None = None) -> None:
        with self._lock:
            if self._state.get("started"):
                if emit:
                    self._emit = emit
                if incident_callback:
                    self._incident_callback = incident_callback
                return
            self._emit = emit
            self._incident_callback = incident_callback
            self._stop.clear()
            self._state["started"] = True
            self._state["lastError"] = None

        self._threads = [
            threading.Thread(target=self._discovery_loop, name="NESS-NetworkDiscovery", daemon=True),
            threading.Thread(target=self._flush_loop, name="NESS-NetworkFlowWriter", daemon=True),
            threading.Thread(target=self._retention_loop, name="NESS-NetworkRetention", daemon=True),
        ]
        for t in self._threads:
            t.start()
        self._start_sniffer()
        self._emit_event("network.monitor.started", self.status())

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            pass
        self._flush_flows(force=True)
        with self._lock:
            self._state["started"] = False
            self._state["sensorState"] = "Stopped"
            self._state["sensorMessage"] = "Network monitor stopped"
        self._emit_event("network.monitor.stopped", self.status())

    def restart_sensor(self) -> dict[str, Any]:
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        except Exception:
            pass
        self._sniffer = None
        self._capture_network = None
        self._start_sniffer()
        return self.status()

    def discover_now(self) -> dict[str, Any]:
        result = discover_network_devices(self._emit)
        with self._lock:
            self._state["devicesDiscovered"] = result.get("online", 0)
            self._state["discoveryRuns"] = int(self._state.get("discoveryRuns") or 0) + 1
            self._state["lastDiscoveryAt"] = _utc_now()
            self._state["interface"] = result.get("interface")
            self._state["cidr"] = result.get("network")
            self._state["lastError"] = None
        self._emit_event("network.discovery.completed", {"online": result.get("online", 0), "network": result.get("network"), "interface": result.get("interface")})
        return result

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._state)
        config = resolve_network_configuration()
        state.update(
            {
                "networkDiscoveryEnabled": setting_enabled("network_discovery_enabled", "true"),
                "networkSensorEnabled": setting_enabled("network_sensor_enabled", "true"),
                "discoveryIntervalSeconds": _int_setting("network_discovery_interval_seconds", 60, 15, 3600),
                "configuredInterface": config.get("configuredInterface"),
                "configuredCidr": config.get("configuredCidr"),
                "resolvedInterface": config.get("interface"),
                "resolvedCidr": config.get("cidr"),
                "configurationError": config.get("error"),
                "captureScope": "Packets visible to selected interface; use gateway/port-mirroring/promiscuous lab setup for full inter-VM visibility",
            }
        )
        return state

    def _emit_event(self, event_type: str, payload: dict | None = None) -> None:
        if not self._emit:
            return
        try:
            self._emit(event_type, payload or {})
        except Exception:
            pass

    def _set_error(self, text: str, sensor_state: str | None = None) -> None:
        with self._lock:
            self._state["lastError"] = text
            if sensor_state:
                self._state["sensorState"] = sensor_state
                self._state["sensorMessage"] = text
        self._emit_event("network.error", {"error": text, "sensorState": sensor_state})

    def _start_sniffer(self) -> None:
        if not setting_enabled("network_sensor_enabled", "true"):
            with self._lock:
                self._state["sensorState"] = "Disabled"
                self._state["sensorMessage"] = "Network packet sensor is disabled in Settings"
            return
        if not SCAPY_AVAILABLE:
            self._set_error("Scapy is not installed. Install project requirements to enable packet capture.", "Degraded")
            return
        config = resolve_network_configuration()
        if config.get("error"):
            self._set_error(str(config["error"]), "Degraded")
            return
        interface = config.get("interface")
        try:
            self._capture_network = _private_lab_network(str(config.get("cidr")))
            scapy_iface = _scapy_interface(interface, config.get("ip"))
            # Open and close a layer-2 socket first so missing Npcap/admin privileges
            # are reported immediately instead of silently failing in a worker thread.
            probe = conf.L2listen(iface=scapy_iface)
            try:
                probe.close()
            except Exception:
                pass
            self._sniffer = AsyncSniffer(iface=scapy_iface, prn=self._handle_packet, store=False)
            self._sniffer.start()
            with self._lock:
                self._state["sensorState"] = "Running"
                self._state["sensorMessage"] = "Passive packet sensor is capturing metadata in real time"
                self._state["interface"] = interface
                self._state["cidr"] = config.get("cidr")
                self._state["lastError"] = None
        except Exception as exc:
            self._capture_network = None
            msg = f"Packet capture unavailable on {interface or 'AUTO'}: {exc.__class__.__name__}: {exc}. On Windows install Npcap and run NESS with Administrator rights."
            self._set_error(msg, "Degraded")

    def _discovery_loop(self) -> None:
        if self._stop.wait(1.5):
            return
        while not self._stop.is_set():
            interval = _int_setting("network_discovery_interval_seconds", 60, 15, 3600)
            if setting_enabled("network_discovery_enabled", "true"):
                try:
                    self.discover_now()
                except Exception as exc:
                    self._set_error(f"Network discovery failed: {exc.__class__.__name__}: {exc}")
            if self._stop.wait(interval):
                break

    def _retention_loop(self) -> None:
        while not self._stop.wait(600):
            hours = _int_setting("network_flow_retention_hours", 24, 1, 720)
            try:
                execute("DELETE FROM network_flows WHERE last_seen < datetime('now', ?)", (f"-{hours} hours",))
            except Exception:
                pass

    def _flush_loop(self) -> None:
        while not self._stop.wait(2.0):
            self._flush_flows(force=False)

    def _flow_key(self, src: str, dst: str, proto: str, sport: int | None, dport: int | None) -> tuple:
        return (src, dst, proto, int(sport or 0), int(dport or 0))

    def _handle_packet(self, packet: Any) -> None:
        try:
            if IP not in packet:
                return
            ip_layer = packet[IP]
            src = str(ip_layer.src)
            dst = str(ip_layer.dst)
            scope = self._capture_network
            if scope is None:
                return
            try:
                if ipaddress.ip_address(src) not in scope and ipaddress.ip_address(dst) not in scope:
                    return
            except Exception:
                return
            proto = "IP"
            sport = dport = None
            flags = ""
            if TCP in packet:
                proto = "TCP"
                tcp = packet[TCP]
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                flags = str(tcp.flags)
            elif UDP in packet:
                proto = "UDP"
                udp = packet[UDP]
                sport = int(udp.sport)
                dport = int(udp.dport)
            elif ICMP in packet:
                proto = "ICMP"
            size = int(len(packet))
            now = time.time()
            now_text = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
            key = self._flow_key(src, dst, proto, sport, dport)
            with self._flow_lock:
                flow = self._flows.get(key)
                if not flow:
                    flow = {
                        "source_ip": src,
                        "destination_ip": dst,
                        "source_port": sport,
                        "destination_port": dport,
                        "protocol": proto,
                        "tcp_flags": flags,
                        "packets": 0,
                        "bytes": 0,
                        "first_seen": now_text,
                        "last_seen": now_text,
                        "started_monotonic": now,
                        "last_update": now,
                        "classification": "Normal",
                        "risk_score": 0,
                        "incident_id": None,
                    }
                    self._flows[key] = flow
                flow["packets"] += 1
                flow["bytes"] += size
                flow["last_seen"] = now_text
                flow["last_update"] = now
                if flags:
                    flow["tcp_flags"] = flags
            with self._lock:
                self._state["packetsCaptured"] = int(self._state.get("packetsCaptured") or 0) + 1
                self._state["bytesCaptured"] = int(self._state.get("bytesCaptured") or 0) + size
                self._state["lastPacketAt"] = _utc_now()

            self._touch_device_from_packet(src, packet, size)
            self._touch_device_from_packet(dst, packet, size)
            detection = self._detect_network_anomaly(src, dst, proto, sport, dport, flags, now)
            if detection:
                incident = self._create_network_incident(detection, src, dst, proto, sport, dport, flags)
                if incident:
                    with self._flow_lock:
                        current = self._flows.get(key)
                        if current:
                            current["classification"] = detection["attack_type"]
                            current["risk_score"] = int(detection.get("risk_score") or 70)
                            current["incident_id"] = incident.get("id")
                    with self._lock:
                        self._state["incidentsDetected"] = int(self._state.get("incidentsDetected") or 0) + 1
                    if self._incident_callback:
                        try:
                            self._incident_callback(incident)
                        except Exception:
                            pass
                    self._emit_event("network.threat.detected", {"incident_id": incident.get("id"), "incident_code": incident.get("incident_code"), "attack_type": incident.get("attack_type"), "severity": incident.get("severity"), "source_ip": src, "target": dst})
        except Exception as exc:
            # Never let one malformed packet stop capture.
            self._set_error(f"Packet processing error: {exc.__class__.__name__}: {exc}")

    def _touch_device_from_packet(self, ip: str, packet: Any, size: int) -> None:
        try:
            addr = ipaddress.ip_address(ip)
            scope = self._capture_network
            if scope is None or addr not in scope:
                return
        except Exception:
            return
        now = time.time()
        if now - self._last_device_touch.get(ip, 0) < 5:
            return
        self._last_device_touch[ip] = now
        config = resolve_network_configuration()
        mac = None
        try:
            if Ether in packet:
                eth = packet[Ether]
                if str(packet[IP].src) == ip:
                    mac = str(eth.src).lower()
                elif str(packet[IP].dst) == ip:
                    mac = str(eth.dst).lower()
        except Exception:
            pass
        _upsert_device(ip, mac, None, config.get("interface"), config.get("cidr"), "Passive Sensor", packets=1, bytes_seen=size)

    def _trim(self, dq: deque, seconds: float, now: float) -> None:
        while dq and now - dq[0][0] > seconds:
            dq.popleft()

    def _detect_network_anomaly(self, src: str, dst: str, proto: str, sport: int | None, dport: int | None, flags: str, now: float) -> dict[str, Any] | None:
        # Ignore multicast/broadcast destinations for anomaly counts.
        try:
            dst_addr = ipaddress.ip_address(dst)
            if dst_addr.is_multicast or str(dst).endswith(".255"):
                return None
        except Exception:
            pass

        if proto == "TCP" and "S" in flags and "A" not in flags:
            events = self._syn_events[src]
            events.append((now, dst, int(dport or 0)))
            self._trim(events, 20.0, now)
            ports_by_target: dict[str, set[int]] = defaultdict(set)
            targets: set[str] = set()
            recent_10 = 0
            for ts, target, port in events:
                targets.add(target)
                ports_by_target[target].add(port)
                if now - ts <= 10:
                    recent_10 += 1
            port_threshold = _int_setting("network_port_scan_threshold", 12, 6, 200)
            host_threshold = _int_setting("network_host_sweep_threshold", 8, 4, 200)
            syn_threshold = _int_setting("network_syn_flood_threshold", 80, 20, 5000)
            if len(ports_by_target.get(dst, set())) >= port_threshold:
                return {
                    "attack_type": "Network Port Scan",
                    "severity": "High",
                    "risk_score": 78,
                    "rule": f"{port_threshold}+ distinct TCP destination ports in 20 seconds",
                    "description": "A single source attempted connections to many TCP ports on the same target in a short period.",
                    "observed": {"distinct_ports": len(ports_by_target.get(dst, set())), "window_seconds": 20},
                }
            if len(targets) >= host_threshold:
                return {
                    "attack_type": "Network Host Sweep",
                    "severity": "High",
                    "risk_score": 74,
                    "rule": f"{host_threshold}+ distinct destination hosts in 20 seconds",
                    "description": "A single source attempted TCP connections to many hosts in the monitored lab network.",
                    "observed": {"distinct_hosts": len(targets), "window_seconds": 20},
                }
            if recent_10 >= syn_threshold:
                return {
                    "attack_type": "TCP SYN Flood",
                    "severity": "Critical",
                    "risk_score": 90,
                    "rule": f"{syn_threshold}+ SYN packets in 10 seconds",
                    "description": "An unusually high rate of TCP SYN packets was observed from one source.",
                    "observed": {"syn_packets": recent_10, "window_seconds": 10},
                }
        elif proto == "ICMP":
            events = self._icmp_events[src]
            events.append((now, dst))
            self._trim(events, 20.0, now)
            threshold = _int_setting("network_icmp_rate_threshold", 40, 10, 5000)
            if len(events) >= threshold:
                distinct_hosts = len({item[1] for item in events})
                attack_type = "ICMP Host Sweep" if distinct_hosts >= 6 else "ICMP Flood"
                severity = "High" if distinct_hosts >= 6 else "Medium"
                return {
                    "attack_type": attack_type,
                    "severity": severity,
                    "risk_score": 72 if distinct_hosts >= 6 else 62,
                    "rule": f"{threshold}+ ICMP packets in 20 seconds",
                    "description": "An abnormal ICMP request rate was observed in the monitored lab network.",
                    "observed": {"icmp_packets": len(events), "distinct_hosts": distinct_hosts, "window_seconds": 20},
                }
        return None

    def _create_network_incident(self, detection: dict[str, Any], src: str, dst: str, proto: str, sport: int | None, dport: int | None, flags: str) -> dict | None:
        key = (detection["attack_type"], src, dst)
        now = time.time()
        if now - self._recent_detections.get(key, 0) < 180:
            return None
        existing = fetch_one(
            """SELECT * FROM incidents WHERE attack_type=? AND source_ip=? AND target=?
               AND created_at >= datetime('now','-3 minutes') ORDER BY id DESC LIMIT 1""",
            (detection["attack_type"], src, dst),
        )
        if existing:
            self._recent_detections[key] = now
            return None

        incident_code = next_code("NESS", "incidents", "incident_code")
        path = f"{dst}:{dport}" if dport else dst
        payload_obj = {
            "sensor": "NESS Passive Network Sensor",
            "source_ip": src,
            "destination_ip": dst,
            "source_port": sport,
            "destination_port": dport,
            "protocol": proto,
            "tcp_flags": flags,
            "detection": detection,
        }
        payload = json.dumps(payload_obj, ensure_ascii=False, sort_keys=True)
        incident_id = execute(
            """
            INSERT INTO incidents(incident_code,attack_type,severity,status,source_ip,source_country,source_city,target,method,path,
                                  query_string,payload,user_agent,description,created_at,updated_at,assigned_to,created_by)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),NULL,NULL)
            """,
            (
                incident_code,
                detection["attack_type"],
                detection["severity"],
                "New",
                src,
                None,
                None,
                dst,
                proto,
                path,
                "",
                payload,
                "NESS Network Sensor",
                f"{detection['description']} Matched rule: {detection['rule']}",
            ),
        )
        raw = json.dumps({**payload_obj, "captured_at": _utc_now()}, ensure_ascii=False, indent=2, sort_keys=True)
        hash_value = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        evidence_code = next_code("EV", "digital_evidence", "evidence_code")
        execute(
            """
            INSERT INTO digital_evidence(evidence_code,incident_id,evidence_type,file_path,hash_value,raw_data,notes,captured_at,captured_by)
            VALUES(?,?,?,?,?,?,?,datetime('now'),NULL)
            """,
            (evidence_code, incident_id, "Network Flow Evidence", None, hash_value, raw, "Captured automatically from network metadata by NESS passive sensor."),
        )
        execute(
            "INSERT INTO incident_status_history(incident_id,changed_by,old_status,new_status,remarks,changed_at) VALUES(?,NULL,NULL,'New','Incident created automatically by network sensor.',datetime('now'))",
            (incident_id,),
        )
        execute(
            "INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))",
            (incident_id, incident_code, "Network Threat Detected", "New", f"{detection['attack_type']} detected automatically from live network metadata."),
        )
        execute(
            "INSERT INTO ints_tracking(incident_id,tracking_code,event_type,status,notes,created_by,created_at) VALUES(?,?,?,?,?,NULL,datetime('now'))",
            (incident_id, incident_code, "Evidence Preserved", "New", f"Network evidence {evidence_code} preserved with SHA-256 integrity hash."),
        )
        execute(
            "INSERT INTO system_logs(category,actor,event,level,created_at) VALUES('Network','NESS Network Sensor',?,?,datetime('now'))",
            (f"{detection['attack_type']} detected for {incident_code}: {src} -> {dst}", detection["severity"]),
        )
        execute("UPDATE network_devices SET risk_score=MAX(risk_score, ?), status='Online' WHERE ip_address=?", (int(detection.get("risk_score") or 70), src))
        self._recent_detections[key] = now
        return fetch_one("SELECT * FROM incidents WHERE id=?", (incident_id,))

    def _flush_flows(self, force: bool = False) -> None:
        now = time.time()
        ready: list[tuple[tuple, dict[str, Any]]] = []
        with self._flow_lock:
            for key, flow in list(self._flows.items()):
                idle_for = now - float(flow.get("last_update") or now)
                open_for = now - float(flow.get("started_monotonic") or flow.get("last_update") or now)
                if force or idle_for >= 1.5 or open_for >= 5.0:
                    ready.append((key, dict(flow)))
                    self._flows.pop(key, None)
        stored_count = 0
        latest_payload: dict[str, Any] | None = None
        for _, flow in ready:
            try:
                flow_key = hashlib.sha1(
                    f"{flow['source_ip']}|{flow['destination_ip']}|{flow['protocol']}|{flow.get('source_port')}|{flow.get('destination_port')}|{flow['first_seen']}".encode("utf-8")
                ).hexdigest()
                execute(
                    """
                    INSERT INTO network_flows(flow_key,source_ip,destination_ip,source_port,destination_port,protocol,tcp_flags,packets,bytes,
                                              first_seen,last_seen,classification,risk_score,incident_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        flow_key,
                        flow["source_ip"],
                        flow["destination_ip"],
                        flow.get("source_port"),
                        flow.get("destination_port"),
                        flow["protocol"],
                        flow.get("tcp_flags") or "",
                        int(flow.get("packets") or 0),
                        int(flow.get("bytes") or 0),
                        flow["first_seen"],
                        flow["last_seen"],
                        flow.get("classification") or "Normal",
                        int(flow.get("risk_score") or 0),
                        flow.get("incident_id"),
                    ),
                )
                with self._lock:
                    self._state["flowsStored"] = int(self._state.get("flowsStored") or 0) + 1
                stored_count += 1
                latest_payload = {
                    "source_ip": flow["source_ip"],
                    "destination_ip": flow["destination_ip"],
                    "protocol": flow["protocol"],
                    "destination_port": flow.get("destination_port"),
                    "packets": flow.get("packets"),
                    "bytes": flow.get("bytes"),
                    "classification": flow.get("classification"),
                    "risk_score": flow.get("risk_score"),
                }
            except Exception as exc:
                self._set_error(f"Network flow storage failed: {exc.__class__.__name__}: {exc}")
        if stored_count:
            self._emit_event(
                "network.flows.updated",
                {"count": stored_count, "latest": latest_payload or {}},
            )


_MONITOR = NetworkMonitor()


def start_network_monitor(emit: EmitCallback | None = None, incident_callback: IncidentCallback | None = None) -> None:
    _MONITOR.start(emit, incident_callback)


def stop_network_monitor() -> None:
    _MONITOR.stop()


def get_network_status() -> dict[str, Any]:
    return _MONITOR.status()


def discover_network_now() -> dict[str, Any]:
    return _MONITOR.discover_now()


def restart_network_sensor() -> dict[str, Any]:
    return _MONITOR.restart_sensor()
