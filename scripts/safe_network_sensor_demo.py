"""Generate a small, authorized TCP SYN pattern for the NESS passive sensor.

Run this from a TEST VM inside the isolated lab, targeting the NESS sensor/server IP.
The script is intentionally constrained:
- literal IPv4 only
- private/loopback/link-local target only
- at most 20 consecutive TCP ports
- no payloads, exploitation, credentials, or external hosts

Example from Test VM:
  python safe_network_sensor_demo.py --target 192.168.56.1
"""
from __future__ import annotations

import argparse
import ipaddress
import socket
import time


def private_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Target must be a literal IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not (address.is_private or address.is_loopback or address.is_link_local):
        raise argparse.ArgumentTypeError("Target must be a private/local IPv4 address in your isolated NESS lab")
    return str(address)


def main() -> int:
    parser = argparse.ArgumentParser(description="NESS constrained private-lab network sensor demonstration")
    parser.add_argument("--target", required=True, type=private_ipv4, help="NESS private lab IP, e.g. 192.168.56.1")
    parser.add_argument("--start-port", type=int, default=5000)
    parser.add_argument("--count", type=int, default=14, help="6-20 consecutive ports; default 14")
    args = parser.parse_args()
    if not (1 <= args.start_port <= 65535):
        parser.error("--start-port must be 1..65535")
    if not (6 <= args.count <= 20):
        parser.error("--count must be 6..20")
    if args.start_port + args.count - 1 > 65535:
        parser.error("Port range exceeds 65535")

    print("NESS SAFE NETWORK-SENSOR LAB DEMO")
    print(f"Private target: {args.target}")
    print(f"Constrained ports: {args.start_port}-{args.start_port + args.count - 1}")
    print("Run only in the isolated lab you control.\n")

    for port in range(args.start_port, args.start_port + args.count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.12)
        try:
            result = sock.connect_ex((args.target, port))
            state = "open/accepted" if result == 0 else "closed/unanswered"
            print(f"TCP {args.target}:{port:<5} {state}")
        except OSError as exc:
            print(f"TCP {args.target}:{port:<5} local error: {exc.__class__.__name__}")
        finally:
            sock.close()
        time.sleep(0.05)

    print("\nSequence complete. With the default NESS threshold, the passive sensor should classify the pattern as Network Port Scan")
    print("and automatically create Incident -> Evidence -> INTS -> Alert -> AI analysis if the selected interface can see this traffic.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
