"""Generate SAFE demonstration traffic for NESS watched endpoints.

The target is restricted in code to localhost or a literal private/link-local IPv4
address. This keeps the demonstration inside an authorized local/virtual lab.

Examples:
  python scripts/safe_demo_requests.py
  python scripts/safe_demo_requests.py --base-url http://192.168.56.1:5000
"""
from __future__ import annotations

import argparse
import ipaddress
import time
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

TIMEOUT = 3


def validate_base_url(value: str) -> str:
    value = value.rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme != "http" or not parsed.hostname:
        raise argparse.ArgumentTypeError("Use an http:// URL inside the isolated NESS lab")
    host = parsed.hostname
    if host.lower() == "localhost":
        return value
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use localhost or a literal private lab IPv4 address; DNS names are not accepted") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not (address.is_private or address.is_loopback or address.is_link_local):
        raise argparse.ArgumentTypeError("The demo target must be a private/local IPv4 address")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="NESS authorized private-lab HTTP demonstration")
    parser.add_argument("--base-url", type=validate_base_url, default="http://127.0.0.1:5000", help="NESS URL, e.g. http://192.168.56.1:5000")
    args = parser.parse_args()
    base = args.base_url

    session = requests.Session()
    session.headers.update({"Connection": "close", "User-Agent": "NESS-Authorized-Private-Lab-Demo/3.0"})

    def send(label: str, method: str, path: str, **kwargs) -> bool:
        try:
            response = session.request(method, base + path, timeout=TIMEOUT, **kwargs)
            print(f"{label:<28} HTTP {response.status_code}  {response.url}")
            return response.ok
        except RequestException as exc:
            print(f"{label:<28} FAILED  {exc}")
            return False

    print("NESS SAFE PRIVATE-LAB DEMONSTRATION")
    print(f"Target: {base}")
    print("The script refuses public/external targets.\n")
    ok = 0

    # Signature-based detections against NESS's purpose-built /watched/* endpoints.
    ok += send("SQL Injection signature", "GET", "/watched/search", params={"q": "' OR '1'='1"})
    time.sleep(0.2)
    ok += send("XSS signature", "GET", "/watched/search", params={"q": "<script>alert('ness-demo')</script>"})
    time.sleep(0.2)
    ok += send("Traversal signature", "GET", "/watched/file", params={"path": "../../etc/passwd"})
    time.sleep(0.2)

    print("\nGenerating a safe authentication-rate sequence...")
    for i in range(8):
        ok += send(f"Login rate {i+1:02d}/08", "POST", "/watched/login", json={"username": "demo", "password": f"invalid-{i}"})
        time.sleep(0.04)

    print("\nGenerating a safe high-request-rate sequence...")
    for i in range(22):
        ok += send(f"Request rate {i+1:02d}/22", "GET", "/watched/search", params={"page": i, "demo": "rate"})
        time.sleep(0.03)

    print(f"\nFinished: {ok} private-lab requests were accepted by the watched endpoints.")
    print("Open NESS: Dashboard -> Incidents -> Real-time Alerts -> INTS Tracking -> AI Analysis.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
