#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, socket, struct, time
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path

ETH_P_ALL = 0x0003
PROTO = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')


def append_event(path: Path, obj: dict):
    obj.setdefault('ts', now_iso())
    line = json.dumps(obj, ensure_ascii=False, separators=(',', ':')) + '\n'
    with path.open('a', encoding='utf-8') as f:
        f.write(line)
        f.flush()


def parse_ipv4(frame: bytes):
    if len(frame) < 34:
        return None
    eth_type = struct.unpack('!H', frame[12:14])[0]
    if eth_type != 0x0800:
        return None
    ipoff = 14
    ver_ihl = frame[ipoff]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if len(frame) < ipoff + ihl:
        return None
    total_len = struct.unpack('!H', frame[ipoff+2:ipoff+4])[0]
    proto_num = frame[ipoff+9]
    src = socket.inet_ntoa(frame[ipoff+12:ipoff+16])
    dst = socket.inet_ntoa(frame[ipoff+16:ipoff+20])
    payload_off = ipoff + ihl
    sport = dport = None
    flags = ''
    if proto_num == 6 and len(frame) >= payload_off + 20:
        sport, dport = struct.unpack('!HH', frame[payload_off:payload_off+4])
        flag_byte = frame[payload_off+13]
        names = [(0x01,'F'),(0x02,'S'),(0x04,'R'),(0x08,'P'),(0x10,'A'),(0x20,'U'),(0x40,'E'),(0x80,'C')]
        flags = ''.join(name for mask, name in names if flag_byte & mask)
    elif proto_num == 17 and len(frame) >= payload_off + 8:
        sport, dport = struct.unpack('!HH', frame[payload_off:payload_off+4])
    return {
        'kind':'packet','source_ip':src,'destination_ip':dst,
        'protocol':PROTO.get(proto_num, f'IP-{proto_num}'),
        'source_port':sport,'destination_port':dport,'tcp_flags':flags,
        'bytes':int(total_len or max(0, len(frame)-14)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--events', default='/var/lib/ness-lab/events.jsonl')
    ap.add_argument('--interface', action='append', required=True, help='iface=CIDR source scope')
    args = ap.parse_args()
    event_path = Path(args.events)
    event_path.parent.mkdir(parents=True, exist_ok=True)
    sockets = []
    for spec in args.interface:
        if '=' not in spec:
            raise SystemExit(f'Invalid interface spec: {spec}')
        iface, cidr = spec.split('=',1)
        scope = ip_network(cidr, strict=False)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((iface, 0))
        s.settimeout(0.25)
        sockets.append((iface, scope, s))
    append_event(event_path, {'kind':'sensor','event':'started','interfaces':[x[0] for x in sockets]})
    while True:
        had = False
        for iface, scope, s in sockets:
            try:
                frame = s.recv(65535)
            except socket.timeout:
                continue
            except InterruptedError:
                continue
            had = True
            item = parse_ipv4(frame)
            if not item:
                continue
            try:
                # Emit each routed packet once: only on the interface where its source subnet enters the gateway.
                if ip_address(item['source_ip']) not in scope:
                    continue
            except Exception:
                continue
            item['interface'] = iface
            append_event(event_path, item)
        if not had:
            time.sleep(0.02)

if __name__ == '__main__':
    main()
