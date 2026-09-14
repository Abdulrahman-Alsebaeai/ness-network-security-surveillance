#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, socketserver, threading
from datetime import datetime, timezone
from pathlib import Path


def now_iso(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')

def append_event(path: Path, obj: dict):
    obj.setdefault('ts', now_iso())
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False, separators=(',',':'))+'\n')

def append_message(path: Path, obj: dict):
    obj.setdefault('stored_at', now_iso())
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(obj, ensure_ascii=False)+'\n')

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        src = self.client_address[0]
        try:
            raw = self.rfile.readline(16384).decode('utf-8','replace').strip()
            req = json.loads(raw or '{}')
            op = req.get('op')
            if op == 'ping':
                resp = {'ok':True,'service':'NESS Lab DB','pong':True}
            elif op == 'store_message':
                msg = {'from':req.get('from','client'),'message':str(req.get('message',''))[:1000]}
                append_message(self.server.messages_path, msg)
                resp = {'ok':True,'stored':True}
            elif op == 'list_messages':
                rows=[]
                if self.server.messages_path.exists():
                    for line in self.server.messages_path.read_text(encoding='utf-8').splitlines()[-20:]:
                        try: rows.append(json.loads(line))
                        except Exception: pass
                resp={'ok':True,'messages':rows}
            else:
                resp={'ok':False,'error':'Unsupported operation'}
            append_event(self.server.events_path, {'kind':'db','source_ip':src,'destination_ip':self.server.server_address[0],'operation':op or 'unknown','success':bool(resp.get('ok'))})
            self.wfile.write((json.dumps(resp,ensure_ascii=False)+'\n').encode())
        except Exception as exc:
            append_event(self.server.events_path, {'kind':'db','source_ip':src,'destination_ip':self.server.server_address[0],'operation':'error','success':False,'error':str(exc)})

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--bind',default='10.10.30.30'); ap.add_argument('--port',type=int,default=5432); ap.add_argument('--events',default='/var/lib/ness-lab/events.jsonl'); ap.add_argument('--messages',default='/var/lib/ness-lab/messages.jsonl'); a=ap.parse_args()
    s=Server((a.bind,a.port),Handler); s.events_path=Path(a.events); s.messages_path=Path(a.messages); s.events_path.parent.mkdir(parents=True,exist_ok=True)
    append_event(s.events_path,{'kind':'service','service':'lab-db','event':'started','ip':a.bind,'port':a.port})
    s.serve_forever()
