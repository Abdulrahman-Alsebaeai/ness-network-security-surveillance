#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, socket, sqlite3
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

EVENTS=Path('/var/lib/ness-lab/events.jsonl')
DB_PATH=Path('/var/lib/ness-lab/webapp.sqlite3')
ROOT=Path('/var/lib/ness-lab/webroot')
FILES=ROOT/'files'
DB_HOST='10.10.30.30'; DB_PORT=5432

def now_iso(): return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00','Z')

def append_event(obj):
    obj.setdefault('ts',now_iso())
    with EVENTS.open('a',encoding='utf-8') as f: f.write(json.dumps(obj,ensure_ascii=False,separators=(',',':'))+'\n')

def init_data():
    ROOT.mkdir(parents=True,exist_ok=True); FILES.mkdir(parents=True,exist_ok=True)
    (FILES/'readme.txt').write_text('NESS Cyber Range public file\n',encoding='utf-8')
    (ROOT/'secret.txt').write_text('NESS-LAB-SECRET: traversal-demo-only\n',encoding='utf-8')
    with sqlite3.connect(DB_PATH) as c:
        c.execute('CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,password TEXT NOT NULL)')
        c.execute("INSERT OR IGNORE INTO users(username,password) VALUES('admin','NESS-Lab-Only-2026')")
        c.commit()

def db_rpc(payload):
    with socket.create_connection((DB_HOST,DB_PORT),timeout=2) as s:
        s.sendall((json.dumps(payload)+'\n').encode())
        data=b''
        while not data.endswith(b'\n') and len(data)<65536:
            chunk=s.recv(4096)
            if not chunk: break
            data+=chunk
    return json.loads(data.decode('utf-8','replace') or '{}')

class H(BaseHTTPRequestHandler):
    server_version='NESS-Lab-Web/1.0'
    def log_message(self,*args): pass
    def _read_body(self):
        try: n=int(self.headers.get('Content-Length','0') or 0)
        except Exception: n=0
        return self.rfile.read(min(n,65536)).decode('utf-8','replace') if n else ''
    def _event(self,body=''):
        p=urlparse(self.path)
        append_event({'kind':'http','method':self.command,'path':p.path,'query_string':p.query,'body':body[:4096],
                      'headers':{'Host':self.headers.get('Host',''),'User-Agent':self.headers.get('User-Agent','')},
                      'source_ip':self.client_address[0],'destination_ip':self.server.server_address[0]})
    def _json(self,code,obj):
        data=json.dumps(obj,ensure_ascii=False).encode(); self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def _text(self,code,text,ctype='text/plain; charset=utf-8'):
        data=text.encode(); self.send_response(code); self.send_header('Content-Type',ctype); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._event(''); p=urlparse(self.path); qs=parse_qs(p.query)
        if p.path=='/': return self._text(200,'NESS Cyber Range Web Server\n')
        if p.path=='/api/health': return self._json(200,{'ok':True,'service':'NESS Lab Web','ip':'10.10.20.20'})
        if p.path=='/api/messages':
            try: return self._json(200,db_rpc({'op':'list_messages'}))
            except Exception as e: return self._json(503,{'ok':False,'error':str(e)})
        if p.path=='/echo':
            # Intentionally vulnerable reflected output, only inside the isolated lab.
            q=(qs.get('q') or [''])[0]
            return self._text(200,f'<html><body>Echo: {q}</body></html>','text/html; charset=utf-8')
        if p.path=='/files':
            # Intentionally vulnerable traversal for the disposable lab. It can only expose files under ROOT.
            name=(qs.get('name') or ['readme.txt'])[0]
            target=Path(os.path.normpath(os.path.join(str(FILES),name)))
            if ROOT not in target.parents and target != ROOT:
                return self._text(403,'Outside lab web root blocked')
            try: return self._text(200,target.read_text(encoding='utf-8'))
            except Exception: return self._text(404,'Not found')
        return self._json(404,{'ok':False,'error':'Not found'})
    def do_POST(self):
        body=self._read_body(); self._event(body); p=urlparse(self.path)
        if p.path=='/api/messages':
            try:
                obj=json.loads(body or '{}'); msg=str(obj.get('message',''))[:1000]
                return self._json(201,db_rpc({'op':'store_message','from':self.client_address[0],'message':msg}))
            except Exception as e: return self._json(400,{'ok':False,'error':str(e)})
        if p.path=='/login':
            form=parse_qs(body); u=(form.get('username') or [''])[0]; pw=(form.get('password') or [''])[0]
            # Deliberately vulnerable SQL for an isolated teaching target.
            sql=f"SELECT username FROM users WHERE username='{u}' AND password='{pw}'"
            try:
                with sqlite3.connect(DB_PATH) as c: row=c.execute(sql).fetchone()
                if row: return self._json(200,{'ok':True,'login':'success','user':row[0]})
                return self._json(401,{'ok':False,'login':'failed'})
            except Exception as e: return self._json(500,{'ok':False,'error':str(e)})
        return self._json(404,{'ok':False,'error':'Not found'})

if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('--bind',default='10.10.20.20'); ap.add_argument('--port',type=int,default=8080); a=ap.parse_args(); init_data(); EVENTS.parent.mkdir(parents=True,exist_ok=True)
    append_event({'kind':'service','service':'lab-web','event':'started','ip':a.bind,'port':a.port})
    ThreadingHTTPServer((a.bind,a.port),H).serve_forever()
