#!/usr/bin/env python3
import argparse,json
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--file',default='/var/lib/ness-lab/events.jsonl');ap.add_argument('--after',type=int,default=0);ap.add_argument('--limit',type=int,default=400);a=ap.parse_args()
p=Path(a.file)
lines=p.read_text(encoding='utf-8',errors='replace').splitlines() if p.exists() else []
start=max(0,a.after); end=min(len(lines),start+max(1,min(a.limit,2000)))
events=[]
for line in lines[start:end]:
    try: events.append(json.loads(line))
    except Exception: pass
print(json.dumps({'ok':True,'next':end,'total':len(lines),'events':events},ensure_ascii=False))
