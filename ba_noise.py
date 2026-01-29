import argparse, glob, http.client, json, random, re, socket, threading, time
from collections import Counter, deque
from pathlib import Path

_PL = threading.Lock()
def _ts(): return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
def _log(act, tgt, ok, msg=""):
    with _PL:
        s = f"{_ts()} {act:<14} {tgt:<21} {'OK' if ok else 'ERR'}"
        if msg: s += f" {msg}"
        print(s, flush=True)

_CONTENT = re.compile(r'\b(?:content|uricontent)\s*:\s*"([^"]*)"', re.I)
_PCRE    = re.compile(r'\bpcre\s*:\s*"([^"]+)"', re.I)
_RULE    = re.compile(r'^(alert|drop|reject|pass)\s+', re.I)

_FORBID_CHARS = set("`|;")  # textual payload only
_FORBID_SUBS  = ("../","..\\","%2e%2e","%2f","%5c","payload=","cmd=","cli=","&&","$(","${")
_TOKS = ("/cgi-bin/","/shell","/system.ini","/login.cgi","/onvif/","/res.php","authorization",
         "newntpserver","timezone=","country=","?images","exec/server","debug","createusers","usernametoken")

def _dec_content(s):
    out=[]; i=0
    while i < len(s):
        if s[i]=="|":
            j=s.find("|", i+1)
            if j<0: out.append(s[i:]); break
            blob=s[i+1:j].strip()
            try:
                b=bytes(int(x,16) for x in blob.split() if x)
                out.append(b.decode("latin-1","ignore"))
            except Exception:
                out.append(s[i:j+1])
            i=j+1
        else:
            out.append(s[i]); i+=1
    return "".join(out)

def _pcre_py(expr):
    m=re.match(r"^m?/(.*)/([A-Za-z]*)$", expr.strip())
    if not m: return (expr, 0)
    pat, fl = m.group(1), m.group(2)
    flags=0
    if "i" in fl: flags |= re.I
    if "m" in fl: flags |= re.M
    if "s" in fl: flags |= re.S
    return (pat, flags)

def _susp(s):
    l=s.lower()
    return any(t in l for t in _TOKS) or any(t in l for t in ("../","..\\","%2e%2e","%2f","%5c")) or bool(re.search(r"/[^ \r\n]{1,80}\.(cgi|ini|php)\b", l))

class Avoid:
    def __init__(self):
        self.sub=set(); self.rx=[]
    def add_sub(self, s):
        s=(s or "").strip()
        if s: self.sub.add(s.lower())
    def add_rx(self, pat, flags=0):
        try: self.rx.append(re.compile(pat, flags))
        except re.error: pass
    def bad(self, text):
        for c in _FORBID_CHARS:
            if c in text: return c
        low=text.lower()
        for b in _FORBID_SUBS:
            if b in low: return b
        for s in self.sub:
            if s and s in low: return s
        for r in self.rx:
            try:
                if r.search(text): return "pcre"
            except Exception:
                pass
        return None

def build_avoid(rules, attacks_json=None):
    db=Avoid()
    for rp in rules:
        try: txt=Path(rp).read_text(encoding="utf-8", errors="replace")
        except Exception: continue
        for line in txt.splitlines():
            line=line.strip()
            if not line or line.startswith("#") or not _RULE.match(line): continue
            for raw in _CONTENT.findall(line):
                dec=_dec_content(raw)
                if _susp(dec): db.add_sub(dec)
            for raw in _PCRE.findall(line):
                pat, fl = _pcre_py(raw)
                if _susp(pat): db.add_rx(pat, fl)
    if attacks_json:
        try:
            cfg=json.loads(Path(attacks_json).read_text(encoding="utf-8", errors="replace"))
            attacks=cfg.get("attacks", []) if isinstance(cfg, dict) else cfg
        except Exception:
            attacks=[]
        for a in attacks if isinstance(attacks, list) else []:
            cmd=str(a.get("command",""))
            for tok in ("BA-AttackRunner","payload=","cmd=","cli=","action=alarm","/system.ini","/shell"):
                if tok in cmd: db.add_sub(tok)
            for m in re.finditer(r"https?://[0-9.]+(?::\d+)?(/[A-Za-z0-9._/\-]+)", cmd, re.I):
                if _susp(m.group(1)): db.add_sub(m.group(1))
            for m in re.finditer(r"rtsp://[0-9.]+(?::\d+)?(/[A-Za-z0-9._/\-]+)", cmd, re.I):
                if _susp(m.group(1)): db.add_sub(m.group(1))
            for m in re.finditer(r"\?[A-Za-z0-9._%=&/\-]{1,80}", cmd):
                if _susp(m.group(0)): db.add_sub(m.group(0))
    for tok in ("ba-attackrunner","action=alarm","ywrtaW46ywrtaW4="): db.add_sub(tok)  # base64 admin:admin
    return db

def parse_targets(s):
    t={"router":("10.10.0.3",80),"camera":("10.10.0.4",80),"mqtt":("10.10.0.5",1883),"rtsp":("10.10.0.6",8554),"coap":("10.10.0.5",5683)}
    if not s: return t
    for part in [p.strip() for p in s.split(",") if p.strip()]:
        if "=" not in part: continue
        k,v=part.split("=",1); k=k.strip().lower(); v=v.strip()
        if not v: continue
        if ":" in v:
            host,sp=v.rsplit(":",1)
            try: port=int(sp)
            except ValueError: continue
        else:
            host,port=v,t.get(k,(v,0))[1]
        t[k]=(host,port)
    return t

_HTTP_UA=["smart-noise/1.0","curl/8.0","python-httpclient/1.0","mozilla/5.0"]
_HTTP_PATH=["/","/status","/health","/index.html","/api/status","/device/status"]

def http_once(rng, avoid, targets):
    key="router" if rng.random()<0.55 else "camera"
    host,port=targets[key]
    meth="HEAD" if rng.random()<0.08 else "GET"
    path=("/"+"".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(4,10)))) if rng.random()<0.12 else rng.choice(_HTTP_PATH)
    ua=rng.choice(_HTTP_UA)
    preview=f"{meth} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nConnection: close\r\n\r\n"
    bad=avoid.bad(preview)
    if bad:
        meth,path,ua=meth,"/","smart-noise/1.0"
        preview=f"{meth} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nConnection: close\r\n\r\n"
        if avoid.bad(preview): return ("HTTP",f"{host}:{port}",False,f"blocked({bad})")
    try:
        c=http.client.HTTPConnection(host,port,timeout=3)
        c.request(meth,path,headers={"User-Agent":ua,"Connection":"close"})
        if rng.random()<0.04: c.close(); return ("HTTP",f"{host}:{port}",True,f"{key} {meth} {path} drop")
        r=c.getresponse(); code=r.status
        try: r.read(128)
        except Exception: pass
        c.close()
        return ("HTTP",f"{host}:{port}",True,f"{key} {meth} {path} {code}")
    except Exception as e:
        return ("HTTP",f"{host}:{port}",False,f"{key} {meth} {path} {type(e).__name__}")

def _mvar(n):
    out=bytearray()
    while True:
        d=n%128; n//=128
        if n: d|=0x80
        out.append(d)
        if not n: break
    return bytes(out)
def _mstr(s):
    b=s.encode("utf-8","ignore")
    return bytes([(len(b)>>8)&0xff,len(b)&0xff])+b

class RawMQTT:
    def __init__(self, host, port, cid, avoid):
        self.host, self.port, self.cid = host, port, cid
        self.avoid=avoid; self.sock=None; self.pid=1; self.last_conn=0.0
    def connect(self):
        if self.sock: return True
        now=time.time()
        if now-self.last_conn<15: return False
        self.last_conn=now
        try:
            s=socket.create_connection((self.host,self.port),timeout=3); s.settimeout(2.0)
            vh=b"\x00\x04MQTT\x04"+bytes([0x02])+b"\x00\x3c"
            pl=_mstr(self.cid)
            s.sendall(b"\x10"+_mvar(len(vh)+len(pl))+vh+pl)
            try: s.recv(4)
            except Exception: pass
            topic="home/telemetry/#"
            if not self.avoid.bad(topic):
                pid=self.pid; self.pid=(self.pid+1)&0xffff or 1
                sub_pl=_mstr(topic)+b"\x00"; sub_vh=bytes([(pid>>8)&0xff,pid&0xff])
                s.sendall(b"\x82"+_mvar(len(sub_vh)+len(sub_pl))+sub_vh+sub_pl)
                try: s.recv(5)
                except Exception: pass
            self.sock=s; return True
        except Exception:
            self.sock=None; return False
    def close(self):
        if self.sock:
            try: self.sock.sendall(b"\xE0\x00")
            except Exception: pass
            try: self.sock.close()
            except Exception: pass
            self.sock=None
    def pub(self, topic, payload, rng):
        if self.avoid.bad(topic+" "+payload): return (False,"blocked")
        if not self.connect(): return (False,"connect")
        try:
            pkt=b"\x30"+_mvar(len(_mstr(topic))+len(payload))+_mstr(topic)+payload.encode()
            self.sock.sendall(pkt)
            if rng.random()<0.03: self.close(); return (True,"drop")
            return (True,f"bytes={len(payload)}")
        except Exception as e:
            self.close(); return (False,type(e).__name__)

def _mpayload(rng, avoid):
    temp=round(18+rng.random()*8,1); hum=int(30+rng.random()*40); bat=int(10+rng.random()*90)
    s=json.dumps({"temp":temp,"hum":hum,"bat":bat,"ts":int(time.time())},separators=(",",":"))
    return s if not avoid.bad(s) else json.dumps({"temp":temp,"hum":hum,"bat":bat},separators=(",",":"))

def mqtt_once(rng, avoid, state):
    c=state["c"]
    if rng.random()<0.02: c.close(); return ("MQTT",f"{c.host}:{c.port}",True,"disconnect")
    payload=_mpayload(rng, avoid)
    ok,info=c.pub(state["topic"],payload,rng)
    return ("MQTT",f"{c.host}:{c.port}",ok,f"PUB {state['topic']} {info}")

_RTSP_UA=["VLC/3.0.20","Lavf/59.27.100","smart-noise-rtsp/1.0"]
_RTSP_PATH=["/","/live","/stream","/media","/cam"]

def rtsp_once(rng, avoid, targets, st):
    host,port=targets["rtsp"]
    now=time.time()
    while st["dt"] and now-st["dt"][0]>60: st["dt"].popleft()
    do_desc=(rng.random()<0.10 and len(st["dt"])<2)
    meth="DESCRIBE" if do_desc else "OPTIONS"
    path=rng.choice(_RTSP_PATH)
    url=f"rtsp://{host}:{port}{path}"
    ua=rng.choice(_RTSP_UA)
    hdr=[f"CSeq: {st['cseq']}",f"User-Agent: {ua}"] + (["Accept: application/sdp"] if do_desc else [])
    req=f"{meth} {url} RTSP/1.0\r\n"+"\r\n".join(hdr)+"\r\n\r\n"; st["cseq"]+=1
    bad=avoid.bad(req)
    if bad:
        url=f"rtsp://{host}:{port}/"
        req=f"OPTIONS {url} RTSP/1.0\r\nCSeq: {st['cseq']}\r\nUser-Agent: smart-noise-rtsp/1.0\r\n\r\n"; st["cseq"]+=1
        if avoid.bad(req): return ("RTSP",f"{host}:{port}",False,f"blocked({bad})")
    try:
        s=socket.create_connection((host,port),timeout=3); s.settimeout(2.0)
        s.sendall(req.encode("utf-8","ignore"))
        if rng.random()<0.05:
            s.close()
            if do_desc: st["dt"].append(time.time())
            return ("RTSP",f"{host}:{port}",True,f"{meth} {path} drop")
        data=b""
        try: data=s.recv(128)
        except Exception: pass
        s.close()
        if do_desc: st["dt"].append(time.time())
        m=re.search(rb"^RTSP/1\.[01]\s+(\d{3})", data)
        code=m.group(1).decode() if m else "?"
        return ("RTSP",f"{host}:{port}",True,f"{meth} {path} {code}")
    except Exception as e:
        return ("RTSP",f"{host}:{port}",False,type(e).__name__)

_COAP_PATH=["/sensor/temp","/sensor/hum","/status"]
def _coap_opts(path):
    segs=[s for s in path.strip("/").split("/") if s]
    prev=0; out=bytearray()
    for seg in segs:
        num=11; delta=num-prev; prev=num
        val=seg.encode("utf-8","ignore")
        if delta>12 or len(val)>12: continue
        out.append((delta<<4)|len(val)); out.extend(val)
    return bytes(out)

def coap_once(rng, avoid, targets):
    host,port=targets.get("coap",("",0))
    if not host or port<=0: return ("COAP","-",False,"no-target")
    path=rng.choice(_COAP_PATH)
    if avoid.bad(path): return ("COAP",f"{host}:{port}",False,"blocked(path)")
    mid=rng.randint(0,0xffff)
    pkt=bytes([0x40,0x01,(mid>>8)&0xff,mid&0xff]) + _coap_opts(path)  # CON GET
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(1.0)
        s.sendto(pkt,(host,port))
        msg=f"GET {path}"
        try:
            data,_=s.recvfrom(64)
            if data: msg+=" resp"
        except Exception:
            pass
        s.close()
        return ("COAP",f"{host}:{port}",True,msg)
    except Exception as e:
        return ("COAP",f"{host}:{port}",False,type(e).__name__)

def _esleep(rng, lam, end, stop):
    if lam<=0: time.sleep(0.25); return
    dt=min(rng.expovariate(lam),2.0)
    until=min(time.time()+dt,end)
    while not stop.is_set() and time.time()<until: time.sleep(0.05)

def _worker(name, lam, end, stop, rng, fn, counts):
    while not stop.is_set() and time.time()<end:
        _esleep(rng, lam, end, stop)
        if stop.is_set() or time.time()>=end: break
        proto,tgt,ok,msg=fn(rng)
        counts[proto]+=1
        _log(f"{proto}:{name}", tgt, ok, msg)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--duration", type=int, default=180)
    ap.add_argument("--rate", type=float, default=60.0)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--targets", default=None)
    ap.add_argument("--attacks-json", default=None)
    ap.add_argument("--rules", nargs="*", default=None)
    a=ap.parse_args()

    dur=max(1,int(a.duration))
    rate=(a.rate if a.rate and a.rate>0 else 10.0)
    if rate>240: _log("WARN","-",True,f"rate capped {rate}->240"); rate=240.0
    targets=parse_targets(a.targets)

    rules=[]
    if a.rules:
        for p in a.rules: rules += glob.glob(p) or [p]
    else:
        rules = glob.glob("*.rules") + glob.glob("suricata.rules")
    avoid=build_avoid(rules, a.attacks_json)

    rng0=random.Random(a.seed)
    dev=f"dev{rng0.randint(100,999)}"
    mh,mp=targets["mqtt"]
    mqtt=RawMQTT(mh,mp,f"sensor-{dev}",avoid)
    mqtt_state={"c":mqtt,"topic":f"home/telemetry/{dev}"}
    rtsp_state={"cseq":1,"dt":deque()}

    _log("START","-",True,f"duration={dur}s rate={rate:.1f}/min seed={a.seed}")
    _log("TARGETS","-",True,",".join(f"{k}={v[0]}:{v[1]}" for k,v in targets.items()))
    _log("AVOID","-",True,f"sub={len(avoid.sub)} rx={len(avoid.rx)} rules={len(rules)}")

    end=time.time()+dur; stop=threading.Event(); counts=Counter()
    lam=rate/60.0
    w={"http":0.35,"mqtt":0.45,"rtsp":0.17,"coap":0.03}
    threads=[
        threading.Thread(target=_worker, args=("http",lam*w["http"],end,stop,random.Random(rng0.randint(0,2**31-1)),
            lambda r: http_once(r,avoid,targets),counts), daemon=True),
        threading.Thread(target=_worker, args=("mqtt",lam*w["mqtt"],end,stop,random.Random(rng0.randint(0,2**31-1)),
            lambda r: mqtt_once(r,avoid,mqtt_state),counts), daemon=True),
        threading.Thread(target=_worker, args=("rtsp",lam*w["rtsp"],end,stop,random.Random(rng0.randint(0,2**31-1)),
            lambda r: rtsp_once(r,avoid,targets,rtsp_state),counts), daemon=True),
        threading.Thread(target=_worker, args=("coap",lam*w["coap"],end,stop,random.Random(rng0.randint(0,2**31-1)),
            lambda r: coap_once(r,avoid,targets),counts), daemon=True),
    ]
    try:
        for t in threads: t.start()
        while time.time()<end: time.sleep(0.2)
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        for t in threads: t.join(timeout=1.0)
        mqtt.close()

    print("\n"+"="*54)
    print(f"{_ts()} SUMMARY  total={sum(counts.values())}")
    for p in ("HTTP","MQTT","RTSP","COAP"):
        print(f"{p:>4}: {counts.get(p,0)}")
    print("="*54)
    return 0

if __name__=="__main__":
    raise SystemExit(main())
