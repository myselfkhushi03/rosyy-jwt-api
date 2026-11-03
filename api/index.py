# api/index.py - FINAL MAST API
from fastapi import FastAPI, Query
import httpx, uuid, random
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

app = FastAPI()

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
GRANT_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

MSDK_AGENTS = ["GarenaMSDK/4.0.42(SM-G998B ;Android 14;en;IN;app 2.131.0 2019118527;)"]

def enc(b): return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(b, 16))
def ev(n):
    out=bytearray()
    while True:
        b=n&0x7F; n>>=7
        if n: b|=0x80
        out.append(b)
        if not n: break
    return bytes(out)
def build_proto(fields):
    p=[]
    for k,v in fields.items():
        if isinstance(v,int): p.append(ev((k<<3)|0)+ev(v))
        elif isinstance(v,(str,bytes)):
            e=v.encode() if isinstance(v,str) else v
            p.append(ev((k<<3)|2)+ev(len(e))+e)
    return b''.join(p)
def read_varint(buf,pos):
    r,s=0,0
    while pos<len(buf):
        b=buf[pos]; pos+=1
        r|=(b&0x7F)<<s
        if not (b&0x80): return r,pos
        s+=7
    raise ValueError()
def parse_proto_raw(buf):
    f,pos={},0
    while pos<len(buf):
        try: key,pos=read_varint(buf,pos)
        except: break
        fn,wire=key>>3,key&0x7
        if wire==0:
            try: val,pos=read_varint(buf,pos)
            except: break
            f.setdefault(fn,[]).append(("varint",val))
        elif wire==2:
            try: ln,pos=read_varint(buf,pos)
            except: break
            if pos+ln>len(buf): break
            f.setdefault(fn,[]).append(("bytes",buf[pos:pos+ln])); pos+=ln
        else:
            pos+=4 if wire==5 else 8
    return f
def bytes_to_str(b):
    try:
        s=b.decode()
        if s.startswith("eyJ") or s.startswith("http"): return s
        if 1<=len(s)<=40 and s.isprintable(): return s
    except: pass
def find_proto(raw, need=True):
    for off in range(min(200,len(raw))):
        try: fields=parse_proto_raw(raw[off:])
        except: continue
        if need:
            ok=any(bytes_to_str(v) and bytes_to_str(v).startswith("eyJ") for es in fields.values() for _,v in es)
            if not ok: continue
        return off,fields
    return None,None
def map_login(fields):
    out={"account_id":None,"region":None,"token":None,"url":None}
    for fn,es in fields.items():
        for wt,v in es:
            if wt=="varint" and fn==1: out["account_id"]=v
            elif wt=="bytes":
                s=bytes_to_str(v)
                if s:
                    if s.startswith("eyJ") and len(s)>100: out["token"]=s
                    elif s.startswith("http"): out["url"]=s
                    elif fn==2: out["region"]=s
    return out
def map_profile(fields):
    out={"nickname":None,"level":None}
    for fn,es in fields.items():
        for wt,v in es:
            if wt=="varint" and fn==6: out["level"]=v
            elif wt=="bytes" and fn==4:
                s=bytes_to_str(v)
                if s: out["nickname"]=s
    return out

async def request_token(uid,pwd,ua):
    data={"uid":uid,"password":pwd,"response_type":"token","client_type":"2","client_secret":CLIENT_SECRET,"client_id":"100067"}
    async with httpx.AsyncClient(verify=False,timeout=20) as c:
        r=await c.post(GRANT_URL,data=data,headers={"User-Agent":ua})
        j=r.json()
        return j["access_token"],j["open_id"],j.get("platform",4)

async def build_majorlogin(oid,at,plat,region):
    dev=f"Google|{uuid.uuid4()}"
    country="IN" if region.upper()=="IND" else region.upper()[:2]
    payload={3:str(datetime.now())[:-7],4:"free fire",5:"1",7:"1.108.3",8:"Android OS 13",19:dev,20:"127.0.0.1",21:"en",22:str(oid),23:str(plat),26:country,29:str(at),30:"1",73:3,76:2,78:2,79:1,81:"32"}
    return enc(build_proto(payload))

async def major_login(data,ver,url):
    h={'User-Agent':'UnityPlayer/2018.4.12f1','Content-Type':'application/x-www-form-urlencoded','X-GA':'v1 1','ReleaseVersion':ver}
    async with httpx.AsyncClient(verify=False,timeout=20) as c:
        r=await c.post(f"{url.rstrip('/')}/MajorLogin",headers=h,data=data)
        return r.content

async def get_login_data(payload,base,token,ver):
    h={'User-Agent':'UnityPlayer/2018.4.12f1','Content-Type':'application/x-www-form-urlencoded','X-GA':'v1 1','ReleaseVersion':ver,'Authorization':f'Bearer {token}'}
    try:
        async with httpx.AsyncClient(verify=False,timeout=10) as c:
            r=await c.post(f"{base.rstrip('/')}/GetLoginData",headers=h,data=payload)
            return r.content
    except: return b""

@app.get("/")
async def root(): return {"use":"/api?uid=UID&password=PASS&region=IND"}

@app.get("/api")
async def api(uid: str=Query(...), password: str=Query(...), region: str="IND"):
    try:
        ua=random.choice(MSDK_AGENTS)
        at,oid,plat=await request_token(uid,password,ua)
        payload=await build_majorlogin(oid,at,plat,region)
        raw=await major_login(payload,"OB49","https://loginbp.ggblueshark.com")
        off,fields=find_proto(raw,True)
        if not fields: return {"success":False,"error":"IP BLOCK"}
        lg=map_login(fields)
        nick=f"Player_{lg['account_id']}"; lvl=1
        try:
            gl=await get_login_data(payload,lg["url"] or "https://client.ind.freefiremobile.com",lg["token"],"OB49")
            off2,f2=find_proto(gl,False)
            if f2:
                pf=map_profile(f2)
                if pf["nickname"]: nick=pf["nickname"]
                if pf["level"]: lvl=pf["level"]
        except: pass
        return {"success":True,"token":lg["token"],"account_id":lg["account_id"],"nickname":nick,"level":lvl,"region":lg["region"] or region,"server_url":lg["url"],"open_id":oid}
    except Exception as e:
        return {"success":False,"error":str(e)}
