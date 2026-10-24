import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape

import asyncpg
import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

DATABASE_URL = os.environ.get("DATABASE_URL", "")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  occurred_at TIMESTAMPTZ NOT NULL,
  event_type TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  tags TEXT[] NOT NULL DEFAULT '{}',
  geo_country TEXT,
  geo_city TEXT,
  geo_lat DOUBLE PRECISION,
  geo_lon DOUBLE PRECISION
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_country TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_city TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_lat DOUBLE PRECISION;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_lon DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS events_occurred_at_idx ON events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS events_type_idx ON events (event_type);
"""

async def open_pool():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=5, command_timeout=5)

@asynccontextmanager
async def lifespan(app: FastAPI):
    pool = None
    for attempt in range(20):
        try:
            pool = await open_pool()
            async with pool.acquire() as conn:
                await conn.execute(SCHEMA)
            break
        except Exception:
            if pool:
                await pool.close()
                pool = None
            if attempt == 19:
                raise
            await asyncio.sleep(3)
    app.state.pool = pool
    yield
    if pool:
        await pool.close()

app = FastAPI(title="Hacker Trap Public Dashboard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

class EventIn(BaseModel):
    timestamp: datetime | None = None
    event: str = Field(min_length=1, max_length=50)
    method: str = Field(default="GET", max_length=12)
    path: str = Field(default="/", max_length=300)
    status_code: int = Field(default=200, ge=100, le=599)
    tags: list[str] = Field(default_factory=list, max_length=30)
    client_ip: str | None = Field(default=None, max_length=64)

def classify(event_type: str, path: str, tags: list[str] | None = None) -> str:
    p = path.lower()
    tag_set = set(tags or [])
    if event_type == "fake_shell_access":
        return "decoy_access"
    if event_type == "login_attempt":
        return "password_attempt"
    if event_type == "server_error":
        return "server_error"
    # UA labels are self-reported and spoofable; these categories are heuristic.
    if "ua_claim:search_crawler" in tag_set:
        return "search_crawler"
    if "assessment:scanner_like" in tag_set:
        return "scanner_like"
    if any(x in p for x in ("/admin", "/dashboard", "wp-login", "wp-admin", "/.env", "phpmyadmin", "/config", "/backup")):
        return "admin_probe"
    if event_type == "http_request" and path != "/health":
        return "knock"
    return "request"

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/ingest")
async def ingest(event: EventIn, authorization: str | None = Header(default=None)):
    if not INGEST_TOKEN or authorization != f"Bearer {INGEST_TOKEN}":
        raise HTTPException(status_code=401, detail="Unauthorized")
    occurred_at = event.timestamp or datetime.now(timezone.utc)
    # Only coarse geolocation is retained; raw IP is sent to the lookup provider
    # for resolution and is never written to the database or public API.
    path = event.path.split("?", 1)[0][:300]
    tags = [str(t)[:80] for t in event.tags[:30]]
    country = city = None
    lat = lon = None
    ip = (event.client_ip or "").strip()
    if ip and ip not in {"127.0.0.1", "::1"}:
        try:
            import ipaddress
            parsed_ip = ipaddress.ip_address(ip)
            if parsed_ip.is_global:
                async with httpx.AsyncClient(timeout=1.5, follow_redirects=False) as client:
                    response = await client.get("https://ipwho.is/" + parsed_ip.compressed)
                    data = response.json() if response.status_code == 200 else {}
                if data.get("success"):
                    country = str(data.get("country") or "")[:100] or None
                    city = str(data.get("city") or "")[:100] or None
                    if isinstance(data.get("latitude"), (int, float)) and isinstance(data.get("longitude"), (int, float)):
                        lat, lon = float(data["latitude"]), float(data["longitude"])
        except Exception:
            pass
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO events
               (occurred_at, event_type, method, path, status_code, tags, geo_country, geo_city, geo_lat, geo_lon)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)""",
            occurred_at, event.event[:50], event.method[:12], path, event.status_code, tags,
            country, city, lat, lon
        )
    return {"accepted": True}

@app.get("/api/dashboard/summary")
async def summary():
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("""
          SELECT
            COUNT(*) FILTER (WHERE event_type = 'http_request' AND path <> '/health') AS knocks,
            COUNT(*) FILTER (WHERE event_type = 'login_attempt') AS password_attempts,
            COUNT(*) FILTER (WHERE event_type = 'http_request' AND
              (LOWER(path) LIKE '%/admin%' OR LOWER(path) LIKE '%wp-login%' OR LOWER(path) LIKE '%wp-admin%' OR LOWER(path) LIKE '%phpmyadmin%' OR LOWER(path) LIKE '%/.env%')) AS admin_probes,
            COUNT(*) FILTER (WHERE event_type = 'server_error') AS server_errors,
            COUNT(*) FILTER (WHERE event_type = 'http_request' AND method = 'GET' AND path = '/') AS recon_visits,
            COUNT(*) FILTER (WHERE event_type = 'http_request' AND method = 'GET' AND path = '/login') AS login_page_views,
            COUNT(*) FILTER (WHERE event_type = 'fake_shell_access') AS decoy_accesses,
            COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '24 hours') AS last_24h,
            MAX(occurred_at) AS last_event
          FROM events
        """)
    return {
        "knocks": row["knocks"],
        "password_attempts": row["password_attempts"],
        "admin_probes": row["admin_probes"],
        "server_errors": row["server_errors"],
        "recon_visits": row["recon_visits"],
        "login_page_views": row["login_page_views"],
        "decoy_accesses": row["decoy_accesses"],
        "last_24h": row["last_24h"],
        "last_event": row["last_event"].isoformat() if row["last_event"] else None,
        "intrusion_success": None,
        "intrusion_note": "この囮アプリには実システムへの侵入経路がないため、実侵入の成否は判定できません。"
    }

@app.get("/api/dashboard/geo")
async def geo_events():
    async with app.state.pool.acquire() as conn:
        # Public map uses coarse 10-degree cells, aggregated across events.
        # Do not expose city names, individual event timestamps, or exact coordinates.
        rows = await conn.fetch("""
          SELECT MIN(id) AS id, MAX(geo_country) AS geo_country,
                 ROUND(AVG(geo_lat) / 10.0) * 10.0 AS geo_lat,
                 ROUND(AVG(geo_lon) / 10.0) * 10.0 AS geo_lon,
                 COUNT(*) AS event_count
          FROM events
          WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
          GROUP BY geo_country, ROUND(geo_lat / 10.0), ROUND(geo_lon / 10.0)
          HAVING COUNT(*) >= 2
          ORDER BY COUNT(*) DESC
          LIMIT 100
        """)
        countries = await conn.fetch("""
          SELECT geo_country AS country, COUNT(*) AS count FROM events
          WHERE geo_country IS NOT NULL GROUP BY geo_country
          ORDER BY count DESC LIMIT 12
        """)
    return {
        "points": [{"id": r["id"], "country": r["geo_country"],
                    "lat": float(r["geo_lat"]), "lon": float(r["geo_lon"]),
                    "count": r["event_count"]} for r in rows],
        "countries": [{"country": r["country"], "count": r["count"]} for r in countries]
    }

@app.get("/api/dashboard/events")
async def recent_events(limit: int = 50):
    limit = max(1, min(limit, 100))
    async with app.state.pool.acquire() as conn:
        rows = await conn.fetch("""
          SELECT id, occurred_at, event_type, method, path, status_code, tags
          FROM events WHERE path <> '/health' ORDER BY occurred_at DESC LIMIT $1
        """, limit)
    result = []
    for r in rows:
        result.append({
            "id": r["id"],
            "timestamp": r["occurred_at"].isoformat(),
            "event_type": r["event_type"],
            "category": classify(r["event_type"], r["path"], r["tags"]),
            "method": r["method"],
            "path": r["path"],
            "status_code": r["status_code"],
            "tags": r["tags"],
        })
    return {"events": result}

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(PAGE)

PAGE = r"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="MK Honeypot — 公開ハニーポット観測ダッシュボード。匿名化・集計したアクセス傾向を公開します。">
<title>MK Honeypot — Public Monitor</title>
<style>
:root{color-scheme:dark;--bg:#080d18;--panel:#111a2b;--line:#24324a;--muted:#91a2bb;--text:#e8eef9;--green:#56e39f;--amber:#ffca70;--red:#ff6e7a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0,#172642 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1180px;margin:auto;padding:30px 20px 56px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;border-bottom:1px solid var(--line);padding-bottom:22px}
.brand{display:flex;align-items:center;gap:13px}.mark{width:42px;height:42px;border:1px solid #3b5578;border-radius:12px;display:grid;place-items:center;color:var(--green);font-weight:900;font-size:20px}
h1{font-size:clamp(21px,4vw,30px);margin:0;letter-spacing:.02em}.sub{color:var(--muted);font-size:13px;margin-top:3px}.live{color:var(--green);border:1px solid #245b48;border-radius:99px;padding:6px 11px;font-size:12px;white-space:nowrap}
.notice{margin:22px 0;padding:13px 16px;background:#201b12;border:1px solid #55452a;color:#f2d9a6;border-radius:10px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#141f33,#101827);border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.label{color:var(--muted);font-size:13px}.value{font-size:clamp(26px,4vw,38px);font-weight:750;letter-spacing:-.03em;margin:9px 0 4px}.hint{color:var(--muted);font-size:12px}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}
section{margin-top:28px}.sectionhead{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px}h2{font-size:17px;margin:0}.small{color:var(--muted);font-size:12px}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:#0d1523}table{width:100%;border-collapse:collapse;min-width:650px}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #1d2a3e;font-size:13px}th{color:var(--muted);font-weight:600;background:#111b2c}td.path{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.badge{display:inline-block;border-radius:6px;padding:3px 7px;background:#1a2b41;color:#bdd5f4;font-size:11px}.badge.warn{background:#392819;color:#ffd08a}.badge.fail{background:#3a202b;color:#ff9da5}.empty{color:var(--muted);text-align:center;padding:28px}
.pathway{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.stage{border:1px solid var(--line);border-radius:10px;padding:14px;background:#0d1523;min-width:0}.stage-num{color:var(--green);font-size:11px;letter-spacing:.08em}.stage-name{font-size:13px;margin:7px 0}.stage-count{font-size:25px;font-weight:750}.stage-arrow{color:#66809f;font-size:12px;margin-top:4px}
.maplayout{display:grid;grid-template-columns:minmax(0,2fr) minmax(210px,1fr);gap:14px}.mapbox{overflow:hidden;background:radial-gradient(ellipse at center,#12243a,#08111e 78%);border:1px solid var(--line);border-radius:12px;min-height:300px}#worldmap{display:block;width:100%;height:auto;min-height:300px}.land{fill:#244563;stroke:#496b8b;stroke-width:.65;stroke-linejoin:round}.borders{fill:none;stroke:#375673;stroke-width:.48;pointer-events:none}.mapgrid{stroke:#1a2b40;stroke-width:1;fill:none}.geo-point{fill:#59e6aa;stroke:#b8ffe0;stroke-width:1.5;cursor:pointer}.pulse{fill:none;stroke:#59e6aa;stroke-width:2;transform-box:fill-box;transform-origin:center;animation:pulse 2.2s ease-out infinite}.route-line{fill:none;stroke:#70f5ff;stroke-width:2.4;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1;filter:drop-shadow(0 0 4px #4cecff);animation:route-flight 1.15s cubic-bezier(.2,.75,.2,1) forwards}.route-core{fill:none;stroke:#e6ffff;stroke-width:1;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1;animation:route-flight 1.15s cubic-bezier(.2,.75,.2,1) forwards}.honeypot-target{fill:#ffcf70;stroke:#fff0c4;stroke-width:2;filter:drop-shadow(0 0 7px #ffb547)}.target-ring{fill:none;stroke:#ffcf70;stroke-width:1.6;transform-box:fill-box;transform-origin:center;animation:pulse 1.8s ease-out infinite}.target-label{fill:#ffdf9b;font:700 13px system-ui,sans-serif;paint-order:stroke;stroke:#08111e;stroke-width:4px;stroke-linejoin:round}@keyframes route-flight{0%{stroke-dashoffset:1;opacity:.25}12%{opacity:1}88%{opacity:1}100%{stroke-dashoffset:0;opacity:0}}@keyframes pulse{0%{opacity:.9;transform:scale(.4)}100%{opacity:0;transform:scale(3.8)}}.countrylist{display:flex;flex-direction:column;gap:8px}.countryrow{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid var(--line);padding:8px 0;font-size:13px}.countryrow b{color:var(--green)}footer{margin-top:28px;color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.pathway{grid-template-columns:repeat(2,minmax(0,1fr))}.maplayout{grid-template-columns:1fr}}@media(max-width:480px){main{padding:20px 12px 36px}.grid{gap:9px}.card{padding:13px}.top{align-items:flex-start}.live{font-size:11px}}
</style></head><body><main>
<header class="top"><div class="brand"><div class="mark">H</div><div><h1>MK Honeypot</h1><div class="sub">PUBLIC SECURITY OBSERVABILITY · LIVE EVENT FEED</div></div></div><div class="live">● 公開モニター</div></header>
<div class="notice">公開観測ダッシュボードです。IPアドレス・生のUser-Agent・認証情報は表示しません。地図は位置情報を約10度単位で集約し、複数イベントがある領域のみ表示します。「スキャナー候補」などの分類はアクセスパターンに基づく推定で、発信元の身元を確認したものではありません。アクセスの観測は侵入成功を意味しません。</div>
<div class="grid">
<article class="card"><div class="label">総アクセス（観測）</div><div class="value" id="knocks">—</div><div class="hint">記録されたHTTPリクエスト</div></article>
<article class="card"><div class="label">パスワード試行</div><div class="value amber" id="passwords">—</div><div class="hint">偽ログイン画面への送信回数</div></article>
<article class="card"><div class="label">管理画面の探索</div><div class="value red" id="probes">—</div><div class="hint">管理・既知パスへのアクセス</div></article>
<article class="card"><div class="label">直近24時間のイベント</div><div class="value green" id="last24">—</div><div class="hint">保存された全イベント</div></article>
</div>
<section><div class="sectionhead"><h2>侵入状況</h2><span class="small">判定の限界</span></div><div class="card"><div class="value amber" style="font-size:20px">実侵入：判定対象外</div><div class="hint" id="intrusionNote">この囮アプリは本物の内部システムを公開していないため、実侵入の成功を判定できません。</div></div></section>
<section><div class="sectionhead"><h2>アクセス元マップ</h2><span class="small">約10度単位の集約位置・5秒ごとに更新</span></div>
<div class="maplayout"><div class="mapbox"><svg id="worldmap" viewBox="0 0 1000 500" role="img" aria-label="アクセス元の概算位置を示す世界地図">
<g class="mapgrid"><path d="M0 100H1000 M0 200H1000 M0 300H1000 M0 400H1000 M200 0V500 M400 0V500 M600 0V500 M800 0V500"/></g>
<g id="world-land" class="land"></g><path id="country-borders" class="borders" d=""/><g id="geo-routes"></g><g id="geo-points"></g><g id="honeypot-target"></g></svg></div>
<div class="card"><h2>アクセス元の国・地域</h2><div class="hint" style="margin-bottom:10px">直近の位置情報付きイベント</div><div id="countries" class="countrylist"><div class="empty">位置情報を待っています…</div></div><div class="hint" style="margin-top:14px">地図の点は複数イベントをまとめた粗い位置区画です。個別イベントや正確な所在地を示すものではありません。</div></div></div>
<div class="hint" style="margin-top:8px">IPアドレスそのものは公開しません。位置推定には外部のIPジオロケーションサービスを利用します。位置情報が取得できないイベントや、複数件に満たない位置区画は地図に表示されません。</div></section>
<section><div class="sectionhead"><h2>観測された侵入経路</h2><span class="small">各段階の累計・同一人物の追跡ではありません</span></div><div class="pathway">
<div class="stage"><div class="stage-num">STEP 01</div><div class="stage-name">偵察・トップページ</div><div class="stage-count" id="recon">—</div><div class="stage-arrow">アクセス観測</div></div>
<div class="stage"><div class="stage-num">STEP 02</div><div class="stage-name">ログイン画面</div><div class="stage-count" id="loginViews">—</div><div class="stage-arrow">画面表示</div></div>
<div class="stage"><div class="stage-num">STEP 03</div><div class="stage-name">パスワード試行</div><div class="stage-count" id="pathPasswords">—</div><div class="stage-arrow">POST リクエスト</div></div>
<div class="stage"><div class="stage-num">STEP 04</div><div class="stage-name">管理画面探索</div><div class="stage-count" id="pathProbes">—</div><div class="stage-arrow">既知パスへのアクセス</div></div>
<div class="stage"><div class="stage-num">STEP 05</div><div class="stage-name">囮コンソール到達</div><div class="stage-count" id="decoyAccesses">—</div><div class="stage-arrow">/fake-shell · 実行機能なし</div></div>
</div><div class="hint" style="margin-top:9px">これは段階別の累計です。プライバシー保護のため訪問者を識別・追跡しておらず、個々のアクセスがこの順番で進んだことを意味しません。</div></section>
<section><div class="sectionhead"><h2>最新イベント</h2><span class="small" id="updated">読み込み中</span></div><div class="tablewrap"><table><thead><tr><th>時刻 (UTC)</th><th>分類</th><th>メソッド</th><th>パス</th><th>HTTP</th><th>タグ</th></tr></thead><tbody id="events"><tr><td colspan="6" class="empty">イベントを取得しています…</td></tr></tbody></table></div></section>
<footer><span>MK Honeypot · Public dashboard</span><span>5秒ごとに更新 · 公開表示用に匿名化</span></footer>
</main>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script><script src="https://cdn.jsdelivr.net/npm/topojson-client@3"></script><script>
let mapProjection=null;
async function initWorldMap(){try{const r=await fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json",{cache:"force-cache"});if(!r.ok)throw Error("map data");const world=await r.json();const features=topojson.feature(world,world.objects.countries).features;mapProjection=d3.geoNaturalEarth1().fitExtent([[12,12],[988,488]],{type:"FeatureCollection",features});const path=d3.geoPath(mapProjection);const land=document.getElementById("world-land");land.replaceChildren();for(const feature of features){const p=document.createElementNS("http://www.w3.org/2000/svg","path");p.setAttribute("d",path(feature));p.setAttribute("class","land");land.append(p)}const borders=document.getElementById("country-borders");borders.setAttribute("d",path(topojson.mesh(world,world.objects.countries,(a,b)=>a!==b)));}catch(e){document.getElementById("worldmap").setAttribute("aria-label","世界地図データを読み込めませんでした。アクセス地点のみ表示します。")}}
const fmtTime=s=>{try{return new Date(s).toISOString().replace('T',' ').slice(0,19)}catch{return s||'—'}};
const label=c=>({http_request:'ノック / HTTP',login_attempt:'パスワード試行',server_error:'サーバーエラー',admin_probe:'管理画面探索',password_attempt:'パスワード試行',knock:'ノック / HTTP',request:'リクエスト',search_crawler:'検索クローラー候補',scanner_like:'スキャナー候補'}[c]||c);
const badge=c=>c==='login_attempt'||c==='password_attempt'||c==='search_crawler'?'warn':c==='server_error'||c==='admin_probe'||c==='scanner_like'?'fail':'';
function project(lon,lat){if(mapProjection){const q=mapProjection([lon,lat]);return {x:q[0],y:q[1]}}return {x:(lon+180)/360*1000,y:(90-lat)/180*500}}
const honeypotLocation={lon:-122.4,lat:37.8,label:'MK Honeypot · SFO'};
let geoSeenCounts=null;
function drawHoneypotTarget(){const layer=document.getElementById('honeypot-target');layer.replaceChildren();const q=project(honeypotLocation.lon,honeypotLocation.lat);const ns='http://www.w3.org/2000/svg';const ring=document.createElementNS(ns,'circle');ring.setAttribute('cx',q.x);ring.setAttribute('cy',q.y);ring.setAttribute('r','7');ring.setAttribute('class','target-ring');layer.append(ring);const dot=document.createElementNS(ns,'circle');dot.setAttribute('cx',q.x);dot.setAttribute('cy',q.y);dot.setAttribute('r','5');dot.setAttribute('class','honeypot-target');layer.append(dot);const label=document.createElementNS(ns,'text');label.setAttribute('x',q.x+10);label.setAttribute('y',q.y-10);label.setAttribute('class','target-label');label.textContent=honeypotLocation.label;layer.append(label)}
function animateRoute(from){const to=project(honeypotLocation.lon,honeypotLocation.lat);if(Math.hypot(from.x-to.x,from.y-to.y)<8)return;const ns='http://www.w3.org/2000/svg';const layer=document.getElementById('geo-routes');const path=document.createElementNS(ns,'path');const mx=(from.x+to.x)/2,my=(from.y+to.y)/2;const dx=to.x-from.x,dy=to.y-from.y;const bend=Math.min(90,Math.max(22,Math.hypot(dx,dy)*.16));const sign=from.x<to.x?-1:1;const d='M '+from.x+' '+from.y+' Q '+(mx)+' '+(my-bend*sign)+' '+to.x+' '+to.y;path.setAttribute('d',d);path.setAttribute('pathLength','1');path.setAttribute('class','route-line');layer.append(path);const core=document.createElementNS(ns,'path');core.setAttribute('d',d);core.setAttribute('pathLength','1');core.setAttribute('class','route-core');layer.append(core);setTimeout(()=>{path.remove();core.remove()},1400)}

async function refreshGeo(){try{
 const r=await fetch('/api/dashboard/geo',{cache:'no-store'});if(!r.ok)throw Error('geo api');
 const data=await r.json(),layer=document.getElementById('geo-points');layer.replaceChildren();
 const points=data.points||[],nextCounts=new Map();
 for(const p of points){const q=project(p.lon,p.lat);if(q.x<0||q.x>1000||q.y<0||q.y>500)continue;
 const key=String(p.id),count=Number(p.count)||0;nextCounts.set(key,count);
 const g=document.createElementNS('http://www.w3.org/2000/svg','g');g.setAttribute('transform','translate('+q.x+','+q.y+')');
 const pulse=document.createElementNS('http://www.w3.org/2000/svg','circle');pulse.setAttribute('r','4');pulse.setAttribute('class','pulse');g.append(pulse);
 const dot=document.createElementNS('http://www.w3.org/2000/svg','circle');dot.setAttribute('r',String(Math.min(8,3+Math.log2(count||1))));dot.setAttribute('class','geo-point');
 const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=[p.country,count.toLocaleString()+' events (aggregated)'].filter(Boolean).join(' · ');dot.append(title);g.append(dot);layer.append(g);}
 // Animate the initial visible sample once, then only buckets whose counts have increased.
 const changed=geoSeenCounts===null?points.slice(0,12):points.filter(p=>Number(p.count||0)>(geoSeenCounts.get(String(p.id))||0)).slice(0,6);
 for(const p of changed){animateRoute(project(p.lon,p.lat))}
 geoSeenCounts=nextCounts;
 drawHoneypotTarget();
 const list=document.getElementById('countries');list.replaceChildren();
 if(!(data.countries||[]).length){const e=document.createElement('div');e.className='empty';e.textContent='まだ位置情報付きイベントはありません';list.append(e)}
 for(const item of (data.countries||[])){const row=document.createElement('div');row.className='countryrow';const name=document.createElement('span');name.textContent=item.country;const count=document.createElement('b');count.textContent=Number(item.count).toLocaleString();row.append(name,count);list.append(row)}
 }catch(e){document.getElementById('countries').textContent='位置情報を取得できません';}}
async function refresh(){try{
 const [s,e]=await Promise.all([fetch('/api/dashboard/summary',{cache:'no-store'}),fetch('/api/dashboard/events?limit=50',{cache:'no-store'})]);
 if(!s.ok||!e.ok)throw Error('API error');const a=await s.json(),b=await e.json();
 document.getElementById('knocks').textContent=a.knocks.toLocaleString();document.getElementById('passwords').textContent=a.password_attempts.toLocaleString();document.getElementById('probes').textContent=a.admin_probes.toLocaleString();document.getElementById('last24').textContent=a.last_24h.toLocaleString();document.getElementById('intrusionNote').textContent=a.intrusion_note;document.getElementById('recon').textContent=a.recon_visits.toLocaleString();document.getElementById('loginViews').textContent=a.login_page_views.toLocaleString();document.getElementById('pathPasswords').textContent=a.password_attempts.toLocaleString();document.getElementById('pathProbes').textContent=a.admin_probes.toLocaleString();document.getElementById('decoyAccesses').textContent=a.decoy_accesses.toLocaleString();
 const body=document.getElementById('events');body.replaceChildren();
 if(!b.events.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.className='empty';td.textContent='まだイベントはありません';tr.append(td);body.append(tr)}
 for(const ev of b.events){const tr=document.createElement('tr');const vals=[fmtTime(ev.timestamp),label(ev.category),ev.method,ev.path,String(ev.status_code),(ev.tags||[]).join(', ')||'—'];vals.forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===3)td.className='path';if(i===1){const span=document.createElement('span');span.className='badge '+badge(ev.category);span.textContent=v;td.replaceChildren(span)}tr.append(td)});body.append(tr)}
 document.getElementById('updated').textContent='最終更新 '+new Date().toLocaleTimeString('ja-JP');
 }catch(e){document.getElementById('updated').textContent='取得エラー';}}
initWorldMap().then(()=>{drawHoneypotTarget();refreshGeo()});refresh();refreshGeo();setInterval(refresh,5000);setInterval(refreshGeo,5000);
</script></body></html>"""
