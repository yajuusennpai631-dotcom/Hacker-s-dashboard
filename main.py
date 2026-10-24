import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from html import escape

import asyncpg
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
  tags TEXT[] NOT NULL DEFAULT '{}'
);
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

def classify(event_type: str, path: str) -> str:
    p = path.lower()
    if event_type == "login_attempt" or (p == "/login" and event_type != "http_request"):
        return "password_attempt"
    if any(x in p for x in ("/admin", "/dashboard", "wp-login", "wp-admin", "/.env", "phpmyadmin")):
        return "admin_probe"
    if event_type == "server_error" or event_type == "http_request" and path != "/health":
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
    # Public dashboard intentionally excludes IP addresses, user-agent strings,
    # query values, request bodies, and credentials.
    path = event.path.split("?", 1)[0][:300]
    tags = [str(t)[:80] for t in event.tags[:30]]
    async with app.state.pool.acquire() as conn:
        await conn.execute(
            """INSERT INTO events (occurred_at, event_type, method, path, status_code, tags)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            occurred_at, event.event[:50], event.method[:12], path, event.status_code, tags
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
            COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '24 hours') AS last_24h,
            MAX(occurred_at) AS last_event
          FROM events
        """)
    return {
        "knocks": row["knocks"],
        "password_attempts": row["password_attempts"],
        "admin_probes": row["admin_probes"],
        "server_errors": row["server_errors"],
        "last_24h": row["last_24h"],
        "last_event": row["last_event"].isoformat() if row["last_event"] else None,
        "intrusion_success": None,
        "intrusion_note": "この囮アプリには実システムへの侵入経路がないため、実侵入の成否は判定できません。"
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
            "category": classify(r["event_type"], r["path"]),
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
<meta name="description" content="Hacker Trap 公開セキュリティ観測ダッシュボード">
<title>Hacker Trap — Public Monitor</title>
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
footer{margin-top:28px;color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){main{padding:20px 12px 36px}.grid{gap:9px}.card{padding:13px}.top{align-items:flex-start}.live{font-size:11px}}
</style></head><body><main>
<header class="top"><div class="brand"><div class="mark">H</div><div><h1>Hacker Trap</h1><div class="sub">PUBLIC SECURITY OBSERVABILITY · LIVE EVENT FEED</div></div></div><div class="live">● 公開モニター</div></header>
<div class="notice">公開ダッシュボードです。プライバシー保護のため、IPアドレス・ユーザーエージェント・認証情報は表示しません。ここでの「ノック」はアクセスの観測を意味し、侵入成功を意味しません。</div>
<div class="grid">
<article class="card"><div class="label">総アクセス（観測）</div><div class="value" id="knocks">—</div><div class="hint">記録されたHTTPリクエスト</div></article>
<article class="card"><div class="label">パスワード試行</div><div class="value amber" id="passwords">—</div><div class="hint">偽ログイン画面への送信回数</div></article>
<article class="card"><div class="label">管理画面の探索</div><div class="value red" id="probes">—</div><div class="hint">管理・既知パスへのアクセス</div></article>
<article class="card"><div class="label">直近24時間のイベント</div><div class="value green" id="last24">—</div><div class="hint">保存された全イベント</div></article>
</div>
<section><div class="sectionhead"><h2>侵入状況</h2><span class="small">判定の限界</span></div><div class="card"><div class="value amber" style="font-size:20px">実侵入：判定対象外</div><div class="hint" id="intrusionNote">この囮アプリは本物の内部システムを公開していないため、実侵入の成功を判定できません。</div></div></section>
<section><div class="sectionhead"><h2>最新イベント</h2><span class="small" id="updated">読み込み中</span></div><div class="tablewrap"><table><thead><tr><th>時刻 (UTC)</th><th>分類</th><th>メソッド</th><th>パス</th><th>HTTP</th><th>タグ</th></tr></thead><tbody id="events"><tr><td colspan="6" class="empty">イベントを取得しています…</td></tr></tbody></table></div></section>
<footer><span>Hacker Trap · Public dashboard</span><span>5秒ごとに更新 · 公開表示用に匿名化</span></footer>
</main>
<script>
const fmtTime=s=>{try{return new Date(s).toISOString().replace('T',' ').slice(0,19)}catch{return s||'—'}};
const label=c=>({http_request:'ノック / HTTP',login_attempt:'パスワード試行',server_error:'サーバーエラー',admin_probe:'管理画面探索',password_attempt:'パスワード試行',knock:'ノック / HTTP',request:'リクエスト'}[c]||c);
const badge=c=>c==='login_attempt'||c==='password_attempt'?'warn':c==='server_error'||c==='admin_probe'?'fail':'';
async function refresh(){try{
 const [s,e]=await Promise.all([fetch('/api/dashboard/summary',{cache:'no-store'}),fetch('/api/dashboard/events?limit=50',{cache:'no-store'})]);
 if(!s.ok||!e.ok)throw Error('API error');const a=await s.json(),b=await e.json();
 document.getElementById('knocks').textContent=a.knocks.toLocaleString();document.getElementById('passwords').textContent=a.password_attempts.toLocaleString();document.getElementById('probes').textContent=a.admin_probes.toLocaleString();document.getElementById('last24').textContent=a.last_24h.toLocaleString();document.getElementById('intrusionNote').textContent=a.intrusion_note;
 const body=document.getElementById('events');body.replaceChildren();
 if(!b.events.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.className='empty';td.textContent='まだイベントはありません';tr.append(td);body.append(tr)}
 for(const ev of b.events){const tr=document.createElement('tr');const vals=[fmtTime(ev.timestamp),label(ev.category),ev.method,ev.path,String(ev.status_code),(ev.tags||[]).join(', ')||'—'];vals.forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===3)td.className='path';if(i===1){const span=document.createElement('span');span.className='badge '+badge(ev.category);span.textContent=v;td.replaceChildren(span)}tr.append(td)});body.append(tr)}
 document.getElementById('updated').textContent='最終更新 '+new Date().toLocaleTimeString('ja-JP');
 }catch(e){document.getElementById('updated').textContent='取得エラー';}}
refresh();setInterval(refresh,5000);
</script></body></html>"""
