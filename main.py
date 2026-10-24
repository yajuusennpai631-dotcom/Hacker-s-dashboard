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
HONEYPOT_HEALTH_URL = os.environ.get("HONEYPOT_HEALTH_URL", "http://honeypot-web.railway.internal:8080/health")

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
  geo_lon DOUBLE PRECISION,
  response_ms DOUBLE PRECISION
);
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_country TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_city TEXT;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_lat DOUBLE PRECISION;
ALTER TABLE events ADD COLUMN IF NOT EXISTS geo_lon DOUBLE PRECISION;
ALTER TABLE events ADD COLUMN IF NOT EXISTS response_ms DOUBLE PRECISION;
CREATE INDEX IF NOT EXISTS events_occurred_at_idx ON events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS events_type_idx ON events (event_type);
CREATE INDEX IF NOT EXISTS events_path_idx ON events (path);
CREATE INDEX IF NOT EXISTS events_status_idx ON events (status_code);
CREATE INDEX IF NOT EXISTS events_method_time_idx ON events (method, occurred_at DESC);
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
    response_ms: float | None = Field(default=None, ge=0, le=120000)

PUBLIC_TAGS = {
    "ua_claim:search_crawler", "ua_claim:scanner_tool", "ua_claim:automation",
    "signal:exploit_probe", "signal:common_scan_path", "signal:non_read_method",
    "assessment:scanner_like",
    "payload:sql_injection_candidate", "payload:path_traversal_candidate",
    "payload:xss_candidate", "payload:command_injection_candidate",
    "payload:sensitive_path_candidate",
}

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
               (occurred_at, event_type, method, path, status_code, tags, geo_country, geo_city, geo_lat, geo_lon, response_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)""",
            occurred_at, event.event[:50], event.method[:12], path, event.status_code, tags,
            country, city, lat, lon, event.response_ms
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


@app.get("/api/dashboard/analytics")
async def analytics():
    async with app.state.pool.acquire() as conn:
        hourly = await conn.fetch("""
          SELECT buckets.bucket AS hour,
                 COUNT(e.id) AS total,
                 COUNT(e.id) FILTER (WHERE e.status_code >= 500) AS errors
          FROM generate_series(
            date_trunc('hour', NOW()) - INTERVAL '23 hours',
            date_trunc('hour', NOW()),
            INTERVAL '1 hour'
          ) AS buckets(bucket)
          LEFT JOIN events e
            ON e.occurred_at >= buckets.bucket
           AND e.occurred_at < buckets.bucket + INTERVAL '1 hour'
           AND e.path <> '/health'
          GROUP BY buckets.bucket
          ORDER BY buckets.bucket
        """)
        categories = await conn.fetch("""
          SELECT CASE
            WHEN event_type = 'fake_shell_access' THEN 'decoy_access'
            WHEN event_type = 'login_attempt' THEN 'password_attempt'
            WHEN event_type = 'server_error' THEN 'server_error'
            WHEN 'ua_claim:search_crawler' = ANY(tags) THEN 'search_crawler'
            WHEN 'assessment:scanner_like' = ANY(tags) THEN 'scanner_like'
            WHEN LOWER(path) LIKE '%/admin%' OR LOWER(path) LIKE '%wp-login%'
              OR LOWER(path) LIKE '%wp-admin%' OR LOWER(path) LIKE '%/.env%'
              OR LOWER(path) LIKE '%phpmyadmin%' OR LOWER(path) LIKE '%/config%'
              OR LOWER(path) LIKE '%/backup%' THEN 'admin_probe'
            WHEN event_type = 'http_request' AND path <> '/health' THEN 'knock'
            ELSE 'request'
          END AS category, COUNT(*) AS count
          FROM events
          WHERE path <> '/health' AND occurred_at >= NOW() - INTERVAL '24 hours'
          GROUP BY category
          ORDER BY count DESC
        """)
        paths = await conn.fetch("""
          SELECT path, COUNT(*) AS count
          FROM events
          WHERE path <> '/health' AND occurred_at >= NOW() - INTERVAL '24 hours'
          GROUP BY path
          ORDER BY count DESC, path ASC
          LIMIT 8
        """)
        statuses = await conn.fetch("""
          SELECT status_code, COUNT(*) AS count
          FROM events
          WHERE path <> '/health' AND occurred_at >= NOW() - INTERVAL '24 hours'
          GROUP BY status_code
          ORDER BY count DESC, status_code ASC
          LIMIT 8
        """)

        timeline = await conn.fetch("""
          SELECT date_trunc('hour', occurred_at)
                   + (FLOOR(EXTRACT(MINUTE FROM occurred_at) / 10) * INTERVAL '10 minutes') AS bucket,
                 COUNT(*) AS total,
                 COUNT(*) FILTER (WHERE status_code >= 500) AS errors,
                 COUNT(*) FILTER (WHERE 'assessment:scanner_like' = ANY(tags)) AS scanner_candidates,
                 COUNT(*) FILTER (WHERE event_type = 'login_attempt') AS login_attempts
          FROM events
          WHERE path <> '/health' AND occurred_at >= NOW() - INTERVAL '24 hours'
          GROUP BY bucket ORDER BY bucket
        """)
        signals = await conn.fetch("""
          SELECT signal, COUNT(*) AS count
          FROM (
            SELECT CASE
              WHEN 'signal:exploit_probe' = ANY(tags) THEN 'Exploitパターン候補'
              WHEN 'signal:common_scan_path' = ANY(tags) THEN '既知スキャンパス候補'
              WHEN 'signal:non_read_method' = ANY(tags) THEN '非読み取りHTTPメソッド'
              WHEN 'assessment:scanner_like' = ANY(tags) THEN 'スキャナー候補'
              WHEN 'ua_claim:search_crawler' = ANY(tags) THEN '検索クローラー申告'
              WHEN event_type = 'login_attempt' THEN 'ログイン試行'
              WHEN status_code >= 500 THEN 'サーバーエラー'
              WHEN LOWER(path) LIKE '%/admin%' OR LOWER(path) LIKE '%wp-login%'
                OR LOWER(path) LIKE '%wp-admin%' OR LOWER(path) LIKE '%/.env%'
                OR LOWER(path) LIKE '%phpmyadmin%' OR LOWER(path) LIKE '%/config%'
                OR LOWER(path) LIKE '%/backup%' THEN '管理パス探索候補'
              ELSE NULL
            END AS signal
            FROM events
            WHERE path <> '/health' AND occurred_at >= NOW() - INTERVAL '24 hours'
          ) detected WHERE signal IS NOT NULL
          GROUP BY signal ORDER BY count DESC LIMIT 10
        """)
        alert_counts = await conn.fetchrow("""
          SELECT
            COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '5 minutes') AS recent,
            COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '60 minutes'
              AND occurred_at < NOW() - INTERVAL '5 minutes') AS previous
          FROM events WHERE path <> '/health'
        """)

        methods = await conn.fetch("""
          SELECT method, COUNT(*) AS count
          FROM events WHERE occurred_at >= NOW() - INTERVAL '24 hours' AND path <> '/health'
          GROUP BY method ORDER BY count DESC LIMIT 10
        """)
        status_families = await conn.fetch("""
          SELECT (status_code / 100)::text || 'xx' AS family, COUNT(*) AS count
          FROM events WHERE occurred_at >= NOW() - INTERVAL '24 hours' AND path <> '/health'
          GROUP BY status_code / 100 ORDER BY status_code / 100
        """)
        latency = await conn.fetchrow("""
          SELECT COUNT(response_ms) AS samples,
                 percentile_cont(0.50) WITHIN GROUP (ORDER BY response_ms) AS p50,
                 percentile_cont(0.95) WITHIN GROUP (ORDER BY response_ms) AS p95,
                 MAX(response_ms) AS max_ms
          FROM events WHERE occurred_at >= NOW() - INTERVAL '24 hours'
            AND path <> '/health' AND response_ms IS NOT NULL
        """)
        payload_signals = await conn.fetch("""
          SELECT signal, COUNT(*) AS count FROM (
            SELECT unnest(tags) AS signal FROM events
            WHERE occurred_at >= NOW() - INTERVAL '24 hours' AND path <> '/health'
          ) s
          WHERE signal IN (
            'payload:sql_injection_candidate','payload:path_traversal_candidate',
            'payload:xss_candidate','payload:command_injection_candidate',
            'payload:sensitive_path_candidate'
          )
          GROUP BY signal ORDER BY count DESC
        """)
        daily_30d = await conn.fetch("""
          SELECT buckets.day AS day, COUNT(e.id) AS total,
                 COUNT(e.id) FILTER (WHERE e.status_code >= 500) AS errors,
                 COUNT(e.id) FILTER (WHERE 'assessment:scanner_like' = ANY(e.tags)) AS scanner_candidates
          FROM generate_series(
            date_trunc('day', NOW()) - INTERVAL '29 days',
            date_trunc('day', NOW()), INTERVAL '1 day'
          ) AS buckets(day)
          LEFT JOIN events e ON e.occurred_at >= buckets.day
            AND e.occurred_at < buckets.day + INTERVAL '1 day'
            AND e.path <> '/health'
          GROUP BY buckets.day ORDER BY buckets.day
        """)
        country_counts_7d = await conn.fetch("""
          SELECT geo_country AS country, COUNT(*) AS count
          FROM events WHERE geo_country IS NOT NULL
            AND occurred_at >= NOW() - INTERVAL '7 days' AND path <> '/health'
          GROUP BY geo_country ORDER BY count DESC LIMIT 10
        """)
        path_behavior = await conn.fetchrow("""
          SELECT
            COUNT(*) FILTER (WHERE hits_1h >= 5) AS repeated_paths_1h,
            COUNT(*) FILTER (WHERE hits_5m >= 3) AS burst_paths_5m,
            COUNT(*) FILTER (WHERE hits_1h >= 1) AS unique_paths_1h
          FROM (
            SELECT path,
              COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '1 hour') AS hits_1h,
              COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '5 minutes') AS hits_5m
            FROM events
            WHERE occurred_at >= NOW() - INTERVAL '1 hour' AND path <> '/health'
            GROUP BY path
          ) p
        """)
        burst_paths = await conn.fetch("""
          SELECT path, COUNT(*) AS count FROM events
          WHERE occurred_at >= NOW() - INTERVAL '5 minutes' AND path <> '/health'
          GROUP BY path HAVING COUNT(*) >= 3
          ORDER BY count DESC, path ASC LIMIT 8
        """)
        path_correlations = await conn.fetch("""
          SELECT path, COUNT(*) AS hits,
                 COUNT(*) FILTER (WHERE tags && ARRAY[
                   'payload:sql_injection_candidate','payload:path_traversal_candidate',
                   'payload:xss_candidate','payload:command_injection_candidate',
                   'payload:sensitive_path_candidate','signal:exploit_probe',
                   'signal:common_scan_path','signal:non_read_method'
                 ]::text[]) AS signal_hits,
                 (COUNT(DISTINCT CASE WHEN 'payload:sql_injection_candidate' = ANY(tags) THEN 'sql' END)
                 + COUNT(DISTINCT CASE WHEN 'payload:path_traversal_candidate' = ANY(tags) THEN 'traversal' END)
                 + COUNT(DISTINCT CASE WHEN 'payload:xss_candidate' = ANY(tags) THEN 'xss' END)
                 + COUNT(DISTINCT CASE WHEN 'payload:command_injection_candidate' = ANY(tags) THEN 'command' END)
                 + COUNT(DISTINCT CASE WHEN 'payload:sensitive_path_candidate' = ANY(tags) THEN 'sensitive_path' END)
                 + COUNT(DISTINCT CASE WHEN 'signal:exploit_probe' = ANY(tags) THEN 'exploit' END)
                 + COUNT(DISTINCT CASE WHEN 'signal:common_scan_path' = ANY(tags) THEN 'scan_path' END)
                 + COUNT(DISTINCT CASE WHEN 'signal:non_read_method' = ANY(tags) THEN 'method' END)) AS signal_types
          FROM events
          WHERE occurred_at >= NOW() - INTERVAL '15 minutes' AND path <> '/health'
          GROUP BY path
          HAVING COUNT(*) >= 2 AND COUNT(*) FILTER (WHERE tags && ARRAY[
            'payload:sql_injection_candidate','payload:path_traversal_candidate',
            'payload:xss_candidate','payload:command_injection_candidate',
            'payload:sensitive_path_candidate','signal:exploit_probe',
            'signal:common_scan_path','signal:non_read_method'
          ]::text[]) >= 1
          ORDER BY signal_types DESC, signal_hits DESC, hits DESC LIMIT 10
        """)
        behavior = await conn.fetchrow("""
          SELECT COUNT(*) FILTER (WHERE 'signal:non_read_method' = ANY(tags)) AS non_read_methods,
                 COUNT(*) FILTER (WHERE 'signal:common_scan_path' = ANY(tags)) AS common_scan_paths,
                 COUNT(*) FILTER (WHERE 'signal:exploit_probe' = ANY(tags)) AS exploit_candidates,
                 COUNT(*) FILTER (WHERE status_code BETWEEN 400 AND 499) AS client_errors,
                 COUNT(*) FILTER (WHERE status_code BETWEEN 500 AND 599) AS server_errors
          FROM events WHERE occurred_at >= NOW() - INTERVAL '24 hours' AND path <> '/health'
        """)
        totals = await conn.fetchrow("""
          SELECT
            COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '1 hour') AS last_hour,
            COUNT(*) FILTER (WHERE status_code >= 500 AND occurred_at >= NOW() - INTERVAL '24 hours') AS errors_24h,
            COUNT(*) FILTER (WHERE 'assessment:scanner_like' = ANY(tags)
              AND occurred_at >= NOW() - INTERVAL '24 hours') AS scanner_candidates_24h
          FROM events WHERE path <> '/health'
        """)
    return {
        "series": [{"hour": r["hour"].isoformat(), "total": r["total"], "errors": r["errors"]} for r in hourly],
        "categories": [{"category": r["category"], "count": r["count"]} for r in categories],
        "top_paths": [{"path": r["path"], "count": r["count"]} for r in paths],
        "statuses": [{"status_code": r["status_code"], "count": r["count"]} for r in statuses],
        "methods": [{"method": r["method"], "count": r["count"]} for r in methods],
        "status_families": [{"family": r["family"], "count": r["count"]} for r in status_families],
        "latency": {"samples": latency["samples"], "p50_ms": round(float(latency["p50"]), 2) if latency["p50"] is not None else None, "p95_ms": round(float(latency["p95"]), 2) if latency["p95"] is not None else None, "max_ms": round(float(latency["max_ms"]), 2) if latency["max_ms"] is not None else None},
        "payload_signals": [{"signal": r["signal"], "count": r["count"]} for r in payload_signals],
        "daily_30d": [{"day": r["day"].date().isoformat(), "total": r["total"], "errors": r["errors"], "scanner_candidates": r["scanner_candidates"]} for r in daily_30d],
        "country_counts_7d": [{"country": r["country"], "count": r["count"]} for r in country_counts_7d],
        "behavior": {**{k: int(behavior[k] or 0) for k in ("non_read_methods", "common_scan_paths", "exploit_candidates", "client_errors", "server_errors")}, "repeated_paths_1h": int(path_behavior["repeated_paths_1h"] or 0), "burst_paths_5m": int(path_behavior["burst_paths_5m"] or 0), "unique_paths_1h": int(path_behavior["unique_paths_1h"] or 0)},
        "burst_paths": [{"path": r["path"], "count": r["count"]} for r in burst_paths],
        "path_correlations": [{"path": r["path"], "hits": r["hits"], "signal_hits": r["signal_hits"], "signal_types": r["signal_types"]} for r in path_correlations],
        "last_hour": totals["last_hour"],
        "errors_24h": totals["errors_24h"],
        "scanner_candidates_24h": totals["scanner_candidates_24h"],
        "timeline": [{"time": r["bucket"].isoformat(), "total": r["total"], "errors": r["errors"], "scanner_candidates": r["scanner_candidates"], "login_attempts": r["login_attempts"]} for r in timeline],
        "threat_signals": [{"signal": r["signal"], "count": r["count"]} for r in signals],
        "alert": {
            "recent_5m": alert_counts["recent"],
            "previous_55m": alert_counts["previous"],
            "baseline_per_5m": round(float(alert_counts["previous"] or 0) / 11, 2),
            "triggered": int(alert_counts["recent"] or 0) >= 10 and int(alert_counts["recent"] or 0) >= max(3, float(alert_counts["previous"] or 0) / 11 * 2.5),
        },
    }


@app.get("/api/dashboard/health")
async def dashboard_health():
    db_ok = False
    honeypot_ok = False
    try:
        async with app.state.pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
            db_ok = True
            row = await conn.fetchrow("""
              SELECT MAX(occurred_at) AS last_event,
                     COUNT(*) FILTER (WHERE occurred_at >= NOW() - INTERVAL '5 minutes'
                       AND path <> '/health') AS events_5m
              FROM events
            """)
    except Exception:
        row = None
    try:
        async with httpx.AsyncClient(timeout=1.2, follow_redirects=False) as client:
            probe = await client.get(HONEYPOT_HEALTH_URL)
            honeypot_ok = probe.status_code == 200
    except Exception:
        honeypot_ok = False
    last_event = row["last_event"] if row else None
    age_seconds = max(0, int((datetime.now(timezone.utc) - last_event).total_seconds())) if last_event else None
    return {
        "status": "ok" if db_ok and honeypot_ok else "degraded",
        "database": "online" if db_ok else "unavailable",
        "honeypot": "online" if honeypot_ok else "unavailable",
        "last_event": last_event.isoformat() if last_event else None,
        "seconds_since_last_event": age_seconds,
        "events_5m": int(row["events_5m"] or 0) if row else 0,
        "checked_at": datetime.now(timezone.utc).isoformat(),
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
          SELECT id, occurred_at, event_type, method, path, status_code, tags, response_ms
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
            "response_ms": round(float(r["response_ms"]), 2) if r["response_ms"] is not None else None,
            "tags": [tag for tag in r["tags"] if tag in PUBLIC_TAGS],
        })
    return {"events": result}

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(PAGE)

PAGE = r"""<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="google-site-verification" content="62QmyJujyPwsJeOmgEp3YLICDEkZNAro_t5qLEHgR2w" />
<meta name="description" content="MK Honeypot — 公開ハニーポット観測ダッシュボード。匿名化・集計したアクセス傾向を公開します。">
<title>MK Honeypot — Public Monitor</title>
<style>
:root{color-scheme:dark;--bg:#080d18;--panel:#111a2b;--line:#24324a;--muted:#91a2bb;--text:#e8eef9;--green:#56e39f;--amber:#ffca70;--red:#ff6e7a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 15% 0,#172642 0,transparent 42%),var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1500px;margin:auto;padding:30px 20px 56px}
.workspace{display:grid;grid-template-columns:220px minmax(0,1fr);gap:22px;align-items:start;margin-top:22px}.sidebar{position:sticky;top:18px;border:1px solid var(--line);background:#0b1422;border-radius:14px;padding:12px;display:flex;flex-direction:column;gap:6px}.sidebar-label{color:var(--muted);font-size:10px;letter-spacing:.13em;padding:8px 10px}.nav-item{display:flex;align-items:center;gap:10px;width:100%;text-align:left;border:1px solid transparent;border-radius:9px;background:transparent;color:var(--muted);padding:10px 11px;font:inherit;font-size:13px;cursor:pointer}.nav-item:hover{background:#142138;color:var(--text)}.nav-item.active{background:#142a38;border-color:#27594e;color:var(--green)}.nav-icon{width:20px;text-align:center;font-size:15px}.page-content{min-width:0}.page-content>.notice{margin-top:0}.page-title{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:4px 0 18px}.page-title h2{font-size:22px}.page-title p{margin:3px 0 0;color:var(--muted);font-size:12px}
@media(max-width:850px){.workspace{grid-template-columns:1fr;gap:12px}.sidebar{position:static;flex-direction:row;overflow-x:auto;gap:5px;padding:8px}.sidebar-label{display:none}.nav-item{flex:0 0 auto;width:auto;white-space:nowrap;padding:9px 11px}.nav-icon{width:auto}.page-title h2{font-size:20px}}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;border-bottom:1px solid var(--line);padding-bottom:22px}
.brand{display:flex;align-items:center;gap:13px}.mark{width:42px;height:42px;border:1px solid #3b5578;border-radius:12px;display:grid;place-items:center;color:var(--green);font-weight:900;font-size:20px}
h1{font-size:clamp(21px,4vw,30px);margin:0;letter-spacing:.02em}.sub{color:var(--muted);font-size:13px;margin-top:3px}.live{color:var(--green);border:1px solid #245b48;border-radius:99px;padding:6px 11px;font-size:12px;white-space:nowrap}
.notice{margin:22px 0;padding:13px 16px;background:#201b12;border:1px solid #55452a;color:#f2d9a6;border-radius:10px;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#141f33,#101827);border:1px solid var(--line);border-radius:14px;padding:18px;min-width:0}.label{color:var(--muted);font-size:13px}.value{font-size:clamp(26px,4vw,38px);font-weight:750;letter-spacing:-.03em;margin:9px 0 4px}.hint{color:var(--muted);font-size:12px}.green{color:var(--green)}.amber{color:var(--amber)}.red{color:var(--red)}
section{margin-top:28px}.sectionhead{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin-bottom:12px}h2{font-size:17px;margin:0}.small{color:var(--muted);font-size:12px}
.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:12px;background:#0d1523}table{width:100%;border-collapse:collapse;min-width:650px}th,td{text-align:left;padding:12px 14px;border-bottom:1px solid #1d2a3e;font-size:13px}th{color:var(--muted);font-weight:600;background:#111b2c}td.path{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.badge{display:inline-block;border-radius:6px;padding:3px 7px;background:#1a2b41;color:#bdd5f4;font-size:11px}.badge.warn{background:#392819;color:#ffd08a}.badge.fail{background:#3a202b;color:#ff9da5}.empty{color:var(--muted);text-align:center;padding:28px}
.pathway{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.stage{border:1px solid var(--line);border-radius:10px;padding:14px;background:#0d1523;min-width:0}.stage-num{color:var(--green);font-size:11px;letter-spacing:.08em}.stage-name{font-size:13px;margin:7px 0}.stage-count{font-size:25px;font-weight:750}.stage-arrow{color:#66809f;font-size:12px;margin-top:4px}
.maplayout{display:grid;grid-template-columns:minmax(0,2fr) minmax(210px,1fr);gap:14px}.mapbox{overflow:hidden;background:radial-gradient(ellipse at center,#12243a,#08111e 78%);border:1px solid var(--line);border-radius:12px;min-height:300px}#worldmap{display:block;width:100%;height:auto;min-height:300px}.land{fill:#244563;stroke:#496b8b;stroke-width:.65;stroke-linejoin:round}.borders{fill:none;stroke:#375673;stroke-width:.48;pointer-events:none}.mapgrid{stroke:#1a2b40;stroke-width:1;fill:none}.geo-point{fill:#59e6aa;stroke:#b8ffe0;stroke-width:1.5;cursor:pointer}.pulse{fill:none;stroke:#59e6aa;stroke-width:2;transform-box:fill-box;transform-origin:center;animation:pulse 2.2s ease-out infinite}.route-line{fill:none;stroke:#70f5ff;stroke-width:2.4;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1;filter:drop-shadow(0 0 4px #4cecff);animation:route-flight 1.15s cubic-bezier(.2,.75,.2,1) forwards}.route-core{fill:none;stroke:#e6ffff;stroke-width:1;stroke-linecap:round;stroke-dasharray:1;stroke-dashoffset:1;animation:route-flight 1.15s cubic-bezier(.2,.75,.2,1) forwards}.honeypot-target{fill:#ffcf70;stroke:#fff0c4;stroke-width:2;filter:drop-shadow(0 0 7px #ffb547)}.target-ring{fill:none;stroke:#ffcf70;stroke-width:1.6;transform-box:fill-box;transform-origin:center;animation:pulse 1.8s ease-out infinite}.target-label{fill:#ffdf9b;font:700 13px system-ui,sans-serif;paint-order:stroke;stroke:#08111e;stroke-width:4px;stroke-linejoin:round}@keyframes route-flight{0%{stroke-dashoffset:1;opacity:.25}12%{opacity:1}88%{opacity:1}100%{stroke-dashoffset:0;opacity:0}}@keyframes pulse{0%{opacity:.9;transform:scale(.4)}100%{opacity:0;transform:scale(3.8)}}.countrylist{display:flex;flex-direction:column;gap:8px}.countryrow{display:flex;justify-content:space-between;gap:8px;border-bottom:1px solid var(--line);padding:8px 0;font-size:13px}.countryrow b{color:var(--green)}.analytics-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(260px,1fr);gap:14px}.chartbox{background:#0b1422;border:1px solid var(--line);border-radius:12px;padding:12px;min-width:0}.chart-svg{width:100%;height:auto;display:block}.chart-grid{stroke:#20314a;stroke-width:1}.chart-line{fill:none;stroke:#59e6ff;stroke-width:3;stroke-linejoin:round;stroke-linecap:round;filter:drop-shadow(0 0 5px #1da7c7)}.chart-area{fill:url(#trendFill)}.chart-label{fill:#91a2bb;font:11px system-ui,sans-serif}.metric-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-bottom:14px}.metric-mini{background:#0c1524;border:1px solid var(--line);border-radius:10px;padding:13px}.metric-mini .value{font-size:25px;margin:4px 0}.rank-list{display:flex;flex-direction:column;gap:10px}.rank-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;font-size:12px}.rank-name{overflow-wrap:anywhere;font-family:ui-monospace,SFMono-Regular,monospace}.rank-count{color:var(--green);font-weight:700}.rank-track{grid-column:1/3;height:5px;background:#1c2b40;border-radius:99px;overflow:hidden}.rank-fill{height:100%;background:linear-gradient(90deg,#3c9bba,#59e6aa);border-radius:99px}.category-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;padding:8px 0;border-bottom:1px solid var(--line);font-size:12px}.category-row b{color:var(--amber)}.status-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:99px;padding:5px 10px;font-size:12px}.status-dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 8px currentColor}.status-dot.warn{background:var(--amber)}.status-dot.fail{background:var(--red)}.health-grid{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px}.health-item{background:#0c1524;border:1px solid var(--line);border-radius:10px;padding:14px;min-width:0}.health-value{font-weight:700;font-size:19px;margin-top:7px;overflow-wrap:anywhere}.alert-banner{display:flex;justify-content:space-between;align-items:center;gap:14px;border:1px solid #245b48;background:#10251f;border-radius:12px;padding:16px;margin-bottom:14px}.alert-banner.triggered{border-color:#70422c;background:#2b1c16}.alert-title{font-weight:750}.alert-detail{font-size:12px;color:var(--muted);margin-top:4px}.timeline{display:flex;flex-direction:column;gap:0}.timeline-row{display:grid;grid-template-columns:110px 14px minmax(0,1fr) auto;gap:12px;align-items:start;padding:12px 0;border-bottom:1px solid var(--line);font-size:13px}.timeline-time{color:var(--muted);font-variant-numeric:tabular-nums}.timeline-pin{width:9px;height:9px;border-radius:50%;background:var(--green);margin-top:5px;box-shadow:0 0 9px #59e6aa80}.timeline-pin.warn{background:var(--amber);box-shadow:0 0 9px #ffca7080}.timeline-pin.fail{background:var(--red);box-shadow:0 0 9px #ff6e7a80}.timeline-count{font-weight:750;color:var(--green)}.timeline-bars{display:flex;gap:3px;align-items:end;height:44px;margin-top:12px}.timeline-bar{flex:1;min-width:2px;background:linear-gradient(180deg,#59e6ff,#2587a3);border-radius:3px 3px 0 0;opacity:.9}.timeline-legend{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:12px;margin-top:10px}.signal-explain{color:var(--muted);font-size:12px;line-height:1.5;margin-top:12px}footer{margin-top:28px;color:var(--muted);font-size:12px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
@media(max-width:850px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.pathway{grid-template-columns:repeat(2,minmax(0,1fr))}.maplayout,.analytics-grid{grid-template-columns:1fr}.health-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:480px){.metric-strip{grid-template-columns:1fr}.chartbox{padding:8px}.timeline-row{grid-template-columns:82px 10px minmax(0,1fr);gap:8px}.timeline-count{grid-column:3}.alert-banner{align-items:flex-start;flex-direction:column}}@media(max-width:480px){main{padding:20px 12px 36px}.grid{gap:9px}.card{padding:13px}.top{align-items:flex-start}.live{font-size:11px}}

/* Subtle motion: quick page entrance, restrained hover feedback, and reduced-motion support. */
@keyframes soft-enter{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:translateY(0)}}
@keyframes value-in{from{opacity:.65;transform:translateY(2px)}to{opacity:1;transform:translateY(0)}}
.page-title{animation:soft-enter .28s ease-out both}
.page-content section:not([hidden]),.page-content>.grid:not([hidden]){animation:soft-enter .32s ease-out both}
.card,.metric-mini,.health-item,.stage{transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease}
.card:hover,.metric-mini:hover,.health-item:hover,.stage:hover{transform:translateY(-2px);border-color:#344b68;box-shadow:0 8px 24px #00000018}
.nav-item{transition:background-color .16s ease,color .16s ease,border-color .16s ease,transform .16s ease}
.nav-item:active{transform:scale(.985)}
.mark{transition:box-shadow .2s ease,border-color .2s ease}
.brand:hover .mark{border-color:#59e6aa;box-shadow:0 0 18px #59e6aa22}
.status-dot{animation:status-breathe 2.4s ease-in-out infinite}
@keyframes status-breathe{0%,100%{opacity:1}50%{opacity:.58}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}

/* SOC command-center visual system */
:root{--bg:#070c15;--panel:#101a2a;--line:#25354b;--muted:#91a4bd;--text:#eaf1fb;--green:#57e6a7;--amber:#ffca70;--red:#ff6f7d;--cyan:#63dff4}
body{background-color:var(--bg);background-image:radial-gradient(ellipse at 14% -8%,#17324a 0,transparent 42%),linear-gradient(#10203522 1px,transparent 1px),linear-gradient(90deg,#10203522 1px,transparent 1px);background-size:auto,32px 32px,32px 32px;background-attachment:fixed}
main{max-width:1580px;padding-top:26px}
.top{border-bottom-color:#2b4059;padding-bottom:20px}
.mark{background:linear-gradient(145deg,#142d39,#0c1725);border-color:#32604f;box-shadow:inset 0 0 18px #57e6a70b}
.brand h1{letter-spacing:.045em}
.sub{letter-spacing:.045em}
.live{background:#10271f;box-shadow:inset 0 0 12px #57e6a70a;font-weight:700;letter-spacing:.06em}
.live:before{content:"";display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--green);margin:0 7px 1px 0;box-shadow:0 0 9px #57e6a7}
.workspace{grid-template-columns:228px minmax(0,1fr);gap:18px}
.sidebar{background:linear-gradient(180deg,#0d1726,#09111d);border-color:#263a52;box-shadow:0 14px 36px #00000018}
.sidebar-label{font-weight:700;color:#7189a5}
.nav-item{border-radius:8px;min-height:42px}
.nav-item.active{background:linear-gradient(90deg,#15372f,#102b2b);border-color:#2d6957;box-shadow:inset 3px 0 0 var(--green);font-weight:650}
.page-title{border-bottom:1px solid #22334a;padding:0 0 14px}
.page-title h2{font-size:21px;letter-spacing:.015em}
.page-title p{letter-spacing:.015em}
.page-title .status-pill{background:#0d201c;border-color:#285442;color:var(--green);font-weight:700;letter-spacing:.04em}
.card{position:relative;overflow:hidden;background:linear-gradient(145deg,#142136,#0d1726 78%);border-color:#293b53;border-radius:12px;box-shadow:0 8px 26px #00000012}
.card:before{content:"";position:absolute;left:0;top:0;right:0;height:2px;background:linear-gradient(90deg,#57e6a7,#63dff4 58%,transparent);opacity:.72}
.grid .card:nth-child(2):before{background:linear-gradient(90deg,#ffca70,#ff8c73,transparent)}
.grid .card:nth-child(3):before{background:linear-gradient(90deg,#ff6f7d,#ffca70,transparent)}
.grid .card:nth-child(4):before{background:linear-gradient(90deg,#63dff4,#688fff,transparent)}
.value{font-variant-numeric:tabular-nums}
.label{font-size:11px;font-weight:750;letter-spacing:.075em;text-transform:uppercase}
.hint{line-height:1.65}
section{margin-top:26px}
.sectionhead{padding-bottom:9px;border-bottom:1px solid #1d2c40}
.sectionhead h2{letter-spacing:.015em}
.tablewrap,.chartbox,.mapbox{border-color:#293b53;box-shadow:0 8px 26px #00000010}
table{font-variant-numeric:tabular-nums}
th{font-size:11px;letter-spacing:.055em;text-transform:uppercase;background:#111e30}
tbody tr{transition:background-color .15s ease}
tbody tr:hover{background:#132238}
td{border-bottom-color:#1b2a3d}
.badge{border:1px solid #29425d}
.badge.warn{border-color:#664b2b}
.badge.fail{border-color:#66303b}
.stage,.metric-mini,.health-item{background:linear-gradient(145deg,#101c2d,#0b1421);border-color:#293b53}
.stage-num{font-weight:750}
.chartbox{background:linear-gradient(145deg,#0d1828,#09121f)}
.chart-grid{stroke:#24354b}
.chart-line{stroke:var(--cyan);filter:drop-shadow(0 0 4px #63dff433)}
.rank-fill{background:linear-gradient(90deg,#2b98b4,#57e6a7)}
.rank-track{background:#1a293d}
.alert-banner{box-shadow:inset 3px 0 0 var(--green)}
.alert-banner.triggered{box-shadow:inset 3px 0 0 var(--red)}
.status-pill{background:#101b2a}
.status-dot{box-shadow:0 0 10px currentColor}
footer{border-top:1px solid #1e2d42;padding-top:16px}
:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
@media(max-width:850px){.workspace{grid-template-columns:1fr}.sidebar{background:#0b1422}.page-title{padding-bottom:12px}}
@media(prefers-reduced-motion:reduce){body{background-attachment:scroll}}

</style></head><body><main>
<header class="top"><div class="brand"><div class="mark">H</div><div><h1>MK Honeypot</h1><div class="sub">PUBLIC SECURITY OBSERVABILITY · LIVE EVENT FEED</div></div></div><div class="live">● 公開モニター</div></header>
<div class="workspace"><aside class="sidebar" aria-label="ダッシュボードのページ"><div class="sidebar-label">OBSERVABILITY</div><button class="nav-item active" data-page-link="overview"><span class="nav-icon">⌂</span>概要</button><button class="nav-item" data-page-link="traffic"><span class="nav-icon">⌁</span>通信・トレンド</button><button class="nav-item" data-page-link="threats"><span class="nav-icon">◈</span>脅威分析</button><button class="nav-item" data-page-link="geography"><span class="nav-icon">◎</span>世界地図</button><button class="nav-item" data-page-link="system"><span class="nav-icon">▣</span>システム稼働</button><button class="nav-item" data-page-link="events"><span class="nav-icon">≡</span>イベント検索</button></aside><div class="page-content"><div class="notice">公開観測ダッシュボードです。IPアドレス・生のUser-Agent・認証情報は表示しません。地図は位置情報を約10度単位で集約し、複数イベントがある領域のみ表示します。「スキャナー候補」などの分類はアクセスパターンに基づく推定で、発信元の身元を確認したものではありません。アクセスの観測は侵入成功を意味しません。</div>
<div class="grid">
<article class="card"><div class="label">総アクセス（観測）</div><div class="value" id="knocks">—</div><div class="hint">記録されたHTTPリクエスト</div></article>
<article class="card"><div class="label">パスワード試行</div><div class="value amber" id="passwords">—</div><div class="hint">偽ログイン画面への送信回数</div></article>
<article class="card"><div class="label">管理画面の探索</div><div class="value red" id="probes">—</div><div class="hint">管理・既知パスへのアクセス</div></article>
<article class="card"><div class="label">直近24時間のイベント</div><div class="value green" id="last24">—</div><div class="hint">保存された全イベント</div></article>
</div>

<section><div class="sectionhead"><h2>リアルタイム分析</h2><span class="small">直近24時間 · 1時間単位 · 5秒ごとに更新</span></div>
<div class="metric-strip">
<div class="metric-mini"><div class="label">直近1時間</div><div class="value green" id="lastHour">—</div><div class="hint">リクエスト数</div></div>
<div class="metric-mini"><div class="label">サーバーエラー</div><div class="value red" id="errors24">—</div><div class="hint">直近24時間 · HTTP 5xx</div></div>
<div class="metric-mini"><div class="label">スキャナー候補</div><div class="value amber" id="scanner24">—</div><div class="hint">直近24時間 · 推定分類</div></div>
</div>
<div class="analytics-grid">
<div class="card"><div class="sectionhead"><h2>アクセス推移</h2><span class="small">時間別</span></div><div class="chartbox"><svg id="trendChart" class="chart-svg" viewBox="0 0 760 250" role="img" aria-label="直近24時間の時間別アクセス数のグラフ"><defs><linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#59e6ff" stop-opacity=".3"/><stop offset="100%" stop-color="#59e6ff" stop-opacity="0"/></linearGradient></defs><g id="trendGrid"></g><path id="trendArea" class="chart-area" d=""></path><polyline id="trendLine" class="chart-line" points=""></polyline><g id="trendPoints"></g><g id="trendLabels"></g></svg></div><div class="hint" id="trendHint">データを読み込んでいます…</div></div>
<div class="card"><div class="sectionhead"><h2>分類別イベント</h2><span class="small">24時間</span></div><div id="categoryList" class="rank-list"><div class="empty">集計を読み込んでいます…</div></div><div class="hint" style="margin-top:12px">分類はアクセスパターンに基づく推定です。発信者の身元や意図を確定するものではありません。</div></div>
</div>
<div class="analytics-grid" style="margin-top:14px">
<div class="card"><div class="sectionhead"><h2>アクセスされたパス TOP 8</h2><span class="small">24時間 · クエリ除外</span></div><div id="pathRanking" class="rank-list"><div class="empty">集計を読み込んでいます…</div></div></div>
<div class="card"><div class="sectionhead"><h2>HTTPステータス</h2><span class="small">24時間</span></div><div id="statusRanking" class="rank-list"><div class="empty">集計を読み込んでいます…</div></div></div>
</div></section>

<section><div class="sectionhead"><h2>アクセス急増アラート</h2><span class="small">直近5分と過去55分の平均を比較</span></div>
<div id="alertBanner" class="alert-banner"><div><div class="alert-title" id="alertTitle">判定中…</div><div class="alert-detail" id="alertDetail">集計データを取得しています</div></div><div class="status-pill"><span id="alertDot" class="status-dot"></span><span id="alertState">CHECKING</span></div></div>
<div class="hint">発火条件：直近5分で10件以上、かつ過去55分の5分換算平均の2.5倍以上。少ないアクセス量ではアラートを抑制します。</div></section>
<section><div class="sectionhead"><h2>システム稼働状況</h2><span class="small">公開可能なヘルス情報のみ</span></div>
<div class="health-grid">
<div class="health-item"><div class="label">Dashboard API</div><div class="health-value" id="healthApi">確認中…</div><div class="hint">直近のヘルスチェック</div></div>
<div class="health-item"><div class="label">データベース</div><div class="health-value" id="healthDb">確認中…</div><div class="hint">簡易クエリ検査</div></div>
<div class="health-item"><div class="label">Honeypot本体</div><div class="health-value" id="healthHoneypot">確認中…</div><div class="hint">内部 /health 応答</div></div>
<div class="health-item"><div class="label">直近5分のイベント</div><div class="health-value" id="healthEvents">—</div><div class="hint">ヘルス確認リクエストを除外</div></div>
<div class="health-item"><div class="label">最終イベント</div><div class="health-value" id="healthLast">—</div><div class="hint" id="healthAge">イベントがない場合は未記録</div></div>
</div><div class="hint" style="margin-top:9px" id="healthChecked">稼働確認を実行しています。</div></section>
<section><div class="sectionhead"><h2>イベントタイムライン</h2><span class="small">直近24時間 · 10分単位</span></div>
<div class="card"><div class="hint">時間帯ごとのイベント数を表示します。個別訪問者の追跡やアクセスの因果関係を示すものではありません。</div><div id="timelineBars" class="timeline-bars" role="img" aria-label="10分ごとのイベント数"></div><div class="timeline-legend"><span>■ アクセス数</span><span id="timelineTotal">合計 — 件</span></div><div id="timelineList" class="timeline" style="margin-top:12px"><div class="empty">タイムラインを読み込んでいます…</div></div></div></section>
<section><div class="sectionhead"><h2>脅威シグナル分析</h2><span class="small">直近24時間 · ヒューリスティック</span></div>
<div class="card"><div id="threatSignalList" class="rank-list"><div class="empty">シグナルを集計しています…</div></div><div class="signal-explain">シグナルは観測されたパス、HTTPメソッド、保存済みの分類タグに基づく候補です。User-Agentの申告は偽装可能であり、攻撃者の身元、意図、侵入成功を証明しません。</div><h2 style="margin-top:18px">反復パスとシグナルの重なり（15分）</h2><div id="pathCorrelationRanking" class="rank-list" style="margin-top:10px"></div><div class="signal-explain">同じパスで複数回観測され、分類シグナルも付いたリクエストを表示します。訪問者単位の相関・追跡は行いません。</div></div></section>

<section><div class="sectionhead"><h2>HTTP・通信観測</h2><span class="small">直近24時間 · Honeypot計測</span></div>
<div class="grid" style="grid-template-columns:repeat(3,minmax(0,1fr))">
<div class="card"><div class="label">応答時間 P50</div><div class="value" id="latencyP50">—</div><div class="hint">記録済みリクエストの中央値</div></div>
<div class="card"><div class="label">応答時間 P95</div><div class="value" id="latencyP95">—</div><div class="hint">95パーセンタイル</div></div>
<div class="card"><div class="label">応答時間 最大</div><div class="value" id="latencyMax">—</div><div class="hint" id="latencySamples">計測サンプル —</div></div>
</div>
<div class="analytics-grid" style="margin-top:14px">
<div class="card"><h2>HTTPメソッド</h2><div id="methodRanking" class="rank-list"></div></div>
<div class="card"><h2>ステータス分類</h2><div id="statusFamilyRanking" class="rank-list"></div></div>
</div>
<div class="hint" style="margin-top:8px">応答時間はアプリケーションのリクエスト処理にかかった概算値で、クライアントから見た全ネットワーク遅延ではありません。</div>
</section>
<section><div class="sectionhead"><h2>不審ペイロード分類</h2><span class="small">直近24時間 · URL/クエリの分類のみ</span></div>
<div class="analytics-grid">
<div class="card"><div id="payloadRanking" class="rank-list"></div><div class="signal-explain">URLパスとクエリに含まれるパターンから、SQLインジェクション、パストラバーサル、XSS、コマンド注入、機密パス探索の候補を集計。生のクエリ値・リクエスト本文は記録・表示せず、本文内容の解析もしません。</div></div>
<div class="card"><h2>行動シグナル</h2><div id="behaviorRanking" class="rank-list"></div><div class="signal-explain">集計は観測したリクエストの分類に基づきます。スキャンの意図や侵入成功を断定しません。</div><h2 style="margin-top:18px">直近5分の反復パス</h2><div id="burstPathRanking" class="rank-list"></div></div>
</div></section>
<section><div class="sectionhead"><h2>長期傾向・地域別推移</h2><span class="small">直近30日 / 地域集計は7日間</span></div>
<div class="analytics-grid">
<div class="card"><div id="dailyBars" class="timeline-bars" style="height:90px"></div><div class="timeline-legend"><span>■ 日別アクセス</span><span id="dailyTotal">合計 — 件</span></div><div class="hint" style="margin-top:8px">横棒は各日の相対的なアクセス量です。30日分を集計。</div></div>
<div class="card"><h2>国・地域別（7日間）</h2><div id="countryTrend" class="rank-list"></div><div class="signal-explain">IPから解決した概算地域。位置情報が得られないアクセスは含まれません。</div></div>
</div></section>
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
<section><div class="sectionhead"><h2>最新イベント</h2><span class="small" id="updated">読み込み中</span></div><div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px"><input id="eventSearch" type="search" placeholder="パス・分類・タグを検索…" aria-label="イベント検索" style="flex:1;min-width:220px;background:#0b1422;border:1px solid var(--line);border-radius:9px;padding:11px 12px;color:var(--text);font:inherit"><select id="eventStatusFilter" aria-label="HTTPステータスで絞り込み" style="background:#0b1422;border:1px solid var(--line);border-radius:9px;padding:11px 12px;color:var(--text);font:inherit"><option value="all">全ステータス</option><option value="2">2xx</option><option value="3">3xx</option><option value="4">4xx</option><option value="5">5xx</option></select><span class="small" id="eventFilterCount" style="align-self:center">最新50件</span></div><div class="tablewrap"><table><thead><tr><th>時刻 (UTC)</th><th>分類</th><th>メソッド</th><th>パス</th><th>HTTP</th><th>応答時間</th><th>タグ</th></tr></thead><tbody id="events"><tr><td colspan="7" class="empty">イベントを取得しています…</td></tr></tbody></table></div></section>
<footer><span>MK Honeypot · Public dashboard</span><span>5秒ごとに更新 · 公開表示用に匿名化</span></footer></div></div>
</main>
<script src="https://cdn.jsdelivr.net/npm/d3@7"></script><script src="https://cdn.jsdelivr.net/npm/topojson-client@3"></script><script>
let mapProjection=null;
async function initWorldMap(){try{const r=await fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json",{cache:"force-cache"});if(!r.ok)throw Error("map data");const world=await r.json();const features=topojson.feature(world,world.objects.countries).features;mapProjection=d3.geoNaturalEarth1().fitExtent([[12,12],[988,488]],{type:"FeatureCollection",features});const path=d3.geoPath(mapProjection);const land=document.getElementById("world-land");land.replaceChildren();for(const feature of features){const p=document.createElementNS("http://www.w3.org/2000/svg","path");p.setAttribute("d",path(feature));p.setAttribute("class","land");land.append(p)}const borders=document.getElementById("country-borders");borders.setAttribute("d",path(topojson.mesh(world,world.objects.countries,(a,b)=>a!==b)));}catch(e){document.getElementById("worldmap").setAttribute("aria-label","世界地図データを読み込めませんでした。アクセス地点のみ表示します。")}}
const fmtTime=s=>{try{return new Date(s).toISOString().replace('T',' ').slice(0,19)}catch{return s||'—'}};
const label=c=>({http_request:'ノック / HTTP',login_attempt:'パスワード試行',server_error:'サーバーエラー',admin_probe:'管理画面探索',password_attempt:'パスワード試行',knock:'通常HTTPアクセス',request:'リクエスト',search_crawler:'検索クローラー候補',scanner_like:'スキャナー候補',decoy_access:'囮コンソールアクセス'}[c]||c);
const badge=c=>c==='login_attempt'||c==='password_attempt'||c==='search_crawler'?'warn':c==='server_error'||c==='admin_probe'||c==='scanner_like'?'fail':'';
function project(lon,lat){if(mapProjection){const q=mapProjection([lon,lat]);return {x:q[0],y:q[1]}}return {x:(lon+180)/360*1000,y:(90-lat)/180*500}}
const honeypotLocation={lon:-122.4,lat:37.8,label:'MK Honeypot · SFO'};
let geoSeenCounts=null;
function drawHoneypotTarget(){const layer=document.getElementById('honeypot-target');layer.replaceChildren();const q=project(honeypotLocation.lon,honeypotLocation.lat);const ns='http://www.w3.org/2000/svg';const ring=document.createElementNS(ns,'circle');ring.setAttribute('cx',q.x);ring.setAttribute('cy',q.y);ring.setAttribute('r','7');ring.setAttribute('class','target-ring');layer.append(ring);const dot=document.createElementNS(ns,'circle');dot.setAttribute('cx',q.x);dot.setAttribute('cy',q.y);dot.setAttribute('r','5');dot.setAttribute('class','honeypot-target');layer.append(dot);const label=document.createElementNS(ns,'text');label.setAttribute('x',q.x+10);label.setAttribute('y',q.y-10);label.setAttribute('class','target-label');label.textContent=honeypotLocation.label;layer.append(label)}
function animateRoute(from){const to=project(honeypotLocation.lon,honeypotLocation.lat);if(Math.hypot(from.x-to.x,from.y-to.y)<8)return;const ns='http://www.w3.org/2000/svg';const layer=document.getElementById('geo-routes');const path=document.createElementNS(ns,'path');const mx=(from.x+to.x)/2,my=(from.y+to.y)/2;const dx=to.x-from.x,dy=to.y-from.y;const bend=Math.min(90,Math.max(22,Math.hypot(dx,dy)*.16));const sign=from.x<to.x?-1:1;const d='M '+from.x+' '+from.y+' Q '+(mx)+' '+(my-bend*sign)+' '+to.x+' '+to.y;path.setAttribute('d',d);path.setAttribute('pathLength','1');path.setAttribute('class','route-line');layer.append(path);const core=document.createElementNS(ns,'path');core.setAttribute('d',d);core.setAttribute('pathLength','1');core.setAttribute('class','route-core');layer.append(core);setTimeout(()=>{path.remove();core.remove()},1400)}


function renderRankList(id,items,nameFn,countFn,colorClass=''){const root=document.getElementById(id);root.replaceChildren();if(!items.length){const e=document.createElement('div');e.className='empty';e.textContent='該当データはありません';root.append(e);return}const max=Math.max(1,...items.map(x=>Number(countFn(x))||0));for(const item of items){const row=document.createElement('div');row.className='rank-row';const name=document.createElement('span');name.className='rank-name';name.textContent=nameFn(item);const count=document.createElement('span');count.className='rank-count '+colorClass;count.textContent=Number(countFn(item)).toLocaleString();const track=document.createElement('div');track.className='rank-track';const fill=document.createElement('div');fill.className='rank-fill';fill.style.width=(Number(countFn(item))/max*100)+'%';track.append(fill);row.append(name,count,track);root.append(row)}}
function renderCategories(items){const root=document.getElementById('categoryList');root.replaceChildren();if(!items.length){const e=document.createElement('div');e.className='empty';e.textContent='直近24時間のイベントはありません';root.append(e);return}for(const item of items){const row=document.createElement('div');row.className='category-row';const name=document.createElement('span');name.textContent=label(item.category);const count=document.createElement('b');count.textContent=Number(item.count).toLocaleString();row.append(name,count);root.append(row)}}
function renderTrend(series){const W=760,H=250,left=38,right=16,top=18,bottom=36,plotW=W-left-right,plotH=H-top-bottom;const vals=series.map(x=>Number(x.total)||0),max=Math.max(4,...vals);const pts=series.map((x,i)=>({x:left+(series.length<2?0:i*plotW/(series.length-1)),y:top+plotH-(Number(x.total)||0)/max*plotH,v:Number(x.total)||0}));const grid=document.getElementById('trendGrid');grid.replaceChildren();for(let i=0;i<=4;i++){const y=top+i*plotH/4;const line=document.createElementNS('http://www.w3.org/2000/svg','line');line.setAttribute('x1',left);line.setAttribute('x2',W-right);line.setAttribute('y1',y);line.setAttribute('y2',y);line.setAttribute('class','chart-grid');grid.append(line);const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',left-8);t.setAttribute('y',y+4);t.setAttribute('text-anchor','end');t.setAttribute('class','chart-label');t.textContent=Math.round(max*(4-i)/4);grid.append(t)}const poly=pts.map(p=>p.x+','+p.y).join(' ');document.getElementById('trendLine').setAttribute('points',poly);document.getElementById('trendArea').setAttribute('d',pts.length?'M '+pts[0].x+' '+(top+plotH)+' L '+pts.map(p=>p.x+' '+p.y).join(' L ')+' L '+pts[pts.length-1].x+' '+(top+plotH)+' Z':'');const pg=document.getElementById('trendPoints');pg.replaceChildren();for(let i=0;i<pts.length;i++){const p=pts[i];const dot=document.createElementNS('http://www.w3.org/2000/svg','circle');dot.setAttribute('cx',p.x);dot.setAttribute('cy',p.y);dot.setAttribute('r','3');dot.setAttribute('fill','#d7fbff');const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=fmtTime(series[i].hour)+' UTC · '+p.v+' events';dot.append(title);pg.append(dot)}const labels=document.getElementById('trendLabels');labels.replaceChildren();for(const i of [0,Math.floor((series.length-1)/3),Math.floor(2*(series.length-1)/3),series.length-1]){if(!series[i])continue;const t=document.createElementNS('http://www.w3.org/2000/svg','text');t.setAttribute('x',pts[i].x);t.setAttribute('y',H-10);t.setAttribute('text-anchor',i===0?'start':i===series.length-1?'end':'middle');t.setAttribute('class','chart-label');t.textContent=new Date(series[i].hour).toLocaleTimeString('ja-JP',{hour:'2-digit',minute:'2-digit',timeZone:'UTC'});labels.append(t)}const total=vals.reduce((a,b)=>a+b,0);document.getElementById('trendHint').textContent='直近24時間の合計 '+total.toLocaleString()+' 件 · 時刻はUTC表示';}

function renderTimeline(items){const bars=document.getElementById('timelineBars'),list=document.getElementById('timelineList');bars.replaceChildren();list.replaceChildren();const max=Math.max(1,...items.map(x=>Number(x.total)||0));const total=items.reduce((s,x)=>s+(Number(x.total)||0),0);for(const item of items){const bar=document.createElement('div');bar.className='timeline-bar';bar.style.height=Math.max(3,(Number(item.total)||0)/max*44)+'px';bar.title=fmtTime(item.time)+' UTC · '+item.total+' 件';bars.append(bar)}document.getElementById('timelineTotal').textContent='合計 '+total.toLocaleString()+' 件';const nonzero=items.filter(x=>Number(x.total)>0).slice(-12).reverse();if(!nonzero.length){const e=document.createElement('div');e.className='empty';e.textContent='直近24時間にイベントはありません';list.append(e);return}for(const item of nonzero){const row=document.createElement('div');row.className='timeline-row';const time=document.createElement('div');time.className='timeline-time';time.textContent=new Date(item.time).toLocaleString('ja-JP',{timeZone:'UTC',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});const pin=document.createElement('div');pin.className='timeline-pin'+(Number(item.errors)>0?' fail':Number(item.scanner_candidates)>0||Number(item.login_attempts)>0?' warn':'');const desc=document.createElement('div');desc.textContent='イベント '+Number(item.total).toLocaleString()+' 件 · エラー '+Number(item.errors).toLocaleString()+' · スキャナー候補 '+Number(item.scanner_candidates).toLocaleString()+' · ログイン試行 '+Number(item.login_attempts).toLocaleString();const count=document.createElement('div');count.className='timeline-count';count.textContent=Number(item.total).toLocaleString()+' 件';row.append(time,pin,desc,count);list.append(row)}}
function renderPayloadSignals(items){const labels={'payload:sql_injection_candidate':'SQLインジェクション候補','payload:path_traversal_candidate':'パストラバーサル候補','payload:xss_candidate':'XSS候補','payload:command_injection_candidate':'コマンド注入候補','payload:sensitive_path_candidate':'機密パス探索候補'};renderRankList('payloadRanking',items,x=>labels[x.signal]||'その他の分類候補',x=>x.count,'amber')}
function renderDaily(items){const root=document.getElementById('dailyBars');root.replaceChildren();const max=Math.max(1,...items.map(x=>Number(x.total)||0));const total=items.reduce((s,x)=>s+(Number(x.total)||0),0);for(const item of items){const bar=document.createElement('div');bar.className='timeline-bar';bar.style.height=Math.max(2,(Number(item.total)||0)/max*90)+'px';bar.title=item.day+' · '+Number(item.total).toLocaleString()+'件 · 5xx '+Number(item.errors).toLocaleString();root.append(bar)}document.getElementById('dailyTotal').textContent='30日合計 '+total.toLocaleString()+' 件'}
function renderBehavior(b,bursts){const items=[{name:'直近1時間のユニークパス',count:b.unique_paths_1h},{name:'5回以上反復したパス（1時間）',count:b.repeated_paths_1h},{name:'3回以上反復したパス（5分）',count:b.burst_paths_5m},{name:'エクスプロイト候補',count:b.exploit_candidates},{name:'既知スキャンパス',count:b.common_scan_paths},{name:'非読み取りメソッド',count:b.non_read_methods},{name:'HTTP 4xx',count:b.client_errors},{name:'HTTP 5xx',count:b.server_errors}];renderRankList('behaviorRanking',items,x=>x.name,x=>x.count,'amber');renderRankList('burstPathRanking',bursts||[],x=>x.path,x=>x.count,'amber')}
function renderThreatSignals(items){const names={'Exploitパターン候補':'不審な文字列など既知パターンとの一致','既知スキャンパス候補':'よく探索される設定・管理パス','非読み取りHTTPメソッド':'GET/HEAD/OPTIONS以外のメソッド','スキャナー候補':'複数のスキャン兆候を含む分類','検索クローラー申告':'User-Agent上の検索クローラー申告','ログイン試行':'偽ログイン画面への送信イベント','サーバーエラー':'HTTP 5xx応答','管理パス探索候補':'管理画面や設定パスへのアクセス'};renderRankList('threatSignalList',items,x=>x.signal+' — '+(names[x.signal]||'観測パターン'),x=>x.count,'amber')}
async function refreshHealth(){const api=document.getElementById('healthApi'),db=document.getElementById('healthDb');try{const r=await fetch('/api/dashboard/health',{cache:'no-store'});if(!r.ok)throw Error('health');const h=await r.json();api.textContent=h.status==='ok'?'正常':'要確認';api.style.color=h.status==='ok'?'var(--green)':'var(--red)';db.textContent=h.database==='online'?'接続正常':'接続不可';db.style.color=h.database==='online'?'var(--green)':'var(--red)';const hp=document.getElementById('healthHoneypot');hp.textContent=h.honeypot==='online'?'応答正常':'応答なし';hp.style.color=h.honeypot==='online'?'var(--green)':'var(--red)';document.getElementById('healthEvents').textContent=Number(h.events_5m).toLocaleString();document.getElementById('healthLast').textContent=h.last_event?new Date(h.last_event).toLocaleTimeString('ja-JP',{timeZone:'UTC'}):'未記録';document.getElementById('healthAge').textContent=h.seconds_since_last_event==null?'イベントはまだありません':h.seconds_since_last_event<60?'最終イベントから1分未満':Math.floor(h.seconds_since_last_event/60)+' 分前';document.getElementById('healthChecked').textContent='最終確認 '+new Date(h.checked_at).toLocaleTimeString('ja-JP')+' · この表示はDashboardとDBの簡易チェックです。Honeypot本体の完全な稼働保証ではありません。'}catch(e){api.textContent='確認失敗';api.style.color='var(--red)';db.textContent='状態不明';db.style.color='var(--amber)';document.getElementById('healthChecked').textContent='ヘルスAPIに接続できません。Dashboardの稼働状況を確認してください。'}}
function renderCorrelations(items){renderRankList('pathCorrelationRanking',items||[],x=>x.path+' · '+x.signal_types+'種のシグナル',x=>x.hits+'件 / シグナル '+x.signal_hits,'amber')}
function renderProtocol(a){const l=a.latency||{};document.getElementById('latencyP50').textContent=l.p50_ms==null?'—':l.p50_ms.toLocaleString()+' ms';document.getElementById('latencyP95').textContent=l.p95_ms==null?'—':l.p95_ms.toLocaleString()+' ms';document.getElementById('latencyMax').textContent=l.max_ms==null?'—':l.max_ms.toLocaleString()+' ms';document.getElementById('latencySamples').textContent='計測サンプル '+Number(l.samples||0).toLocaleString();renderRankList('methodRanking',a.methods||[],x=>x.method,x=>x.count);renderRankList('statusFamilyRanking',a.status_families||[],x=>x.family,x=>x.count);renderPayloadSignals(a.payload_signals||[]);renderBehavior(a.behavior||{},a.burst_paths||[]);renderCorrelations(a.path_correlations||[]);renderDaily(a.daily_30d||[]);renderRankList('countryTrend',a.country_counts_7d||[],x=>x.country,x=>x.count)}
function renderAlert(a){const box=document.getElementById('alertBanner'),dot=document.getElementById('alertDot');const triggered=!!a.triggered;box.classList.toggle('triggered',triggered);dot.className='status-dot'+(triggered?' fail':'');document.getElementById('alertState').textContent=triggered?'SPIKE DETECTED':'NORMAL';document.getElementById('alertTitle').textContent=triggered?'アクセス急増を検知しました':'アクセス急増は検知されていません';document.getElementById('alertDetail').textContent='直近5分 '+Number(a.recent_5m).toLocaleString()+' 件 · 過去55分の5分換算平均 '+Number(a.baseline_per_5m).toLocaleString()+' 件'+(triggered?' · 通常より大きく増加':' · 閾値に達していません')}

async function refreshAnalytics(){try{const r=await fetch('/api/dashboard/analytics',{cache:'no-store'});if(!r.ok)throw Error('analytics api');const a=await r.json();document.getElementById('lastHour').textContent=Number(a.last_hour).toLocaleString();document.getElementById('errors24').textContent=Number(a.errors_24h).toLocaleString();document.getElementById('scanner24').textContent=Number(a.scanner_candidates_24h).toLocaleString();renderTrend(a.series||[]);renderCategories(a.categories||[]);renderRankList('pathRanking',a.top_paths||[],x=>x.path,x=>x.count);renderRankList('statusRanking',a.statuses||[],x=>'HTTP '+x.status_code,x=>x.count);renderTimeline(a.timeline||[]);renderThreatSignals(a.threat_signals||[]);renderProtocol(a);renderAlert(a.alert||{});}catch(e){document.getElementById('trendHint').textContent='分析データを取得できません';}}

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
let eventRows=[];
function applyEventFilters(){const q=(document.getElementById('eventSearch')?.value||'').trim().toLowerCase(),status=document.getElementById('eventStatusFilter')?.value||'all';let visible=0;for(const tr of document.querySelectorAll('#events tr[data-search]')){const matchesText=!q||tr.dataset.search.includes(q);const matchesStatus=status==='all'||String(tr.dataset.status).startsWith(status);const show=matchesText&&matchesStatus;tr.hidden=!show;if(show)visible++}const count=document.getElementById('eventFilterCount');if(count)count.textContent=visible+'件表示 / '+eventRows.length+'件'}
document.addEventListener('input',e=>{if(e.target.id==='eventSearch')applyEventFilters()});document.addEventListener('change',e=>{if(e.target.id==='eventStatusFilter')applyEventFilters()});
function initNavigation(){const titles={overview:['概要','ライブ観測の主要指標と急増アラート'],traffic:['通信・トレンド','HTTP応答、時間推移、長期統計'],threats:['脅威分析','パターン候補、反復行動、シグナル相関'],geography:['世界地図','地域別に集約されたアクセス観測'],system:['システム稼働','Dashboard・DB・Honeypotのヘルス状態'],events:['イベント検索','直近イベントをパス・分類・HTTPステータスで絞り込み']};document.querySelector('.page-content>.grid')?.setAttribute('data-page','overview');for(const section of document.querySelectorAll('.page-content section')){const h=section.querySelector('h2')?.textContent||'';let page='overview';if(h.includes('システム稼働'))page='system';else if(h.includes('イベントタイムライン')||h.includes('HTTP・通信')||h.includes('長期傾向'))page='traffic';else if(h.includes('脅威シグナル')||h.includes('不審ペイロード')||h.includes('観測された侵入経路'))page='threats';else if(h.includes('アクセス元マップ'))page='geography';else if(h.includes('最新イベント'))page='events';section.dataset.page=page}function show(page){document.querySelectorAll('.page-content section').forEach(el=>el.hidden=el.dataset.page!==page);const grid=document.querySelector('.page-content>.grid');if(grid)grid.hidden=page!=='overview';document.querySelectorAll('[data-page-link]').forEach(btn=>{const active=btn.dataset.pageLink===page;btn.classList.toggle('active',active);btn.setAttribute('aria-current',active?'page':'false')});let head=document.getElementById('pageTitle');if(!head){head=document.createElement('div');head.id='pageTitle';head.className='page-title';document.querySelector('.page-content>.notice')?.after(head)}head.innerHTML='<div><h2>'+titles[page][0]+'</h2><p>'+titles[page][1]+'</p></div><span class="status-pill"><span class="status-dot"></span>LIVE</span>';history.replaceState(null,'','#'+page)}document.querySelectorAll('[data-page-link]').forEach(btn=>btn.addEventListener('click',()=>show(btn.dataset.pageLink)));const initial=location.hash.slice(1);show(titles[initial]?initial:'overview')}
async function refresh(){try{
 const [s,e]=await Promise.all([fetch('/api/dashboard/summary',{cache:'no-store'}),fetch('/api/dashboard/events?limit=50',{cache:'no-store'})]);
 if(!s.ok||!e.ok)throw Error('API error');const a=await s.json(),b=await e.json();
 document.getElementById('knocks').textContent=a.knocks.toLocaleString();document.getElementById('passwords').textContent=a.password_attempts.toLocaleString();document.getElementById('probes').textContent=a.admin_probes.toLocaleString();document.getElementById('last24').textContent=a.last_24h.toLocaleString();document.getElementById('intrusionNote').textContent=a.intrusion_note;document.getElementById('recon').textContent=a.recon_visits.toLocaleString();document.getElementById('loginViews').textContent=a.login_page_views.toLocaleString();document.getElementById('pathPasswords').textContent=a.password_attempts.toLocaleString();document.getElementById('pathProbes').textContent=a.admin_probes.toLocaleString();document.getElementById('decoyAccesses').textContent=a.decoy_accesses.toLocaleString();
 const body=document.getElementById('events');body.replaceChildren();eventRows=b.events||[];
 if(!b.events.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=7;td.className='empty';td.textContent='まだイベントはありません';tr.append(td);body.append(tr)}
 for(const ev of b.events){const tr=document.createElement('tr');const vals=[fmtTime(ev.timestamp),label(ev.category),ev.method,ev.path,String(ev.status_code),ev.response_ms==null?'—':Number(ev.response_ms).toFixed(1)+' ms',(ev.tags||[]).join(', ')||'—'];tr.dataset.search=vals.join(' ').toLowerCase();tr.dataset.status=String(ev.status_code);vals.forEach((v,i)=>{const td=document.createElement('td');td.textContent=v;if(i===3)td.className='path';if(i===1){const span=document.createElement('span');span.className='badge '+badge(ev.category);span.textContent=v;td.replaceChildren(span)}tr.append(td)});body.append(tr)}
 applyEventFilters();document.getElementById('updated').textContent='最終更新 '+new Date().toLocaleTimeString('ja-JP');
 }catch(e){document.getElementById('updated').textContent='取得エラー';}}
initNavigation();initWorldMap().then(()=>{drawHoneypotTarget();refreshGeo()});refresh();refreshGeo();refreshAnalytics();refreshHealth();setInterval(refresh,5000);setInterval(refreshGeo,5000);setInterval(refreshAnalytics,5000);setInterval(refreshHealth,15000);
</script></body></html>"""
