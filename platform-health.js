// SolarSync — real platform health for the reseller's Platform Health screen.
//
// Measured by this server itself, so figures cover the time since it last started
// (a restart or redeploy resets them). Nothing here is estimated or sample data:
//   - requests and response times for /api calls (last 24 hours, per hour)
//   - server errors (5xx) in the last 24 hours, with the most recent ones
//   - live checks: database round-trip, and which services are configured
//   - storage held in the database per tenant (photos and documents)
const { rows, one } = require("./db");
const A = require("./auth");
const storage = require("./storage");

const STARTED = Date.now();
const HOUR = 3600 * 1000;
const hours = new Map();       // hour start (ms) -> { n, errors }
const samples = [];            // recent response times (ms), newest last
const recentErrors = [];       // { at, method, path, status }

function hourBucket(t) {
  const k = Math.floor(t / HOUR) * HOUR;
  let b = hours.get(k);
  if (!b) {
    b = { n: 0, errors: 0 };
    hours.set(k, b);
    for (const key of hours.keys()) if (key < k - 24 * HOUR) hours.delete(key);
  }
  return b;
}

// Express middleware: time every /api request.
function track(req, res, next) {
  if (!req.path.startsWith("/api/")) return next();
  const t0 = process.hrtime.bigint();
  res.on("finish", () => {
    const ms = Number(process.hrtime.bigint() - t0) / 1e6;
    const b = hourBucket(Date.now());
    b.n++;
    samples.push(ms);
    if (samples.length > 2000) samples.shift();
    if (res.statusCode >= 500) {
      b.errors++;
      // Path only (ids trimmed) — no query strings, bodies or user details.
      recentErrors.push({ at: new Date().toISOString(), method: req.method,
        path: req.path.replace(/\/[^/]*\d[^/]*/g, "/:id"), status: res.statusCode });
      if (recentErrors.length > 20) recentErrors.shift();
    }
  });
  next();
}

const pct = (arr, p) => {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor(p * s.length))];
};

function register(app, { h, ok }) {
  app.get("/api/platform/health", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
    // Live database round-trip.
    const t0 = Date.now();
    let dbOk = true;
    try { await one("select 1 as ok"); } catch (e) { dbOk = false; }
    const dbMs = Date.now() - t0;
    let dbBytes = null;
    try { dbBytes = Number((await one("select pg_database_size(current_database()) as n")).n); } catch (e) { /* not available locally */ }

    // Photos and documents stored in the database, per tenant.
    let byTenant = [];
    try {
      byTenant = await rows(`select t.id, t.name, coalesce(p.b, 0) + coalesce(d.b, 0) as bytes
        from tenants t
        left join (select tenant_id, sum(length(data))::bigint as b from job_photos group by tenant_id) p on p.tenant_id = t.id
        left join (select tenant_id, sum(length(data))::bigint as b from field_documents group by tenant_id) d on d.tenant_id = t.id
        order by bytes desc`);
    } catch (e) { /* tables may not exist on a very old database */ }

    const now = Date.now();
    const series = [];
    for (let i = 23; i >= 0; i--) {
      const k = Math.floor((now - i * HOUR) / HOUR) * HOUR;
      const b = hours.get(k) || { n: 0, errors: 0 };
      series.push({ hour: new Date(k).toISOString(), n: b.n, errors: b.errors });
    }
    const key = process.env.STRIPE_SECRET_KEY || "";
    const services = [
      { name: "Database", status: dbOk ? "operational" : "down", detail: dbOk ? dbMs + " ms round-trip" : "not responding",
        ms: dbOk ? dbMs : null },
      { name: "Payments (Stripe)", status: key ? (process.env.STRIPE_WEBHOOK_SECRET ? "operational" : "attention") : "not configured",
        detail: key ? (key.startsWith("sk_live") ? "live mode" : "test mode") + (process.env.STRIPE_WEBHOOK_SECRET ? " · webhook verified" : " · webhook secret missing") : "STRIPE_SECRET_KEY not set" },
      { name: "Document library storage (Spaces)", status: storage.isConfigured() ? "operational" : "not configured",
        detail: storage.isConfigured() ? "configured" : "photos and field documents still work (kept in the database)" },
      { name: "AI Assistant", status: process.env.ANTHROPIC_API_KEY ? "operational" : "not configured",
        detail: process.env.ANTHROPIC_API_KEY ? "API key set" : "add-on unavailable until ANTHROPIC_API_KEY is set" },
      { name: "Sign-in security", status: process.env.JWT_SECRET && process.env.JWT_SECRET !== "dev-only-change-me" ? "operational" : "attention",
        detail: process.env.JWT_SECRET && process.env.JWT_SECRET !== "dev-only-change-me" ? "signing secret set" : "using the development signing secret" },
    ];
    const day = series.reduce((a, s) => ({ n: a.n + s.n, errors: a.errors + s.errors }), { n: 0, errors: 0 });
    ok(res, {
      started_at: new Date(STARTED).toISOString(), uptime_s: Math.round((now - STARTED) / 1000),
      requests_24h: day.n, errors_24h: day.errors, recent_errors: [...recentErrors].reverse(),
      latency_ms: { avg: samples.length ? samples.reduce((a, b) => a + b, 0) / samples.length : null, p95: pct(samples, 0.95), sample: samples.length },
      series, services, db_bytes: dbBytes, storage_by_tenant: byTenant.map(t => ({ ...t, bytes: Number(t.bytes) })),
    });
  }));
}

module.exports = { register, track };
