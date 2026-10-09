// SolarSync — tenant-requested support access.
//
// A tenant admin opens a support request (with an expiry). While it is open, the
// reseller can enter THAT tenant's portal to diagnose and fix configuration —
// without seeing the private details of the tenant's customers, staff or
// contractors. Privacy is enforced here on the server, not just hidden in the UI:
//
//   - The support session uses a short-lived token tied to the request. Every API
//     call re-checks the request is still open, so a tenant revoke (or expiry)
//     ends access immediately.
//   - Only an allow-list of endpoints is reachable. Reads are masked: names,
//     contact details, addresses, notes, signatures and rooftop images are replaced
//     before the response leaves the server. Messages, documents, photos, payroll,
//     accounting and the like are not reachable at all.
//   - Writes are limited to configuration (branding, letterhead, products/stock),
//     so masked placeholder values can never be saved back over real records.
//   - Requesting, entering, every change, exiting, revoking and closing are audited.
const jwt = require("jsonwebtoken");
const { rows, one, run, rid, audit } = require("./db");
const A = require("./auth");

const MASK = "•••";
const DURATIONS = [2, 8, 24, 72];          // hours a tenant can grant
const SESSION_MAX_MS = 60 * 60 * 1000;     // a support token lives at most 1h (re-enter after)

// Endpoints a support session can READ (masked). Exact paths or prefixes ending "/".
const READ_OK = [
  "/api/branding", "/api/letterhead", "/api/products", "/api/stock-movements",
  "/api/my-features", "/api/entitlements/", "/api/report-templates",
  "/api/quotes", "/api/quotes/", "/api/deals", "/api/clients", "/api/bookings",
  "/api/team", "/api/staff", "/api/invoices", "/api/clock/status",
  "/api/support-requests/current", "/api/health",
];
// Endpoints a support session can CHANGE — configuration only, never people records.
const WRITE_OK = [
  ["PUT", /^\/api\/branding$/], ["PUT", /^\/api\/letterhead$/],
  ["POST", /^\/api\/products$/], ["PUT", /^\/api\/products\/[\w-]+$/],
  ["DELETE", /^\/api\/products\/[\w-]+$/], ["POST", /^\/api\/products\/[\w-]+\/stock$/],
  ["POST", /^\/api\/support-requests\/exit$/],
];
// Responses that are the tenant's own business setup — shown as-is.
const NO_MASK = ["/api/branding", "/api/letterhead", "/api/products", "/api/my-features", "/api/entitlements/", "/api/report-templates", "/api/health", "/api/support-requests/current"];

// Personal-data keys masked wherever they appear in a support response.
const PII_KEYS = new Set([
  "email", "phone", "mobile", "address", "site_address", "suburb", "postcode", "street",
  "customer", "client", "client_name", "contact", "installer", "buyer", "notes",
  "signature", "sig", "signame", "designimage", "siteplan", "lat", "lng",
  "pin_hash", "totp_secret", "body_html", "message", "dob", "tfn", "bsb", "account_number",
]);
// Extra keys that are a person's name/identifier on these endpoints.
const PATH_KEYS = [
  [/^\/api\/(clients|team|staff|users)/, ["name", "display_name", "licence"]],
  [/^\/api\/bookings/, ["title"]],
];

const matches = (p, list) => list.some(x => x.endsWith("/") ? p.startsWith(x) : p === x);

// Keep the value's shape (the UI expects objects/arrays where they were) but
// replace every piece of text inside it.
function maskValue(v) {
  if (typeof v === "number") return null;
  if (typeof v === "boolean") return v;
  if (Array.isArray(v)) return v.map(maskValue);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).map(k => [k, maskValue(v[k])]));
  return MASK;
}
function maskDeep(v, extra) {
  if (Array.isArray(v)) return v.map(x => maskDeep(x, extra));
  if (v && typeof v === "object" && !(v instanceof Date)) {
    const out = {};
    for (const [k, val] of Object.entries(v)) {
      const key = k.toLowerCase();
      out[k] = (val != null && (PII_KEYS.has(key) || extra.has(key))) ? maskValue(val) : maskDeep(val, extra);
    }
    return out;
  }
  return v;
}

function bearer(req) {
  const h = req.headers.authorization || "";
  return h.startsWith("Bearer ") ? h.slice(7) : null;
}

async function activeRequest(id) {
  return one("select * from support_requests where id=$1 and status='open' and expires_at > now()", [id]);
}

// Runs before every /api route. Does nothing for normal tokens.
function guard() {
  return async (req, res, next) => {
    const tok = bearer(req);
    if (!tok) return next();
    let p; try { p = A.verify(tok); } catch (e) { return next(); }   // authRequired reports bad tokens
    if (!p.support) return next();
    try {
      const sr = await activeRequest(p.support);
      if (!sr || sr.tenant_id !== p.tenant_id) return res.status(401).json({ error: "support_ended" });
      const path = req.baseUrl + req.path;
      const method = req.method;
      if (method === "GET") {
        if (!matches(path, READ_OK)) return res.status(403).json({ error: "support_restricted" });
      } else if (!WRITE_OK.some(([m, re]) => m === method && re.test(path))) {
        return res.status(403).json({ error: "support_read_only" });
      } else if (!path.endsWith("/exit")) {
        await audit(p.by, "support_change", method + " " + path, sr.tenant_id, { request: sr.id });
      }
      if (!matches(path, NO_MASK)) {
        const extra = new Set();
        for (const [re, keys] of PATH_KEYS) if (re.test(path)) keys.forEach(k => extra.add(k));
        const json = res.json.bind(res);
        res.json = body => json(maskDeep(body, extra));
      }
      req.support = { request: sr, by: p.by };
      next();
    } catch (e) { next(e); }
  };
}

function register(app, { h, ok }) {
  const isTenantAdmin = req => req.user.app_role === "tenant_admin" && !req.user.support;

  // Tenant opens a request — this is their consent, for a limited time.
  app.post("/api/support-requests", A.authRequired, A.requireRole("tenant_admin"), h(async (req, res) => {
    if (!isTenantAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const message = String((req.body && req.body.message) || "").trim().slice(0, 2000);
    const hours = Number(req.body && req.body.hours);
    if (!message) return res.status(400).json({ error: "message_required" });
    if (!DURATIONS.includes(hours)) return res.status(400).json({ error: "bad_duration" });
    const id = "sr-" + rid().slice(0, 8);
    await run(`insert into support_requests (id, tenant_id, requested_by, message, expires_at)
      values ($1,$2,$3,$4, now() + ($5 || ' hours')::interval)`, [id, req.user.tenant_id, req.user.sub, message, String(hours)]);
    await audit(req.user.sub, "support_request_open", id, req.user.tenant_id, { hours });
    ok(res, await one("select *, (status='open' and expires_at > now()) as active from support_requests where id=$1", [id]));
  }));

  // Tenant sees their own requests; reseller sees every tenant's.
  app.get("/api/support-requests", A.authRequired, A.requireRole("tenant_admin", "reseller"), h(async (req, res) => {
    if (req.user.app_role === "reseller") {
      return ok(res, await rows(`select sr.*, t.name as tenant_name, (sr.status='open' and sr.expires_at > now()) as active
        from support_requests sr left join tenants t on t.id = sr.tenant_id order by sr.created_at desc limit 200`));
    }
    if (!isTenantAdmin(req)) return res.status(403).json({ error: "forbidden" });
    ok(res, await rows(`select *, (status='open' and expires_at > now()) as active from support_requests
      where tenant_id=$1 order by created_at desc limit 50`, [req.user.tenant_id]));
  }));

  // Tenant withdraws access at any time — takes effect on the very next API call.
  app.post("/api/support-requests/:id/revoke", A.authRequired, A.requireRole("tenant_admin"), h(async (req, res) => {
    if (!isTenantAdmin(req)) return res.status(403).json({ error: "forbidden" });
    const sr = await one("select * from support_requests where id=$1", [req.params.id]);
    if (!sr || sr.tenant_id !== req.user.tenant_id) return res.status(404).json({ error: "not_found" });
    await run("update support_requests set status='revoked', closed_at=now(), closed_by=$1 where id=$2 and status='open'", [req.user.sub, sr.id]);
    await audit(req.user.sub, "support_request_revoke", sr.id, sr.tenant_id);
    ok(res, { ok: true });
  }));

  // Reseller marks the issue done.
  app.post("/api/support-requests/:id/close", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
    const sr = await one("select * from support_requests where id=$1", [req.params.id]);
    if (!sr) return res.status(404).json({ error: "not_found" });
    await run("update support_requests set status='closed', closed_at=now(), closed_by=$1 where id=$2 and status='open'", [req.user.sub, sr.id]);
    await audit(req.user.sub, "support_request_close", sr.id, sr.tenant_id);
    ok(res, { ok: true });
  }));

  // Reseller enters the tenant's portal. The token acts as that tenant's admin, but
  // carries `support` so the guard restricts and masks everything it touches.
  app.post("/api/support-requests/:id/enter", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
    const sr = await activeRequest(req.params.id);
    if (!sr) return res.status(409).json({ error: "not_active" });
    const t = await one("select id, name from tenants where id=$1", [sr.tenant_id]);
    const remaining = new Date(sr.expires_at).getTime() - Date.now();
    const ttl = Math.max(60, Math.floor(Math.min(remaining, SESSION_MAX_MS) / 1000));
    const user = { id: req.user.sub, app_role: "tenant_admin", tenant_id: sr.tenant_id, display_name: "SolarSync Support", support: sr.id };
    const access_token = jwt.sign({ sub: req.user.sub, app_role: "tenant_admin", tenant_id: sr.tenant_id,
      display_name: "SolarSync Support", support: sr.id, by: req.user.sub }, A.JWT_SECRET, { expiresIn: ttl });
    await audit(req.user.sub, "support_session_enter", sr.id, sr.tenant_id);
    ok(res, { access_token, user, tenant: t, expires_at: sr.expires_at, session_ends_at: new Date(Date.now() + ttl * 1000).toISOString() });
  }));

  app.get("/api/support-requests/current", A.authRequired, h(async (req, res) => {
    if (!req.support) return res.status(404).json({ error: "not_in_support" });
    const t = await one("select name from tenants where id=$1", [req.support.request.tenant_id]);
    ok(res, { id: req.support.request.id, tenant_name: t && t.name, expires_at: req.support.request.expires_at, message: req.support.request.message });
  }));

  app.post("/api/support-requests/exit", A.authRequired, h(async (req, res) => {
    if (req.support) await audit(req.support.by, "support_session_exit", req.support.request.id, req.support.request.tenant_id);
    ok(res, { ok: true });
  }));
}

module.exports = { guard, register, maskDeep };
