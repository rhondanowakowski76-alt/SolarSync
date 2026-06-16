// SolarSync backend — single self-contained server (API + front-end). PostgreSQL.
const express = require("express");
const path = require("path");
const fs = require("fs");
const { rows, one, run, rid, audit } = require("./db");
const A = require("./auth");
const QRCode = require("qrcode");

const app = express();
app.use(express.json({ limit: "12mb" }));

const ok = (res, body) => res.json(body);
const tenantOf = (req) => req.user.tenant_id;
const isReseller = (req) => req.user.app_role === "reseller";

// anti-brute-force (DB writes here, async)
async function bumpFail(u) {
  const n = (u.failed_attempts || 0) + 1;
  if (n >= 5) await run("update users set failed_attempts=0, locked_until=$1 where id=$2", [new Date(Date.now() + 5 * 60000).toISOString(), u.id]);
  else await run("update users set failed_attempts=$1 where id=$2", [n, u.id]);
}
async function clearFail(id) { await run("update users set failed_attempts=0, locked_until=null where id=$1", [id]); }

// wrap async handlers so errors return 500 instead of crashing
const h = (fn) => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: String(e.message || e) }); });

// ============================================================
// AUTH (PIN + TOTP only — no email)
// ============================================================
app.post("/api/auth/accounts", h(async (req, res) => {
  const { tenant_id } = req.body || {};
  const r = tenant_id
    ? await rows("select id, display_name, app_role from users where status='active' and tenant_id=$1 order by app_role", [tenant_id])
    : await rows("select id, display_name, app_role from users where status='active' order by app_role");
  ok(res, r);
}));

app.post("/api/auth/pin", h(async (req, res) => {
  const { user_id, pin } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u) return res.status(404).json({ error: "not_found" });
  if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
  if (!u.pin_hash) return res.status(409).json({ error: "no_pin", must_set: true });
  if (!A.bcrypt.compareSync(String(pin), u.pin_hash)) { await bumpFail(u); return res.status(401).json({ error: "bad_pin" }); }
  await clearFail(u.id);
  if (!u.totp_enrolled) return res.status(409).json({ error: "needs_enrol", must_enrol: true });
  ok(res, { challenge: true });
}));

app.post("/api/auth/totp", h(async (req, res) => {
  const { user_id, code } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u || !u.totp_secret) return res.status(404).json({ error: "not_found" });
  if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
  if (!A.verifyTotp(u.totp_secret, code)) { await bumpFail(u); return res.status(401).json({ error: "bad_code" }); }
  await clearFail(u.id);
  if (!u.totp_enrolled) await run("update users set totp_enrolled=true where id=$1", [u.id]);
  await audit(u.id, "login", u.id, u.tenant_id);
  ok(res, {
    access_token: A.mintAccess(u), refresh_token: A.mintRefresh(u),
    user: { id: u.id, display_name: u.display_name, app_role: u.app_role, tenant_id: u.tenant_id },
  });
}));

app.post("/api/auth/enrol", h(async (req, res) => {
  const { user_id } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u) return res.status(404).json({ error: "not_found" });
  const secret = A.randomBase32();
  await run("update users set totp_secret=$1 where id=$2", [secret, u.id]);  // enrolled flag set on first verify
  const uri = A.otpauthUri(u.display_name, secret);
  let qr = null; try { qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 }); } catch (e) {}
  ok(res, { otpauth_uri: uri, secret, qr });
}));

app.post("/api/auth/set-pin", h(async (req, res) => {
  const { user_id, pin, code } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u || !u.totp_secret) return res.status(404).json({ error: "not_found" });
  if (!A.verifyTotp(u.totp_secret, code)) return res.status(401).json({ error: "bad_code" });
  if (!/^\d{6}$/.test(String(pin))) return res.status(400).json({ error: "pin_format" });
  await run("update users set pin_hash=$1, must_reset=false where id=$2", [A.bcrypt.hashSync(String(pin), 10), u.id]);
  ok(res, { ok: true });
}));

app.post("/api/auth/refresh", h(async (req, res) => {
  let p; try { p = A.verify((req.body || {}).refresh_token); } catch { return res.status(401).json({ error: "bad_token" }); }
  if (p.typ !== "refresh") return res.status(401).json({ error: "bad_token" });
  const u = await one("select * from users where id=$1", [p.sub]);
  if (!u) return res.status(404).json({ error: "not_found" });
  ok(res, { access_token: A.mintAccess(u) });
}));

app.post("/api/admin/reset-user", A.authRequired, A.requireRole("reseller", "tenant_admin"), h(async (req, res) => {
  const { user_id } = req.body || {};
  const target = await one("select * from users where id=$1", [user_id]);
  if (!target) return res.status(404).json({ error: "not_found" });
  if (!isReseller(req) && target.tenant_id !== tenantOf(req)) return res.status(403).json({ error: "forbidden" });
  await run("update users set pin_hash=null, totp_secret=null, totp_enrolled=false, must_reset=true, failed_attempts=0, locked_until=null where id=$1", [user_id]);
  await audit(req.user.sub, "admin_reset", user_id, target.tenant_id);
  ok(res, { ok: true });
}));

// ============================================================
// ENTITLEMENTS (server-enforced add-on / branding gate)
// ============================================================
async function complianceUnlocked(tenant_id, token) {
  if (tenant_id) {
    const a = await one("select active from tenant_addons where tenant_id=$1 and addon_key='compliance-suite'", [tenant_id]);
    if (a && a.active) return { unlocked: true, source: "addon" };
  }
  if (token) {
    const t = await one("select active from tester_tokens where token=$1 and active=true", [String(token).toUpperCase()]);
    if (t) return { unlocked: true, source: "token" };
  }
  return { unlocked: false, source: null };
}
app.get("/api/entitlements/compliance", A.authRequired, h(async (req, res) =>
  ok(res, await complianceUnlocked(tenantOf(req), req.query.token))));

app.post("/api/tenants/:id/addons/:key", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const { id, key } = req.params; const active = !!req.body.active;
  await run(`insert into tenant_addons (tenant_id, addon_key, active, activated_at) values ($1,$2,$3,now())
    on conflict (tenant_id, addon_key) do update set active=excluded.active, activated_at=now()`, [id, key, active]);
  await audit(req.user.sub, "addon_toggle", key, id, { active });
  ok(res, { ok: true });
}));

// ============================================================
// LETTERHEAD
// ============================================================
app.get("/api/letterhead", A.authRequired, h(async (req, res) =>
  ok(res, (await one("select * from letterheads where tenant_id=$1", [tenantOf(req)])) || {})));

app.put("/api/letterhead", A.authRequired, A.requireRole("tenant_admin", "staff"), h(async (req, res) => {
  const d = req.body || {};
  await run(`insert into letterheads (tenant_id, legal_name, abn, address, phone, email, licence, logo_url, updated_at)
    values ($1,$2,$3,$4,$5,$6,$7,$8,now())
    on conflict (tenant_id) do update set legal_name=excluded.legal_name, abn=excluded.abn, address=excluded.address,
      phone=excluded.phone, email=excluded.email, licence=excluded.licence, logo_url=excluded.logo_url, updated_at=now()`,
    [tenantOf(req), d.legal_name, d.abn, d.address, d.phone, d.email, d.licence, d.logo_url]);
  ok(res, { ok: true });
}));

// ============================================================
// REPORT TEMPLATES + REPORTS
// ============================================================
app.get("/api/report-templates", A.authRequired, h(async (req, res) =>
  ok(res, await rows("select key, category, title, body_html from report_templates"))));

app.get("/api/reports", A.authRequired, h(async (req, res) => {
  const r = isReseller(req)
    ? await rows("select * from reports order by updated_at desc")
    : await rows("select * from reports where tenant_id=$1 order by updated_at desc", [tenantOf(req)]);
  ok(res, r);
}));

app.post("/api/reports", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const id = rid(); const d = req.body || {};
  await run(`insert into reports (id, tenant_id, template_key, job_ref, title, body_html, status, created_by)
    values ($1,$2,$3,$4,$5,$6,'draft',$7)`, [id, tenantOf(req), d.template_key, d.job_ref, d.title, d.body_html, req.user.sub]);
  ok(res, { id });
}));

app.put("/api/reports/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const r = await one("select * from reports where id=$1", [req.params.id]);
  if (!r || r.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  await run("update reports set title=$1, body_html=$2, updated_at=now() where id=$3", [d.title ?? r.title, d.body_html ?? r.body_html, r.id]);
  ok(res, { ok: true });
}));

app.post("/api/reports/:id/publish", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const r = await one("select * from reports where id=$1", [req.params.id]);
  if (!r || r.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const { client_id, title, body_html } = req.body || {};
  await run("delete from report_publications where report_id=$1 and client_id=$2", [r.id, client_id]);
  await run(`insert into report_publications (id, report_id, tenant_id, client_id, title, body_html)
    values ($1,$2,$3,$4,$5,$6)`, [rid(), r.id, r.tenant_id, client_id, title || r.title, body_html || r.body_html]);
  await run("update reports set status='published' where id=$1", [r.id]);
  await audit(req.user.sub, "publish_report", r.id, r.tenant_id, { client_id });
  ok(res, { ok: true });
}));

app.get("/api/client/reports", A.authRequired, A.requireRole("client"), h(async (req, res) => {
  const client = await one("select * from clients where user_id=$1", [req.user.sub]);
  if (!client) return ok(res, { paid: false, reports: [] });
  const paid = !!(await one("select 1 from invoices where client_id=$1 and status='paid' limit 1", [client.id]));
  if (!paid) {
    const c = await one("select count(*)::int as c from report_publications where client_id=$1", [client.id]);
    return ok(res, { paid: false, count: c ? c.c : 0, reports: [] });
  }
  const reports = await rows("select id, title, body_html, published_at from report_publications where client_id=$1 order by published_at desc", [client.id]);
  ok(res, { paid: true, reports });
}));

// ============================================================
// INVOICES + PAYMENTS (Stripe)
// ============================================================
app.get("/api/invoices", A.authRequired, h(async (req, res) => {
  if (req.user.app_role === "client") {
    const c = await one("select * from clients where user_id=$1", [req.user.sub]);
    return ok(res, c ? await rows("select * from invoices where client_id=$1 order by created_at desc", [c.id]) : []);
  }
  ok(res, await rows("select * from invoices where tenant_id=$1 order by created_at desc", [tenantOf(req)]));
}));

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? require("stripe")(stripeKey) : null;

app.post("/api/invoices/:id/pay-intent", A.authRequired, h(async (req, res) => {
  const inv = await one("select * from invoices where id=$1", [req.params.id]);
  if (!inv) return res.status(404).json({ error: "not_found" });
  if (!stripe) return res.status(503).json({ error: "stripe_not_configured" });
  const pi = await stripe.paymentIntents.create({
    amount: Math.round(Number(inv.amount) * 100), currency: "aud",
    metadata: { invoice_id: inv.id, tenant_id: inv.tenant_id, client_id: inv.client_id },
    automatic_payment_methods: { enabled: true },
  });
  await run("update invoices set stripe_payment_intent=$1 where id=$2", [pi.id, inv.id]);
  ok(res, { client_secret: pi.client_secret });
}));

// Hosted Stripe Checkout — simplest, most secure: redirect the client to Stripe's card page.
app.post("/api/invoices/:id/checkout", A.authRequired, h(async (req, res) => {
  const inv = await one("select * from invoices where id=$1", [req.params.id]);
  if (!inv) return res.status(404).json({ error: "not_found" });
  if (!stripe) return res.status(503).json({ error: "stripe_not_configured" });
  const origin = req.headers.origin || (req.headers.host ? "https://" + req.headers.host : "");
  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    line_items: [{ price_data: { currency: "aud", product_data: { name: "Invoice " + (inv.number || inv.id) }, unit_amount: Math.round(Number(inv.amount) * 100) }, quantity: 1 }],
    metadata: { invoice_id: inv.id, tenant_id: inv.tenant_id, client_id: inv.client_id || "" },
    success_url: origin + "/app?paid=" + encodeURIComponent(inv.id),
    cancel_url: origin + "/app?pay=cancelled",
  });
  ok(res, { url: session.url });
}));

app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event = null;
  const sig = req.headers["stripe-signature"];
  const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
  try { event = (stripe && whSecret) ? stripe.webhooks.constructEvent(req.body, sig, whSecret) : JSON.parse(req.body); }
  catch (e) { return res.status(400).send(`bad sig: ${e.message}`); }
  if (event.type === "payment_intent.succeeded" || event.type === "checkout.session.completed") {
    const obj = event.data.object;
    const invId = obj.metadata && obj.metadata.invoice_id;
    if (invId) { run("update invoices set status='paid', paid_at=now() where id=$1", [invId]).then(() => audit(null, "invoice_paid", invId, obj.metadata.tenant_id)).catch(()=>{}); }
  }
  res.json({ received: true });
});

app.post("/api/invoices/:id/mark-paid", A.authRequired, A.requireRole("tenant_admin", "staff"), h(async (req, res) => {
  const inv = await one("select * from invoices where id=$1", [req.params.id]);
  if (!inv || inv.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  await run("update invoices set status='paid', paid_at=now() where id=$1", [inv.id]);
  await audit(req.user.sub, "invoice_paid_manual", inv.id, inv.tenant_id);
  ok(res, { ok: true });
}));

// ============================================================
// BETA TESTER ACCESS — issue / list / revoke / restore / delete / redeem
// Tester magic-link tokens are signed JWTs (HS256, JWT_SECRET).
// Server-side revocation: redeem() checks beta_testers.revoked before
// minting an access token, so even a still-validly-signed JWT stops
// working the moment you flip the flag.
// ============================================================
const jwt = require("jsonwebtoken");
function _makeId(len = 14) {
  // No I/O/0/1 — display-friendly + URL-safe.
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const b = require("crypto").randomBytes(len);
  let s = ""; for (let i = 0; i < len; i++) s += a[b[i] & 31];
  return s;
}
function _testerOrigin(req) {
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
  const host  = req.headers["x-forwarded-host"]  || req.headers.host;
  return `${proto}://${host}`;
}
function _testerLink(req, jwtToken) {
  return `${_testerOrigin(req)}/app?tester=${encodeURIComponent(jwtToken)}`;
}

// Issue — reseller only
app.post("/api/testers/issue", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const { name, email, duration_days, notes } = req.body || {};
  if (!name || !String(name).trim()) return res.status(400).json({ error: "name_required" });
  const id = _makeId();
  const now = new Date();
  const validDurations = { "30": 30, "60": 60, "90": 90 };
  const days = (duration_days === "never" || duration_days === null) ? null : (validDurations[String(duration_days)] || 30);
  const expiresAt = days === null ? null : new Date(now.getTime() + days * 24 * 3600 * 1000);
  const finalEmail = (email && String(email).trim()) || (`tester+${id.toLowerCase().slice(0,8)}@solarsync.demo`);
  await run(
    `insert into beta_testers (id, issued_by, name, email, scope, plan, notes, issued_at, expires_at) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [id, req.user.sub, String(name).trim(), finalEmail, "tenant,contractor,client", "Scale", notes ? String(notes).trim() : null, now, expiresAt]
  );
  // Sign JWT with the same secret used for normal auth.
  const expSec = expiresAt ? Math.floor(expiresAt.getTime() / 1000) : Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 365 * 10;
  const token = jwt.sign({ typ: "tester", id, name: String(name).trim(), email: finalEmail, scope: ["tenant","contractor","client"], exp: expSec }, process.env.JWT_SECRET || "dev-only-change-me");
  await audit(req.user.sub, "tester_issue", id, null, { name, email: finalEmail, expiresAt });
  ok(res, {
    id, name: String(name).trim(), email: finalEmail, plan: "Scale",
    issued_at: now.toISOString(), expires_at: expiresAt ? expiresAt.toISOString() : null,
    notes: notes ? String(notes).trim() : null,
    scope: ["tenant","contractor","client"], revoked: false,
    token, link: _testerLink(req, token),
  });
}));

// List — reseller only
app.get("/api/testers", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const r = await rows(`select id, name, email, scope, plan, notes, issued_at, expires_at, revoked, revoked_at, last_seen, use_count from beta_testers order by issued_at desc`);
  ok(res, r);
}));

// Revoke — reseller only
app.post("/api/testers/:id/revoke", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const r = await one(`select id from beta_testers where id=$1`, [req.params.id]);
  if (!r) return res.status(404).json({ error: "not_found" });
  await run(`update beta_testers set revoked=true, revoked_at=$1 where id=$2`, [new Date(), req.params.id]);
  await audit(req.user.sub, "tester_revoke", req.params.id, null);
  ok(res, { ok: true });
}));

// Restore — reseller only
app.post("/api/testers/:id/restore", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  await run(`update beta_testers set revoked=false, revoked_at=null where id=$1`, [req.params.id]);
  await audit(req.user.sub, "tester_restore", req.params.id, null);
  ok(res, { ok: true });
}));

// Delete — reseller only
app.delete("/api/testers/:id", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  await run(`delete from beta_testers where id=$1`, [req.params.id]);
  await audit(req.user.sub, "tester_delete", req.params.id, null);
  ok(res, { ok: true });
}));

// Redeem — PUBLIC. Tester clicks the magic link → portal POSTs the token here.
// We verify JWT signature + DB state (revoked / expired) then mint a regular
// access token for a synthetic tenant_admin user pointing at a demo tenant.
app.post("/api/testers/redeem", h(async (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: "token_required" });
  let p;
  try { p = jwt.verify(token, process.env.JWT_SECRET || "dev-only-change-me"); }
  catch (e) { return res.status(401).json({ error: "invalid_token" }); }
  if (p.typ !== "tester" || !p.id) return res.status(401).json({ error: "invalid_token" });
  const row = await one(`select * from beta_testers where id=$1`, [p.id]);
  if (!row) return res.status(404).json({ error: "not_found" });
  if (row.revoked) return res.status(403).json({ error: "revoked" });
  if (row.expires_at && new Date(row.expires_at).getTime() < Date.now()) return res.status(403).json({ error: "expired" });
  await run(`update beta_testers set last_seen=$1, use_count=use_count+1 where id=$2`, [new Date(), p.id]);
  // Synthetic user — never persisted. tenant_id points at the demo tenant.
  const syntheticUser = {
    id: `tester-${p.id}`, tenant_id: "tenant-helios", app_role: "tenant_admin",
    display_name: p.name || "Beta Tester",
  };
  const accessToken  = A.mintAccess(syntheticUser);
  const refreshToken = A.mintRefresh(syntheticUser);
  await audit(syntheticUser.id, "tester_redeem", p.id, syntheticUser.tenant_id);
  ok(res, {
    access_token: accessToken, refresh_token: refreshToken,
    user: { id: syntheticUser.id, display_name: syntheticUser.display_name, app_role: syntheticUser.app_role, tenant_id: syntheticUser.tenant_id, is_tester: true },
    tester: { id: row.id, name: row.name, email: row.email, plan: row.plan, expires_at: row.expires_at, scope: (row.scope || "tenant,contractor,client").split(",") },
  });
}));

// ============================================================
// Health + serve the front-end
// ============================================================
app.get("/api/health", h(async (req, res) => ok(res, { ok: true, ts: Date.now() })));

const BUNDLE = path.join(__dirname, "public", "index.html");
const LANDING = path.join(__dirname, "public", "landing.html");
const PRIVACY = path.join(__dirname, "public", "privacy.html");
const TERMS = path.join(__dirname, "public", "terms.html");
// Marketing landing page at the root; the app (login) lives at /app and all other routes.
app.get("/", (req, res) => {
  if (fs.existsSync(LANDING)) return res.sendFile(LANDING);
  if (fs.existsSync(BUNDLE)) return res.sendFile(BUNDLE);
  res.status(200).send("SolarSync CRM");
});
app.get("/privacy", (req, res) => { if (fs.existsSync(PRIVACY)) return res.sendFile(PRIVACY); res.redirect("/"); });
app.get("/terms", (req, res) => { if (fs.existsSync(TERMS)) return res.sendFile(TERMS); res.redirect("/"); });
app.get("*", (req, res) => {
  if (fs.existsSync(BUNDLE)) return res.sendFile(BUNDLE);
  res.status(200).send("SolarSync API running. Front-end goes at backend/public/index.html");
});

const PORT = process.env.PORT || 3000;
// ensure DB is initialised (and schema migrated) before accepting traffic
require("./db").db().then(() => {
  app.listen(PORT, () => console.log(`SolarSync backend on :${PORT} (${process.env.DATABASE_URL ? "Postgres" : "PGlite local"})`));
}).catch(e => { console.error("DB init failed:", e); process.exit(1); });
