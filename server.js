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

// Tenant's own client list — used by the "Send to customer" / "Fill for customer" pickers.
// Includes system_spec so the front-end can autofill system fields into a form.
app.get("/api/clients", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  ok(res, await rows("select id, name, site_address, install_status, system_spec from clients where tenant_id=$1 order by name", [tenantOf(req)]));
}));

// Documents an installer has sent to THIS logged-in customer (snapshot at publish time).
app.get("/api/client/documents", A.authRequired, A.requireRole("client"), h(async (req, res) => {
  const client = await one("select * from clients where user_id=$1", [req.user.sub]);
  if (!client) return ok(res, []);
  const docs = await rows(
    `select id, title, filename, mime_type, size_bytes, published_at,
            (body_html is not null) as has_html
     from document_publications where client_id=$1 order by published_at desc`,
    [client.id]
  );
  ok(res, docs);
}));

// Customer view of a filled/edited HTML document their installer sent them.
app.get("/api/client/documents/:pubId/view", A.authRequired, A.requireRole("client"), h(async (req, res) => {
  const client = await one("select * from clients where user_id=$1", [req.user.sub]);
  if (!client) return res.status(404).json({ error: "not_found" });
  const pub = await one("select * from document_publications where id=$1", [req.params.pubId]);
  if (!pub || pub.client_id !== client.id) return res.status(404).json({ error: "not_found" });
  if (!pub.body_html) return res.status(409).json({ error: "no_html" });
  await audit(req.user.sub, "client_doc_view", pub.id, pub.tenant_id);
  ok(res, { title: pub.title, body_html: pub.body_html });
}));

// Customer download of a document their installer sent them (presigned, scoped to them).
app.get("/api/client/documents/:pubId/download", A.authRequired, A.requireRole("client"), h(async (req, res) => {
  const client = await one("select * from clients where user_id=$1", [req.user.sub]);
  if (!client) return res.status(404).json({ error: "not_found" });
  const pub = await one("select * from document_publications where id=$1", [req.params.pubId]);
  if (!pub || pub.client_id !== client.id) return res.status(404).json({ error: "not_found" });
  if (!pub.spaces_key) return res.status(409).json({ error: "no_file" });
  if (!storage.isConfigured()) return res.status(503).json({ error: "storage_not_configured" });
  const url = await storage.presignDownload(pub.spaces_key, pub.filename);
  await audit(req.user.sub, "client_doc_download", pub.id, pub.tenant_id);
  ok(res, { url, filename: pub.filename, expires_in: 300 });
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
// TENANT DOCUMENT LIBRARY (paid add-on: addon_key = 'document-library')
// Storage: DigitalOcean Spaces (S3-compatible) — see backend/storage.js.
// ============================================================
const multer = require("multer");
const storage = require("./storage");

const ALLOWED_MIMES = new Set([
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/pdf",
  "image/png", "image/jpeg",
]);
const ALLOWED_EXTS = /\.(doc|docx|pdf|png|jpe?g)$/i;

// 25 MB ceiling, buffered in memory then streamed to Spaces.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIMES.has(file.mimetype) || ALLOWED_EXTS.test(file.originalname)) return cb(null, true);
    cb(new Error("unsupported_file_type"));
  },
});

// HTML form detection — HTML-based forms (the format the SolarSync manuals and the
// portal's own forms use) can be autofilled from customer data and edited in-browser.
// Real binary .doc/.docx/.pdf are not HTML and stay download-only.
const HTML_EXT = /\.(html?|doc)$/i;
function extractFormHtml(file) {
  const isHtmlMime = file.mimetype === "text/html" || file.mimetype === "application/xhtml+xml";
  if (!isHtmlMime && !HTML_EXT.test(file.originalname)) return null;
  let text;
  try { text = file.buffer.toString("utf8"); } catch (e) { return null; }
  if (/<html[\s>]|<!doctype html/i.test(text.slice(0, 2000))) return text.slice(0, 2000000);
  return null;
}

// Paid-gated: unlocked when the tenant has an active 'document-library' add-on row,
// OR a valid tester token is presented (mirrors complianceUnlocked so the feature is
// testable before a real paid activation). Real tenants without either stay locked.
// The connected-demo tenant always has it on, matching how the demo showcases the
// Compliance Suite and other premium features (unlocked without a real purchase).
const DEMO_TENANT = "tenant-helios";
async function documentLibraryUnlocked(tenant_id, token) {
  if (tenant_id === DEMO_TENANT) return true;
  if (tenant_id) {
    const a = await one("select active from tenant_addons where tenant_id=$1 and addon_key='document-library'", [tenant_id]);
    if (a && a.active) return true;
  }
  if (token) {
    const t = await one("select active from tester_tokens where token=$1 and active=true", [String(token).toUpperCase()]);
    if (t) return true;
  }
  return false;
}

// Proper async middleware: must receive AND forward `next` (cannot use the h() wrapper,
// which only passes req,res and would leave next undefined on the pass-through path).
async function requireDocLibrary(req, res, next) {
  try {
    if (!storage.isConfigured()) return res.status(503).json({ error: "storage_not_configured" });
    if (!(await documentLibraryUnlocked(tenantOf(req), req.query.token))) return res.status(402).json({ error: "addon_required", addon: "document-library" });
    next();
  } catch (e) { next(e); }
}

// Entitlement probe — UI uses this to show locked vs unlocked state without trying an upload.
app.get("/api/entitlements/document-library", A.authRequired, h(async (req, res) => {
  const unlocked = await documentLibraryUnlocked(tenantOf(req), req.query.token);
  ok(res, { unlocked, configured: storage.isConfigured() });
}));

// List all current documents for the calling tenant (one row per doc_group).
app.get("/api/tenant/documents", A.authRequired, requireDocLibrary, h(async (req, res) => {
  const r = await rows(
    `select id, doc_group, version, title, category, filename, mime_type, size_bytes,
            uploaded_by, uploaded_at, visibility, notes,
            (content_html is not null) as fillable
     from tenant_documents
     where tenant_id=$1 and is_current=true and is_deleted=false
     order by uploaded_at desc`,
    [tenantOf(req)]
  );
  ok(res, r);
}));

// Version history for one doc_group (current + all prior). Tenant-scoped.
app.get("/api/tenant/documents/:doc_group/versions", A.authRequired, requireDocLibrary, h(async (req, res) => {
  const r = await rows(
    `select id, version, is_current, title, filename, mime_type, size_bytes, uploaded_by, uploaded_at
     from tenant_documents
     where tenant_id=$1 and doc_group=$2 and is_deleted=false
     order by version desc`,
    [tenantOf(req), req.params.doc_group]
  );
  ok(res, r);
}));

// Upload a brand-new document (new doc_group, version 1).
// multipart form: file (binary), title, category, visibility?, notes?
app.post("/api/tenant/documents", A.authRequired, requireDocLibrary, upload.single("file"), h(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "no_file" });
  const { title, category, visibility, notes } = req.body || {};
  if (!title || String(title).trim() === "") return res.status(400).json({ error: "title_required" });
  const id = rid();
  const doc_group = rid();
  const tenant_id = tenantOf(req);
  const key = storage.makeKey(tenant_id, doc_group, 1, req.file.originalname);
  await storage.putObject(key, req.file.buffer, req.file.mimetype);
  const content_html = extractFormHtml(req.file);
  await run(
    `insert into tenant_documents (id, tenant_id, doc_group, version, is_current, title, category,
        filename, mime_type, size_bytes, spaces_key, uploaded_by, visibility, notes, content_html)
     values ($1,$2,$3,1,true,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [id, tenant_id, doc_group, String(title).trim().slice(0, 200), (category || "Other").slice(0, 50),
     req.file.originalname.slice(0, 200), req.file.mimetype, req.file.size, key,
     req.user.sub, (visibility || "tenant").slice(0, 20), (notes || "").slice(0, 1000), content_html]
  );
  await audit(req.user.sub, "doc_upload", id, tenant_id, { title, category, size: req.file.size, fillable: !!content_html });
  ok(res, { id, doc_group, version: 1, fillable: !!content_html });
}));

// Upload a new VERSION of an existing document (same doc_group). Old row's is_current is flipped off.
app.put("/api/tenant/documents/:doc_group", A.authRequired, requireDocLibrary, upload.single("file"), h(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "no_file" });
  const tenant_id = tenantOf(req);
  const { doc_group } = req.params;
  const current = await one(
    `select id, version, title, category, visibility from tenant_documents
     where tenant_id=$1 and doc_group=$2 and is_current=true and is_deleted=false`,
    [tenant_id, doc_group]
  );
  if (!current) return res.status(404).json({ error: "not_found" });
  const newVersion = (current.version || 1) + 1;
  const id = rid();
  const key = storage.makeKey(tenant_id, doc_group, newVersion, req.file.originalname);
  await storage.putObject(key, req.file.buffer, req.file.mimetype);
  const content_html = extractFormHtml(req.file);
  await run("update tenant_documents set is_current=false where tenant_id=$1 and doc_group=$2 and is_current=true", [tenant_id, doc_group]);
  await run(
    `insert into tenant_documents (id, tenant_id, doc_group, version, is_current, title, category,
        filename, mime_type, size_bytes, spaces_key, uploaded_by, visibility, notes, content_html)
     values ($1,$2,$3,$4,true,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, tenant_id, doc_group, newVersion,
     (req.body && req.body.title) || current.title, (req.body && req.body.category) || current.category,
     req.file.originalname.slice(0, 200), req.file.mimetype, req.file.size, key,
     req.user.sub, (req.body && req.body.visibility) || current.visibility, (req.body && req.body.notes || "").slice(0, 1000), content_html]
  );
  await audit(req.user.sub, "doc_new_version", id, tenant_id, { doc_group, version: newVersion });
  ok(res, { id, doc_group, version: newVersion, fillable: !!content_html });
}));

// Fetch a form's editable HTML content (for the autofill + in-browser editor flow).
app.get("/api/tenant/documents/:id/content", A.authRequired, requireDocLibrary, h(async (req, res) => {
  const row = await one("select * from tenant_documents where id=$1", [req.params.id]);
  if (!row || row.is_deleted || row.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  if (!row.content_html) return res.status(409).json({ error: "not_fillable" });
  ok(res, { id: row.id, title: row.title, filename: row.filename, content_html: row.content_html });
}));

// Presigned download URL (5 min). Works for the current row OR any prior version (by id).
app.get("/api/tenant/documents/:id/download", A.authRequired, requireDocLibrary, h(async (req, res) => {
  const d = await one("select * from tenant_documents where id=$1", [req.params.id]);
  if (!d || d.is_deleted || d.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const url = await storage.presignDownload(d.spaces_key, d.filename);
  await audit(req.user.sub, "doc_download", d.id, d.tenant_id);
  ok(res, { url, filename: d.filename, expires_in: 300 });
}));

// Soft-delete a single version. If it was the current row, promote the previous version
// in the same doc_group to current. If no prior version exists, the whole group is gone.
app.delete("/api/tenant/documents/:id", A.authRequired, requireDocLibrary, h(async (req, res) => {
  const d = await one("select * from tenant_documents where id=$1", [req.params.id]);
  if (!d || d.is_deleted || d.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  await run("update tenant_documents set is_deleted=true where id=$1", [d.id]);
  if (d.is_current) {
    const prev = await one(
      `select id from tenant_documents where tenant_id=$1 and doc_group=$2 and is_deleted=false
       order by version desc limit 1`,
      [d.tenant_id, d.doc_group]
    );
    if (prev) await run("update tenant_documents set is_current=true where id=$1", [prev.id]);
  }
  await audit(req.user.sub, "doc_delete", d.id, d.tenant_id, { version: d.version });
  ok(res, { ok: true });
}));

// Send a document to a customer — snapshots the chosen version into document_publications
// so the customer keeps what they were sent even if the tenant later edits/deletes it
// (mirrors how reports publish). Re-publishing the same doc_group to the same client replaces.
app.post("/api/tenant/documents/:id/publish", A.authRequired, requireDocLibrary, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const d = await one("select * from tenant_documents where id=$1", [req.params.id]);
  if (!d || d.is_deleted || d.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const { client_id } = req.body || {};
  if (!client_id) return res.status(400).json({ error: "client_required" });
  const client = await one("select id from clients where id=$1 and tenant_id=$2", [client_id, tenantOf(req)]);
  if (!client) return res.status(404).json({ error: "client_not_found" });
  // Optional filled/edited HTML (from the autofill + editor flow). When present the customer
  // views it as a rendered document; otherwise they download the original Spaces file.
  const body_html = (req.body && typeof req.body.body_html === "string" && req.body.body_html.trim())
    ? req.body.body_html.slice(0, 2000000) : null;
  if (d.doc_group) await run("delete from document_publications where client_id=$1 and doc_group=$2", [client_id, d.doc_group]);
  await run(
    `insert into document_publications (id, document_id, doc_group, tenant_id, client_id, title, filename, mime_type, size_bytes, spaces_key, body_html, published_by)
     values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [rid(), d.id, d.doc_group, d.tenant_id, client_id, d.title, d.filename, d.mime_type, d.size_bytes, d.spaces_key, body_html, req.user.sub]
  );
  await audit(req.user.sub, "doc_publish", d.id, d.tenant_id, { client_id, version: d.version, html: !!body_html });
  ok(res, { ok: true });
}));

// multer error → JSON
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) return res.status(400).json({ error: err.code === "LIMIT_FILE_SIZE" ? "file_too_large" : err.code });
  if (err && err.message === "unsupported_file_type") return res.status(400).json({ error: "unsupported_file_type" });
  next(err);
});

// SolarSync template downloads (public, no auth — these are tenant-editable starter files)
app.use("/templates", express.static(path.join(__dirname, "public", "templates"), { maxAge: "1h" }));

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

// One-time, idempotent data backfill run at startup (safe to run every boot):
// gives the connected-demo customer a system spec so form autofill can populate
// system fields (kW / panels / inverter). Only fills when it's currently empty,
// so it never overwrites real data a tenant has entered.
async function startupBackfill() {
  try {
    const spec = JSON.stringify({
      systemKw: 6.6, panels: 16, panelModel: "Jinko Tiger Neo 440W",
      inverter: "Fronius Primo GEN24 5.0", battery: null,
      phone: "0412 345 678", email: "adam.smith@email.com",
    });
    await run(
      "update clients set system_spec=$1::jsonb where id='c-adam' and (system_spec is null or system_spec='{}'::jsonb)",
      [spec]
    );
  } catch (e) { console.error("startupBackfill failed:", e.message); }
}

// ensure DB is initialised (and schema migrated) before accepting traffic
require("./db").db().then(async () => {
  await startupBackfill();
  app.listen(PORT, () => console.log(`SolarSync backend on :${PORT} (${process.env.DATABASE_URL ? "Postgres" : "PGlite local"})`));
}).catch(e => { console.error("DB init failed:", e); process.exit(1); });
