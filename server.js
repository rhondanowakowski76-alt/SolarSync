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

app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event = null;
  const sig = req.headers["stripe-signature"];
  const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
  try { event = (stripe && whSecret) ? stripe.webhooks.constructEvent(req.body, sig, whSecret) : JSON.parse(req.body); }
  catch (e) { return res.status(400).send(`bad sig: ${e.message}`); }
  if (event.type === "payment_intent.succeeded") {
    const pi = event.data.object;
    const invId = pi.metadata && pi.metadata.invoice_id;
    if (invId) { run("update invoices set status='paid', paid_at=now() where id=$1", [invId]).then(() => audit(null, "invoice_paid", invId, pi.metadata.tenant_id)).catch(()=>{}); }
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
// Health + serve the front-end
// ============================================================
app.get("/api/health", h(async (req, res) => ok(res, { ok: true, ts: Date.now() })));

const BUNDLE = path.join(__dirname, "public", "index.html");
app.get("*", (req, res) => {
  if (fs.existsSync(BUNDLE)) return res.sendFile(BUNDLE);
  res.status(200).send("SolarSync API running. Front-end goes at backend/public/index.html");
});

const PORT = process.env.PORT || 3000;
// ensure DB is initialised (and schema migrated) before accepting traffic
require("./db").db().then(() => {
  app.listen(PORT, () => console.log(`SolarSync backend on :${PORT} (${process.env.DATABASE_URL ? "Postgres" : "PGlite local"})`));
}).catch(e => { console.error("DB init failed:", e); process.exit(1); });
