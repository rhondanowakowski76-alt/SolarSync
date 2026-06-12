// SolarSync backend — single self-contained server (API + front-end)
const express = require("express");
const path = require("path");
const fs = require("fs");
const { db, audit, rid } = require("./db");
const A = require("./auth");
const QRCode = require("qrcode");

const app = express();
app.use(express.json({ limit: "12mb" }));   // reports carry embedded photos

// ---- tiny helpers ----
const ok = (res, body) => res.json(body);
const tenantOf = (req) => req.user.tenant_id;
const isReseller = (req) => req.user.app_role === "reseller";

// ============================================================
// AUTH (PIN + TOTP only — no email)
// ============================================================
app.post("/api/auth/accounts", (req, res) => {
  const { tenant_id } = req.body || {};
  const rows = tenant_id
    ? db.prepare("select id, display_name, app_role from users where status='active' and tenant_id=?").all(tenant_id)
    : db.prepare("select id, display_name, app_role from users where status='active'").all();
  ok(res, rows);
});

app.post("/api/auth/pin", (req, res) => {
  const { user_id, pin } = req.body || {};
  const u = db.prepare("select * from users where id=?").get(user_id);
  if (!u) return res.status(404).json({ error: "not_found" });
  if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
  if (!u.pin_hash) return res.status(409).json({ error: "no_pin", must_set: true });
  if (!A.bcrypt.compareSync(String(pin), u.pin_hash)) { A.bumpFail(u); return res.status(401).json({ error: "bad_pin" }); }
  A.clearFail(u.id);
  if (!u.totp_enrolled) return res.status(409).json({ error: "needs_enrol", must_enrol: true });
  ok(res, { challenge: true });
});

app.post("/api/auth/totp", (req, res) => {
  const { user_id, code } = req.body || {};
  const u = db.prepare("select * from users where id=?").get(user_id);
  if (!u || !u.totp_secret) return res.status(404).json({ error: "not_found" });
  if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
  if (!A.verifyTotp(u.totp_secret, code)) { A.bumpFail(u); return res.status(401).json({ error: "bad_code" }); }
  A.clearFail(u.id);
  audit(u.id, "login", u.id, u.tenant_id);
  ok(res, {
    access_token: A.mintAccess(u), refresh_token: A.mintRefresh(u),
    user: { id: u.id, display_name: u.display_name, app_role: u.app_role, tenant_id: u.tenant_id },
  });
});

app.post("/api/auth/enrol", async (req, res) => {
  const { user_id } = req.body || {};
  const u = db.prepare("select * from users where id=?").get(user_id);
  if (!u) return res.status(404).json({ error: "not_found" });
  const secret = A.randomBase32();
  db.prepare("update users set totp_secret=?, totp_enrolled=1 where id=?").run(secret, u.id);
  const uri = A.otpauthUri(u.display_name, secret);
  let qr = null; try { qr = await QRCode.toDataURL(uri, { margin: 1, width: 220 }); } catch (e) {}
  ok(res, { otpauth_uri: uri, secret, qr });
});

app.post("/api/auth/set-pin", (req, res) => {
  const { user_id, pin, code } = req.body || {};
  const u = db.prepare("select * from users where id=?").get(user_id);
  if (!u || !u.totp_secret) return res.status(404).json({ error: "not_found" });
  if (!A.verifyTotp(u.totp_secret, code)) return res.status(401).json({ error: "bad_code" });
  if (!/^\d{6}$/.test(String(pin))) return res.status(400).json({ error: "pin_format" });
  db.prepare("update users set pin_hash=?, must_reset=0 where id=?").run(A.bcrypt.hashSync(String(pin), 10), u.id);
  ok(res, { ok: true });
});

app.post("/api/auth/refresh", (req, res) => {
  try {
    const p = A.verify((req.body || {}).refresh_token);
    if (p.typ !== "refresh") return res.status(401).json({ error: "bad_token" });
    const u = db.prepare("select * from users where id=?").get(p.sub);
    if (!u) return res.status(404).json({ error: "not_found" });
    ok(res, { access_token: A.mintAccess(u) });
  } catch { res.status(401).json({ error: "bad_token" }); }
});

// Admin-initiated reset (no email recovery). Reseller resets tenant admins; tenant admin resets their people.
app.post("/api/admin/reset-user", A.authRequired, A.requireRole("reseller", "tenant_admin"), (req, res) => {
  const { user_id } = req.body || {};
  const target = db.prepare("select * from users where id=?").get(user_id);
  if (!target) return res.status(404).json({ error: "not_found" });
  if (!isReseller(req) && target.tenant_id !== tenantOf(req)) return res.status(403).json({ error: "forbidden" });
  db.prepare("update users set pin_hash=null, totp_secret=null, totp_enrolled=0, must_reset=1, failed_attempts=0, locked_until=null where id=?").run(user_id);
  audit(req.user.sub, "admin_reset", user_id, target.tenant_id);
  ok(res, { ok: true });
});

// ============================================================
// ENTITLEMENTS (server-enforced branding/add-on gate)
// ============================================================
function complianceUnlocked(tenant_id, token) {
  const addon = db.prepare("select active from tenant_addons where tenant_id=? and addon_key='compliance-suite'").get(tenant_id);
  if (addon && addon.active) return { unlocked: true, source: "addon" };
  if (token) {
    const t = db.prepare("select active from tester_tokens where token=? and active=1").get(String(token).toUpperCase());
    if (t) return { unlocked: true, source: "token" };
  }
  return { unlocked: false, source: null };
}
app.get("/api/entitlements/compliance", A.authRequired, (req, res) =>
  ok(res, complianceUnlocked(tenantOf(req), req.query.token)));

app.post("/api/tenants/:id/addons/:key", A.authRequired, A.requireRole("reseller"), (req, res) => {
  const { id, key } = req.params; const active = req.body.active ? 1 : 0;
  db.prepare(`insert into tenant_addons (tenant_id, addon_key, active, activated_at)
    values (?,?,?,datetime('now'))
    on conflict(tenant_id, addon_key) do update set active=excluded.active, activated_at=datetime('now')`)
    .run(id, key, active);
  audit(req.user.sub, "addon_toggle", key, id, { active: !!active });
  ok(res, { ok: true });
});

// ============================================================
// LETTERHEAD
// ============================================================
app.get("/api/letterhead", A.authRequired, (req, res) =>
  ok(res, db.prepare("select * from letterheads where tenant_id=?").get(tenantOf(req)) || {}));
app.put("/api/letterhead", A.authRequired, A.requireRole("tenant_admin", "staff"), (req, res) => {
  const t = tenantOf(req); const d = req.body || {};
  db.prepare(`insert into letterheads (tenant_id, legal_name, abn, address, phone, email, licence, logo_url, updated_at)
    values (?,?,?,?,?,?,?,?,datetime('now'))
    on conflict(tenant_id) do update set legal_name=excluded.legal_name, abn=excluded.abn, address=excluded.address,
      phone=excluded.phone, email=excluded.email, licence=excluded.licence, logo_url=excluded.logo_url, updated_at=datetime('now')`)
    .run(t, d.legal_name, d.abn, d.address, d.phone, d.email, d.licence, d.logo_url);
  ok(res, { ok: true });
});

// ============================================================
// REPORT TEMPLATES + REPORTS
// ============================================================
app.get("/api/report-templates", A.authRequired, (req, res) =>
  ok(res, db.prepare("select key, category, title, body_html from report_templates").all()));

app.get("/api/reports", A.authRequired, (req, res) => {
  const rows = isReseller(req)
    ? db.prepare("select * from reports order by updated_at desc").all()
    : db.prepare("select * from reports where tenant_id=? order by updated_at desc").all(tenantOf(req));
  ok(res, rows);
});

app.post("/api/reports", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), (req, res) => {
  const id = rid(); const d = req.body || {};
  db.prepare(`insert into reports (id, tenant_id, template_key, job_ref, title, body_html, status, created_by)
    values (?,?,?,?,?,?,?,?)`).run(id, tenantOf(req), d.template_key, d.job_ref, d.title, d.body_html, "draft", req.user.sub);
  ok(res, { id });
});

app.put("/api/reports/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), (req, res) => {
  const r = db.prepare("select * from reports where id=?").get(req.params.id);
  if (!r || r.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  db.prepare("update reports set title=?, body_html=?, updated_at=datetime('now') where id=?")
    .run(d.title ?? r.title, d.body_html ?? r.body_html, r.id);
  ok(res, { ok: true });
});

// Publish a completed report to a client (snapshot). Visibility gated by invoice (below).
app.post("/api/reports/:id/publish", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), (req, res) => {
  const r = db.prepare("select * from reports where id=?").get(req.params.id);
  if (!r || r.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const { client_id, title, body_html } = req.body || {};
  db.prepare("delete from report_publications where report_id=? and client_id=?").run(r.id, client_id);
  db.prepare(`insert into report_publications (id, report_id, tenant_id, client_id, title, body_html)
    values (?,?,?,?,?,?)`).run(rid(), r.id, r.tenant_id, client_id, title || r.title, body_html || r.body_html);
  db.prepare("update reports set status='published' where id=?").run(r.id);
  audit(req.user.sub, "publish_report", r.id, r.tenant_id, { client_id });
  ok(res, { ok: true });
});

// CLIENT view — reports only visible when the client's invoice is PAID (server-enforced gate)
app.get("/api/client/reports", A.authRequired, A.requireRole("client"), (req, res) => {
  const client = db.prepare("select * from clients where user_id=?").get(req.user.sub);
  if (!client) return ok(res, { paid: false, reports: [] });
  const paid = !!db.prepare("select 1 from invoices where client_id=? and status='paid' limit 1").get(client.id);
  if (!paid) {
    const count = db.prepare("select count(*) c from report_publications where client_id=?").get(client.id).c;
    return ok(res, { paid: false, count, reports: [] });
  }
  const reports = db.prepare("select id, title, body_html, published_at from report_publications where client_id=? order by published_at desc").all(client.id);
  ok(res, { paid: true, reports });
});

// ============================================================
// INVOICES + PAYMENTS (Stripe)
// ============================================================
app.get("/api/invoices", A.authRequired, (req, res) => {
  if (req.user.app_role === "client") {
    const c = db.prepare("select * from clients where user_id=?").get(req.user.sub);
    return ok(res, c ? db.prepare("select * from invoices where client_id=? order by created_at desc").all(c.id) : []);
  }
  ok(res, db.prepare("select * from invoices where tenant_id=? order by created_at desc").all(tenantOf(req)));
});

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? require("stripe")(stripeKey) : null;

// Create a PaymentIntent for an invoice (test mode until your Stripe account is live)
app.post("/api/invoices/:id/pay-intent", A.authRequired, async (req, res) => {
  const inv = db.prepare("select * from invoices where id=?").get(req.params.id);
  if (!inv) return res.status(404).json({ error: "not_found" });
  if (!stripe) return res.status(503).json({ error: "stripe_not_configured", hint: "set STRIPE_SECRET_KEY" });
  try {
    const pi = await stripe.paymentIntents.create({
      amount: Math.round(inv.amount * 100), currency: "aud",
      metadata: { invoice_id: inv.id, tenant_id: inv.tenant_id, client_id: inv.client_id },
      automatic_payment_methods: { enabled: true },
    });
    db.prepare("update invoices set stripe_payment_intent=? where id=?").run(pi.id, inv.id);
    ok(res, { client_secret: pi.client_secret });
  } catch (e) { res.status(500).json({ error: String(e.message || e) }); }
});

// Stripe webhook — payment success marks invoice paid -> this is what unlocks client reports
app.post("/api/webhooks/stripe", express.raw({ type: "application/json" }), (req, res) => {
  let event = null;
  const sig = req.headers["stripe-signature"];
  const whSecret = process.env.STRIPE_WEBHOOK_SECRET;
  try {
    event = (stripe && whSecret) ? stripe.webhooks.constructEvent(req.body, sig, whSecret) : JSON.parse(req.body);
  } catch (e) { return res.status(400).send(`bad sig: ${e.message}`); }
  if (event.type === "payment_intent.succeeded") {
    const pi = event.data.object;
    const invId = pi.metadata && pi.metadata.invoice_id;
    if (invId) {
      db.prepare("update invoices set status='paid', paid_at=datetime('now') where id=?").run(invId);
      audit(null, "invoice_paid", invId, pi.metadata.tenant_id);
    }
  }
  res.json({ received: true });
});

// DEV/manual: mark an invoice paid (tenant staff) — also used to demo the unlock without live Stripe
app.post("/api/invoices/:id/mark-paid", A.authRequired, A.requireRole("tenant_admin", "staff"), (req, res) => {
  const inv = db.prepare("select * from invoices where id=?").get(req.params.id);
  if (!inv || inv.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  db.prepare("update invoices set status='paid', paid_at=datetime('now') where id=?").run(inv.id);
  audit(req.user.sub, "invoice_paid_manual", inv.id, inv.tenant_id);
  ok(res, { ok: true });
});

// ============================================================
// Health + serve the front-end bundle from the same service
// ============================================================
app.get("/api/health", (req, res) => ok(res, { ok: true, ts: Date.now() }));

const BUNDLE = path.join(__dirname, "public", "index.html");
app.get("*", (req, res) => {
  if (fs.existsSync(BUNDLE)) return res.sendFile(BUNDLE);
  res.status(200).send("SolarSync API running. Put the front-end at backend/public/index.html");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SolarSync backend on :${PORT}`));
