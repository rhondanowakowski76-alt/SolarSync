// SolarSync backend — single self-contained server (API + front-end). PostgreSQL.
const express = require("express");
const path = require("path");
const fs = require("fs");
const https = require("https");
const { rows, one, run, rid, audit } = require("./db");
const A = require("./auth");
const QRCode = require("qrcode");
const erp = require("./erp");

const app = express();
app.use(express.json({ limit: "12mb" }));

const ok = (res, body) => res.json(body);
// The reseller keeps its OWN ERP book under the fixed id "reseller-platform"
// (matches erp.js) so its products, POs, stock and quotes stay separate from
// every tenant. Tenants use their own tenant_id.
const tenantOf = (req) => req.user.app_role === "reseller" ? "reseller-platform" : req.user.tenant_id;
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

// Recovery / backup codes: single-use codes a person can use to sign in when they
// can't reach their authenticator app. We store only bcrypt hashes; the plaintext
// is shown to the user exactly once. Generating a new set replaces any old ones.
const BC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous 0/O/1/I
function normBackup(s) { return String(s || "").toUpperCase().replace(/[^A-Z0-9]/g, ""); }
async function issueBackupCodes(user_id, n = 10) {
  await run("delete from backup_codes where user_id=$1", [user_id]);
  const crypto = require("crypto");
  const shown = [];
  for (let i = 0; i < n; i++) {
    const bytes = crypto.randomBytes(8);
    let raw = ""; for (const b of bytes) raw += BC_ALPHABET[b % 32];   // 8 chars, no dash
    shown.push(raw.slice(0, 4) + "-" + raw.slice(4, 8));               // display form: XXXX-XXXX
    await run("insert into backup_codes (id, user_id, code_hash) values ($1,$2,$3)",
      [rid(), user_id, A.bcrypt.hashSync(raw, 10)]);                   // hash the normalised (dash-free) form
  }
  return shown;
}

// ============================================================
// AUTH (PIN + TOTP only — no email)
// ============================================================
// Live-safe sign-in: nobody can list the user base. The person types their
// sign-in name and we only return accounts whose full name matches exactly.
app.post("/api/auth/lookup", h(async (req, res) => {
  const norm = (s) => String(s || "").trim().toLowerCase().replace(/\s+/g, " ");
  const name = norm((req.body || {}).name);
  if (name.length < 3) return ok(res, []);
  const r = await rows("select id, display_name, app_role from users where status='active'");
  ok(res, r.filter(u => norm(u.display_name) === name)
           .map(u => ({ id: u.id, display_name: u.display_name, app_role: u.app_role })));
}));

// A suspended tenant's people can't sign in (reseller flips this per tenant).
async function tenantSuspended(u) {
  if (!u || !u.tenant_id) return false;
  const t = await one("select status from tenants where id=$1", [u.tenant_id]);
  return !!(t && t.status === "suspended");
}

app.post("/api/auth/pin", h(async (req, res) => {
  const { user_id, pin } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u) return res.status(404).json({ error: "not_found" });
  if (await tenantSuspended(u)) return res.status(403).json({ error: "suspended" });
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
  if (await tenantSuspended(u)) return res.status(403).json({ error: "suspended" });
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
  // Setting a PIN proves control of the authenticator — a good moment to hand the
  // person a fresh set of single-use recovery codes (shown once). Best-effort: a
  // failure here must never block the PIN update itself.
  let backup_codes = [];
  try { backup_codes = await issueBackupCodes(u.id); } catch (e) { console.error("backup code issue failed", e); }
  ok(res, { ok: true, backup_codes });
}));

// Sign in with a single-use recovery code instead of the authenticator app.
// Same result as a successful authenticator step: issues the session tokens.
app.post("/api/auth/backup", h(async (req, res) => {
  const { user_id, code } = req.body || {};
  const u = await one("select * from users where id=$1", [user_id]);
  if (!u) return res.status(404).json({ error: "not_found" });
  if (await tenantSuspended(u)) return res.status(403).json({ error: "suspended" });
  if (A.lockedOut(u)) return res.status(429).json({ error: "locked", until: u.locked_until });
  const norm = normBackup(code);
  if (norm.length < 8) { await bumpFail(u); return res.status(401).json({ error: "bad_code" }); }
  const candidates = await rows("select id, code_hash from backup_codes where user_id=$1 and used_at is null", [user_id]);
  let matched = null;
  for (const c of candidates) { if (A.bcrypt.compareSync(norm, c.code_hash)) { matched = c; break; } }
  if (!matched) { await bumpFail(u); return res.status(401).json({ error: "bad_code" }); }
  await run("update backup_codes set used_at=now() where id=$1", [matched.id]);
  await clearFail(u.id);
  await audit(u.id, "login_backup_code", u.id, u.tenant_id);
  ok(res, {
    access_token: A.mintAccess(u), refresh_token: A.mintRefresh(u),
    user: { id: u.id, display_name: u.display_name, app_role: u.app_role, tenant_id: u.tenant_id },
    backup_codes_remaining: candidates.length - 1,
  });
}));

// Logged-in user regenerates their recovery codes (invalidates the old set).
app.post("/api/auth/backup/regenerate", A.authRequired, h(async (req, res) => {
  const codes = await issueBackupCodes(req.user.sub);
  await audit(req.user.sub, "backup_codes_regenerate", req.user.sub, req.user.tenant_id || "");
  ok(res, { backup_codes: codes });
}));

// How many unused recovery codes remain (for a "you have N left" nudge).
app.get("/api/auth/backup/count", A.authRequired, h(async (req, res) => {
  const r = await one("select count(*)::int as c from backup_codes where user_id=$1 and used_at is null", [req.user.sub]);
  ok(res, { remaining: (r && r.c) || 0 });
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

// Reseller "Support view": the owner can step into the tenant/contractor/
// client portal shells to test that the app's mechanics work — WITHOUT ever
// seeing a real tenant's private records. Every data read for a reseller token
// is scoped to the reseller's own 'reseller-platform' book by tenantOf(), so no
// customer PII, money, documents or messages are ever served here. Entering
// support view is a deliberate, audited action.
app.post("/api/support/enter", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const portal = (req.body && req.body.portal) || null;
  await audit(req.user.sub, "support_view_enter", portal, "reseller-platform", { ua: req.headers["user-agent"] || null });
  ok(res, { ok: true });
}));

// ============================================================
// AI ASSISTANT — customer-service copilot (staff) + client helper
// Uses the Anthropic API when ANTHROPIC_API_KEY is set in the
// environment; otherwise tells the UI it isn't configured yet.
// ============================================================
app.post("/api/ai/assist", A.authRequired, h(async (req, res) => {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) return ok(res, { configured: false });
  const { messages, persona, brand_name } = req.body || {};
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: "messages_required" });
  const clean = messages.slice(-20).map(m => ({
    role: m.role === "assistant" ? "assistant" : "user",
    content: String(m.content || "").slice(0, 4000),
  }));
  const brandName = String(brand_name || "our company").slice(0, 80);
  const system = persona === "client"
    ? `You are the friendly customer assistant for ${brandName}, an Australian solar installation company. Help the customer understand their solar journey: quotes, installation steps, bookings, invoices, warranties, maintenance and how solar works. Be concise and plain-spoken. You cannot see their account data — if asked about it, point them to the right portal section (Bookings, Documents, Invoices) or suggest contacting ${brandName} staff. Never mention SolarSync, other companies' branding, or other customers.`
    : `You are the customer-service copilot for staff at ${brandName}, an Australian solar company. Help staff draft replies to customers, explain solar concepts (STCs, feed-in tariffs, AS/NZS compliance), summarise job notes, and suggest next steps in a client's journey. Be concise and practical. Never invent customer data — work only from what the staff member tells you.`;
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": key, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: process.env.ANTHROPIC_MODEL || "claude-sonnet-5", max_tokens: 700, system, messages: clean }),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok) { console.error("ai_assist_upstream", j); return res.status(502).json({ error: "ai_upstream" }); }
  const text = ((j && j.content) || []).filter(c => c.type === "text").map(c => c.text).join("\n");
  ok(res, { configured: true, reply: text });
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

// ============================================================
// DEALS / CRM PIPELINE (tenant-scoped, full CRUD)
// ============================================================
const DEAL_COLS = "id, tenant_id, client_id, client, type, job_type, stage, system, value, installer, suburb, due, notes, updated_at, created_at";

app.get("/api/deals", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const r = isReseller(req)
    ? await rows(`select ${DEAL_COLS} from deals order by updated_at desc`)
    : await rows(`select ${DEAL_COLS} from deals where tenant_id=$1 order by updated_at desc`, [tenantOf(req)]);
  ok(res, r);
}));

app.post("/api/deals", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.client) return res.status(400).json({ error: "client_required" });
  const id = d.id && /^[\w-]+$/.test(d.id) ? d.id : "SS-" + rid().slice(0, 8);
  await run(`insert into deals (id, tenant_id, client_id, client, type, job_type, stage, system, value, installer, suburb, due, notes, created_by)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, tenantOf(req), d.client_id || null, d.client, d.type || "install", d.job_type || null,
     d.stage || "enquiry", d.system || null, Number(d.value) || 0, d.installer || null, d.suburb || null, d.due || null, d.notes || null, req.user.sub]);
  await audit(req.user.sub, "create_deal", id, tenantOf(req));
  ok(res, await one(`select ${DEAL_COLS} from deals where id=$1`, [id]));
}));

app.put("/api/deals/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const cur = await one("select * from deals where id=$1", [req.params.id]);
  if (!cur || (!isReseller(req) && cur.tenant_id !== tenantOf(req))) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  await run(`update deals set client=$1, type=$2, job_type=$3, stage=$4, system=$5, value=$6, installer=$7, suburb=$8, due=$9, notes=$10, client_id=$11, updated_at=now() where id=$12`,
    [d.client ?? cur.client, d.type ?? cur.type, d.job_type ?? cur.job_type, d.stage ?? cur.stage, d.system ?? cur.system,
     d.value != null ? Number(d.value) : cur.value, d.installer ?? cur.installer, d.suburb ?? cur.suburb, d.due ?? cur.due,
     d.notes ?? cur.notes, d.client_id ?? cur.client_id, cur.id]);
  await audit(req.user.sub, "update_deal", cur.id, cur.tenant_id);
  ok(res, await one(`select ${DEAL_COLS} from deals where id=$1`, [cur.id]));
}));

app.delete("/api/deals/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const cur = await one("select * from deals where id=$1", [req.params.id]);
  if (!cur || (!isReseller(req) && cur.tenant_id !== tenantOf(req))) return res.status(404).json({ error: "not_found" });
  await run("delete from deals where id=$1", [cur.id]);
  await audit(req.user.sub, "delete_deal", cur.id, cur.tenant_id);
  ok(res, { ok: true });
}));

// ============================================================
// PRODUCTS / CATALOG + INVENTORY (tenant-scoped)
// ============================================================
const PROD_COLS = "id, tenant_id, cat, name, spec, unit, price, cost, watts, stock, reorder_point, direct_sale, recreational, note, active, updated_at, created_at";

app.get("/api/products", A.authRequired, h(async (req, res) => {
  // Reseller normally sees the whole platform catalogue (for "viewing as" a tenant),
  // but its OWN ERP book (Accounting → Purchasing/Stock) passes ?mine=1 to get just
  // the reseller's own products — office equipment, consumables, resale items, etc.
  const ownBook = !isReseller(req) || req.query.mine === "1";
  const r = ownBook
    ? await rows(`select ${PROD_COLS} from products where tenant_id=$1 and active=true order by cat, name`, [tenantOf(req)])
    : await rows(`select ${PROD_COLS} from products where active=true order by cat, name`);
  ok(res, r);
}));

app.post("/api/products", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.name) return res.status(400).json({ error: "name_required" });
  const id = d.id && /^[\w-]+$/.test(d.id) ? d.id : "prd-" + rid().slice(0, 8);
  await run(`insert into products (id, tenant_id, cat, name, spec, unit, price, cost, watts, stock, reorder_point, direct_sale, recreational, note)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, tenantOf(req), d.cat || null, d.name, d.spec || null, d.unit || "unit", Number(d.price) || 0, Number(d.cost) || 0, Number(d.watts) || 0,
     d.stock == null || d.stock === "" ? null : Number(d.stock), Number(d.reorder_point) || 5,
     d.direct_sale !== false, !!d.recreational, d.note || null]);
  await audit(req.user.sub, "create_product", id, tenantOf(req));
  ok(res, await one(`select ${PROD_COLS} from products where id=$1`, [id]));
}));

app.put("/api/products/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const cur = await one("select * from products where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  await run(`update products set cat=$1, name=$2, spec=$3, unit=$4, price=$5, watts=$6, stock=$7, reorder_point=$8, direct_sale=$9, recreational=$10, note=$11, cost=$13, updated_at=now() where id=$12`,
    [d.cat ?? cur.cat, d.name ?? cur.name, d.spec ?? cur.spec, d.unit ?? cur.unit,
     d.price != null ? Number(d.price) : cur.price, d.watts != null ? Number(d.watts) : cur.watts,
     d.stock === "" ? null : (d.stock != null ? Number(d.stock) : cur.stock), d.reorder_point != null ? Number(d.reorder_point) : cur.reorder_point,
     d.direct_sale != null ? d.direct_sale : cur.direct_sale, d.recreational != null ? d.recreational : cur.recreational, d.note ?? cur.note, cur.id,
     d.cost != null ? Number(d.cost) : cur.cost]);
  await audit(req.user.sub, "update_product", cur.id, cur.tenant_id);
  ok(res, await one(`select ${PROD_COLS} from products where id=$1`, [cur.id]));
}));

app.delete("/api/products/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const cur = await one("select * from products where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  await run("update products set active=false, updated_at=now() where id=$1", [cur.id]);  // soft delete keeps history intact
  await audit(req.user.sub, "delete_product", cur.id, cur.tenant_id);
  ok(res, { ok: true });
}));

// Adjust stock (over-the-counter sale, restock, correction) and record the movement.
app.post("/api/products/:id/stock", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const cur = await one("select * from products where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  const delta = Number(d.delta) || 0;
  if (!delta) return res.status(400).json({ error: "delta_required" });
  const base = cur.stock == null ? 0 : cur.stock;
  const next = Math.max(0, base + delta);
  await run("update products set stock=$1, updated_at=now() where id=$2", [next, cur.id]);
  const mid = "mov-" + rid().slice(0, 8);
  await run(`insert into stock_movements (id, tenant_id, product_id, delta, reason, buyer, total, job_id, unit_cost, created_by)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [mid, cur.tenant_id, cur.id, delta, d.reason || (delta < 0 ? "sale" : "restock"), d.buyer || null,
     d.total != null ? Number(d.total) : Math.abs(delta) * Number(cur.price || 0),
     d.job_id || null, cur.cost != null ? Number(cur.cost) : null, req.user.sub]);
  await audit(req.user.sub, "stock_move", cur.id, cur.tenant_id, { delta });
  // Ledger: an over-the-counter sale books revenue + GST + COGS automatically.
  if (delta < 0 && (d.reason || "sale") === "sale") {
    try {
      const mov = await one("select * from stock_movements where id=$1", [mid]);
      await erp.postCounterSale(mov, cur, req.user.sub);
    } catch (e) { console.error("ledger post (counter sale) failed:", e.message); }
  }
  ok(res, { stock: next, movement_id: mid });
}));

app.get("/api/stock-movements", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const r = await rows(`select m.id, m.product_id, p.name as product, m.delta, m.reason, m.buyer, m.total, m.created_at
    from stock_movements m left join products p on p.id=m.product_id
    where m.tenant_id=$1 order by m.created_at desc limit 100`, [tenantOf(req)]);
  ok(res, r);
}));

// ============================================================
// BOOKINGS / SCHEDULE (service requests + scheduled jobs)
//   - clients create "requested" bookings from their portal
//   - tenants/contractors see them on the calendar and confirm/schedule
// ============================================================
const BOOK_COLS = "id, tenant_id, client_id, client, type, title, date, time, end_time, suburb, job_id, status, notes, value, installer, source, updated_at, created_at";

// Resolve the clients row for a logged-in client user (used to attribute + scope bookings).
async function clientRowOf(req) {
  return await one("select * from clients where user_id=$1", [req.user.sub]);
}

// List bookings. Tenants/contractors see their tenant's; a client sees only their own.
app.get("/api/bookings", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  if (req.user.app_role === "client") {
    const c = await clientRowOf(req);
    if (!c) return ok(res, []);
    return ok(res, await rows(`select ${BOOK_COLS} from bookings where client_id=$1 order by date, created_at`, [c.id]));
  }
  const r = isReseller(req)
    ? await rows(`select ${BOOK_COLS} from bookings order by date, created_at`)
    : await rows(`select ${BOOK_COLS} from bookings where tenant_id=$1 order by date, created_at`, [tenantOf(req)]);
  ok(res, r);
}));

// Create a booking. A client raises a "requested" service; a tenant can create a confirmed event directly.
app.post("/api/bookings", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  const d = req.body || {};
  const id = "bk-" + rid().slice(0, 8);
  let tenant_id, client_id = d.client_id || null, client = d.client || null, source = d.source || "tenant", status = d.status || "confirmed";
  if (req.user.app_role === "client") {
    const c = await clientRowOf(req);
    if (!c) return res.status(400).json({ error: "no_client_record" });
    tenant_id = c.tenant_id; client_id = c.id; client = c.name; source = "client"; status = "pending";
  } else {
    tenant_id = tenantOf(req);
  }
  await run(`insert into bookings (id, tenant_id, client_id, client, type, title, date, time, end_time, suburb, job_id, status, notes, value, installer, source, created_by)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
    [id, tenant_id, client_id, client, d.type || "clean", d.title || null, d.date || null, d.time || null,
     d.end_time || d.end || null, d.suburb || null, d.job_id || d.jobId || null,
     status, d.notes || null, Number(d.value) || 0, d.installer || null, source, req.user.sub]);
  await audit(req.user.sub, "create_booking", id, tenant_id, { type: d.type, source });
  ok(res, await one(`select ${BOOK_COLS} from bookings where id=$1`, [id]));
}));

// Update a booking (confirm, reschedule, complete, cancel). Clients may only touch their own.
app.put("/api/bookings/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  const cur = await one("select * from bookings where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  if (req.user.app_role === "client") {
    const c = await clientRowOf(req);
    if (!c || cur.client_id !== c.id) return res.status(403).json({ error: "forbidden" });
  } else if (!isReseller(req) && cur.tenant_id !== tenantOf(req)) {
    return res.status(404).json({ error: "not_found" });
  }
  const d = req.body || {};
  await run(`update bookings set type=$1, title=$2, date=$3, time=$4, end_time=$5, suburb=$6, job_id=$7, status=$8, notes=$9, value=$10, installer=$11, updated_at=now() where id=$12`,
    [d.type ?? cur.type, d.title ?? cur.title, d.date ?? cur.date, d.time ?? cur.time,
     (d.end_time ?? d.end) ?? cur.end_time, d.suburb ?? cur.suburb, (d.job_id ?? d.jobId) ?? cur.job_id,
     d.status ?? cur.status, d.notes ?? cur.notes, d.value != null ? Number(d.value) : cur.value, d.installer ?? cur.installer, cur.id]);
  await audit(req.user.sub, "update_booking", cur.id, cur.tenant_id, { status: d.status });
  ok(res, await one(`select ${BOOK_COLS} from bookings where id=$1`, [cur.id]));
}));

app.delete("/api/bookings/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  const cur = await one("select * from bookings where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  if (req.user.app_role === "client") {
    const c = await clientRowOf(req);
    if (!c || cur.client_id !== c.id) return res.status(403).json({ error: "forbidden" });
  } else if (!isReseller(req) && cur.tenant_id !== tenantOf(req)) {
    return res.status(404).json({ error: "not_found" });
  }
  await run("delete from bookings where id=$1", [cur.id]);
  await audit(req.user.sub, "delete_booking", cur.id, cur.tenant_id);
  ok(res, { ok: true });
}));

// ============================================================
// QUOTES (persisted quote/proposal builder — tenant-scoped)
// ============================================================
const QUOTE_COLS = "id, tenant_id, number, client_id, deal_id, customer, enq, status, validity, notes, lines, spec, total, updated_at, created_at";

const QUOTE_LIST_COLS = "id, tenant_id, number, client_id, deal_id, customer, enq, status, validity, total, updated_at, created_at, (spec->>'stock_allocated_at') as stock_allocated_at";
app.get("/api/quotes", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const r = await rows(`select ${QUOTE_LIST_COLS} from quotes where tenant_id=$1 order by updated_at desc`, [tenantOf(req)]);
  ok(res, r);
}));

app.get("/api/quotes/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const q = await one(`select ${QUOTE_COLS} from quotes where id=$1`, [req.params.id]);
  if (!q || q.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  ok(res, q);
}));

app.post("/api/quotes", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  const id = d.id && /^[\w-]+$/.test(d.id) ? d.id : "qt-" + rid().slice(0, 8);
  // Sequential-ish human number; fine for display (not a uniqueness guarantee).
  const cnt = await one("select count(*)::int as c from quotes where tenant_id=$1", [tenantOf(req)]);
  const number = d.number || ("QT-" + (2050 + ((cnt && cnt.c) || 0)));
  await run(`insert into quotes (id, tenant_id, number, client_id, deal_id, customer, enq, status, validity, notes, lines, spec, total, created_by)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [id, tenantOf(req), number, d.client_id || null, d.deal_id || null,
     JSON.stringify(d.customer || {}), d.enq || "install", d.status || "Draft", String(d.validity || "30"),
     d.notes || null, JSON.stringify(d.lines || []), JSON.stringify(d.spec || {}), Number(d.total) || 0, req.user.sub]);
  await audit(req.user.sub, "create_quote", id, tenantOf(req));
  ok(res, await one(`select ${QUOTE_COLS} from quotes where id=$1`, [id]));
}));

app.put("/api/quotes/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const cur = await one("select * from quotes where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  await run(`update quotes set number=$1, client_id=$2, deal_id=$3, customer=$4, enq=$5, status=$6, validity=$7, notes=$8, lines=$9, spec=$10, total=$11, updated_at=now() where id=$12`,
    [d.number ?? cur.number, d.client_id ?? cur.client_id, d.deal_id ?? cur.deal_id,
     d.customer != null ? JSON.stringify(d.customer) : cur.customer, d.enq ?? cur.enq, d.status ?? cur.status,
     d.validity != null ? String(d.validity) : cur.validity, d.notes ?? cur.notes,
     d.lines != null ? JSON.stringify(d.lines) : cur.lines, d.spec != null ? JSON.stringify(d.spec) : cur.spec,
     d.total != null ? Number(d.total) : cur.total, cur.id]);
  await audit(req.user.sub, "update_quote", cur.id, cur.tenant_id, { status: d.status });
  ok(res, await one(`select ${QUOTE_COLS} from quotes where id=$1`, [cur.id]));
}));

app.delete("/api/quotes/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const cur = await one("select * from quotes where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  await run("delete from quotes where id=$1", [cur.id]);
  await audit(req.user.sub, "delete_quote", cur.id, cur.tenant_id);
  ok(res, { ok: true });
}));

// Allocate a quote's stock against the customer order (ERP draw-down, MYOB/Xero style).
// Each stockable line reduces on-hand inventory in THIS book, records a negative stock
// movement tagged to the job, and posts COGS → Inventory-out to the ledger.
// Idempotent: a quote allocates once (guarded by spec.stock_allocated_at).
app.post("/api/quotes/:id/allocate-stock", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const round2 = (n) => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
  const cur = await one("select * from quotes where id=$1", [req.params.id]);
  if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  let spec = {}; try { spec = typeof cur.spec === "string" ? JSON.parse(cur.spec) : (cur.spec || {}); } catch (e) {}
  if (spec.stock_allocated_at) return res.status(409).json({ error: "already_allocated", allocated_at: spec.stock_allocated_at });
  let lines = []; try { lines = Array.isArray(cur.lines) ? cur.lines : JSON.parse(cur.lines || "[]"); } catch (e) {}
  let customer = {}; try { customer = typeof cur.customer === "string" ? JSON.parse(cur.customer) : (cur.customer || {}); } catch (e) {}
  const job = cur.deal_id || cur.id;
  const allocated = []; const skipped = []; let totalCost = 0;
  for (const l of lines) {
    const pid = l.product_id || l.id;
    const qty = Number(l.qty) || 0;
    if (!pid || qty <= 0) continue;
    const p = await one("select * from products where id=$1", [pid]);
    if (!p || p.tenant_id !== cur.tenant_id) { skipped.push({ name: l.name || pid, reason: "not_a_stocked_product" }); continue; }
    const base = p.stock == null ? 0 : Number(p.stock);
    const next = Math.max(0, base - qty);
    const unitCost = p.cost != null ? Number(p.cost) : 0;
    await run("update products set stock=$1, updated_at=now() where id=$2", [next, p.id]);
    await run(`insert into stock_movements (id, tenant_id, product_id, delta, reason, buyer, total, job_id, unit_cost, created_by)
      values ($1,$2,$3,$4,'allocation',$5,$6,$7,$8,$9)`,
      ["mov-" + rid().slice(0, 8), cur.tenant_id, p.id, -qty, customer.name || null,
       round2(qty * unitCost), job, unitCost, req.user.sub]);
    totalCost += qty * unitCost;
    allocated.push({ product_id: p.id, name: p.name, qty, from: base, to: next, short: base < qty });
  }
  if (!allocated.length) return res.status(400).json({ error: "no_stock_lines", detail: "No line items match a stocked product in this book.", skipped });
  try { await erp.postStockAllocation(cur.tenant_id, { source_id: cur.id, posted_by: req.user.sub, cost: totalCost, memo: `Stock allocated — quote ${cur.number || cur.id}` }); }
  catch (e) { console.error("ledger post (stock allocation) failed:", e.message); }
  spec.stock_allocated_at = new Date().toISOString();
  await run("update quotes set spec=$1, status=(CASE WHEN status='Draft' OR status='Sent' THEN 'Accepted' ELSE status END), updated_at=now() where id=$2",
    [JSON.stringify(spec), cur.id]);
  await audit(req.user.sub, "allocate_stock", cur.id, cur.tenant_id, { lines: allocated.length, cost: round2(totalCost) });
  ok(res, { ok: true, allocated, skipped, total_cost: round2(totalCost) });
}));

// ============================================================
// MESSAGES (shared client <-> installer threads; one thread per client)
// ============================================================
// Tenant sees a conversation list (one per client that has a thread or any client);
// a client sees only their own single thread with the installer.
app.get("/api/message-threads", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor"), h(async (req, res) => {
  const tid = tenantOf(req);
  // All clients for the tenant, with the latest message + unread-ish preview.
  const clients = await rows("select id, name, site_address from clients where tenant_id=$1 order by name", [tid]);
  const last = await rows(`select distinct on (client_id) client_id, body, created_at, sender_role
    from messages where tenant_id=$1 order by client_id, created_at desc`, [tid]);
  const lastBy = {}; last.forEach(m => { lastBy[m.client_id] = m; });
  ok(res, clients.map(c => ({ id: c.id, who: c.name, role: "Client", address: c.site_address,
    last: lastBy[c.id] ? lastBy[c.id].body : "", last_at: lastBy[c.id] ? lastBy[c.id].created_at : null })));
}));

app.get("/api/messages", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  let tid = tenantOf(req), clientId = req.query.client_id;
  if (req.user.app_role === "client") {
    const c = await one("select * from clients where user_id=$1", [req.user.sub]);
    if (!c) return ok(res, []);
    tid = c.tenant_id; clientId = c.id;
  }
  if (!clientId) return res.status(400).json({ error: "client_id_required" });
  ok(res, await rows(`select id, sender_role, sender_id, sender_name, body, created_at
    from messages where tenant_id=$1 and client_id=$2 order by created_at`, [tid, clientId]));
}));

app.post("/api/messages", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "client"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.body || !String(d.body).trim()) return res.status(400).json({ error: "body_required" });
  let tid = tenantOf(req), clientId = d.client_id;
  if (req.user.app_role === "client") {
    const c = await one("select * from clients where user_id=$1", [req.user.sub]);
    if (!c) return res.status(400).json({ error: "no_client_record" });
    tid = c.tenant_id; clientId = c.id;
  }
  if (!clientId) return res.status(400).json({ error: "client_id_required" });
  const id = "msg-" + rid().slice(0, 10);
  await run(`insert into messages (id, tenant_id, client_id, sender_role, sender_id, sender_name, body)
    values ($1,$2,$3,$4,$5,$6,$7)`,
    [id, tid, clientId, req.user.app_role, req.user.sub, req.user.display_name || null, String(d.body).trim()]);
  await audit(req.user.sub, "send_message", id, tid, { client_id: clientId });
  ok(res, await one("select id, sender_role, sender_id, sender_name, body, created_at from messages where id=$1", [id]));
}));

// ============================================================
// TEAM / CREW (installers & staff — tenant-scoped)
// ============================================================
const TEAM_COLS = "id, tenant_id, name, role, type, licence, hrs, status, jobs, rate, approved, updated_at, created_at";

app.get("/api/team", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  // Reseller default view = oversight of everyone; ?mine=1 = only the
  // reseller's OWN staff (kept in the separate 'reseller-platform' book).
  const r = isReseller(req)
    ? (req.query.mine
        ? await rows(`select ${TEAM_COLS} from team_members where tenant_id='reseller-platform' and active=true order by name`)
        : await rows(`select ${TEAM_COLS} from team_members where active=true order by name`))
    : await rows(`select ${TEAM_COLS} from team_members where tenant_id=$1 and active=true order by name`, [tenantOf(req)]);
  // Contractors can see who's on the crew, but not what everyone is paid.
  ok(res, req.user.app_role === "contractor" ? r.map(({ rate, ...m }) => m) : r);
}));

app.post("/api/team", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.name) return res.status(400).json({ error: "name_required" });
  const id = "tm-" + rid().slice(0, 8);
  await run(`insert into team_members (id, tenant_id, name, role, type, licence, hrs, status, jobs, rate)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [id, isReseller(req) ? "reseller-platform" : tenantOf(req), d.name, d.role || null, d.type || "Staff", d.licence || null,
     Number(d.hrs) || 0, d.status || "Off", Number(d.jobs) || 0, Number(d.rate) || (d.type === "Contractor" ? 55 : 48)]);
  await audit(req.user.sub, "create_team_member", id, tenantOf(req));
  ok(res, await one(`select ${TEAM_COLS} from team_members where id=$1`, [id]));
}));

app.put("/api/team/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const cur = await one("select * from team_members where id=$1", [req.params.id]);
  if (!cur || (!isReseller(req) && cur.tenant_id !== tenantOf(req))) return res.status(404).json({ error: "not_found" });
  const d = req.body || {};
  await run(`update team_members set name=$1, role=$2, type=$3, licence=$4, hrs=$5, status=$6, jobs=$7, rate=$8, approved=$9, updated_at=now() where id=$10`,
    [d.name ?? cur.name, d.role ?? cur.role, d.type ?? cur.type, d.licence ?? cur.licence,
     d.hrs != null ? Number(d.hrs) : cur.hrs, d.status ?? cur.status, d.jobs != null ? Number(d.jobs) : cur.jobs,
     d.rate != null ? Number(d.rate) : cur.rate, d.approved != null ? d.approved : cur.approved, cur.id]);
  await audit(req.user.sub, "update_team_member", cur.id, cur.tenant_id);
  ok(res, await one(`select ${TEAM_COLS} from team_members where id=$1`, [cur.id]));
}));

app.delete("/api/team/:id", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const cur = await one("select * from team_members where id=$1", [req.params.id]);
  if (!cur || (!isReseller(req) && cur.tenant_id !== tenantOf(req))) return res.status(404).json({ error: "not_found" });
  await run("update team_members set active=false, updated_at=now() where id=$1", [cur.id]);
  await audit(req.user.sub, "delete_team_member", cur.id, cur.tenant_id);
  ok(res, { ok: true });
}));

// ============================================================
// CLOCK ON / CLOCK OFF — geo-tagged site attendance for installers
// ============================================================
const clockBook = (req) => isReseller(req) ? "reseller-platform" : tenantOf(req);

app.post("/api/clock", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (d.kind !== "on" && d.kind !== "off") return res.status(400).json({ error: "kind_must_be_on_or_off" });
  const kind = d.kind;
  const id = "ck-" + rid().slice(0, 10);
  await run(`insert into clock_events (id, tenant_id, user_id, user_name, job_id, job_label, kind, lat, lng, accuracy, client_time)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [id, clockBook(req), req.user.sub, req.user.display_name || null, d.job_id || null, d.job_label || null, kind,
     d.lat != null ? Number(d.lat) : null, d.lng != null ? Number(d.lng) : null,
     d.accuracy != null ? Number(d.accuracy) : null, d.client_time || null]);
  await audit(req.user.sub, "clock_" + kind, id, clockBook(req), { job_id: d.job_id || null, geo: d.lat != null });
  ok(res, await one("select * from clock_events where id=$1", [id]));
}));

app.get("/api/clock/status", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const last = await one("select * from clock_events where user_id=$1 order by created_at desc limit 1", [req.user.sub]);
  ok(res, { clocked_on: !!last && last.kind === "on", last: last || null });
}));

app.get("/api/clock/events", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const lim = Math.min(500, Number(req.query.limit) || 200);
  const r = req.query.user_id
    ? await rows(`select * from clock_events where tenant_id=$1 and user_id=$2 order by created_at desc limit ${lim}`, [clockBook(req), req.query.user_id])
    : await rows(`select * from clock_events where tenant_id=$1 order by created_at desc limit ${lim}`, [clockBook(req)]);
  ok(res, r);
}));

// ============================================================
// JOB PHOTOS — taken onsite (camera) or uploaded in the office
// ============================================================
app.get("/api/job-photos", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const r = req.query.job_id
    ? await rows("select id, photo_key, job_id, kind, data, uploaded_by, lat, lng, created_at from job_photos where tenant_id=$1 and job_id=$2 order by created_at", [clockBook(req), req.query.job_id])
    : await rows("select id, photo_key, job_id, kind, data, uploaded_by, lat, lng, created_at from job_photos where tenant_id=$1 order by created_at", [clockBook(req)]);
  ok(res, r);
}));

app.post("/api/job-photos", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.photo_key || !d.data) return res.status(400).json({ error: "photo_key_and_data_required" });
  if (!/^data:image\//.test(String(d.data))) return res.status(400).json({ error: "data_must_be_image_data_url" });
  if (String(d.data).length > 6 * 1024 * 1024) return res.status(413).json({ error: "photo_too_large" });
  const id = "ph-" + rid().slice(0, 10);
  await run(`insert into job_photos (id, tenant_id, photo_key, job_id, kind, data, uploaded_by, lat, lng)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    on conflict (tenant_id, photo_key) do update set data=excluded.data, uploaded_by=excluded.uploaded_by,
      lat=excluded.lat, lng=excluded.lng, created_at=now()`,
    [id, clockBook(req), String(d.photo_key), d.job_id || null, d.kind || null, d.data,
     req.user.display_name || req.user.sub, d.lat != null ? Number(d.lat) : null, d.lng != null ? Number(d.lng) : null]);
  await audit(req.user.sub, "upload_photo", String(d.photo_key), clockBook(req), { job_id: d.job_id || null });
  ok(res, { ok: true, photo_key: d.photo_key });
}));

app.delete("/api/job-photos/:key", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  await run("delete from job_photos where tenant_id=$1 and photo_key=$2", [clockBook(req), req.params.key]);
  ok(res, { ok: true });
}));

// ============================================================
// ONSITE REPORTS — checklist forms filled & signed in the field
// ============================================================
app.get("/api/onsite-reports", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) =>
  ok(res, await rows("select id, rid, type, job_id, payload, signed_by, completed, updated_at from onsite_reports where tenant_id=$1 order by updated_at desc", [clockBook(req)]))));

app.post("/api/onsite-reports", A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.rid) return res.status(400).json({ error: "rid_required" });
  const id = "osr-" + rid().slice(0, 10);
  await run(`insert into onsite_reports (id, tenant_id, rid, type, job_id, payload, signed_by, completed, updated_at)
    values ($1,$2,$3,$4,$5,$6,$7,$8,now())
    on conflict (tenant_id, rid) do update set payload=excluded.payload, signed_by=excluded.signed_by,
      completed=excluded.completed, updated_at=now()`,
    [id, clockBook(req), String(d.rid), d.type || null, d.job_id || null,
     JSON.stringify(d.payload || {}), d.signed_by || null, !!d.completed]);
  await audit(req.user.sub, "onsite_report", String(d.rid), clockBook(req), { completed: !!d.completed });
  ok(res, { ok: true, rid: d.rid });
}));

// ============================================================
// TENANT FEATURES — ERP module upgrade toggle + accounting source
// ============================================================
app.get("/api/my-features", A.authRequired, h(async (req, res) => {
  if (isReseller(req)) return ok(res, { erp_enabled: true, accounting_provider: "builtin" });
  const t = await one("select erp_enabled, accounting_provider from tenants where id=$1", [tenantOf(req)]);
  ok(res, { erp_enabled: t ? t.erp_enabled !== false : true, accounting_provider: (t && t.accounting_provider) || "builtin" });
}));

app.get("/api/tenants/:id/features", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const cur = await one("select id, erp_enabled, accounting_provider from tenants where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  ok(res, cur);
}));

app.put("/api/tenants/:id/features", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const d = req.body || {};
  const cur = await one("select id, erp_enabled, accounting_provider from tenants where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  await run("update tenants set erp_enabled=$1, accounting_provider=$2 where id=$3",
    [d.erp_enabled != null ? !!d.erp_enabled : cur.erp_enabled,
     d.accounting_provider != null ? String(d.accounting_provider).toLowerCase() : cur.accounting_provider, cur.id]);
  await audit(req.user.sub, "tenant_features", cur.id, cur.id, d);
  ok(res, await one("select id, erp_enabled, accounting_provider from tenants where id=$1", [cur.id]));
}));

// ============================================================
// TENANT LIFECYCLE (reseller-only): list, provision, plan, suspend
// ============================================================
const PLAN_PRICES = { Starter: 199, Growth: 499, Scale: 899 };

app.get("/api/tenants", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const ts = await rows("select id, name, domain, plan, status, region, branding, created_at from tenants order by created_at");
  const counts = await rows("select tenant_id, count(*)::int as n from users where status='active' and tenant_id is not null group by tenant_id");
  const cmap = {}; for (const c of counts) cmap[c.tenant_id] = c.n;
  const inst = await rows("select tenant_id, count(*)::int as n from deals where stage='installed' and tenant_id is not null group by tenant_id");
  const imap = {}; for (const c of inst) imap[c.tenant_id] = c.n;
  ok(res, ts.map(t => ({ ...t, users: cmap[t.id] || 0, installs: imap[t.id] || 0, mrr: PLAN_PRICES[t.plan] || 0 })));
}));

app.post("/api/tenants", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || "").trim();
  const domain = String(b.domain || "").trim().toLowerCase();
  const region = String(b.region || "").trim();
  const plan = ["Starter", "Growth", "Scale"].includes(b.plan) ? b.plan : "Growth";
  const adminName = String(b.admin_name || "").trim().replace(/\s+/g, " ");
  if (name.length < 2) return res.status(400).json({ error: "name_required" });
  if (adminName.length < 3 || !adminName.includes(" ")) return res.status(400).json({ error: "admin_name_required" });
  const id = "tenant-" + (name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30) || rid());
  if (await one("select id from tenants where id=$1 or (domain<>'' and domain=$2)", [id, domain]))
    return res.status(409).json({ error: "tenant_exists" });
  // sign-in is by exact full name, so names must stay unambiguous platform-wide
  if (await one("select id from users where status='active' and lower(display_name)=lower($1)", [adminName]))
    return res.status(409).json({ error: "admin_name_taken" });
  const branding = { name };
  if (Array.isArray(b.accent) && b.accent.length) branding.accent = b.accent.slice(0, 3).map(String);
  if (b.logo_url) branding.logo_url = String(b.logo_url).slice(0, 400000);
  await run("insert into tenants (id, reseller_id, name, domain, plan, region, branding, status) values ($1,$2,$3,$4,$5,$6,$7::jsonb,'active')",
    [id, "reseller-solarsync", name, domain, plan, region, JSON.stringify(branding)]);
  const pin = String(require("crypto").randomInt(100000, 1000000));
  const uid = "u-" + rid();
  await run("insert into users (id, tenant_id, app_role, display_name, pin_hash) values ($1,$2,'tenant_admin',$3,$4)",
    [uid, id, adminName, A.bcrypt.hashSync(pin, 10)]);
  await audit(req.user.sub, "provision_tenant", id, id);
  // the PIN is returned exactly once — hand it to the tenant admin, then they
  // set up their authenticator on first sign-in
  ok(res, { id, name, domain, plan, region, admin: { id: uid, display_name: adminName, pin } });
}));

app.put("/api/tenants/:id/plan", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const plan = String((req.body || {}).plan || "");
  if (!["Starter", "Growth", "Scale"].includes(plan)) return res.status(400).json({ error: "bad_plan" });
  const cur = await one("select id from tenants where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  await run("update tenants set plan=$1 where id=$2", [plan, cur.id]);
  await audit(req.user.sub, "tenant_plan", cur.id, cur.id, { plan });
  ok(res, { id: cur.id, plan });
}));

app.put("/api/tenants/:id/status", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
  const status = String((req.body || {}).status || "");
  if (!["active", "suspended"].includes(status)) return res.status(400).json({ error: "bad_status" });
  const cur = await one("select id from tenants where id=$1", [req.params.id]);
  if (!cur) return res.status(404).json({ error: "not_found" });
  await run("update tenants set status=$1 where id=$2", [status, cur.id]);
  await audit(req.user.sub, status === "suspended" ? "tenant_suspended" : "tenant_reactivated", cur.id, cur.id);
  ok(res, { id: cur.id, status });
}));

// ============================================================
// USER PROVISIONING — how new people get a sign-in.
// Reseller can create logins for any tenant (or reseller staff);
// a tenant admin can create staff/contractor/client logins for
// their own tenant only. The starter PIN is returned exactly once.
// ============================================================
// Who has a sign-in: reseller sees everyone, tenant admin sees only their own team.
app.get("/api/users", A.authRequired, A.requireRole("reseller", "tenant_admin"), h(async (req, res) => {
  const list = isReseller(req)
    ? await rows("select id, display_name, app_role, tenant_id, status, totp_enrolled from users order by created_at")
    : await rows("select id, display_name, app_role, tenant_id, status, totp_enrolled from users where tenant_id=$1 order by created_at", [tenantOf(req)]);
  ok(res, list);
}));

app.post("/api/users", A.authRequired, A.requireRole("reseller", "tenant_admin"), h(async (req, res) => {
  const b = req.body || {};
  const displayName = String(b.display_name || "").trim().replace(/\s+/g, " ");
  const role = String(b.app_role || "");
  const isRes = isReseller(req);
  const allowed = isRes ? ["reseller", "tenant_admin", "staff", "contractor", "client"] : ["staff", "contractor", "client"];
  if (!allowed.includes(role)) return res.status(403).json({ error: "bad_role" });
  const tenantId = role === "reseller" ? null : (isRes ? String(b.tenant_id || "") : tenantOf(req));
  if (role !== "reseller") {
    if (!tenantId) return res.status(400).json({ error: "tenant_required" });
    if (!await one("select id from tenants where id=$1", [tenantId])) return res.status(404).json({ error: "tenant_not_found" });
  }
  if (displayName.length < 3 || !displayName.includes(" ")) return res.status(400).json({ error: "full_name_required" });
  if (await one("select id from users where status='active' and lower(display_name)=lower($1)", [displayName]))
    return res.status(409).json({ error: "name_taken" });
  const pin = String(require("crypto").randomInt(100000, 1000000));
  const uid = "u-" + rid();
  await run("insert into users (id, tenant_id, app_role, display_name, pin_hash) values ($1,$2,$3,$4,$5)",
    [uid, tenantId, role, displayName, A.bcrypt.hashSync(pin, 10)]);
  await audit(req.user.sub, "create_user", uid, tenantId);
  ok(res, { id: uid, display_name: displayName, app_role: role, tenant_id: tenantId, pin });
}));

// ============================================================
// WHITE-LABEL BRANDING (tenant colours/name/logo — applies across all portals)
// ============================================================
app.get("/api/branding", A.authRequired, h(async (req, res) => {
  const tid = tenantOf(req);
  if (!tid) return ok(res, {});
  const t = await one("select branding from tenants where id=$1", [tid]);
  ok(res, (t && t.branding) || {});
}));

app.put("/api/branding", A.authRequired, A.requireRole("tenant_admin"), h(async (req, res) => {
  const tid = tenantOf(req);
  const d = req.body || {};
  const branding = {
    accent: Array.isArray(d.accent) ? d.accent.slice(0, 3) : undefined,
    glow: d.glow, name: d.name, tagline: d.tagline, logo_url: d.logo_url,
  };
  Object.keys(branding).forEach(k => branding[k] === undefined && delete branding[k]);
  await run("update tenants set branding=$1::jsonb where id=$2", [JSON.stringify(branding), tid]);
  await audit(req.user.sub, "update_branding", tid, tid);
  ok(res, branding);
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

// Create an invoice (tenant staff or reseller — each scoped to its own book). client_id optional.
app.post("/api/invoices", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const d = req.body || {};
  if (!d.amount || Number(d.amount) <= 0) return res.status(400).json({ error: "amount_required" });
  const id = "inv-" + rid().slice(0, 8);
  const cnt = await one("select count(*)::int as c from invoices where tenant_id=$1", [tenantOf(req)]);
  const number = d.number || ("INV-" + (2100 + ((cnt && cnt.c) || 0)));
  const invLines = Array.isArray(d.lines) ? d.lines : [];
  await run(`insert into invoices (id, tenant_id, client_id, client_name, number, amount, status, description, due, quote_id, lines)
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [id, tenantOf(req), d.client_id || null, d.client_name || null, number, Number(d.amount),
     d.status || "due", d.description || null, d.due || null, d.quote_id || null, JSON.stringify(invLines)]);
  await audit(req.user.sub, "create_invoice", id, tenantOf(req));
  const inv = await one("select * from invoices where id=$1", [id]);
  try { await erp.postInvoiceCreated(inv, req.user.sub); } catch (e) { console.error("ledger post (invoice) failed:", e.message); }
  ok(res, inv);
}));

// Convert a saved quote into an invoice (carries client, amount and a link back).
app.post("/api/quotes/:id/invoice", A.authRequired, A.requireRole("tenant_admin", "staff"), h(async (req, res) => {
  const q = await one("select * from quotes where id=$1", [req.params.id]);
  if (!q || (!isReseller(req) && q.tenant_id !== tenantOf(req))) return res.status(404).json({ error: "not_found" });
  const cust = q.customer || {};
  const id = "inv-" + rid().slice(0, 8);
  const cnt = await one("select count(*)::int as c from invoices where tenant_id=$1", [q.tenant_id]);
  const number = "INV-" + (2100 + ((cnt && cnt.c) || 0));
  let qLines = []; try { qLines = Array.isArray(q.lines) ? q.lines : JSON.parse(q.lines || "[]"); } catch (e) {}
  await run(`insert into invoices (id, tenant_id, client_id, client_name, number, amount, status, description, due, quote_id, lines)
    values ($1,$2,$3,$4,$5,$6,'due',$7,$8,$9,$10)`,
    [id, q.tenant_id, q.client_id || null, cust.name || null, number, Number(q.total) || 0,
     "From quote " + (q.number || q.id), req.body && req.body.due || null, q.id, JSON.stringify(qLines)]);
  await run("update quotes set status='Accepted', updated_at=now() where id=$1", [q.id]);
  await audit(req.user.sub, "quote_to_invoice", id, q.tenant_id, { quote: q.id });
  const inv = await one("select * from invoices where id=$1", [id]);
  try { await erp.postInvoiceCreated(inv, req.user.sub); } catch (e) { console.error("ledger post (quote invoice) failed:", e.message); }
  ok(res, inv);
}));

const stripeKey = process.env.STRIPE_SECRET_KEY;
const stripe = stripeKey ? require("stripe")(stripeKey) : null;

app.post("/api/invoices/:id/pay-intent", A.authRequired, h(async (req, res) => {
  const inv = await one("select * from invoices where id=$1", [req.params.id]);
  if (!inv) return res.status(404).json({ error: "not_found" });
  if (inv.is_demo) return res.status(403).json({ error: "demo_invoice", message: "This is a demo invoice — charging is disabled." });
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
  if (inv.is_demo) return res.status(403).json({ error: "demo_invoice", message: "This is a demo invoice — charging is disabled." });
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
    if (invId) {
      run("update invoices set status='paid', paid_at=now() where id=$1", [invId])
        .then(() => audit(null, "invoice_paid", invId, obj.metadata.tenant_id))
        .then(() => one("select * from invoices where id=$1", [invId]))
        .then(inv => erp.postInvoicePaid(inv, "stripe"))
        .catch(e => console.error("ledger post (stripe payment) failed:", e && e.message));
    }
  }
  res.json({ received: true });
});

app.post("/api/invoices/:id/mark-paid", A.authRequired, A.requireRole("tenant_admin", "staff", "reseller"), h(async (req, res) => {
  const inv = await one("select * from invoices where id=$1", [req.params.id]);
  if (!inv || inv.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
  await run("update invoices set status='paid', paid_at=now() where id=$1", [inv.id]);
  await audit(req.user.sub, "invoice_paid_manual", inv.id, inv.tenant_id);
  try { await erp.postInvoicePaid(inv, req.user.sub); } catch (e) { console.error("ledger post (mark paid) failed:", e.message); }
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

// Issue — reseller only. Returns the signed magic link exactly once.
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

// Redeem — public (the magic link is the credential). Verifies the JWT,
// then checks server-side revocation/expiry before minting real tokens.
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

// Paid-gated: unlocked when the tenant has an active 'document-library' add-on row.
// A valid tester token (?token=) also unlocks, mirroring the compliance gate.
async function documentLibraryUnlocked(tenant_id) {
  // TEMP (pre-launch): available to any signed-in tenant while billing is finalised.
  // To re-gate for monetisation, restore the tenant_addons check
  // (see git history for commit that gated on addon_key='document-library').
  return !!tenant_id;
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
  console.log("[doclib] entitlement check tenant=%s unlocked=%s configured=%s", tenantOf(req), unlocked, storage.isConfigured());
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

// Front-end vendor libraries (e.g. Word-import converter for bring-your-own forms)
app.use("/vendor", express.static(path.join(__dirname, "public", "vendor"), { maxAge: "7d" }));

// PWA home-screen icons (must be a real static route — the "*" catch-all below
// would otherwise return the HTML bundle for these .png paths).
app.use("/icons", express.static(path.join(__dirname, "public", "icons"), { maxAge: "7d" }));

// Same-origin proxy for the client's rooftop satellite image (Esri World Imagery
// export). The live map tiles are cross-origin, so the proposal screenshot tool
// (html2canvas) can't capture them; fetching one composited image through our own
// server makes it same-origin and canvas-safe, so the quote can show the panels on
// the client's REAL roof. Read-only image passthrough, day-cached.
app.get("/api/roof-image", (req, res) => {
  const lat = parseFloat(req.query.lat), lng = parseFloat(req.query.lng), zoom = parseFloat(req.query.zoom);
  let w = Math.round(parseFloat(req.query.w)), h = Math.round(parseFloat(req.query.h));
  if (![lat, lng, zoom, w, h].every(Number.isFinite)) return res.status(400).json({ error: "bad_params" });
  w = Math.max(64, Math.min(1600, w)); h = Math.max(64, Math.min(1600, h));
  // Web-Mercator (EPSG:3857) bbox for this centre + zoom + on-screen size, so the
  // exported image lines up with the tile view the installer placed the panels over.
  const RMAJ = 6378137;
  const x = RMAJ * (lng * Math.PI / 180);
  const y = RMAJ * Math.log(Math.tan(Math.PI / 4 + (lat * Math.PI / 180) / 2));
  const mpp = 156543.03392804097 / Math.pow(2, zoom);   // 3857 metres/pixel at this zoom
  const hw = (w / 2) * mpp, hh = (h / 2) * mpp;
  const bbox = [x - hw, y - hh, x + hw, y + hh].join(",");
  const url = "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/export"
    + `?bbox=${bbox}&bboxSR=3857&imageSR=3857&size=${w},${h}&format=jpg&transparent=false&f=image`;
  const up = https.get(url, (r2) => {
    if (r2.statusCode !== 200) { r2.resume(); return res.status(502).json({ error: "upstream", code: r2.statusCode }); }
    res.set("Content-Type", r2.headers["content-type"] || "image/jpeg");
    res.set("Cache-Control", "public, max-age=86400");
    r2.pipe(res);
  });
  up.on("error", () => { if (!res.headersSent) res.status(502).json({ error: "fetch_failed" }); });
  up.setTimeout(8000, () => up.destroy());
});

// ============================================================
// ERP — accounting, purchasing, stock valuation, payroll,
// financial reports, BAS, bank rec, Xero/MYOB export (erp.js)
// ============================================================
erp.register(app, { h, ok, tenantOf });

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
// PWA offline support: served explicitly so the "*" catch-all below doesn't return the SPA bundle.
// sw.js must be uncached and root-scoped so it can control /app on remote, no-signal sites.
app.get("/sw.js", (req, res) => {
  const SW = path.join(__dirname, "public", "sw.js");
  if (!fs.existsSync(SW)) return res.status(404).end();
  res.set("Service-Worker-Allowed", "/");
  res.set("Cache-Control", "no-cache");
  res.type("application/javascript");
  res.sendFile(SW);
});
app.get("/manifest.webmanifest", (req, res) => {
  const MF = path.join(__dirname, "public", "manifest.webmanifest");
  if (!fs.existsSync(MF)) return res.status(404).end();
  res.type("application/manifest+json");
  res.sendFile(MF);
});
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
    // Owner bootstrap: the platform owner sets OWNER_NAME + OWNER_PIN as
    // environment variables and the account creates itself on the next boot.
    // The PIN keeps syncing from the variable until the authenticator is
    // enrolled (so a typo'd PIN is fixable by editing the variable); after
    // enrolment the app owns the PIN and the variable is ignored.
    const ownerName = String(process.env.OWNER_NAME || "").trim().replace(/\s+/g, " ");
    const ownerPin = String(process.env.OWNER_PIN || "").trim();
    if (ownerName.length >= 3 && /^\d{6}$/.test(ownerPin)) {
      const u = await one("select * from users where app_role='reseller' and lower(display_name)=lower($1)", [ownerName]);
      if (!u) {
        const uo = await one("select * from users where id='u-owner'");
        if (uo && !uo.totp_enrolled) {
          // OWNER_NAME was corrected before first sign-in — rename in place.
          await run("update users set display_name=$1, pin_hash=$2, status='active', failed_attempts=0, locked_until=null where id='u-owner'",
            [ownerName, A.bcrypt.hashSync(ownerPin, 10)]);
        } else if (!uo) {
          await run("insert into users (id, tenant_id, app_role, display_name, pin_hash) values ('u-owner', null, 'reseller', $1, $2)",
            [ownerName, A.bcrypt.hashSync(ownerPin, 10)]);
          console.log(`Owner account ready for "${ownerName}" — sign in with the OWNER_PIN to set up the authenticator.`);
        }
      } else if (!u.totp_enrolled) {
        await run("update users set pin_hash=$1, status='active', failed_attempts=0, locked_until=null where id=$2",
          [A.bcrypt.hashSync(ownerPin, 10), u.id]);
      }
      // Any other reseller login that never finished authenticator setup is a
      // demo leftover (e.g. the old seeded admin) — switch it off on live.
      await run("update users set status='disabled' where app_role='reseller' and totp_enrolled=false and lower(display_name)<>lower($1)", [ownerName]);
    }

    // Ensure exactly one fully-functional sample tenant (Helios) exists on every
    // deployment, so the live reseller portal always has a real, working example
    // to open. Idempotent and non-destructive: each row is created only when it
    // is absent (WHERE NOT EXISTS), so real tenants/users are never touched.
    if (!await one("select id from tenants where id='tenant-helios'")) {
      const pin = A.bcrypt.hashSync("123456", 10);
      await run("insert into resellers (id,name) select 'reseller-solarsync','SolarSync' where not exists (select 1 from resellers where id='reseller-solarsync')");
      await run("insert into tenants (id,reseller_id,name,domain,plan,status,region) select 'tenant-helios','reseller-solarsync','Helios Solar','portal.heliossolar.com.au','Scale','active','QLD' where not exists (select 1 from tenants where id='tenant-helios')");
      for (const [id, role, name] of [["u-admin","tenant_admin","Sarah Chen"],["u-contractor","contractor","Dan Webb"],["u-client","client","Adam Smith"]])
        await run("insert into users (id,tenant_id,app_role,display_name,pin_hash,totp_secret,totp_enrolled) select $1,'tenant-helios',$2,$3,$4,null,false where not exists (select 1 from users where id=$1)", [id, role, name, pin]);
      await run("insert into clients (id,tenant_id,user_id,name,site_address,install_status) select 'c-adam','tenant-helios','u-client','Adam Smith','42 Solar Ave, Brisbane QLD 4000','installed' where not exists (select 1 from clients where id='c-adam')");
      for (const [k,n,p] of [["compliance-suite","Compliance Reports Suite",69],["vpp","VPP Enrollment Assistant",49],["document-library","Document Library",29]])
        await run("insert into addons (key,name,price) select $1,$2,$3 where not exists (select 1 from addons where key=$1)", [k,n,p]);
      for (const k of ["compliance-suite","vpp","document-library"])
        await run("insert into tenant_addons (tenant_id,addon_key,active,activated_at) select 'tenant-helios',$1,true,now() where not exists (select 1 from tenant_addons where tenant_id='tenant-helios' and addon_key=$1)", [k]);
      for (const [k,ti,b] of [["rep-gridconnect","Grid-Connect Solar Installation — Compliance Report","<h1>Grid-Connect Solar Installation — Compliance Report</h1><p>AS/NZS 5033 · 4777.1 · 3000</p>"],["rep-instmanual","Solar Installation Manual & Handover Pack","<h1>Solar Installation Manual & Handover Pack</h1><p>Full AS/NZS-compliant install procedure, photos, sign-off.</p>"]])
        await run("insert into report_templates (key,category,title,body_html) select $1,'compliance',$2,$3 where not exists (select 1 from report_templates where key=$1)", [k,ti,b]);
      await run("insert into invoices (id,tenant_id,client_id,number,amount,status,is_demo) select 'inv-2048','tenant-helios','c-adam','INV-2048',5880,'due',true where not exists (select 1 from invoices where id='inv-2048')");
      console.log("Sample tenant 'Helios Solar' ensured (functional example for the reseller portal).");
    }

    // Safety: the seeded demo invoice must never be chargeable on live Stripe keys.
    await run("update invoices set is_demo=true where id='inv-2048'");
    const spec = JSON.stringify({
      systemKw: 6.6, panels: 16, panelModel: "Jinko Tiger Neo 440W",
      inverter: "Fronius Primo GEN24 5.0", battery: null,
      phone: "0412 345 678", email: "adam.smith@email.com",
    });
    await run(
      "update clients set system_spec=$1::jsonb where id='c-adam' and (system_spec is null or system_spec='{}'::jsonb)",
      [spec]
    );
    // Seed the CRM pipeline for the connected-demo tenant only if it's empty,
    // so an existing DB (which won't re-run seed.js) still shows a populated board.
    const dc = await one("select count(*)::int as c from deals where tenant_id='tenant-helios'");
    if (!dc || dc.c === 0) {
      const demo = [
        ["SS-1042","Smith Residence","install","solar_installation","installed","6.6 kW · 16 panels",8400,"Dan Webb","Toowoomba QLD"],
        ["SS-1041","Jones Farm","install","solar_installation","scheduled","13.2 kW · 32 panels",16900,"Kira Park","Gatton QLD"],
        ["SS-1043","Patel Townhouse","inspection","site_inspection","enquiry","Site inspection",0,"Unassigned","Ipswich QLD"],
        ["SS-1040","Delta Office Park","install","solar_installation","quote","24 kW · 58 panels",41500,"Unassigned","Springfield QLD"],
        ["SS-1039","Clarkson Home","install","solar_installation","accepted","10 kWh battery",11200,"Unassigned","Brisbane QLD"],
        ["SS-1044","Nguyen Residence","cleaning","panel_cleaning","deposit","Panel clean × 22",480,"Mia Tran","Logan QLD"],
        ["SS-1037","Marlow Cottage","install","solar_installation","manual","5 kW · 12 panels",6300,"Mia Tran","Redlands QLD"],
        ["SS-1036","Riverside Cafe","install","solar_installation","invoiced","8.8 kW · 22 panels",10800,"Kira Park","Brisbane QLD"],
      ];
      for (const d of demo) {
        await run(`insert into deals (id, tenant_id, client, type, job_type, stage, system, value, installer, suburb, created_by)
          values ($1,'tenant-helios',$2,$3,$4,$5,$6,$7,$8,$9,'system') on conflict (id) do nothing`, d);
      }
    }
    // Seed the product catalog + stock for the demo tenant if empty (from products-seed.json).
    const pc = await one("select count(*)::int as c from products where tenant_id='tenant-helios'");
    if (!pc || pc.c === 0) {
      let seed = [];
      try { seed = require("./products-seed.json"); } catch (e) { console.error("products-seed.json missing:", e.message); }
      for (const p of seed) {
        await run(`insert into products (id, tenant_id, cat, name, spec, unit, price, watts, stock, direct_sale, recreational, note)
          values ($1,'tenant-helios',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) on conflict (id) do nothing`,
          [p.id, p.cat, p.name, p.spec, p.unit, p.price, p.watts, p.stock, p.direct_sale, p.recreational, p.note]);
      }
    }

    // Seed the crew for the demo tenant if empty.
    const tc = await one("select count(*)::int as c from team_members where tenant_id='tenant-helios'");
    if (!tc || tc.c === 0) {
      const crew = [
        ["Dan Webb", "Lead Installer · SAA A1234", "Staff", "SAA A1234", 38, "Clocked on", 3, 48],
        ["Kira Park", "Installer · SAA A2231", "Staff", "SAA A2231", 41, "On site", 2, 46],
        ["Mia Tran", "Electrician · SAA A4456", "Contractor", "SAA A4456", 33, "Off", 2, 62],
        ["Sam Cole", "Apprentice", "Staff", "Apprentice", 36, "On site", 1, 32],
        ["Joel Ruiz", "Cleaning crew", "Contractor", "Contractor", 22, "Off", 4, 40],
      ];
      for (const [name, role, type, licence, hrs, status, jobs, rate] of crew) {
        await run(`insert into team_members (id, tenant_id, name, role, type, licence, hrs, status, jobs, rate)
          values ($1,'tenant-helios',$2,$3,$4,$5,$6,$7,$8,$9)`,
          ["tm-" + Buffer.from(name).toString("hex").slice(0, 8), name, role, type, licence, hrs, status, jobs, rate]);
      }
    }
  } catch (e) { console.error("startupBackfill failed:", e.message); }
}

// ensure DB is initialised (and schema migrated) before accepting traffic
require("./db").db().then(async () => {
  await startupBackfill();
  app.listen(PORT, () => console.log(`SolarSync backend on :${PORT} (${process.env.DATABASE_URL ? "Postgres" : "PGlite local"}) [BUILD: doclib-ui 18Jun]`));
}).catch(e => { console.error("DB init failed:", e); process.exit(1); });
