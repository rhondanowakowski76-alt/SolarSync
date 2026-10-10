// SolarSync — MYOB Business / AccountRight connection (per tenant).
//
// The tenant's admin signs in to MYOB (OAuth 2.0), picks their company file, and from
// then on SolarSync pushes invoices to that file (customer created if needed, GST
// mapped) and reads back which ones have been paid in MYOB.
//
// Switched on by setting, on the server (never in code):
//   MYOB_CLIENT_ID, MYOB_CLIENT_SECRET   — from the SolarSync app registered with MYOB
//   MYOB_REDIRECT_URI (optional)         — defaults to <site>/api/integrations/myob/callback
//   ACCOUNTING_TOKEN_KEY (recommended)   — encrypts stored MYOB tokens; falls back to JWT_SECRET
//   MYOB_SCOPES (optional)               — defaults to the post-March-2025 sme-* scopes
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const A = require("./auth");
const { rows, one, run, audit } = require("./db");

const AUTH_BASE = (process.env.MYOB_AUTH_BASE || "https://secure.myob.com").replace(/\/$/, "");
const API_BASE = (process.env.MYOB_API_BASE || "https://api.myob.com/accountright").replace(/\/$/, "");
const SCOPES = process.env.MYOB_SCOPES || "sme-company-file sme-contact sme-sale sme-general-ledger";
const PROVIDER = "myob";
const DEFAULTS = { income_account: "4-1000", tax_code: "GST", auto_push: true };

const configured = () => !!(process.env.MYOB_CLIENT_ID && process.env.MYOB_CLIENT_SECRET);

// ---------- token encryption (AES-256-GCM) ----------
const encKey = () => crypto.createHash("sha256").update(process.env.ACCOUNTING_TOKEN_KEY || A.JWT_SECRET).digest();
function seal(obj) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const data = Buffer.concat([c.update(JSON.stringify(obj), "utf8"), c.final()]);
  return [iv, c.getAuthTag(), data].map(b => b.toString("base64")).join(".");
}
function unseal(s) {
  try {
    const [iv, tag, data] = String(s || "").split(".").map(x => Buffer.from(x, "base64"));
    const d = crypto.createDecipheriv("aes-256-gcm", encKey(), iv);
    d.setAuthTag(tag);
    return JSON.parse(Buffer.concat([d.update(data), d.final()]).toString("utf8"));
  } catch (e) { return null; }
}

// ---------- connection row ----------
const conn = (tenantId) => one("select * from accounting_connections where tenant_id=$1 and provider=$2", [tenantId, PROVIDER]);
const settingsOf = (c) => ({ ...DEFAULTS, ...((c && c.settings) || {}) });
async function setError(tenantId, msg) {
  await run("update accounting_connections set last_error=$1 where tenant_id=$2 and provider=$3", [msg ? String(msg).slice(0, 400) : null, tenantId, PROVIDER]);
}

// ---------- OAuth ----------
function redirectUri(req) {
  if (process.env.MYOB_REDIRECT_URI) return process.env.MYOB_REDIRECT_URI;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "https";
  return proto.split(",")[0] + "://" + req.get("host") + "/api/integrations/myob/callback";
}
async function tokenRequest(params) {
  const body = new URLSearchParams({ client_id: process.env.MYOB_CLIENT_ID, client_secret: process.env.MYOB_CLIENT_SECRET, ...params });
  const r = await fetch(AUTH_BASE + "/oauth2/v1/authorize", {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body,
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error("myob_token_" + (j.error || r.status));
  return { access: j.access_token, refresh: j.refresh_token, expires_at: Date.now() + (Number(j.expires_in) || 1200) * 1000 };
}

// A fresh access token for this tenant, refreshing (and re-storing) when close to expiry.
async function accessToken(c) {
  const t = unseal(c.tokens_enc);
  if (!t || !t.refresh) throw new Error("myob_reconnect");
  if (t.expires_at - Date.now() > 90 * 1000) return t.access;
  let nt;
  try { nt = await tokenRequest({ grant_type: "refresh_token", refresh_token: t.refresh }); }
  catch (e) {
    await run("update accounting_connections set status='expired' where tenant_id=$1 and provider=$2", [c.tenant_id, PROVIDER]);
    throw new Error("myob_reconnect");
  }
  if (!nt.refresh) nt.refresh = t.refresh;
  await run("update accounting_connections set tokens_enc=$1 where tenant_id=$2 and provider=$3", [seal(nt), c.tenant_id, PROVIDER]);
  return nt.access;
}

// ---------- API ----------
async function api(c, method, path, body) {
  const token = await accessToken(c);
  const r = await fetch(API_BASE + "/" + encodeURIComponent(c.business_id) + path, {
    method,
    headers: {
      authorization: "Bearer " + token, "x-myobapi-key": process.env.MYOB_CLIENT_ID, "x-myobapi-version": "v2",
      accept: "application/json", ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let j = null; try { j = text ? JSON.parse(text) : null; } catch (e) {}
  if (!r.ok) {
    const msg = (j && j.Errors && j.Errors[0] && (j.Errors[0].Message || j.Errors[0].Name)) || ("HTTP " + r.status);
    throw new Error("MYOB: " + msg);
  }
  // Creates answer 201 with the new record's URL in Location; its last segment is the UID.
  const loc = r.headers.get("location");
  return { data: j, uid: loc ? loc.split("/").pop() : null };
}
const q = (s) => String(s).replace(/'/g, "''");   // OData string literal
async function firstUid(c, path) {
  const { data } = await api(c, "GET", path);
  const it = data && data.Items && data.Items[0];
  return it ? it.UID : null;
}

async function lookups(c) {
  const s = settingsOf(c);
  const tax = await firstUid(c, "/GeneralLedger/TaxCode?$filter=" + encodeURIComponent("Code eq '" + q(s.tax_code) + "'"));
  if (!tax) throw new Error("MYOB: tax code '" + s.tax_code + "' not found in this company file");
  const acct = await firstUid(c, "/GeneralLedger/Account?$filter=" + encodeURIComponent("DisplayID eq '" + q(s.income_account) + "'"));
  if (!acct) throw new Error("MYOB: income account " + s.income_account + " not found in this company file");
  return { tax, acct };
}

async function customerUid(c, inv, tax) {
  const client = inv.client_id ? await one("select * from clients where id=$1 and tenant_id=$2", [inv.client_id, c.tenant_id]) : null;
  const name = String((client && client.name) || inv.client_name || "SolarSync customer").slice(0, 50);
  const key = client ? "c:" + client.id : "n:" + name.toLowerCase();
  const link = await one("select myob_uid from myob_customer_links where tenant_id=$1 and client_key=$2", [c.tenant_id, key]);
  if (link) return link.myob_uid;
  let uid = await firstUid(c, "/Contact/Customer?$filter=" + encodeURIComponent("CompanyName eq '" + q(name) + "'"));
  if (!uid) {
    let spec = {}; try { spec = typeof client.system_spec === "string" ? JSON.parse(client.system_spec) : (client.system_spec || {}); } catch (e) {}
    const addr = { Location: 1 };
    if (client && client.site_address) addr.Street = String(client.site_address).slice(0, 255);
    if (spec.email) addr.Email = String(spec.email).slice(0, 255);
    if (spec.phone) addr.Phone1 = String(spec.phone).slice(0, 21);
    const r = await api(c, "POST", "/Contact/Customer", {
      IsIndividual: false, CompanyName: name, Addresses: [addr],
      SellingDetails: { TaxCode: { UID: tax }, FreightTaxCode: { UID: tax } },
    });
    uid = r.uid;
  }
  if (!uid) throw new Error("MYOB: customer could not be created");
  await run(`insert into myob_customer_links (tenant_id, client_key, myob_uid) values ($1,$2,$3)
    on conflict (tenant_id, client_key) do update set myob_uid=excluded.myob_uid`, [c.tenant_id, key, uid]);
  return uid;
}

// Push one SolarSync invoice (amounts are GST-inclusive) as a MYOB service invoice.
async function pushInvoice(c, inv, lk) {
  // Claim the invoice first, so an automatic push and a "Sync now" running at the same
  // moment can never both send it. A failed push releases the claim for the next try.
  const claim = await one(`insert into myob_invoice_links (invoice_id, tenant_id, myob_uid) values ($1,$2,'pending')
    on conflict (invoice_id) do nothing returning invoice_id`, [inv.id, c.tenant_id]);
  if (!claim) return false;
  try {
    await sendInvoice(c, inv, lk);
    return true;
  } catch (e) {
    await run("delete from myob_invoice_links where invoice_id=$1 and myob_uid='pending'", [inv.id]);
    throw e;
  }
}
async function sendInvoice(c, inv, lk) {
  lk = lk || await lookups(c);
  const cust = await customerUid(c, inv, lk.tax);
  const d = inv.created_at ? new Date(inv.created_at) : new Date();
  const r = await api(c, "POST", "/Sale/Invoice/Service", {
    Date: d.toISOString().slice(0, 19), Customer: { UID: cust }, IsTaxInclusive: true,
    CustomerPurchaseOrderNumber: String(inv.number || "").slice(0, 20),
    JournalMemo: ("SolarSync " + (inv.number || "")).slice(0, 255),
    Lines: [{ Type: "Transaction", Description: String(inv.description || ("Invoice " + inv.number)).slice(0, 255),
      Total: Number(inv.amount) || 0, Account: { UID: lk.acct }, TaxCode: { UID: lk.tax } }],
  });
  if (!r.uid) throw new Error("MYOB: invoice was not created");
  await run("update myob_invoice_links set myob_uid=$1, pushed_at=now() where invoice_id=$2", [r.uid, inv.id]);
}

// Push every invoice MYOB doesn't have yet, then mark invoices paid that MYOB shows as closed.
async function syncTenant(tenantId, erp) {
  const c = await conn(tenantId);
  if (!c || c.status !== "connected" || !c.business_id) throw new Error("not_connected");
  const out = { pushed: 0, paid: 0, errors: [] };
  try {
    const todo = await rows(`select * from invoices i where tenant_id=$1 and coalesce(is_demo,false)=false
      and not exists (select 1 from myob_invoice_links l where l.invoice_id=i.id) order by created_at`, [tenantId]);
    let lk = null;
    for (const inv of todo) {
      try { lk = lk || await lookups(c); if (await pushInvoice(c, inv, lk)) out.pushed++; }
      catch (e) { if (e.message === "myob_reconnect" || !lk) throw e; out.errors.push(inv.number + ": " + e.message); }
    }
    const open = await rows(`select i.*, l.myob_uid from invoices i join myob_invoice_links l on l.invoice_id=i.id
      where i.tenant_id=$1 and i.status<>'paid' and l.myob_uid<>'pending'`, [tenantId]);
    for (const inv of open) {
      try {
        const { data } = await api(c, "GET", "/Sale/Invoice/Service/" + encodeURIComponent(inv.myob_uid));
        if (data && (data.Status === "Closed" || Number(data.BalanceDueAmount) === 0)) {
          await run("update invoices set status='paid', paid_at=now() where id=$1 and status<>'paid'", [inv.id]);
          await audit(null, "invoice_paid_myob", inv.id, tenantId);
          if (erp) { try { await erp.postInvoicePaid(inv, "myob"); } catch (e) { console.error("ledger post (myob paid) failed:", e.message); } }
          out.paid++;
        }
      } catch (e) { if (e.message === "myob_reconnect") throw e; out.errors.push(inv.number + ": " + e.message); }
    }
    await run("update accounting_connections set last_sync=now(), last_error=$1 where tenant_id=$2 and provider=$3",
      [out.errors.length ? out.errors.slice(0, 3).join("; ").slice(0, 400) : null, tenantId, PROVIDER]);
  } catch (e) {
    await setError(tenantId, e.message === "myob_reconnect" ? "MYOB sign-in expired — reconnect MYOB" : e.message);
    throw e;
  }
  return out;
}

function register(app, { h, ok, erp }) {
  const admin = [A.authRequired, A.requireRole("tenant_admin")];
  const staff = [A.authRequired, A.requireRole("tenant_admin", "staff")];
  const tid = (req) => req.user.tenant_id;

  app.get("/api/integrations/myob", ...staff, h(async (req, res) => {
    const c = await conn(tid(req));
    const pushed = await one("select count(*)::int as n from myob_invoice_links where tenant_id=$1 and myob_uid<>'pending'", [tid(req)]);
    ok(res, {
      configured: configured(),
      status: (c && c.status) || "disconnected",
      connected: !!(c && c.status === "connected"),
      business_name: (c && c.business_name) || null,
      last_sync: (c && c.last_sync) || null, last_error: (c && c.last_error) || null,
      settings: settingsOf(c), invoices_pushed: (pushed && pushed.n) || 0,
    });
  }));

  // Start sign-in: returns MYOB's consent page URL (state is signed and short-lived).
  app.post("/api/integrations/myob/connect", ...admin, h(async (req, res) => {
    if (!configured()) return res.status(503).json({ error: "myob_not_configured" });
    const state = jwt.sign({ typ: "myob_state", tid: tid(req), sub: req.user.sub }, A.JWT_SECRET, { expiresIn: "15m" });
    const u = new URL(AUTH_BASE + "/oauth2/account/authorize");
    u.search = new URLSearchParams({ client_id: process.env.MYOB_CLIENT_ID, redirect_uri: redirectUri(req),
      response_type: "code", scope: SCOPES, prompt: "consent", state }).toString();
    ok(res, { url: u.toString() });
  }));

  // MYOB sends the browser back here with ?code, ?businessId and our state.
  app.get("/api/integrations/myob/callback", h(async (req, res) => {
    const back = (s) => res.redirect("/app?myob=" + encodeURIComponent(s));
    let st; try { st = jwt.verify(String(req.query.state || ""), A.JWT_SECRET); } catch (e) { return back("expired"); }
    if (st.typ !== "myob_state" || !st.tid) return back("expired");
    if (req.query.error) return back("cancelled");
    const businessId = String(req.query.businessId || req.query.businessid || "");
    if (!req.query.code || !/^[0-9a-fA-F-]{36}$/.test(businessId)) return back("no_file");
    try {
      const t = await tokenRequest({ grant_type: "authorization_code", code: String(req.query.code), redirect_uri: redirectUri(req), scope: SCOPES });
      await run(`insert into accounting_connections (tenant_id, provider, tokens_enc, status, business_id, connected_by, last_error)
        values ($1,$2,$3,'connected',$4,$5,null)
        on conflict (tenant_id, provider) do update set tokens_enc=excluded.tokens_enc, status='connected',
          business_id=excluded.business_id, connected_by=excluded.connected_by, last_error=null`,
        [st.tid, PROVIDER, seal(t), businessId, st.sub]);
      const c = await conn(st.tid);
      try { const { data } = await api(c, "GET", "/Company"); if (data && data.CompanyName)
        await run("update accounting_connections set business_name=$1 where tenant_id=$2 and provider=$3", [String(data.CompanyName).slice(0, 200), st.tid, PROVIDER]); }
      catch (e) { /* name is cosmetic */ }
      await audit(st.sub, "myob_connected", businessId, st.tid);
      back("connected");
    } catch (e) { console.error("myob callback failed:", e.message); back("failed"); }
  }));

  app.put("/api/integrations/myob/settings", ...admin, h(async (req, res) => {
    const c = await conn(tid(req));
    if (!c) return res.status(409).json({ error: "not_connected" });
    const b = req.body || {}; const cur = settingsOf(c);
    const next = {
      income_account: /^\d-\d{4}$/.test(String(b.income_account || "")) ? String(b.income_account) : cur.income_account,
      tax_code: /^[A-Za-z0-9]{1,3}$/.test(String(b.tax_code || "")) ? String(b.tax_code).toUpperCase() : cur.tax_code,
      auto_push: typeof b.auto_push === "boolean" ? b.auto_push : cur.auto_push,
    };
    await run("update accounting_connections set settings=$1::jsonb where tenant_id=$2 and provider=$3", [JSON.stringify(next), c.tenant_id, PROVIDER]);
    ok(res, next);
  }));

  app.post("/api/integrations/myob/sync", ...staff, h(async (req, res) => {
    try { ok(res, await syncTenant(tid(req), erp)); }
    catch (e) {
      if (e.message === "not_connected") return res.status(409).json({ error: "not_connected" });
      if (e.message === "myob_reconnect") return res.status(409).json({ error: "myob_reconnect" });
      res.status(502).json({ error: "myob_failed", message: e.message });
    }
  }));

  app.delete("/api/integrations/myob", ...admin, h(async (req, res) => {
    await run("update accounting_connections set status='disconnected', tokens_enc=null where tenant_id=$1 and provider=$2", [tid(req), PROVIDER]);
    await audit(req.user.sub, "myob_disconnected", null, tid(req));
    ok(res, { ok: true });
  }));

  // Background: every 15 minutes, sync each connected tenant (new invoices out, payments back).
  if (configured() && process.env.NODE_ENV !== "test") {
    setInterval(async () => {
      try {
        for (const c of await rows("select tenant_id from accounting_connections where provider=$1 and status='connected'", [PROVIDER]))
          await syncTenant(c.tenant_id, erp).catch(() => {});
      } catch (e) { console.error("myob background sync failed:", e.message); }
    }, 15 * 60 * 1000).unref();
  }
}

// Called after an invoice is created: push it straight away when the tenant wants that.
async function onInvoiceCreated(inv) {
  try {
    if (!configured() || !inv || inv.is_demo) return;
    const c = await conn(inv.tenant_id);
    if (!c || c.status !== "connected" || !settingsOf(c).auto_push) return;
    await pushInvoice(c, inv);
  } catch (e) {
    await setError(inv.tenant_id, e.message === "myob_reconnect" ? "MYOB sign-in expired — reconnect MYOB" : e.message).catch(() => {});
  }
}

module.exports = { register, onInvoiceCreated, syncTenant, configured };
