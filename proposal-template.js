// SolarSync — "Bold" proposal template.
//
// Each tenant keeps one company template: the look (blue, dark or their brand
// colour), page order and hidden pages, their own default wording, payment
// schedule, warranties and photos. Staff build every proposal from it and can
// still change any text or photo on a single proposal.
//
// The same design is sold on its own as the Proposal Template Pack add-on
// ($19/month): an editable PowerPoint file with the tenant's logo, colours and
// photos, for tenants who just want the documents.
const { one, run, rows, audit } = require("./db");
const A = require("./auth");

const LOOKS = ["blue", "dark", "brand"];
const PAGES = ["cover", "intro", "overview", "glance", "benefits", "savings", "invest", "timeline", "whyus", "next", "ready", "contact"];
const PHOTO_SLOTS = ["hero", "team", "install", "handover", "panels", "inverter", "meter", "app", "sign", "phone", "sky", "closeup"];
const MAX_PHOTO = 1.6 * 1024 * 1024;   // data-URL length; the browser resizes to ~1600px first
const MAX_TEXT = 1200;

const str = (v, n = MAX_TEXT) => (typeof v === "string" ? v.slice(0, n) : "");
const isColour = v => typeof v === "string" && /^#[0-9a-f]{6}$/i.test(v);

// Keep only the fields the app understands, as plain text (never HTML).
function clean(s) {
  s = s && typeof s === "object" ? s : {};
  const text = {};
  if (s.text && typeof s.text === "object") for (const [k, v] of Object.entries(s.text).slice(0, 200)) {
    if (/^[a-z0-9_.]{1,60}$/i.test(k) && typeof v === "string") text[k] = str(v);
  }
  const list = (a, f, n) => (Array.isArray(a) ? a.slice(0, n).map(f).filter(Boolean) : undefined);
  return {
    look: LOOKS.includes(s.look) ? s.look : "blue",
    brand_color: isColour(s.brand_color) ? s.brand_color : "",
    default_template: s.default_template === "bold" ? "bold" : "classic",
    hidden: list(s.hidden, k => (PAGES.includes(k) ? k : null), PAGES.length) || [],
    text,
    payment: list(s.payment, p => (p && str(p.label, 60) ? { label: str(p.label, 60), pct: Math.max(0, Math.min(100, Number(p.pct) || 0)) } : null), 6),
    warranties: list(s.warranties, w => (w && str(w.label, 60) ? { label: str(w.label, 60), value: str(w.value, 40) } : null), 8),
    qr_url: /^https?:\/\/\S{3,300}$/i.test(s.qr_url || "") ? s.qr_url : "",
  };
}

async function load(tenantId) {
  const r = await one("select settings from proposal_templates where tenant_id=$1", [tenantId]);
  return clean(r && r.settings);
}
async function photos(tenantId) {
  const out = {};
  for (const p of await rows("select slot, data from proposal_photos where tenant_id=$1", [tenantId])) out[p.slot] = p.data;
  return out;
}
// Templates plan ($19/month): the company only gets the proposal templates, so
// every other tenant API is refused for its users. Full plans include the
// templates. Plans are looked up per request (cached briefly).
const TEMPLATES_OK = [/^\/api\/auth\//, /^\/api\/me\b/, /^\/api\/my-features$/, /^\/api\/proposal-template\b/,
  /^\/api\/billing\b/, /^\/api\/letterhead\b/, /^\/api\/branding\b/, /^\/api\/documents\b/];
const planCache = new Map();
async function planOf(tenantId) {
  const c = planCache.get(tenantId);
  if (c && c.at > Date.now() - 30000) return c.plan;
  const t = await one("select plan from tenants where id=$1", [tenantId]);
  planCache.set(tenantId, { plan: t && t.plan, at: Date.now() });
  return t && t.plan;
}
function templatesOnlyGuard() {
  return async (req, res, next) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
    if (!m) return next();
    let p; try { p = A.verify(m[1]); } catch (e) { return next(); }   // authRequired reports bad tokens
    if (!p.tenant_id || p.app_role === "reseller") return next();
    try {
      if ((await planOf(p.tenant_id)) !== "Templates") return next();
      const path = req.baseUrl + req.path;
      if (TEMPLATES_OK.some(re => re.test(path))) return next();
      res.status(403).json({ error: "templates_plan" });
    } catch (e) { next(e); }
  };
}
async function qrFor(url) {
  if (!url) return null;
  try { return await require("qrcode").toDataURL(url, { margin: 1, width: 240 }); } catch (e) { return null; }
}

// Colour helpers matching with the browser renderer (public/index.html, boldPalette).
function mix(a, b, t) {
  const p = x => [1, 3, 5].map(i => parseInt(x.slice(i, i + 2), 16));
  const [r1, g1, b1] = p(a), [r2, g2, b2] = p(b);
  return "#" + [r1 + (r2 - r1) * t, g1 + (g2 - g1) * t, b1 + (b2 - b1) * t].map(v => Math.round(v).toString(16).padStart(2, "0")).join("");
}
function palette(look, base) {
  if (look === "dark") return { bg: "#06162e", ink: "#ffffff", muted: "#9aa8c0", b1: "#0f4f9a", b2: "#1d6fd1", b3: "#0a3770", card: "#0e2a52" };
  if (look === "brand" && isColour(base)) return { bg: "#ffffff", ink: "#141414", muted: "#6b7280", b1: mix(base, "#ffffff", 0.08), b2: mix(base, "#ffffff", 0.32), b3: mix(base, "#000000", 0.06), card: base };
  return { bg: "#ffffff", ink: "#0b0b0b", muted: "#6b7280", b1: "#003a78", b2: "#0052a0", b3: "#00295a", card: "#00336d" };
}

function register(app, { h, ok }) {
  const makers = [A.authRequired, A.requireRole("tenant_admin", "staff", "contractor")];
  const admin = [A.authRequired, A.requireRole("tenant_admin")];
  const tid = req => req.user.tenant_id;

  app.get("/api/proposal-template", ...makers, h(async (req, res) => {
    if (!tid(req)) return ok(res, { settings: clean({}), photos: {}, qr: null, pack_active: true });
    const settings = await load(tid(req));
    ok(res, { settings, photos: await photos(tid(req)), qr: await qrFor(settings.qr_url), pack_active: true });
  }));

  app.put("/api/proposal-template", ...admin, h(async (req, res) => {
    if (!tid(req)) return res.status(400).json({ error: "no_tenant" });
    const settings = clean(req.body && req.body.settings);
    await run(`insert into proposal_templates (tenant_id, settings, updated_at) values ($1,$2,now())
      on conflict (tenant_id) do update set settings=excluded.settings, updated_at=now()`, [tid(req), JSON.stringify(settings)]);
    await audit(req.user.sub, "proposal_template_save", "proposal_template", tid(req), { look: settings.look });
    ok(res, { settings, qr: await qrFor(settings.qr_url) });
  }));

  app.put("/api/proposal-template/photos/:slot", ...admin, h(async (req, res) => {
    const slot = req.params.slot, data = req.body && req.body.data;
    if (!PHOTO_SLOTS.includes(slot)) return res.status(400).json({ error: "bad_slot" });
    if (typeof data !== "string" || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(data)) return res.status(400).json({ error: "bad_image" });
    if (data.length > MAX_PHOTO) return res.status(413).json({ error: "image_too_large" });
    await run(`insert into proposal_photos (tenant_id, slot, data, updated_at) values ($1,$2,$3,now())
      on conflict (tenant_id, slot) do update set data=excluded.data, updated_at=now()`, [tid(req), slot, data]);
    ok(res, { ok: true });
  }));

  app.delete("/api/proposal-template/photos/:slot", ...admin, h(async (req, res) => {
    await run("delete from proposal_photos where tenant_id=$1 and slot=$2", [tid(req), req.params.slot]);
    ok(res, { ok: true });
  }));
}

module.exports = { register, templatesOnlyGuard, clean, palette, PAGES, PHOTO_SLOTS };
