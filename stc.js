// SolarSync — STC (small-scale technology certificate) calculator.
//
// Solar panels follow the Clean Energy Regulator's method:
//   STCs = rated output (kW) × postcode zone rating × deeming years, rounded down.
//   Deeming years = whole years left in the scheme, which ends in 2030
//   (an install in 2026 gets 5).
// The postcode → zone table comes from the Clean Energy Regulator's published
// file. The reseller uploads it (CSV), so the app never depends on an outside site.
// Battery STCs use a per-kWh rate each tenant enters from the regulator's figures.
const { rows, one, run, audit } = require("./db");
const A = require("./auth");

// Zone ratings in MWh per kW of rated output (Clean Energy Regulator).
const ZONE_RATINGS = { 1: 1.622, 2: 1.536, 3: 1.382, 4: 1.185 };
const SCHEME_END = 2030;
const BATTERY_MAX_KWH = 50;            // STCs are created on at most 50 kWh usable

const deemingYears = (year) => Math.max(0, SCHEME_END - Number(year) + 1);

function panelStcs(kw, zone, year) {
  const r = ZONE_RATINGS[zone];
  if (!r || !(kw > 0)) return 0;
  return Math.floor(kw * r * deemingYears(year));
}

// Parse the regulator's postcode file. Accepts rows like "800,821,2" (from, to,
// zone) or "800,2" (single postcode, zone); a header row and other columns are ignored.
function parsePostcodeCsv(text) {
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const nums = (line.match(/\d+(\.\d+)?/g) || []).map(Number);
    const ints = nums.filter(n => Number.isInteger(n));
    if (ints.length < 2) continue;
    const zone = ints[ints.length - 1];
    if (zone < 1 || zone > 4) continue;
    const from = ints[0], to = ints.length >= 3 ? ints[1] : ints[0];
    if (from > 9999 || to > 9999 || to < from) continue;
    out.push([from, to, zone]);
  }
  return out;
}

async function zoneFor(postcode) {
  const pc = parseInt(String(postcode || "").trim(), 10);
  if (!(pc >= 0 && pc <= 9999)) return null;
  const r = await one("select zone from stc_postcode_zones where pc_from <= $1 and pc_to >= $1 order by pc_to - pc_from limit 1", [pc]);
  return r ? r.zone : null;
}

function register(app, { h, ok }) {
  const field = [A.authRequired, A.requireRole("tenant_admin", "staff", "contractor", "reseller")];

  app.get("/api/stc/zone", ...field, h(async (req, res) => {
    const loaded = !!(await one("select 1 from stc_postcode_zones limit 1"));
    const zone = loaded ? await zoneFor(req.query.postcode) : null;
    ok(res, { zone, rating: zone ? ZONE_RATINGS[zone] : null, table_loaded: loaded });
  }));

  app.get("/api/stc/settings", ...field, h(async (req, res) => {
    const t = req.user.tenant_id ? await one("select stc_settings from tenants where id=$1", [req.user.tenant_id]) : null;
    const loaded = await one("select count(*)::int as n, max(loaded_at) as at from stc_postcode_zones");
    ok(res, { ...((t && t.stc_settings) || {}), zone_ratings: ZONE_RATINGS, scheme_end: SCHEME_END,
      battery_max_kwh: BATTERY_MAX_KWH, postcode_rows: loaded.n, postcodes_loaded_at: loaded.at });
  }));

  app.put("/api/stc/settings", A.authRequired, A.requireRole("tenant_admin"), h(async (req, res) => {
    const d = req.body || {};
    const num = (v, max) => (v === "" || v == null) ? null : (Number(v) >= 0 && Number(v) <= max ? Number(v) : undefined);
    const s = { stc_price: num(d.stc_price, 100), battery_factor: num(d.battery_factor, 50) };
    if (Object.values(s).includes(undefined)) return res.status(400).json({ error: "bad_value" });
    await run("update tenants set stc_settings=$1 where id=$2", [JSON.stringify(s), req.user.tenant_id]);
    await audit(req.user.sub, "stc_settings", req.user.tenant_id, req.user.tenant_id, s);
    ok(res, s);
  }));

  // Reseller loads the regulator's postcode → zone file for the whole platform.
  app.post("/api/stc/postcodes", A.authRequired, A.requireRole("reseller"), h(async (req, res) => {
    const list = parsePostcodeCsv(req.body && req.body.csv);
    if (list.length < 50) return res.status(400).json({ error: "not_a_postcode_file", rows: list.length });
    await run("delete from stc_postcode_zones");
    for (let i = 0; i < list.length; i += 500) {
      const chunk = list.slice(i, i + 500);
      const vals = chunk.map((_, k) => `($${k * 3 + 1},$${k * 3 + 2},$${k * 3 + 3})`).join(",");
      await run(`insert into stc_postcode_zones (pc_from, pc_to, zone) values ${vals}`, chunk.flat());
    }
    await audit(req.user.sub, "stc_postcodes_loaded", String(list.length), null);
    ok(res, { rows: list.length });
  }));
}

module.exports = { register, panelStcs, deemingYears, parsePostcodeCsv, ZONE_RATINGS };
