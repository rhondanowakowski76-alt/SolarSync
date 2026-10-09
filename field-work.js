// SolarSync — field work: availability, crew clash checks and field documents.
//
//   - Availability: staff and contractors keep their own calendar entries
//     ("not available" blocks and personal entries). Tenant admins see everyone
//     in their tenant and can add or remove entries for any member.
//   - Crew: a booking's `installer` field may hold several names ("A, B").
//     crewClashes() reports anyone booked who has marked themselves unavailable.
//   - Field documents: a member's own compliance documents (licence, insurance,
//     white card ...) and documents attached to a job. Files are stored in the
//     database as data URLs so the app needs no outside storage service.
const { rows, one, run, rid, audit } = require("./db");
const A = require("./auth");

const FIELD_ROLES = ["tenant_admin", "staff", "contractor"];
const MAX_DOC_CHARS = 11 * 1024 * 1024;   // ~8 MB file once base64-encoded
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const isAdmin = (req) => req.user.app_role === "tenant_admin";
const tenantOf = (req) => req.user.tenant_id;
const myName = (req) => String(req.user.display_name || "").trim();

// "Dan Webb, Kira Park" -> ["Dan Webb", "Kira Park"]
function crewNames(installer) {
  return String(installer || "").split(",").map(s => s.trim()).filter(Boolean);
}

// Who in `installer` is marked unavailable on `date`? Returns [{ person, reason }].
async function crewClashes(tenantId, installer, date) {
  const names = crewNames(installer);
  if (!names.length || !date || !DATE_RE.test(String(date))) return [];
  const r = await rows(
    `select person, title from availability
      where tenant_id=$1 and kind='unavailable' and date_from <= $2 and date_to >= $2`,
    [tenantId, String(date)]);
  const want = new Set(names.map(n => n.toLowerCase()));
  return r.filter(a => want.has(String(a.person).toLowerCase()))
          .map(a => ({ person: a.person, reason: a.title || "Not available" }));
}

function register(app, { h, ok }) {
  // ── Availability ──────────────────────────────────────────────
  const AV_COLS = "id, tenant_id, user_id, person, kind, title, date_from, date_to, time, end_time, notes, created_at";

  app.get("/api/availability", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    // Everyone in the tenant sees "not available" blocks (needed to schedule around
    // them); personal entries are visible only to their owner and the tenant admin.
    const r = await rows(`select ${AV_COLS} from availability where tenant_id=$1 order by date_from, time`, [tenantOf(req)]);
    ok(res, r.filter(a => isAdmin(req) || a.user_id === req.user.sub || a.kind === "unavailable")
             .map(a => (isAdmin(req) || a.user_id === req.user.sub) ? a : { ...a, notes: null }));
  }));

  app.post("/api/availability", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const d = req.body || {};
    const kind = d.kind === "entry" ? "entry" : "unavailable";
    const from = String(d.date_from || "");
    const to = String(d.date_to || d.date_from || "");
    if (!DATE_RE.test(from) || !DATE_RE.test(to)) return res.status(400).json({ error: "dates_required" });
    if (to < from) return res.status(400).json({ error: "end_before_start" });
    if (kind === "entry" && !String(d.title || "").trim()) return res.status(400).json({ error: "title_required" });
    // Members add their own entries; only a tenant admin may add one for someone else.
    const person = isAdmin(req) && d.person ? String(d.person).trim().slice(0, 80) : myName(req);
    if (!person) return res.status(400).json({ error: "person_required" });
    const id = "av-" + rid().slice(0, 10);
    await run(`insert into availability (id, tenant_id, user_id, person, kind, title, date_from, date_to, time, end_time, notes)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [id, tenantOf(req), person === myName(req) ? req.user.sub : null, person, kind,
       String(d.title || "").slice(0, 120) || null, from, to,
       d.time || null, d.end_time || null, String(d.notes || "").slice(0, 1000) || null]);
    await audit(req.user.sub, "availability_add", id, tenantOf(req), { kind, from, to });
    ok(res, await one(`select ${AV_COLS} from availability where id=$1`, [id]));
  }));

  app.delete("/api/availability/:id", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const cur = await one("select * from availability where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (!isAdmin(req) && cur.user_id !== req.user.sub) return res.status(403).json({ error: "forbidden" });
    await run("delete from availability where id=$1", [cur.id]);
    await audit(req.user.sub, "availability_remove", cur.id, cur.tenant_id);
    ok(res, { ok: true });
  }));

  // Clash check the scheduler calls before saving a booking.
  app.get("/api/availability/clashes", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) =>
    ok(res, await crewClashes(tenantOf(req), req.query.installer, req.query.date))));

  // ── Field documents ───────────────────────────────────────────
  const DOC_COLS = "id, tenant_id, user_id, person, scope, job_id, category, name, mime, size, expiry, created_at";

  // List: members see their own documents plus documents on jobs; the admin sees all.
  app.get("/api/field-docs", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const params = [tenantOf(req)];
    let where = "tenant_id=$1";
    if (req.query.job_id) { params.push(String(req.query.job_id)); where += ` and job_id=$${params.length}`; }
    if (req.query.scope) { params.push(String(req.query.scope)); where += ` and scope=$${params.length}`; }
    if (!isAdmin(req)) { params.push(req.user.sub); where += ` and (user_id=$${params.length} or scope='job')`; }
    ok(res, await rows(`select ${DOC_COLS} from field_documents where ${where} order by created_at desc`, params));
  }));

  app.post("/api/field-docs", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const d = req.body || {};
    const scope = d.scope === "job" ? "job" : "compliance";
    const data = String(d.data || "");
    const m = /^data:([a-z0-9.+\/-]+);base64,/i.exec(data);
    if (!m) return res.status(400).json({ error: "data_must_be_base64_data_url" });
    if (!/^(application\/pdf|image\/(png|jpe?g|webp|heic|heif)|application\/(msword|vnd\.openxmlformats-officedocument\.wordprocessingml\.document))$/i.test(m[1]))
      return res.status(415).json({ error: "file_type_not_allowed" });
    if (data.length > MAX_DOC_CHARS) return res.status(413).json({ error: "file_too_large" });
    if (scope === "job" && !d.job_id) return res.status(400).json({ error: "job_id_required" });
    if (d.expiry && !DATE_RE.test(String(d.expiry))) return res.status(400).json({ error: "bad_expiry" });
    const id = "fd-" + rid().slice(0, 10);
    await run(`insert into field_documents (id, tenant_id, user_id, person, scope, job_id, category, name, mime, size, expiry, data)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, tenantOf(req), req.user.sub, myName(req) || null, scope, scope === "job" ? String(d.job_id) : null,
       String(d.category || "Other").slice(0, 60), String(d.name || "document").slice(0, 160), m[1].toLowerCase(),
       Math.round(data.length * 0.75), d.expiry || null, data]);
    await audit(req.user.sub, "field_doc_upload", id, tenantOf(req), { scope, job_id: d.job_id || null });
    ok(res, await one(`select ${DOC_COLS} from field_documents where id=$1`, [id]));
  }));

  const canSee = (req, doc) => doc && doc.tenant_id === tenantOf(req)
    && (isAdmin(req) || doc.user_id === req.user.sub || doc.scope === "job");

  app.get("/api/field-docs/:id/file", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const doc = await one("select * from field_documents where id=$1", [req.params.id]);
    if (!canSee(req, doc)) return res.status(404).json({ error: "not_found" });
    ok(res, { name: doc.name, mime: doc.mime, data: doc.data });
  }));

  app.delete("/api/field-docs/:id", A.authRequired, A.requireRole(...FIELD_ROLES), h(async (req, res) => {
    const doc = await one("select * from field_documents where id=$1", [req.params.id]);
    if (!doc || doc.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (!isAdmin(req) && doc.user_id !== req.user.sub) return res.status(403).json({ error: "forbidden" });
    await run("delete from field_documents where id=$1", [doc.id]);
    await audit(req.user.sub, "field_doc_delete", doc.id, doc.tenant_id);
    ok(res, { ok: true });
  }));
}

module.exports = { register, crewClashes, crewNames };
