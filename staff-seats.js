// SolarSync — staff & contractor seat management (Express router)
// Drop-in module. CommonJS, uses your existing pg-style db + JWT auth.
//
// ── INTEGRATION (server.js) ─────────────────────────────────────────────
//   const staffSeats = require('./staff-seats');
//   app.use('/api/staff', staffSeats);           // after your auth middleware
//
// Wired into server.js as:
//   app.use('/api/staff', A.authRequired, require('./staff-seats'));
//
// Matches this app's actual conventions (confirmed against auth.js/db.js):
//   - req.user = { sub, app_role, tenant_id, display_name } (from auth.js JWT).
//   - app_role values: 'reseller' (super, any tenant) | 'tenant_admin' (bounded
//     by seat limit) | 'staff' | 'contractor' | 'client'.
//   - All IDs (tenants.id, tenant_staff.id) are text, generated with db.js's
//     rid() — not integers/SERIAL.
//   - db.js exports query(sql, params) returning { rows }, plus rid().
//   - staff_seat_limit column + tenant_staff table are created automatically
//     by db.js's migrate() (runs on every boot) — no manual SQL needed.
// ─────────────────────────────────────────────────────────────────────────

const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const db = require('./db');
const { rid } = db;

// Map subscription plan -> number of staff seats. Tune to your Stripe prices.
const PLAN_SEATS = {
  starter: 3,
  pro: 10,
  business: 25,
  enterprise: 100,
};

// Resolve which tenant this request may act on.
// Reseller may pass ?tenant_id / body.tenant_id for any tenant; others are locked
// to their own token's tenant_id.
function resolveTenantId(req) {
  const isReseller = req.user && req.user.app_role === 'reseller';
  const requested = req.body.tenant_id || req.query.tenant_id;
  if (isReseller && requested) return String(requested);
  return req.user ? req.user.tenant_id || null : null;
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// Only reseller or a tenant admin may manage staff.
function requireManager(req, res, next) {
  const role = req.user && req.user.app_role;
  if (role === 'reseller' || role === 'tenant_admin') return next();
  return res.status(403).json({ error: 'Not allowed to manage staff' });
}

// GET /api/staff  -> list staff + seat usage for the tenant
router.get('/', requireAuth, async (req, res) => {
  const tenantId = resolveTenantId(req);
  if (!tenantId) return res.status(400).json({ error: 'No tenant context' });
  try {
    const staff = await db.query(
      `SELECT id, name, email, role, member_type, counts_seat, status, created_at
         FROM tenant_staff
        WHERE tenant_id = $1 AND status <> 'removed'
        ORDER BY created_at DESC`,
      [tenantId]
    );
    const usage = await getSeatUsage(tenantId);
    res.json({ tenant_id: tenantId, ...usage, staff: staff.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/staff  -> add a staff member / contractor (enforces seat limit)
// body: { name, email?, role?, member_type?, counts_seat?, pin?, tenant_id? }
router.post('/', requireAuth, requireManager, async (req, res) => {
  const tenantId = resolveTenantId(req);
  if (!tenantId) return res.status(400).json({ error: 'No tenant context' });

  const {
    name, email = null,
    role = 'staff',
    member_type = 'employee',
    pin = null,
  } = req.body;

  if (!name) return res.status(400).json({ error: 'name is required' });

  // Contractors default to NOT consuming a seat; employees do. Override with body.counts_seat.
  const counts_seat =
    typeof req.body.counts_seat === 'boolean'
      ? req.body.counts_seat
      : member_type !== 'contractor';

  try {
    // Reseller bypasses the seat limit; tenant admins are bounded by it.
    if (req.user.app_role !== 'reseller' && counts_seat) {
      const usage = await getSeatUsage(tenantId);
      if (usage.seats_used >= usage.seat_limit) {
        return res.status(409).json({
          error: 'Seat limit reached',
          message: `Your plan allows ${usage.seat_limit} staff seats and all are in use. ` +
                   `Remove a member or upgrade your subscription to add more.`,
          ...usage,
        });
      }
    }

    const pin_hash = pin ? await bcrypt.hash(String(pin), 10) : null;
    const created_by = req.user.display_name || req.user.sub || 'system';

    const ins = await db.query(
      `INSERT INTO tenant_staff
         (id, tenant_id, name, email, role, member_type, counts_seat, pin_hash, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING id, name, email, role, member_type, counts_seat, status, created_at`,
      [rid(), tenantId, name, email, role, member_type, counts_seat, pin_hash, created_by]
    );
    const usage = await getSeatUsage(tenantId);
    res.status(201).json({ member: ins.rows[0], ...usage });
  } catch (e) {
    if (/unique/i.test(e.message)) {
      return res.status(409).json({ error: 'A staff member with that email already exists for this tenant' });
    }
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/staff/:id  -> remove (frees a seat). Soft-delete keeps history.
router.delete('/:id', requireAuth, requireManager, async (req, res) => {
  const tenantId = resolveTenantId(req);
  try {
    await db.query(
      `UPDATE tenant_staff SET status = 'removed'
        WHERE id = $1 AND tenant_id = $2`,
      [req.params.id, tenantId]
    );
    const usage = await getSeatUsage(tenantId);
    res.json({ ok: true, ...usage });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Count active, seat-consuming members vs the tenant's limit.
async function getSeatUsage(tenantId) {
  const lim = await db.query(
    `SELECT COALESCE(staff_seat_limit, 0) AS seat_limit FROM tenants WHERE id = $1`,
    [tenantId]
  );
  const used = await db.query(
    `SELECT COUNT(*)::int AS n FROM tenant_staff
      WHERE tenant_id = $1 AND status = 'active' AND counts_seat = TRUE`,
    [tenantId]
  );
  const seat_limit = lim.rows[0] ? lim.rows[0].seat_limit : 0;
  const seats_used = used.rows[0] ? used.rows[0].n : 0;
  return { seat_limit, seats_used, seats_available: Math.max(0, seat_limit - seats_used) };
}

// Call this from your Stripe webhook when a subscription is created/updated,
// so the seat limit always matches the plan.
async function setSeatLimitForPlan(tenantId, planKey) {
  const seats = PLAN_SEATS[planKey];
  if (!seats) return;
  await db.query(`UPDATE tenants SET staff_seat_limit = $1 WHERE id = $2`, [seats, tenantId]);
}

module.exports = router;
module.exports.getSeatUsage = getSeatUsage;
module.exports.setSeatLimitForPlan = setSeatLimitForPlan;
module.exports.PLAN_SEATS = PLAN_SEATS;
