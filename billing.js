// SolarSync — tenant subscriptions through Stripe.
//
//   Plans (AUD per month, ex-GST; GST is added at checkout):
//     Starter $199 · 5 seats   Growth $499 · 25 seats   Scale $899 · unlimited
//   Extra seat: $15/month each. Add-ons from the `addons` table (AI assistant $19).
//
//   - A seat is any active tenant login: tenant admins, staff and contractors.
//     End customers (client logins) never use a seat.
//   - When every seat is used, adding a person is blocked until the tenant buys an
//     extra seat. Buying one charges the card straight away (pro-rata) and the seat
//     unlocks only once Stripe accepts the payment.
//   - Signup runs through Stripe Checkout with a 14-day free trial; the card is
//     collected up front and charged when the trial ends.
//   - Stripe prices are created once and remembered in platform_settings, so no
//     manual setup is needed in the Stripe dashboard.
const { rows, one, run, audit } = require("./db");
const A = require("./auth");

const PLANS = {
  Starter: { price: 199, seats: 5 },
  Growth: { price: 499, seats: 25 },
  Scale: { price: 899, seats: null },   // unlimited
};
const SEAT_PRICE = 15;
const TRIAL_DAYS = 14;
const AI_MONTHLY_CAP = 300;             // assistant replies per tenant per month
const SEAT_ROLES = ["tenant_admin", "staff", "contractor"];
const LIVE_STATUSES = ["trialing", "active", "past_due"];

let _stripe = null;
function stripe() {
  if (_stripe) return _stripe;
  if (!process.env.STRIPE_SECRET_KEY) return null;
  _stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
  return _stripe;
}

async function setting(key) { const r = await one("select value from platform_settings where key=$1", [key]); return r ? r.value : null; }
async function setSetting(key, value) {
  await run(`insert into platform_settings (key, value) values ($1,$2)
    on conflict (key) do update set value=excluded.value`, [key, value]);
}

// One 10% GST rate, added on top of the ex-GST prices.
async function gstRate() {
  let id = await setting("stripe_gst_rate");
  if (id) return id;
  const r = await stripe().taxRates.create({ display_name: "GST", percentage: 10, inclusive: false, country: "AU", description: "Australian GST" });
  await setSetting("stripe_gst_rate", r.id);
  return r.id;
}

// A monthly AUD price, created the first time it's needed. The key includes the
// amount, so changing a price here creates a new Stripe price automatically.
async function priceFor(key, name, dollars) {
  const k = `stripe_price:${key}:${Math.round(dollars * 100)}`;
  let id = await setting(k);
  if (id) return id;
  const p = await stripe().prices.create({
    currency: "aud", unit_amount: Math.round(dollars * 100), recurring: { interval: "month" },
    product_data: { name: "SolarSync " + name }, metadata: { ss_key: key },
  });
  await setSetting(k, p.id);
  return p.id;
}
const planPrice = (plan) => priceFor("plan-" + plan.toLowerCase(), plan + " plan", PLANS[plan].price);
const seatPrice = () => priceFor("seat", "extra seat", SEAT_PRICE);
async function addonPrice(key) {
  const a = await one("select key, name, price from addons where key=$1", [key]);
  if (!a || !(Number(a.price) > 0)) return null;
  return priceFor("addon-" + key, a.name + " add-on", Number(a.price));
}

async function seatUsage(tenantId) {
  const t = await one("select plan, extra_seats from tenants where id=$1", [tenantId]);
  const plan = PLANS[t && t.plan] ? t.plan : "Growth";
  const base = PLANS[plan].seats;
  const extra = Number(t && t.extra_seats) || 0;
  const used = (await one(`select count(*)::int as n from users where tenant_id=$1 and status='active' and app_role = any($2)`,
    [tenantId, SEAT_ROLES])).n;
  return { plan, included: base, extra, limit: base == null ? null : base + extra, used };
}

// Called before creating a staff/contractor login. Returns null when allowed.
async function seatBlock(tenantId) {
  const u = await seatUsage(tenantId);
  if (u.limit != null && u.used >= u.limit) return { error: "seat_limit", ...u, seat_price: SEAT_PRICE };
  return null;
}

// AI assistant: needs the add-on, and is capped per month. Returns null when allowed.
async function aiBlock(tenantId) {
  const a = await one("select active from tenant_addons where tenant_id=$1 and addon_key='ai-assistant'", [tenantId]);
  if (!a || !a.active) return { status: 402, error: "addon_required", addon: "ai-assistant" };
  const month = new Date().toISOString().slice(0, 7);
  const r = await one("select count from ai_usage where tenant_id=$1 and month=$2", [tenantId, month]);
  if (r && r.count >= AI_MONTHLY_CAP) return { status: 429, error: "ai_monthly_limit", limit: AI_MONTHLY_CAP };
  await run(`insert into ai_usage (tenant_id, month, count) values ($1,$2,1)
    on conflict (tenant_id, month) do update set count = ai_usage.count + 1`, [tenantId, month]);
  return null;
}

const baseUrl = (req) => process.env.PUBLIC_URL || (req.protocol + "://" + req.get("host"));

// Bring our copy of a tenant's subscription in line with Stripe.
async function syncSubscription(sub) {
  const tenantId = sub.metadata && sub.metadata.tenant_id
    || ((await one("select id from tenants where stripe_subscription_id=$1", [sub.id])) || {}).id;
  if (!tenantId) return;
  const items = (sub.items && sub.items.data) || [];
  const seatId = await setting(`stripe_price:seat:${SEAT_PRICE * 100}`);
  const seats = items.filter(i => i.price && i.price.id === seatId).reduce((n, i) => n + (i.quantity || 0), 0);
  const ended = sub.status === "canceled" || sub.status === "incomplete_expired";
  await run(`update tenants set stripe_subscription_id=$1, stripe_customer_id=coalesce($2, stripe_customer_id),
      billing_status=$3, trial_ends_at=$4, current_period_end=$5, extra_seats=$6 where id=$7`,
    [sub.id, typeof sub.customer === "string" ? sub.customer : null, sub.status,
     sub.trial_end ? new Date(sub.trial_end * 1000) : null,
     sub.current_period_end ? new Date(sub.current_period_end * 1000) : null,
     ended ? 0 : seats, tenantId]);
  // Billed add-ons follow the subscription: on while billed, off once removed or
  // cancelled. Add-ons the reseller switched on for free (billed=false) are untouched.
  const billed = new Set(items.map(i => i.price && i.price.metadata && i.price.metadata.ss_key).filter(Boolean));
  for (const a of await rows("select key from addons where price > 0")) {
    const on = !ended && billed.has("addon-" + a.key);
    const cur = await one("select active, billed from tenant_addons where tenant_id=$1 and addon_key=$2", [tenantId, a.key]);
    if (on) {
      await run(`insert into tenant_addons (tenant_id, addon_key, active, billed, activated_at) values ($1,$2,true,true,now())
        on conflict (tenant_id, addon_key) do update set active=true, billed=true`, [tenantId, a.key]);
    } else if (cur && cur.billed) {
      await run("update tenant_addons set active=false, billed=false where tenant_id=$1 and addon_key=$2", [tenantId, a.key]);
    }
  }
}

// Stripe webhook events this module cares about. Returns true when handled.
async function handleEvent(event) {
  const o = event.data && event.data.object;
  if (!o) return false;
  if (event.type === "checkout.session.completed" && o.mode === "subscription" && o.subscription) {
    const sub = await stripe().subscriptions.retrieve(o.subscription, { expand: ["items.data.price"] });
    await syncSubscription(sub);
    await audit(null, "subscription_started", sub.id, sub.metadata && sub.metadata.tenant_id);
    return true;
  }
  if (event.type.startsWith("customer.subscription.")) {
    await syncSubscription(o);
    return true;
  }
  return false;
}

function register(app, { h, ok }) {
  const admin = [A.authRequired, A.requireRole("tenant_admin")];
  const need = (res) => { if (!stripe()) { res.status(503).json({ error: "stripe_not_configured" }); return false; } return true; };
  const tenantRow = (req) => one("select * from tenants where id=$1", [req.user.tenant_id]);
  const liveSub = (t) => t && t.stripe_subscription_id && LIVE_STATUSES.includes(t.billing_status);

  // Overview for the tenant's Subscription screen.
  app.get("/api/billing", A.authRequired, A.requireRole("tenant_admin", "staff"), h(async (req, res) => {
    const t = await tenantRow(req);
    if (!t) return res.status(404).json({ error: "not_found" });
    const addons = await rows(`select a.key, a.name, a.price, coalesce(ta.active, false) as active, coalesce(ta.billed, false) as billed
      from addons a left join tenant_addons ta on ta.addon_key=a.key and ta.tenant_id=$1 order by a.price, a.name`, [t.id]);
    ok(res, {
      configured: !!stripe(), status: t.billing_status || "none", trial_ends_at: t.trial_ends_at,
      current_period_end: t.current_period_end, plans: PLANS, seat_price: SEAT_PRICE, trial_days: TRIAL_DAYS,
      seats: await seatUsage(t.id), addons, ai_monthly_cap: AI_MONTHLY_CAP,
    });
  }));

  // Start the subscription: Stripe Checkout collects the card; 14-day free trial.
  app.post("/api/billing/checkout", ...admin, h(async (req, res) => {
    if (!need(res)) return;
    const t = await tenantRow(req);
    if (liveSub(t)) return res.status(409).json({ error: "already_subscribed" });
    const plan = PLANS[t.plan] ? t.plan : "Growth";
    let customer = t.stripe_customer_id;
    if (!customer) {
      customer = (await stripe().customers.create({ name: t.name, metadata: { tenant_id: t.id } })).id;
      await run("update tenants set stripe_customer_id=$1 where id=$2", [customer, t.id]);
    }
    const tax = [await gstRate()];
    const line_items = [{ price: await planPrice(plan), quantity: 1, tax_rates: tax }];
    // Carry over seats/add-ons already in use (e.g. switched on before billing started).
    if (t.extra_seats > 0) line_items.push({ price: await seatPrice(), quantity: t.extra_seats, tax_rates: tax });
    const session = await stripe().checkout.sessions.create({
      mode: "subscription", customer, line_items,
      payment_method_collection: "always",
      subscription_data: { trial_period_days: TRIAL_DAYS, metadata: { tenant_id: t.id } },
      metadata: { tenant_id: t.id },
      success_url: baseUrl(req) + "/app?billing=done",
      cancel_url: baseUrl(req) + "/app?billing=cancelled",
    });
    await audit(req.user.sub, "billing_checkout", session.id, t.id, { plan });
    ok(res, { url: session.url });
  }));

  // Add to the subscription and take payment now. The change only sticks if Stripe
  // accepts the payment (error_if_incomplete); otherwise nothing is unlocked.
  async function addItem(t, price, quantity) {
    const sub = await stripe().subscriptions.retrieve(t.stripe_subscription_id, { expand: ["items.data.price"] });
    const existing = sub.items.data.find(i => i.price.id === price);
    const items = existing ? [{ id: existing.id, quantity: existing.quantity + quantity }]
                           : [{ price, quantity, tax_rates: [await gstRate()] }];
    const updated = await stripe().subscriptions.update(sub.id, {
      items, proration_behavior: "always_invoice", payment_behavior: "error_if_incomplete",
      expand: ["items.data.price"],
    });
    await syncSubscription(updated);
  }
  // Stripe errors (declined card, authentication needed ...) mean nothing was bought.
  // Anything else is a real fault and surfaces as one.
  const paymentError = (res, e) => {
    if (!(e && String(e.type || "").startsWith("Stripe"))) throw e;
    res.status(402).json({ error: "payment_failed", message: e.message || "Card declined" });
  };

  app.post("/api/billing/seats", ...admin, h(async (req, res) => {
    if (!need(res)) return;
    const t = await tenantRow(req);
    if (!liveSub(t)) return res.status(409).json({ error: "no_subscription" });
    const n = Math.min(Math.max(parseInt(req.body && req.body.count, 10) || 1, 1), 50);
    try { await addItem(t, await seatPrice(), n); }
    catch (e) { return paymentError(res, e); }
    await audit(req.user.sub, "billing_add_seats", t.id, t.id, { count: n });
    ok(res, { ok: true, seats: await seatUsage(t.id) });
  }));

  app.post("/api/billing/addons/:key", ...admin, h(async (req, res) => {
    if (!need(res)) return;
    const t = await tenantRow(req);
    if (!liveSub(t)) return res.status(409).json({ error: "no_subscription" });
    const price = await addonPrice(req.params.key);
    if (!price) return res.status(404).json({ error: "addon_not_found" });
    const on = !(req.body && req.body.active === false);
    if (on) {
      try { await addItem(t, price, 1); }
      catch (e) { return paymentError(res, e); }
    } else {
      const sub = await stripe().subscriptions.retrieve(t.stripe_subscription_id, { expand: ["items.data.price"] });
      const item = sub.items.data.find(i => i.price.id === price);
      if (item) await stripe().subscriptionItems.del(item.id, { proration_behavior: "create_prorations" });
      await run("update tenant_addons set active=false, billed=false where tenant_id=$1 and addon_key=$2", [t.id, req.params.key]);
    }
    await audit(req.user.sub, on ? "billing_addon_on" : "billing_addon_off", req.params.key, t.id);
    ok(res, { ok: true });
  }));

  app.post("/api/billing/plan", ...admin, h(async (req, res) => {
    if (!need(res)) return;
    const plan = String((req.body && req.body.plan) || "");
    if (!PLANS[plan]) return res.status(400).json({ error: "bad_plan" });
    const t = await tenantRow(req);
    if (plan === t.plan) return ok(res, { ok: true });
    // Moving down must still fit everyone currently using a seat.
    const u = await seatUsage(t.id);
    if (PLANS[plan].seats != null && u.used > PLANS[plan].seats + u.extra)
      return res.status(409).json({ error: "too_many_people", used: u.used, limit: PLANS[plan].seats + u.extra });
    if (liveSub(t)) {
      const sub = await stripe().subscriptions.retrieve(t.stripe_subscription_id, { expand: ["items.data.price"] });
      const cur = sub.items.data.find(i => String(i.price.metadata && i.price.metadata.ss_key || "").startsWith("plan-"));
      try {
        await stripe().subscriptions.update(sub.id, {
          items: [cur ? { id: cur.id, price: await planPrice(plan) } : { price: await planPrice(plan), tax_rates: [await gstRate()] }],
          proration_behavior: "always_invoice", payment_behavior: "error_if_incomplete",
        });
      } catch (e) { return paymentError(res, e); }
    }
    await run("update tenants set plan=$1 where id=$2", [plan, t.id]);
    await audit(req.user.sub, "billing_plan", plan, t.id, { from: t.plan });
    ok(res, { ok: true, seats: await seatUsage(t.id) });
  }));

  // Stripe's own page for changing the card, viewing invoices or cancelling.
  app.post("/api/billing/portal", ...admin, h(async (req, res) => {
    if (!need(res)) return;
    const t = await tenantRow(req);
    if (!t.stripe_customer_id) return res.status(409).json({ error: "no_subscription" });
    try {
      const s = await stripe().billingPortal.sessions.create({ customer: t.stripe_customer_id, return_url: baseUrl(req) + "/app" });
      ok(res, { url: s.url });
    } catch (e) {
      res.status(503).json({ error: "portal_not_set_up", message: "Turn on the customer portal in Stripe → Settings → Billing → Customer portal." });
    }
  }));
}

module.exports = { register, handleEvent, seatBlock, seatUsage, aiBlock, PLANS, SEAT_PRICE };
