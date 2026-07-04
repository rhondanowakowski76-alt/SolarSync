// SolarSync ERP — double-entry accounting (Australian standards), purchasing,
// stock valuation, payroll (PAYG + super), financial reports, BAS, bank rec,
// and Xero/MYOB-compatible CSV export.
//
// Money convention: sale/bill amounts are GST-INCLUSIVE (Australian retail
// convention, same as MYOB/Xero "amounts are tax inclusive" default).
// GST rate 10%: ex-GST = total/1.1, GST = total − ex.
const { rows, one, run, rid, audit } = require("./db");
const A = require("./auth");

const r2 = (n) => Math.round((Number(n) + Number.EPSILON) * 100) / 100;
const exGst = (total) => r2(Number(total) / 1.1);
const gstOf = (total) => r2(Number(total) - Number(total) / 1.1);
const today = () => new Date().toISOString().slice(0, 10);

// ============================================================
// CHART OF ACCOUNTS (Australian small-business standard)
// ============================================================
const COA = [
  // code, name, type, tax_code
  ["1-1100", "Cash at Bank", "asset", "NONE"],
  ["1-1200", "Accounts Receivable", "asset", "NONE"],
  ["1-1300", "Inventory on Hand", "asset", "NONE"],
  ["1-1400", "Stripe Clearing", "asset", "NONE"],
  ["2-1100", "Accounts Payable", "liability", "NONE"],
  ["2-1200", "GST Collected", "liability", "GST"],
  ["2-1300", "GST Paid (Input Credits)", "liability", "GST"],
  ["2-1400", "PAYG Withholding Payable", "liability", "NONE"],
  ["2-1500", "Superannuation Payable", "liability", "NONE"],
  ["2-1600", "Wages Payable", "liability", "NONE"],
  ["3-1000", "Owner's Equity", "equity", "NONE"],
  ["3-9000", "Retained Earnings", "equity", "NONE"],
  ["4-1000", "Sales — Installations", "income", "GST"],
  ["4-2000", "Sales — Service & Cleaning", "income", "GST"],
  ["4-3000", "Sales — Products (Counter)", "income", "GST"],
  ["5-1000", "Cost of Goods Sold — Materials", "cogs", "GST"],
  ["6-1000", "Wages & Salaries", "expense", "NONE"],
  ["6-1100", "Superannuation Expense", "expense", "NONE"],
  ["6-2000", "Subcontractors", "expense", "GST"],
  ["6-3000", "General & Operating Expenses", "expense", "GST"],
];

async function ensureAccounts(tenant_id) {
  if (!tenant_id) return;
  const c = await one("select count(*)::int as c from accounts where tenant_id=$1", [tenant_id]);
  if (c && c.c > 0) return;
  for (const [code, name, type, tax] of COA) {
    await run(
      `insert into accounts (id, tenant_id, code, name, type, tax_code, is_system)
       values ($1,$2,$3,$4,$5,$6,true) on conflict do nothing`,
      ["acc-" + rid().slice(0, 8), tenant_id, code, name, type, tax]);
  }
}

async function acct(tenant_id, code) {
  return await one("select * from accounts where tenant_id=$1 and code=$2", [tenant_id, code]);
}

// ============================================================
// JOURNAL ENGINE — the single write-path into the ledger.
// Lines reference account CODES; must balance to the cent.
// (source, source_id) is unique → posting is idempotent.
// ============================================================
async function postJournal(tenant_id, { date, memo, source, source_id, posted_by, lines }) {
  await ensureAccounts(tenant_id);
  const clean = (lines || [])
    .map(l => ({ code: l.code, debit: r2(l.debit || 0), credit: r2(l.credit || 0), memo: l.memo || null }))
    .filter(l => l.debit !== 0 || l.credit !== 0);
  if (!clean.length) throw new Error("journal_empty");
  const dr = r2(clean.reduce((s, l) => s + l.debit, 0));
  const cr = r2(clean.reduce((s, l) => s + l.credit, 0));
  if (Math.abs(dr - cr) > 0.005) throw new Error(`journal_unbalanced (dr ${dr} != cr ${cr})`);
  if (source_id) {
    const dup = await one("select id from journals where tenant_id=$1 and source=$2 and source_id=$3", [tenant_id, source || "manual", source_id]);
    if (dup) return dup.id; // already posted — idempotent
  }
  const jid = "jrn-" + rid().slice(0, 10);
  await run(`insert into journals (id, tenant_id, date, memo, source, source_id, posted_by)
    values ($1,$2,$3,$4,$5,$6,$7)`,
    [jid, tenant_id, date || today(), memo || null, source || "manual", source_id || null, posted_by || null]);
  for (const l of clean) {
    const a = await acct(tenant_id, l.code);
    if (!a) throw new Error(`unknown_account ${l.code}`);
    await run(`insert into journal_lines (id, journal_id, tenant_id, account_id, debit, credit, memo)
      values ($1,$2,$3,$4,$5,$6,$7)`,
      ["jl-" + rid().slice(0, 10), jid, tenant_id, a.id, l.debit, l.credit, l.memo]);
  }
  return jid;
}

// ---------- automatic postings from business events ----------
async function postInvoiceCreated(inv, posted_by) {
  if (!inv || inv.is_demo) return null;
  const total = Number(inv.amount) || 0; if (total <= 0) return null;
  return postJournal(inv.tenant_id, {
    date: today(), memo: `Invoice ${inv.number} — ${inv.client_name || inv.client_id || ""}`.trim(),
    source: "invoice", source_id: inv.id, posted_by,
    lines: [
      { code: "1-1200", debit: total, memo: `AR ${inv.number}` },
      { code: "4-1000", credit: exGst(total), memo: "Sale ex-GST" },
      { code: "2-1200", credit: gstOf(total), memo: "GST collected" },
    ],
  });
}

async function postInvoicePaid(inv, posted_by) {
  if (!inv || inv.is_demo) return null;
  const total = Number(inv.amount) || 0; if (total <= 0) return null;
  return postJournal(inv.tenant_id, {
    date: today(), memo: `Payment — invoice ${inv.number}`,
    source: "invoice_payment", source_id: inv.id, posted_by,
    lines: [
      { code: "1-1100", debit: total, memo: "Funds received" },
      { code: "1-1200", credit: total, memo: `Clear AR ${inv.number}` },
    ],
  });
}

// Over-the-counter sale recorded from a negative stock movement with a $ total.
async function postCounterSale(mov, product, posted_by) {
  if (!mov || Number(mov.delta) >= 0) return null;
  const total = Number(mov.total) || 0;
  const qty = Math.abs(Number(mov.delta));
  const cost = r2(qty * Number((product && product.cost) || 0));
  const lines = [];
  if (total > 0) {
    lines.push({ code: "1-1100", debit: total, memo: "Counter sale" });
    lines.push({ code: "4-3000", credit: exGst(total), memo: `${qty} × ${product ? product.name : mov.product_id}` });
    lines.push({ code: "2-1200", credit: gstOf(total), memo: "GST collected" });
  }
  if (cost > 0) {
    lines.push({ code: "5-1000", debit: cost, memo: "COGS" });
    lines.push({ code: "1-1300", credit: cost, memo: "Inventory out" });
  }
  if (!lines.length) return null;
  return postJournal(mov.tenant_id, {
    date: today(), memo: `Stock sale — ${product ? product.name : mov.product_id}`,
    source: "stock_sale", source_id: mov.id, posted_by, lines,
  });
}

// Stock allocated to a customer order (quote go-ahead). Moves value out of
// Inventory on Hand into Cost of Goods Sold. Revenue is booked separately when
// the order is invoiced, so this posts COGS only. Idempotent per source_id.
async function postStockAllocation(tenant_id, { source_id, posted_by, cost, memo }) {
  const c = r2(cost || 0);
  if (c <= 0) return null;
  return postJournal(tenant_id, {
    date: today(), memo: memo || "Stock allocated to order",
    source: "stock_allocation", source_id, posted_by,
    lines: [
      { code: "5-1000", debit: c, memo: "COGS — materials allocated" },
      { code: "1-1300", credit: c, memo: "Inventory out" },
    ],
  });
}

async function postBillCreated(bill, posted_by) {
  const total = Number(bill.total) || 0; if (total <= 0) return null;
  const expenseCode = bill.category === "inventory" ? "1-1300" : (bill.category === "subcontractor" ? "6-2000" : "6-3000");
  return postJournal(bill.tenant_id, {
    date: bill.date || today(), memo: `Bill ${bill.number || bill.id}`,
    source: "bill", source_id: bill.id, posted_by,
    lines: [
      { code: expenseCode, debit: exGst(total), memo: bill.category },
      { code: "2-1300", debit: gstOf(total), memo: "GST input credit" },
      { code: "2-1100", credit: total, memo: "Accounts payable" },
    ],
  });
}

async function postBillPaid(bill, posted_by) {
  const total = Number(bill.total) || 0; if (total <= 0) return null;
  return postJournal(bill.tenant_id, {
    date: today(), memo: `Payment — bill ${bill.number || bill.id}`,
    source: "bill_payment", source_id: bill.id, posted_by,
    lines: [
      { code: "2-1100", debit: total, memo: "Clear AP" },
      { code: "1-1100", credit: total, memo: "Funds paid" },
    ],
  });
}

// ============================================================
// PAYG WITHHOLDING — ATO Schedule 1, Scale 2 (tax-free threshold
// claimed), weekly coefficients, 2024–25. y = a·x − b, x = floor
// of weekly earnings + 0.99.
// ============================================================
const PAYG_WEEKLY = [
  { upTo: 361,      a: 0,      b: 0 },
  { upTo: 500,      a: 0.16,   b: 57.8462 },
  { upTo: 625,      a: 0.26,   b: 107.8462 },
  { upTo: 721,      a: 0.18,   b: 57.8462 },
  { upTo: 865,      a: 0.189,  b: 64.3365 },
  { upTo: 1282,     a: 0.3227, b: 180.0385 },
  { upTo: 2596,     a: 0.32,   b: 176.5769 },
  { upTo: 3653,     a: 0.39,   b: 358.3077 },
  { upTo: Infinity, a: 0.47,   b: 650.6154 },
];
function paygWeekly(gross) {
  const x = Math.floor(Number(gross)) + 0.99;
  const band = PAYG_WEEKLY.find(t => x < t.upTo) || PAYG_WEEKLY[PAYG_WEEKLY.length - 1];
  return Math.max(0, Math.round(band.a * x - band.b));
}
const SUPER_RATE = 0.12; // superannuation guarantee from 1 July 2025

// ============================================================
// ROUTES
// ============================================================
const TENANT_ROLES = ["tenant_admin", "staff", "reseller"];
const ALL_STAFF = ["tenant_admin", "staff", "contractor", "reseller"];

// Two separate sets of books: each TENANT keeps its own ledger under its
// tenant_id, and the RESELLER (platform owner) keeps a completely separate
// ledger under the fixed book id "reseller-platform". Nothing is shared.
const RESELLER_BOOK = "reseller-platform";

function register(app, { h, ok, tenantOf: _tenantOf }) {
  const tenantOf = (req) => req.user.app_role === "reseller" ? RESELLER_BOOK : req.user.tenant_id;

  // ---------------- Chart of accounts ----------------
  app.get("/api/accounts", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    await ensureAccounts(tenantOf(req));
    ok(res, await rows("select * from accounts where tenant_id=$1 and active=true order by code", [tenantOf(req)]));
  }));

  app.post("/api/accounts", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const d = req.body || {};
    if (!d.code || !d.name || !d.type) return res.status(400).json({ error: "code_name_type_required" });
    if (!["asset", "liability", "equity", "income", "cogs", "expense"].includes(d.type)) return res.status(400).json({ error: "bad_type" });
    await ensureAccounts(tenantOf(req));
    const id = "acc-" + rid().slice(0, 8);
    await run(`insert into accounts (id, tenant_id, code, name, type, tax_code) values ($1,$2,$3,$4,$5,$6)`,
      [id, tenantOf(req), String(d.code).trim(), String(d.name).trim(), d.type, d.tax_code || "GST"]);
    await audit(req.user.sub, "create_account", id, tenantOf(req));
    ok(res, await one("select * from accounts where id=$1", [id]));
  }));

  app.put("/api/accounts/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from accounts where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    const d = req.body || {};
    await run("update accounts set name=$1, tax_code=$2, active=$3 where id=$4",
      [d.name ?? cur.name, d.tax_code ?? cur.tax_code, d.active != null ? !!d.active : cur.active, cur.id]);
    ok(res, await one("select * from accounts where id=$1", [cur.id]));
  }));

  // ---------------- Journals ----------------
  app.get("/api/journals", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const tid = tenantOf(req);
    const { from, to } = req.query;
    const js = await rows(
      `select * from journals where tenant_id=$1
       and ($2::date is null or date >= $2::date) and ($3::date is null or date <= $3::date)
       order by date desc, created_at desc limit 300`, [tid, from || null, to || null]);
    const ids = js.map(j => j.id);
    let lines = [];
    if (ids.length) lines = await rows(
      `select jl.*, a.code, a.name as account_name from journal_lines jl
       join accounts a on a.id = jl.account_id
       where jl.journal_id = any($1) order by jl.debit desc`, [ids]);
    const byJ = {}; lines.forEach(l => { (byJ[l.journal_id] = byJ[l.journal_id] || []).push(l); });
    ok(res, js.map(j => ({ ...j, lines: byJ[j.id] || [] })));
  }));

  app.post("/api/journals", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const d = req.body || {};
    const jid = await postJournal(tenantOf(req), {
      date: d.date, memo: d.memo, source: "manual", source_id: null,
      posted_by: req.user.sub, lines: d.lines,
    });
    await audit(req.user.sub, "manual_journal", jid, tenantOf(req));
    ok(res, { id: jid });
  }));

  // ---------------- Suppliers ----------------
  app.get("/api/suppliers", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) =>
    ok(res, await rows("select * from suppliers where tenant_id=$1 and active=true order by name", [tenantOf(req)]))));

  app.post("/api/suppliers", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const d = req.body || {};
    if (!d.name) return res.status(400).json({ error: "name_required" });
    const id = "sup-" + rid().slice(0, 8);
    await run(`insert into suppliers (id, tenant_id, name, abn, email, phone, address, terms, notes)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, tenantOf(req), d.name, d.abn || null, d.email || null, d.phone || null, d.address || null, d.terms || "30 days", d.notes || null]);
    await audit(req.user.sub, "create_supplier", id, tenantOf(req));
    ok(res, await one("select * from suppliers where id=$1", [id]));
  }));

  app.put("/api/suppliers/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from suppliers where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    const d = req.body || {};
    await run(`update suppliers set name=$1, abn=$2, email=$3, phone=$4, address=$5, terms=$6, notes=$7, updated_at=now() where id=$8`,
      [d.name ?? cur.name, d.abn ?? cur.abn, d.email ?? cur.email, d.phone ?? cur.phone, d.address ?? cur.address, d.terms ?? cur.terms, d.notes ?? cur.notes, cur.id]);
    ok(res, await one("select * from suppliers where id=$1", [cur.id]));
  }));

  app.delete("/api/suppliers/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from suppliers where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    await run("update suppliers set active=false, updated_at=now() where id=$1", [cur.id]);
    ok(res, { ok: true });
  }));

  // ---------------- Purchase orders ----------------
  // lines: [{ product_id, name, qty, unit_cost }] — unit_cost GST-inclusive.
  function poTotals(lines) {
    const total = r2((lines || []).reduce((s, l) => s + (Number(l.qty) || 0) * (Number(l.unit_cost) || 0), 0));
    return { total, subtotal: exGst(total), gst: gstOf(total) };
  }

  app.get("/api/purchase-orders", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) =>
    ok(res, await rows(`select po.*, s.name as supplier_name from purchase_orders po
      left join suppliers s on s.id = po.supplier_id
      where po.tenant_id=$1 order by po.created_at desc limit 200`, [tenantOf(req)]))));

  app.post("/api/purchase-orders", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const d = req.body || {};
    const lines = Array.isArray(d.lines) ? d.lines : [];
    if (!lines.length) return res.status(400).json({ error: "lines_required" });
    const { total, subtotal, gst } = poTotals(lines);
    const id = "po-" + rid().slice(0, 8);
    const cnt = await one("select count(*)::int as c from purchase_orders where tenant_id=$1", [tenantOf(req)]);
    const number = d.number || ("PO-" + (1000 + ((cnt && cnt.c) || 0)));
    await run(`insert into purchase_orders (id, tenant_id, supplier_id, number, status, lines, subtotal, gst, total, expected, notes, created_by)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [id, tenantOf(req), d.supplier_id || null, number, d.status || "draft",
       JSON.stringify(lines), subtotal, gst, total, d.expected || null, d.notes || null, req.user.sub]);
    await audit(req.user.sub, "create_po", id, tenantOf(req));
    ok(res, await one("select * from purchase_orders where id=$1", [id]));
  }));

  app.put("/api/purchase-orders/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from purchase_orders where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "received" || cur.status === "billed") return res.status(409).json({ error: "already_received" });
    const d = req.body || {};
    const lines = d.lines != null ? d.lines : cur.lines;
    const { total, subtotal, gst } = poTotals(lines);
    await run(`update purchase_orders set supplier_id=$1, status=$2, lines=$3, subtotal=$4, gst=$5, total=$6, expected=$7, notes=$8, updated_at=now() where id=$9`,
      [d.supplier_id ?? cur.supplier_id, d.status ?? cur.status, JSON.stringify(lines), subtotal, gst, total,
       d.expected ?? cur.expected, d.notes ?? cur.notes, cur.id]);
    ok(res, await one("select * from purchase_orders where id=$1", [cur.id]));
  }));

  app.delete("/api/purchase-orders/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from purchase_orders where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "received" || cur.status === "billed") return res.status(409).json({ error: "already_received" });
    await run("update purchase_orders set status='cancelled', updated_at=now() where id=$1", [cur.id]);
    ok(res, { ok: true });
  }));

  // Receive a PO: stock quantities in, product cost updated (last cost),
  // and (default) a supplier bill raised — which posts to the ledger.
  app.post("/api/purchase-orders/:id/receive", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from purchase_orders where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "received" || cur.status === "billed") return res.status(409).json({ error: "already_received" });
    const lines = Array.isArray(cur.lines) ? cur.lines : JSON.parse(cur.lines || "[]");
    for (const l of lines) {
      if (!l.product_id) continue;
      const p = await one("select * from products where id=$1", [l.product_id]);
      if (!p || p.tenant_id !== cur.tenant_id) continue;
      const qty = Number(l.qty) || 0;
      const next = (p.stock == null ? 0 : Number(p.stock)) + qty;
      const unitCostEx = exGst(Number(l.unit_cost) || 0);
      await run("update products set stock=$1, cost=$2, updated_at=now() where id=$3", [next, unitCostEx, p.id]);
      await run(`insert into stock_movements (id, tenant_id, product_id, delta, reason, total, unit_cost, created_by)
        values ($1,$2,$3,$4,'po_receive',$5,$6,$7)`,
        ["mov-" + rid().slice(0, 8), cur.tenant_id, p.id, qty, r2(qty * (Number(l.unit_cost) || 0)), unitCostEx, req.user.sub]);
    }
    const makeBill = (req.body && req.body.create_bill) !== false; // default true
    let bill = null;
    if (makeBill && Number(cur.total) > 0) {
      const bid = "bill-" + rid().slice(0, 8);
      await run(`insert into bills (id, tenant_id, supplier_id, po_id, number, date, due, category, subtotal, gst, total, status, created_by)
        values ($1,$2,$3,$4,$5,$6,$7,'inventory',$8,$9,$10,'due',$11)`,
        [bid, cur.tenant_id, cur.supplier_id, cur.id, "BILL-" + (cur.number || cur.id).replace(/^PO-/, ""),
         today(), req.body && req.body.due || null, cur.subtotal, cur.gst, cur.total, req.user.sub]);
      bill = await one("select * from bills where id=$1", [bid]);
      await postBillCreated(bill, req.user.sub);
    }
    await run("update purchase_orders set status=$1, received_at=now(), updated_at=now() where id=$2",
      [bill ? "billed" : "received", cur.id]);
    await audit(req.user.sub, "receive_po", cur.id, cur.tenant_id, { bill: bill && bill.id });
    ok(res, { ok: true, bill });
  }));

  // ---------------- Supplier bills (AP) ----------------
  // Contractors may SUBMIT their invoice to the tenant and see only their own;
  // the tenant's full accounts-payable list stays admin/staff-only.
  app.get("/api/bills", A.authRequired, A.requireRole(...ALL_STAFF), h(async (req, res) => {
    const r = await rows(`select b.*, s.name as supplier_name from bills b
      left join suppliers s on s.id = b.supplier_id
      where b.tenant_id=$1 order by b.created_at desc limit 200`, [tenantOf(req)]);
    ok(res, req.user.app_role === "contractor" ? r.filter(b => b.created_by === req.user.sub) : r);
  }));

  app.post("/api/bills", A.authRequired, A.requireRole(...ALL_STAFF), h(async (req, res) => {
    const d = req.body || {};
    const total = r2(d.total);
    if (!total || total <= 0) return res.status(400).json({ error: "total_required" });
    const id = "bill-" + rid().slice(0, 8);
    const cnt = await one("select count(*)::int as c from bills where tenant_id=$1", [tenantOf(req)]);
    const number = d.number || ("BILL-" + (3000 + ((cnt && cnt.c) || 0)));
    await run(`insert into bills (id, tenant_id, supplier_id, po_id, number, date, due, category, subtotal, gst, total, status, notes, created_by)
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'due',$12,$13)`,
      [id, tenantOf(req), d.supplier_id || null, d.po_id || null, number, d.date || today(), d.due || null,
       d.category || "expense", exGst(total), gstOf(total), total, d.notes || null, req.user.sub]);
    const bill = await one("select * from bills where id=$1", [id]);
    await postBillCreated(bill, req.user.sub);
    await audit(req.user.sub, "create_bill", id, tenantOf(req));
    ok(res, bill);
  }));

  app.post("/api/bills/:id/pay", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from bills where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "paid") return res.status(409).json({ error: "already_paid" });
    await run("update bills set status='paid', paid_at=now() where id=$1", [cur.id]);
    await postBillPaid(cur, req.user.sub);
    await audit(req.user.sub, "pay_bill", cur.id, cur.tenant_id);
    ok(res, { ok: true });
  }));

  // ---------------- Timesheets ----------------
  // Contractors see ONLY their own timesheet rows (matched by linked user or name);
  // tenant admin/staff see the whole team's.
  const isContractor = (req) => req.user.app_role === "contractor";
  const memberMatchesUser = (m, req) =>
    (m.user_id && m.user_id === req.user.sub) ||
    (m.name && req.user.display_name && m.name.trim().toLowerCase() === req.user.display_name.trim().toLowerCase());
  app.get("/api/timesheets", A.authRequired, A.requireRole(...ALL_STAFF), h(async (req, res) => {
    const { week_start, status } = req.query;
    const r = await rows(
      `select t.*, m.name as member_name, m.rate, m.user_id as member_user_id from timesheets t
       join team_members m on m.id = t.member_id
       where t.tenant_id=$1
       and ($2::date is null or t.week_start=$2::date)
       and ($3::text is null or t.status=$3)
       order by t.week_start desc, m.name limit 300`,
      [tenantOf(req), week_start || null, status || null]);
    ok(res, isContractor(req)
      ? r.filter(t => (t.member_user_id && t.member_user_id === req.user.sub) ||
          (t.member_name && req.user.display_name && t.member_name.trim().toLowerCase() === req.user.display_name.trim().toLowerCase()))
      : r);
  }));

  // Upsert this week's hours for a team member.
  app.post("/api/timesheets", A.authRequired, A.requireRole(...ALL_STAFF), h(async (req, res) => {
    const d = req.body || {};
    if (!d.member_id || !d.week_start) return res.status(400).json({ error: "member_and_week_required" });
    const m = await one("select * from team_members where id=$1", [d.member_id]);
    if (!m || m.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "member_not_found" });
    if (isContractor(req) && !memberMatchesUser(m, req)) return res.status(403).json({ error: "own_timesheet_only" });
    const hours = Math.max(0, Number(d.hours) || 0);
    const existing = await one("select * from timesheets where tenant_id=$1 and member_id=$2 and week_start=$3",
      [tenantOf(req), d.member_id, d.week_start]);
    if (existing) {
      if (existing.status === "paid") return res.status(409).json({ error: "already_paid" });
      await run("update timesheets set hours=$1, job_id=$2, notes=$3, status='submitted', approved_by=null, approved_at=null where id=$4",
        [hours, d.job_id || existing.job_id, d.notes ?? existing.notes, existing.id]);
      return ok(res, await one("select * from timesheets where id=$1", [existing.id]));
    }
    const id = "ts-" + rid().slice(0, 8);
    await run(`insert into timesheets (id, tenant_id, member_id, week_start, hours, job_id, notes)
      values ($1,$2,$3,$4,$5,$6,$7)`,
      [id, tenantOf(req), d.member_id, d.week_start, hours, d.job_id || null, d.notes || null]);
    ok(res, await one("select * from timesheets where id=$1", [id]));
  }));

  app.post("/api/timesheets/:id/approve", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from timesheets where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "paid") return res.status(409).json({ error: "already_paid" });
    const approve = (req.body && req.body.approve) !== false;
    await run("update timesheets set status=$1, approved_by=$2, approved_at=$3 where id=$4",
      [approve ? "approved" : "submitted", approve ? req.user.sub : null, approve ? new Date() : null, cur.id]);
    ok(res, await one("select * from timesheets where id=$1", [cur.id]));
  }));

  // Self-service pay for the logged-in team member (staff or contractor):
  // their member record, recent timesheets, finalised payslips and YTD totals.
  // Powers the contractor Timesheets / Payslips / Earnings screens with live data.
  app.get("/api/me/pay", A.authRequired, A.requireRole(...ALL_STAFF), h(async (req, res) => {
    const tid = tenantOf(req);
    const m = await one(
      `select * from team_members where tenant_id=$1 and active=true
         and (user_id=$2 or lower(name)=lower($3)) order by (user_id=$2) desc limit 1`,
      [tid, req.user.sub, req.user.display_name || ""]);
    if (!m) return ok(res, { member: null, timesheets: [], payslips: [], ytd: { gross: 0, tax: 0, super: 0, net: 0 } });
    const timesheets = await rows(
      "select * from timesheets where tenant_id=$1 and member_id=$2 order by week_start desc limit 16", [tid, m.id]);
    const payslips = await rows(
      `select p.*, r.finalised_at, r.status as run_status from payslips p
         join payroll_runs r on r.id = p.run_id
        where p.tenant_id=$1 and p.member_id=$2 and r.status='finalised'
        order by r.finalised_at desc limit 24`, [tid, m.id]);
    const ytd = payslips.reduce((a, p) => ({
      gross: r2(a.gross + Number(p.gross)), tax: r2(a.tax + Number(p.tax)),
      super: r2(a.super + Number(p.super)), net: r2(a.net + Number(p.net)),
    }), { gross: 0, tax: 0, super: 0, net: 0 });
    ok(res, { member: { id: m.id, name: m.name, role: m.role, rate: Number(m.rate) || 0 }, timesheets, payslips, ytd });
  }));

  // ---------------- Payroll ----------------
  app.get("/api/payroll/runs", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) =>
    ok(res, await rows("select * from payroll_runs where tenant_id=$1 order by created_at desc limit 100", [tenantOf(req)]))));

  app.get("/api/payroll/runs/:id", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const runRow = await one("select * from payroll_runs where id=$1", [req.params.id]);
    if (!runRow || runRow.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    ok(res, { ...runRow, payslips: await rows("select * from payslips where run_id=$1 order by member_name", [runRow.id]) });
  }));

  // Create a payroll run from all APPROVED (unpaid) timesheets. Draft → review → finalise.
  app.post("/api/payroll/runs", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const tid = tenantOf(req);
    const ts = await rows(
      `select t.*, m.name as member_name, m.rate from timesheets t
       join team_members m on m.id = t.member_id
       where t.tenant_id=$1 and t.status='approved' and t.payroll_run_id is null order by m.name`, [tid]);
    if (!ts.length) return res.status(400).json({ error: "no_approved_timesheets" });
    const id = "pr-" + rid().slice(0, 8);
    // group hours by member (a run may cover multiple weeks)
    const byMember = {};
    for (const t of ts) {
      const k = t.member_id;
      byMember[k] = byMember[k] || { member_id: k, member_name: t.member_name, rate: Number(t.rate) || 0, hours: 0, weeks: 0, ids: [] };
      byMember[k].hours += Number(t.hours) || 0;
      byMember[k].weeks += 1;
      byMember[k].ids.push(t.id);
    }
    let G = 0, T = 0, S = 0, N = 0;
    const dates = ts.map(t => t.week_start).sort();
    await run(`insert into payroll_runs (id, tenant_id, period_start, period_end, status, created_by)
      values ($1,$2,$3,$4,'draft',$5)`, [id, tid, dates[0], dates[dates.length - 1], req.user.sub]);
    for (const m of Object.values(byMember)) {
      const gross = r2(m.hours * m.rate);
      // PAYG is a weekly table — withhold per covered week then sum.
      const weeklyGross = m.weeks > 0 ? gross / m.weeks : gross;
      const tax = r2(paygWeekly(weeklyGross) * Math.max(1, m.weeks));
      const sup = r2(gross * SUPER_RATE);
      const net = r2(gross - tax);
      G = r2(G + gross); T = r2(T + tax); S = r2(S + sup); N = r2(N + net);
      await run(`insert into payslips (id, tenant_id, run_id, member_id, member_name, hours, rate, gross, tax, super, net)
        values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        ["ps-" + rid().slice(0, 8), tid, id, m.member_id, m.member_name, r2(m.hours), m.rate, gross, tax, sup, net]);
      for (const tsId of m.ids) await run("update timesheets set payroll_run_id=$1 where id=$2", [id, tsId]);
    }
    await run("update payroll_runs set gross=$1, tax=$2, super=$3, net=$4 where id=$5", [G, T, S, N, id]);
    await audit(req.user.sub, "create_payroll_run", id, tid, { gross: G });
    ok(res, { ...(await one("select * from payroll_runs where id=$1", [id])), payslips: await rows("select * from payslips where run_id=$1", [id]) });
  }));

  // Finalise: post wages/PAYG/super to the ledger and pay net wages from bank.
  app.post("/api/payroll/runs/:id/finalise", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const cur = await one("select * from payroll_runs where id=$1", [req.params.id]);
    if (!cur || cur.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    if (cur.status === "finalised") return res.status(409).json({ error: "already_finalised" });
    await postJournal(cur.tenant_id, {
      date: today(), memo: `Payroll run ${cur.id} (${cur.period_start} → ${cur.period_end})`,
      source: "payroll", source_id: cur.id, posted_by: req.user.sub,
      lines: [
        { code: "6-1000", debit: Number(cur.gross), memo: "Gross wages" },
        { code: "6-1100", debit: Number(cur.super), memo: "Superannuation guarantee 12%" },
        { code: "2-1400", credit: Number(cur.tax), memo: "PAYG withheld" },
        { code: "2-1500", credit: Number(cur.super), memo: "Super payable" },
        { code: "1-1100", credit: Number(cur.net), memo: "Net wages paid" },
      ],
    });
    await run("update payroll_runs set status='finalised', finalised_at=now() where id=$1", [cur.id]);
    await run("update timesheets set status='paid' where payroll_run_id=$1", [cur.id]);
    await audit(req.user.sub, "finalise_payroll", cur.id, cur.tenant_id);
    ok(res, { ok: true });
  }));

  // ---------------- Financial reports ----------------
  async function ledgerTotals(tid, { from, to } = {}) {
    return await rows(
      `select a.id, a.code, a.name, a.type,
              coalesce(sum(jl.debit),0)::numeric as debit,
              coalesce(sum(jl.credit),0)::numeric as credit
       from accounts a
       left join journal_lines jl on jl.account_id = a.id
       left join journals j on j.id = jl.journal_id
        and ($2::date is null or j.date >= $2::date)
        and ($3::date is null or j.date <= $3::date)
       where a.tenant_id=$1 and a.active=true
       group by a.id, a.code, a.name, a.type order by a.code`, [tid, from || null, to || null]);
  }

  app.get("/api/finance/trial-balance", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    await ensureAccounts(tenantOf(req));
    const t = await ledgerTotals(tenantOf(req), { to: req.query.to });
    const out = t.map(a => {
      const bal = r2(Number(a.debit) - Number(a.credit));
      return { code: a.code, name: a.name, type: a.type, debit: bal > 0 ? bal : 0, credit: bal < 0 ? -bal : 0 };
    }).filter(a => a.debit !== 0 || a.credit !== 0);
    ok(res, { rows: out,
      total_debit: r2(out.reduce((s, a) => s + a.debit, 0)),
      total_credit: r2(out.reduce((s, a) => s + a.credit, 0)) });
  }));

  app.get("/api/finance/profit-loss", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    await ensureAccounts(tenantOf(req));
    const t = await ledgerTotals(tenantOf(req), { from: req.query.from, to: req.query.to });
    const income = t.filter(a => a.type === "income").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.credit) - Number(a.debit)) }));
    const cogs = t.filter(a => a.type === "cogs").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.debit) - Number(a.credit)) }));
    const expenses = t.filter(a => a.type === "expense").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.debit) - Number(a.credit)) }));
    const totalIncome = r2(income.reduce((s, a) => s + a.amount, 0));
    const totalCogs = r2(cogs.reduce((s, a) => s + a.amount, 0));
    const totalExp = r2(expenses.reduce((s, a) => s + a.amount, 0));
    ok(res, { income, cogs, expenses,
      total_income: totalIncome, total_cogs: totalCogs, gross_profit: r2(totalIncome - totalCogs),
      total_expenses: totalExp, net_profit: r2(totalIncome - totalCogs - totalExp) });
  }));

  app.get("/api/finance/balance-sheet", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    await ensureAccounts(tenantOf(req));
    const t = await ledgerTotals(tenantOf(req), { to: req.query.to });
    const assets = t.filter(a => a.type === "asset").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.debit) - Number(a.credit)) })).filter(a => a.amount !== 0);
    const liabilities = t.filter(a => a.type === "liability").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.credit) - Number(a.debit)) })).filter(a => a.amount !== 0);
    const equity = t.filter(a => a.type === "equity").map(a => ({ code: a.code, name: a.name, amount: r2(Number(a.credit) - Number(a.debit)) })).filter(a => a.amount !== 0);
    const pl = r2(
      t.filter(a => a.type === "income").reduce((s, a) => s + Number(a.credit) - Number(a.debit), 0)
      - t.filter(a => a.type === "cogs" || a.type === "expense").reduce((s, a) => s + Number(a.debit) - Number(a.credit), 0));
    equity.push({ code: "3-9999", name: "Current Earnings", amount: pl });
    const ta = r2(assets.reduce((s, a) => s + a.amount, 0));
    const tl = r2(liabilities.reduce((s, a) => s + a.amount, 0));
    const te = r2(equity.reduce((s, a) => s + a.amount, 0));
    ok(res, { assets, liabilities, equity, total_assets: ta, total_liabilities: tl, total_equity: te, balanced: Math.abs(ta - tl - te) < 0.02 });
  }));

  // BAS summary: G1 total sales (inc GST), 1A GST collected, 1B GST credits,
  // W1 gross wages, W2 PAYG withheld, net GST position.
  app.get("/api/finance/bas", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    await ensureAccounts(tenantOf(req));
    const { from, to } = req.query;
    const t = await ledgerTotals(tenantOf(req), { from, to });
    const get = (code) => t.find(a => a.code === code) || { debit: 0, credit: 0 };
    const salesEx = r2(t.filter(a => a.type === "income").reduce((s, a) => s + Number(a.credit) - Number(a.debit), 0));
    const gstCollected = r2(Number(get("2-1200").credit) - Number(get("2-1200").debit));
    const gstPaid = r2(Number(get("2-1300").debit) - Number(get("2-1300").credit));
    const wages = r2(Number(get("6-1000").debit) - Number(get("6-1000").credit));
    const payg = r2(Number(get("2-1400").credit) - Number(get("2-1400").debit));
    ok(res, {
      period: { from: from || null, to: to || null },
      G1_total_sales: r2(salesEx + gstCollected),
      G1_sales_ex_gst: salesEx,
      "1A_gst_on_sales": gstCollected,
      "1B_gst_credits": gstPaid,
      W1_gross_wages: wages,
      W2_payg_withheld: payg,
      net_gst: r2(gstCollected - gstPaid),
      amount_owing_to_ato: r2(gstCollected - gstPaid + payg),
    });
  }));

  // AR aging (customer invoices) + AP aging (supplier bills) in 30/60/90 buckets.
  app.get("/api/finance/aging", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const tid = tenantOf(req);
    const bucket = (days) => days <= 30 ? "current" : days <= 60 ? "d30" : days <= 90 ? "d60" : "d90";
    const ar = await rows(`select id, number, client_name, amount, created_at from invoices
      where tenant_id=$1 and status!='paid' and (is_demo is not true)`, [tid]);
    const ap = await rows(`select b.id, b.number, s.name as supplier_name, b.total as amount, b.created_at from bills b
      left join suppliers s on s.id=b.supplier_id where b.tenant_id=$1 and b.status!='paid'`, [tid]);
    const shape = (list, who) => {
      const buckets = { current: 0, d30: 0, d60: 0, d90: 0 };
      const items = list.map(x => {
        const days = Math.floor((Date.now() - new Date(x.created_at).getTime()) / 86400000);
        const b = bucket(days);
        buckets[b] = r2(buckets[b] + Number(x.amount));
        return { id: x.id, number: x.number, who: x[who] || "—", amount: r2(x.amount), days, bucket: b };
      });
      return { items, buckets, total: r2(items.reduce((s, i) => s + i.amount, 0)) };
    };
    ok(res, { receivables: shape(ar, "client_name"), payables: shape(ap, "supplier_name") });
  }));

  // Stock on hand: quantity, valuation at cost, sell value, low-stock flags.
  app.get("/api/finance/stock-report", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const ps = await rows(`select id, cat, name, unit, price, cost, stock, reorder_point from products
      where tenant_id=$1 and active=true and stock is not null order by cat, name`, [tenantOf(req)]);
    const items = ps.map(p => ({
      ...p, stock: Number(p.stock), cost: Number(p.cost) || 0, price: Number(p.price) || 0,
      value_at_cost: r2(Number(p.stock) * (Number(p.cost) || 0)),
      value_at_sell: r2(Number(p.stock) * (Number(p.price) || 0)),
      low: p.reorder_point != null && Number(p.stock) <= Number(p.reorder_point),
    }));
    ok(res, { items,
      total_at_cost: r2(items.reduce((s, i) => s + i.value_at_cost, 0)),
      total_at_sell: r2(items.reduce((s, i) => s + i.value_at_sell, 0)),
      low_count: items.filter(i => i.low).length });
  }));

  // Job costing: quoted value vs actual materials + labour for one deal/job.
  app.get("/api/jobs/:id/costing", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const deal = await one("select * from deals where id=$1", [req.params.id]);
    if (!deal || deal.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    const mats = await rows(`select m.*, p.name as product, p.cost from stock_movements m
      left join products p on p.id=m.product_id
      where m.tenant_id=$1 and m.job_id=$2 and m.delta < 0`, [deal.tenant_id, deal.id]);
    const labour = await rows(`select t.*, m.name as member_name, m.rate from timesheets t
      join team_members m on m.id=t.member_id
      where t.tenant_id=$1 and t.job_id=$2`, [deal.tenant_id, deal.id]);
    const matCost = r2(mats.reduce((s, m) => s + Math.abs(m.delta) * Number(m.unit_cost != null ? m.unit_cost : (m.cost || 0)), 0));
    const labCost = r2(labour.reduce((s, t) => s + Number(t.hours) * Number(t.rate || 0), 0));
    const quoted = Number(deal.value) || 0;
    const quotedEx = exGst(quoted);
    ok(res, {
      job: { id: deal.id, client: deal.client, quoted_inc_gst: quoted, quoted_ex_gst: quotedEx },
      materials: { items: mats, cost: matCost },
      labour: { items: labour, cost: labCost },
      total_cost: r2(matCost + labCost),
      margin: r2(quotedEx - matCost - labCost),
      margin_pct: quotedEx > 0 ? r2(100 * (quotedEx - matCost - labCost) / quotedEx) : null,
    });
  }));

  // ---------------- Bank reconciliation ----------------
  app.get("/api/bank/transactions", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) =>
    ok(res, await rows("select * from bank_transactions where tenant_id=$1 order by date desc, imported_at desc limit 300", [tenantOf(req)]))));

  // Import statement rows: [{date:'YYYY-MM-DD', description, amount}] (amount +credit / −debit)
  app.post("/api/bank/import", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const list = Array.isArray(req.body && req.body.rows) ? req.body.rows : [];
    if (!list.length) return res.status(400).json({ error: "rows_required" });
    let n = 0;
    for (const r of list.slice(0, 1000)) {
      if (r.amount == null || !r.date) continue;
      await run(`insert into bank_transactions (id, tenant_id, date, description, amount)
        values ($1,$2,$3,$4,$5)`,
        ["bt-" + rid().slice(0, 10), tenantOf(req), String(r.date).slice(0, 10), String(r.description || "").slice(0, 300), r2(r.amount)]);
      n++;
    }
    await audit(req.user.sub, "bank_import", null, tenantOf(req), { count: n });
    ok(res, { imported: n });
  }));

  // Ledger entries touching Cash at Bank, with match state — the other half of the rec screen.
  app.get("/api/bank/ledger", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const tid = tenantOf(req);
    await ensureAccounts(tid);
    const bank = await acct(tid, "1-1100");
    const ls = await rows(
      `select j.id as journal_id, j.date, j.memo, jl.debit, jl.credit,
              exists (select 1 from bank_transactions bt where bt.tenant_id=$1 and bt.matched_journal_id=j.id) as matched
       from journal_lines jl join journals j on j.id=jl.journal_id
       where jl.tenant_id=$1 and jl.account_id=$2
       order by j.date desc limit 300`, [tid, bank.id]);
    ok(res, ls.map(l => ({ ...l, amount: r2(Number(l.debit) - Number(l.credit)) })));
  }));

  app.post("/api/bank/transactions/:id/match", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const bt = await one("select * from bank_transactions where id=$1", [req.params.id]);
    if (!bt || bt.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    const jid = req.body && req.body.journal_id;
    if (jid) {
      const j = await one("select * from journals where id=$1", [jid]);
      if (!j || j.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "journal_not_found" });
      await run("update bank_transactions set status='matched', matched_journal_id=$1 where id=$2", [jid, bt.id]);
    } else {
      await run("update bank_transactions set status='unmatched', matched_journal_id=null where id=$1", [bt.id]);
    }
    ok(res, { ok: true });
  }));

  // ---------------- Xero / MYOB export + connection settings ----------------
  function csvEscape(v) { const s = v == null ? "" : String(v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
  function sendCsv(res, name, header, rowsArr) {
    const body = [header.join(",")].concat(rowsArr.map(r => r.map(csvEscape).join(","))).join("\r\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${name}"`);
    res.send(body);
  }

  // Xero "Sales Invoices" import format.
  app.get("/api/export/xero/invoices", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const inv = await rows(`select * from invoices where tenant_id=$1 and (is_demo is not true) order by created_at`, [tenantOf(req)]);
    sendCsv(res, "solarsync-invoices-xero.csv",
      ["*ContactName", "*InvoiceNumber", "*InvoiceDate", "*DueDate", "*Description", "*Quantity", "*UnitAmount", "*AccountCode", "*TaxType", "Status"],
      inv.map(i => [i.client_name || "Customer", i.number, String(i.created_at).slice(0, 10), i.due || "",
        i.description || "SolarSync invoice", 1, r2(exGst(i.amount)), "4-1000", "GST on Income", i.status === "paid" ? "PAID" : "AUTHORISED"]));
  }));

  // MYOB-style general journal export.
  app.get("/api/export/myob/journals", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const ls = await rows(
      `select j.date, j.id as jid, j.memo, a.code, a.name, jl.debit, jl.credit
       from journal_lines jl join journals j on j.id=jl.journal_id join accounts a on a.id=jl.account_id
       where jl.tenant_id=$1 order by j.date, j.id`, [tenantOf(req)]);
    sendCsv(res, "solarsync-journals.csv",
      ["Date", "Journal ID", "Memo", "Account Code", "Account Name", "Debit", "Credit"],
      ls.map(l => [String(l.date).slice(0, 10), l.jid, l.memo || "", l.code, l.name, r2(l.debit), r2(l.credit)]));
  }));

  app.get("/api/export/payroll/:runId", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const runRow = await one("select * from payroll_runs where id=$1", [req.params.runId]);
    if (!runRow || runRow.tenant_id !== tenantOf(req)) return res.status(404).json({ error: "not_found" });
    const ps = await rows("select * from payslips where run_id=$1 order by member_name", [runRow.id]);
    sendCsv(res, `solarsync-payroll-${runRow.id}.csv`,
      ["Employee", "Hours", "Rate", "Gross", "PAYG Tax", "Super (12%)", "Net Pay"],
      ps.map(p => [p.member_name, r2(p.hours), r2(p.rate), r2(p.gross), r2(p.tax), r2(p.super), r2(p.net)]));
  }));

  app.get("/api/accounting/connection", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) =>
    ok(res, await rows("select provider, status, last_sync from accounting_connections where tenant_id=$1", [tenantOf(req)]))));

  app.put("/api/accounting/connection", A.authRequired, A.requireRole(...TENANT_ROLES), h(async (req, res) => {
    const { provider, status } = req.body || {};
    if (!provider) return res.status(400).json({ error: "provider_required" });
    await run(`insert into accounting_connections (tenant_id, provider, status) values ($1,$2,$3)
      on conflict (tenant_id, provider) do update set status=excluded.status`,
      [tenantOf(req), String(provider).toLowerCase(), status || "export_only"]);
    ok(res, { ok: true });
  }));
}

module.exports = { register, postJournal, postInvoiceCreated, postInvoicePaid, postCounterSale, postStockAllocation, ensureAccounts, paygWeekly };
