// SolarSync backend — database layer (PostgreSQL).
// Production: connects to DATABASE_URL (DigitalOcean Managed Postgres, Sydney).
// Local dev/test: falls back to in-process PGlite (same Postgres SQL, no server).
const crypto = require("crypto");

let _db = null;
let _ready = null;

async function init() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require("pg");
    // Strip sslmode from the URL so our explicit ssl config wins. DigitalOcean
    // databases present a self-signed CA, so we connect over TLS but skip strict
    // certificate-chain verification (rejectUnauthorized:false).
    const cs = process.env.DATABASE_URL.replace(/([?&])sslmode=[^&]*/gi, "$1").replace(/[?&]+$/g, "");
    _db = new Pool({
      connectionString: cs,
      ssl: { rejectUnauthorized: false },
      max: 5,
      options: "-c search_path=app,public",   // use our own schema (PG15+ locks down public)
    });
  } else {
    const { PGlite } = require("@electric-sql/pglite");
    const path = require("path");
    _db = await PGlite.create(process.env.PGLITE_DIR || path.join(__dirname, "data", "pg"));
  }
  await migrate();
  return _db;
}

async function db() {
  if (_db) return _db;
  if (!_ready) _ready = init();
  await _ready;
  return _db;
}

// Both pg.Pool and PGlite expose .query(sql, params) -> { rows }
async function query(sql, params = []) {
  const d = await db();
  return d.query(sql, params);
}
async function rows(sql, params = []) { return (await query(sql, params)).rows; }
async function one(sql, params = []) { return (await query(sql, params)).rows[0] || null; }
async function run(sql, params = []) { await query(sql, params); }

function rid() { return crypto.randomUUID(); }

async function audit(actor_id, action, target, tenant_id, meta = {}) {
  try {
    await run(
      `insert into audit_log (id, actor_id, action, target, tenant_id, meta) values ($1,$2,$3,$4,$5,$6)`,
      [rid(), actor_id, action, target, tenant_id, JSON.stringify(meta)]
    );
  } catch (e) {}
}

async function migrate() {
  // Create and use a dedicated schema (PostgreSQL 15+ revokes CREATE on public).
  await _db.query("create schema if not exists app");
  try { await _db.query("set search_path to app, public"); } catch (e) {}
  const stmts = [
    `create table if not exists resellers (
      id text primary key, name text not null, branding jsonb default '{}', created_at timestamptz default now())`,
    `create table if not exists tenants (
      id text primary key, reseller_id text, name text not null, domain text,
      plan text default 'Growth', branding jsonb default '{}', status text default 'active',
      created_at timestamptz default now())`,
    `create table if not exists users (
      id text primary key, tenant_id text, app_role text not null, display_name text not null,
      pin_hash text, totp_secret text, totp_enrolled boolean default false,
      must_reset boolean default false, failed_attempts int default 0, locked_until timestamptz,
      status text default 'active', created_at timestamptz default now())`,
    `create table if not exists clients (
      id text primary key, tenant_id text not null, user_id text,
      name text not null, site_address text, system_spec jsonb default '{}', install_status text,
      created_at timestamptz default now())`,
    `create table if not exists deals (
      id text primary key, tenant_id text not null, client_id text,
      client text not null, type text default 'install', job_type text,
      stage text default 'enquiry', system text, value numeric default 0,
      installer text, suburb text, due text, notes text,
      created_by text, updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists deals_tenant_idx on deals (tenant_id, updated_at desc)`,
    `create table if not exists products (
      id text primary key, tenant_id text not null, cat text, name text not null, spec text,
      unit text default 'unit', price numeric default 0, watts int default 0,
      stock int, reorder_point int default 5, direct_sale boolean default true,
      recreational boolean default false, note text, active boolean default true,
      updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists products_tenant_idx on products (tenant_id, cat)`,
    `create table if not exists stock_movements (
      id text primary key, tenant_id text not null, product_id text not null,
      delta int not null, reason text, buyer text, total numeric,
      created_by text, created_at timestamptz default now())`,
    `create index if not exists stock_moves_idx on stock_movements (tenant_id, created_at desc)`,
    `create table if not exists bookings (
      id text primary key, tenant_id text not null, client_id text, client text,
      type text default 'clean', title text, date text, time text, end_time text,
      suburb text, job_id text, status text default 'requested', notes text,
      value numeric default 0, installer text, source text default 'client',
      created_by text, updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists bookings_tenant_idx on bookings (tenant_id, date)`,
    `create index if not exists bookings_client_idx on bookings (client_id, created_at desc)`,
    `create table if not exists quotes (
      id text primary key, tenant_id text not null, number text, client_id text, deal_id text,
      customer jsonb, enq text default 'install', status text default 'Draft',
      validity text default '30', notes text, lines jsonb, spec jsonb,
      total numeric default 0, created_by text,
      updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists quotes_tenant_idx on quotes (tenant_id, updated_at desc)`,
    `create table if not exists messages (
      id text primary key, tenant_id text not null, client_id text not null,
      sender_role text not null, sender_id text, sender_name text, body text not null,
      created_at timestamptz default now())`,
    `create index if not exists messages_thread_idx on messages (tenant_id, client_id, created_at)`,
    `create table if not exists team_members (
      id text primary key, tenant_id text not null, name text not null, role text,
      type text default 'Staff', licence text, hrs numeric default 0, status text default 'Off',
      jobs int default 0, rate numeric default 48, approved boolean default false,
      active boolean default true, updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists team_tenant_idx on team_members (tenant_id, name)`,
    `alter table team_members add column if not exists user_id text`,
    `create table if not exists addons ( key text primary key, name text not null, price numeric default 0 )`,
    `create table if not exists tenant_addons (
      tenant_id text, addon_key text, active boolean default false, activated_at timestamptz,
      primary key (tenant_id, addon_key))`,
    `create table if not exists tester_tokens ( token text primary key, scope text default 'compliance', active boolean default true )`,
    `create table if not exists report_templates ( key text primary key, category text default 'compliance', title text not null, body_html text not null )`,
    `create table if not exists letterheads (
      tenant_id text primary key, legal_name text, abn text, address text, phone text, email text,
      licence text, logo_url text, updated_at timestamptz default now())`,
    `create table if not exists reports (
      id text primary key, tenant_id text not null, template_key text, job_ref text,
      title text not null, body_html text not null, status text default 'draft',
      created_by text, updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create table if not exists report_publications (
      id text primary key, report_id text, tenant_id text not null, client_id text not null,
      title text, body_html text, published_at timestamptz default now())`,
    `create table if not exists invoices (
      id text primary key, tenant_id text not null, client_id text not null, number text not null,
      amount numeric not null, status text default 'due', stripe_payment_intent text, paid_at timestamptz,
      created_at timestamptz default now())`,
    `create table if not exists accounting_connections (
      tenant_id text, provider text, tokens_enc text, status text default 'disconnected', last_sync timestamptz,
      primary key (tenant_id, provider))`,
    `create table if not exists files (
      id text primary key, tenant_id text not null, owner_type text, owner_id text, kind text,
      url text not null, mime text, created_at timestamptz default now())`,
    `create table if not exists audit_log (
      id text primary key, actor_id text, action text not null, target text, tenant_id text,
      meta jsonb default '{}', created_at timestamptz default now())`,
    `create table if not exists beta_testers (
      id text primary key,
      issued_by text,
      name text not null,
      email text,
      scope text default 'tenant,contractor,client',
      plan text default 'Scale',
      notes text,
      issued_at timestamptz default now(),
      expires_at timestamptz,
      revoked boolean default false,
      revoked_at timestamptz,
      last_seen timestamptz,
      use_count int default 0)`,
    `create table if not exists tenant_documents (
      id text primary key,
      tenant_id text not null,
      doc_group text not null,
      version int not null default 1,
      is_current boolean not null default true,
      title text not null,
      category text default 'Other',
      filename text not null,
      mime_type text,
      size_bytes bigint,
      spaces_key text not null,
      uploaded_by text,
      uploaded_at timestamptz default now(),
      visibility text default 'tenant',
      notes text,
      content_html text,
      is_deleted boolean default false)`,
    `create index if not exists tenant_documents_group_idx on tenant_documents (tenant_id, doc_group, version desc)`,
    `create index if not exists tenant_documents_current_idx on tenant_documents (tenant_id, is_current) where is_current = true and is_deleted = false`,
    `create table if not exists document_publications (
      id text primary key,
      document_id text not null,
      doc_group text,
      tenant_id text not null,
      client_id text not null,
      title text,
      filename text,
      mime_type text,
      size_bytes bigint,
      spaces_key text,
      body_html text,
      published_by text,
      published_at timestamptz default now())`,
    `create index if not exists document_publications_client_idx on document_publications (client_id, published_at desc)`,
    // ---------- ERP: accounting, purchasing, payroll ----------
    `create table if not exists accounts (
      id text primary key, tenant_id text not null, code text not null, name text not null,
      type text not null, tax_code text default 'GST', is_system boolean default false,
      active boolean default true, created_at timestamptz default now())`,
    `create unique index if not exists accounts_code_idx on accounts (tenant_id, code)`,
    `create table if not exists journals (
      id text primary key, tenant_id text not null, date date not null default current_date,
      memo text, source text default 'manual', source_id text, posted_by text,
      created_at timestamptz default now())`,
    `create index if not exists journals_tenant_idx on journals (tenant_id, date desc)`,
    `create unique index if not exists journals_source_idx on journals (tenant_id, source, source_id) where source_id is not null`,
    `create table if not exists journal_lines (
      id text primary key, journal_id text not null, tenant_id text not null,
      account_id text not null, debit numeric default 0, credit numeric default 0, memo text)`,
    `create index if not exists journal_lines_acct_idx on journal_lines (tenant_id, account_id)`,
    `create index if not exists journal_lines_jrn_idx on journal_lines (journal_id)`,
    `create table if not exists suppliers (
      id text primary key, tenant_id text not null, name text not null, abn text, email text,
      phone text, address text, terms text default '30 days', notes text, active boolean default true,
      updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create table if not exists purchase_orders (
      id text primary key, tenant_id text not null, supplier_id text, number text,
      status text default 'draft', lines jsonb default '[]', subtotal numeric default 0,
      gst numeric default 0, total numeric default 0, expected text, notes text,
      received_at timestamptz, created_by text,
      updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create index if not exists po_tenant_idx on purchase_orders (tenant_id, created_at desc)`,
    `create table if not exists bills (
      id text primary key, tenant_id text not null, supplier_id text, po_id text, number text,
      date date default current_date, due text, category text default 'inventory',
      subtotal numeric default 0, gst numeric default 0, total numeric default 0,
      status text default 'due', paid_at timestamptz, notes text, created_by text,
      created_at timestamptz default now())`,
    `create index if not exists bills_tenant_idx on bills (tenant_id, created_at desc)`,
    `create table if not exists timesheets (
      id text primary key, tenant_id text not null, member_id text not null,
      week_start date not null, hours numeric not null default 0, job_id text, notes text,
      status text default 'submitted', approved_by text, approved_at timestamptz,
      payroll_run_id text, created_at timestamptz default now())`,
    `create unique index if not exists timesheets_member_week_idx on timesheets (tenant_id, member_id, week_start)`,
    `create table if not exists payroll_runs (
      id text primary key, tenant_id text not null, period_start date, period_end date,
      status text default 'draft', gross numeric default 0, tax numeric default 0,
      super numeric default 0, net numeric default 0, created_by text,
      finalised_at timestamptz, created_at timestamptz default now())`,
    `create table if not exists payslips (
      id text primary key, tenant_id text not null, run_id text not null, member_id text not null,
      member_name text, hours numeric default 0, rate numeric default 0, gross numeric default 0,
      tax numeric default 0, super numeric default 0, net numeric default 0,
      created_at timestamptz default now())`,
    `create index if not exists payslips_run_idx on payslips (run_id)`,
    `create table if not exists bank_transactions (
      id text primary key, tenant_id text not null, date date, description text,
      amount numeric not null, status text default 'unmatched', matched_journal_id text,
      imported_at timestamptz default now())`,
    `create index if not exists bank_tx_tenant_idx on bank_transactions (tenant_id, date desc)`,
    `create table if not exists clock_events (
      id text primary key, tenant_id text not null, user_id text not null, user_name text,
      job_id text, job_label text, kind text not null,
      lat numeric, lng numeric, accuracy numeric,
      client_time timestamptz, created_at timestamptz default now())`,
    `create index if not exists clock_events_tenant_idx on clock_events (tenant_id, created_at desc)`,
    `create index if not exists clock_events_user_idx on clock_events (user_id, created_at desc)`,
    `create table if not exists job_photos (
      id text primary key, tenant_id text not null, photo_key text not null, job_id text, kind text,
      data text, uploaded_by text, lat numeric, lng numeric, created_at timestamptz default now())`,
    `create unique index if not exists job_photos_key_idx on job_photos (tenant_id, photo_key)`,
    `create table if not exists onsite_reports (
      id text primary key, tenant_id text not null, rid text not null, type text, job_id text,
      payload jsonb default '{}', signed_by text, completed boolean default false,
      updated_at timestamptz default now(), created_at timestamptz default now())`,
    `create unique index if not exists onsite_reports_rid_idx on onsite_reports (tenant_id, rid)`,
    `alter table tenants add column if not exists erp_enabled boolean default true`,
    `alter table tenants add column if not exists accounting_provider text default 'builtin'`,
    `alter table tenants add column if not exists region text`,
    `alter table products add column if not exists cost numeric default 0`,
    `alter table stock_movements add column if not exists job_id text`,
    `alter table stock_movements add column if not exists unit_cost numeric`,
    // Idempotent column adds for DBs created by an earlier deploy (tables already exist):
    `alter table tenant_documents add column if not exists content_html text`,
    `alter table document_publications add column if not exists body_html text`,
    `alter table document_publications alter column spaces_key drop not null`,
    `alter table invoices add column if not exists is_demo boolean default false`,
    `alter table invoices add column if not exists client_name text`,
    `alter table invoices add column if not exists description text`,
    `alter table invoices add column if not exists due text`,
    `alter table invoices add column if not exists quote_id text`,
    `alter table invoices add column if not exists lines jsonb default '[]'`,
    `alter table invoices alter column client_id drop not null`,
  ];
  for (const s of stmts) { try { await _db.query(s); } catch (e) { console.error("migrate stmt failed:", e.message); } }
}

module.exports = { db, query, rows, one, run, rid, audit, init };
