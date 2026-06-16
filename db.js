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
  ];
  for (const s of stmts) await _db.query(s);
}

module.exports = { db, query, rows, one, run, rid, audit, init };
