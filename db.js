// SolarSync backend — database (SQLite, single-file, Railway-volume friendly)
const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");

// On Railway, set DB_PATH to a mounted volume path (e.g. /data/solarsync.db)
// so data survives redeploys. Locally it falls back to ./data.
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "data", "solarsync.db");
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
create table if not exists resellers (
  id text primary key, name text not null, branding text default '{}',
  created_at text default (datetime('now'))
);
create table if not exists tenants (
  id text primary key, reseller_id text, name text not null, domain text,
  plan text default 'Growth', branding text default '{}', status text default 'active',
  created_at text default (datetime('now'))
);
create table if not exists users (
  id text primary key, tenant_id text, app_role text not null, display_name text not null,
  pin_hash text, totp_secret text, totp_enrolled integer default 0,
  must_reset integer default 0, failed_attempts integer default 0, locked_until text,
  status text default 'active', created_at text default (datetime('now'))
);
create table if not exists clients (
  id text primary key, tenant_id text not null, user_id text,
  name text not null, site_address text, system_spec text default '{}', install_status text,
  created_at text default (datetime('now'))
);
create table if not exists addons ( key text primary key, name text not null, price real default 0 );
create table if not exists tenant_addons (
  tenant_id text, addon_key text, active integer default 0, activated_at text,
  primary key (tenant_id, addon_key)
);
create table if not exists tester_tokens ( token text primary key, scope text default 'compliance', active integer default 1 );
create table if not exists report_templates ( key text primary key, category text default 'compliance', title text not null, body_html text not null );
create table if not exists letterheads (
  tenant_id text primary key, legal_name text, abn text, address text, phone text, email text,
  licence text, logo_url text, updated_at text default (datetime('now'))
);
create table if not exists reports (
  id text primary key, tenant_id text not null, template_key text, job_ref text,
  title text not null, body_html text not null, status text default 'draft',
  created_by text, updated_at text default (datetime('now')), created_at text default (datetime('now'))
);
create table if not exists report_publications (
  id text primary key, report_id text, tenant_id text not null, client_id text not null,
  title text, body_html text, published_at text default (datetime('now'))
);
create table if not exists invoices (
  id text primary key, tenant_id text not null, client_id text not null, number text not null,
  amount real not null, status text default 'due', stripe_payment_intent text, paid_at text,
  created_at text default (datetime('now'))
);
create table if not exists files (
  id text primary key, tenant_id text not null, owner_type text, owner_id text, kind text,
  url text not null, mime text, created_at text default (datetime('now'))
);
create table if not exists audit_log (
  id text primary key, actor_id text, action text not null, target text, tenant_id text,
  meta text default '{}', created_at text default (datetime('now'))
);
`);

function audit(actor_id, action, target, tenant_id, meta = {}) {
  db.prepare(`insert into audit_log (id, actor_id, action, target, tenant_id, meta)
    values (?,?,?,?,?,?)`).run(rid(), actor_id, action, target, tenant_id, JSON.stringify(meta));
}
function rid() { return require("crypto").randomUUID(); }

module.exports = { db, audit, rid };
