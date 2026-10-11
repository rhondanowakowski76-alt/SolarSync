// SolarSync — full data backup / restore (every table in the app schema → one JSON file).
//
//   node backup-data.js                    back up to data-backups/solarsync-backup-<time>.json.enc
//   node backup-data.js --restore <file>   put rows from a backup back (never overwrites:
//                                          rows whose id already exists are skipped)
//
// Uses the same connection as the app: DATABASE_URL when set (production Postgres),
// otherwise the local PGlite database in data/pg.
//
// Backups are ENCRYPTED. They hold customer details, PIN hashes and authenticator
// secrets, so the file is compressed and sealed with AES-256-GCM using a key made from
// the BACKUP_KEY environment variable (scrypt, fresh random salt and IV per file). A
// wrong key or a tampered file fails to open. Set BACKUP_KEY on the server — at least
// 16 characters, kept in your hosting's secret settings, never in code or chat — and
// store a copy somewhere safe: a backup cannot be restored without it.
// Without BACKUP_KEY the backup refuses to run (add --unencrypted only for a local
// test database). Older plain .json backups can still be restored.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");

const FORMAT = "solarsync-backup-enc-v1";
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function backupKey(required) {
  const k = process.env.BACKUP_KEY || "";
  if (!k) { if (required) throw new Error("BACKUP_KEY is not set. Set it in the server's secret settings (at least 16 characters)."); return null; }
  if (k.length < 16) throw new Error("BACKUP_KEY is too short — use at least 16 characters.");
  return k;
}

function seal(json, passphrase) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32, SCRYPT);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const data = Buffer.concat([c.update(zlib.gzipSync(Buffer.from(json, "utf8"))), c.final()]);
  return JSON.stringify({ format: FORMAT, kdf: "scrypt", salt: salt.toString("base64"), iv: iv.toString("base64"),
    tag: c.getAuthTag().toString("base64"), data: data.toString("base64") });
}

function open(text, passphrase) {
  const env = JSON.parse(text);
  if (env.format !== FORMAT) return env;   // an older, unencrypted backup
  const key = crypto.scryptSync(passphrase, Buffer.from(env.salt, "base64"), 32, SCRYPT);
  const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(env.iv, "base64"));
  d.setAuthTag(Buffer.from(env.tag, "base64"));
  let plain;
  try { plain = Buffer.concat([d.update(Buffer.from(env.data, "base64")), d.final()]); }
  catch (e) { throw new Error("Could not open the backup — wrong BACKUP_KEY, or the file was changed."); }
  return JSON.parse(zlib.gunzipSync(plain).toString("utf8"));
}
const { init, rows, query } = require("./db");

function describeTarget() {
  if (!process.env.DATABASE_URL) return "LOCAL test database (" + (process.env.PGLITE_DIR || "data/pg") + ") — DATABASE_URL is not set";
  try { return "Postgres at " + new URL(process.env.DATABASE_URL).hostname; } catch (e) { return "Postgres (DATABASE_URL)"; }
}

async function tables() {
  const r = await rows(
    "select table_name from information_schema.tables where table_schema='app' and table_type='BASE TABLE' order by table_name");
  return r.map(t => t.table_name);
}

// Every table as one object (used by the command line here and the owner portal's
// "Create encrypted backup" button).
async function collect(log) {
  const out = { created_at: new Date().toISOString(), source: describeTarget(), tables: {} };
  let total = 0;
  for (const t of await tables()) {
    out.tables[t] = await rows(`select * from app."${t}"`);
    total += out.tables[t].length;
    if (log) log(`  ${t.padEnd(24)} ${out.tables[t].length} rows`);
  }
  return { out, total };
}

async function backup() {
  const unencrypted = process.argv.includes("--unencrypted");
  if (unencrypted && process.env.DATABASE_URL) throw new Error("--unencrypted is only for a local test database, never production.");
  const passphrase = unencrypted ? null : backupKey(true);
  const { out, total } = await collect(console.log);
  const dir = path.join(__dirname, "data-backups");
  fs.mkdirSync(dir, { recursive: true });
  const base = path.join(dir, "solarsync-backup-" + out.created_at.replace(/[:.]/g, "-") + ".json");
  const file = passphrase ? base + ".enc" : base;
  fs.writeFileSync(file, passphrase ? seal(JSON.stringify(out), passphrase) : JSON.stringify(out), { mode: 0o600 });
  console.log(`\nBacked up ${total} rows from ${Object.keys(out.tables).length} tables`);
  console.log("Source: " + out.source);
  console.log("Saved to: " + file + (passphrase ? "  (encrypted)" : "  (NOT encrypted — local test only)"));
}

async function restore(file) {
  const text = fs.readFileSync(file, "utf8");
  const sealed = JSON.parse(text).format === FORMAT;
  const data = open(text, sealed ? backupKey(true) : null);
  const existing = new Set(await tables());
  let added = 0;
  for (const [t, list] of Object.entries(data.tables || {})) {
    if (!existing.has(t)) { console.log(`  ${t}: table not in this database — skipped`); continue; }
    let n = 0;
    for (const row of list) {
      const cols = Object.keys(row);
      const vals = cols.map(c => (row[c] !== null && typeof row[c] === "object") ? JSON.stringify(row[c]) : row[c]);
      const r = await query(
        `insert into app."${t}" (${cols.map(c => `"${c}"`).join(",")}) values (${cols.map((_, i) => "$" + (i + 1)).join(",")}) on conflict do nothing`,
        vals);
      n += r.affectedRows ?? r.rowCount ?? 0;
    }
    added += n;
    console.log(`  ${t.padEnd(24)} ${n} of ${list.length} rows restored`);
  }
  console.log(`\nRestored ${added} rows into ${describeTarget()} (existing rows left unchanged)`);
}

module.exports = { collect, seal, backupKey };

if (require.main === module) (async () => {
  await init();
  console.log("Database: " + describeTarget() + "\n");
  const i = process.argv.indexOf("--restore");
  if (i !== -1) {
    if (!process.argv[i + 1]) throw new Error("Give the backup file: node backup-data.js --restore <file>");
    await restore(process.argv[i + 1]);
  } else {
    await backup();
  }
  process.exit(0);
})().catch(e => { console.error("Backup failed: " + e.message); process.exit(1); });
