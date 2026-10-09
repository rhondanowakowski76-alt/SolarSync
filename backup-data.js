// SolarSync — full data backup / restore (every table in the app schema → one JSON file).
//
//   node backup-data.js                    back up to data-backups/solarsync-backup-<time>.json
//   node backup-data.js --restore <file>   put rows from a backup back (never overwrites:
//                                          rows whose id already exists are skipped)
//
// Uses the same connection as the app: DATABASE_URL when set (production Postgres),
// otherwise the local PGlite database in data/pg. The backup holds customer details,
// PIN hashes and authenticator secrets — keep the file private and never commit it.
const fs = require("fs");
const path = require("path");
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

async function backup() {
  const out = { created_at: new Date().toISOString(), source: describeTarget(), tables: {} };
  let total = 0;
  for (const t of await tables()) {
    out.tables[t] = await rows(`select * from app."${t}"`);
    total += out.tables[t].length;
    console.log(`  ${t.padEnd(24)} ${out.tables[t].length} rows`);
  }
  const dir = path.join(__dirname, "data-backups");
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, "solarsync-backup-" + out.created_at.replace(/[:.]/g, "-") + ".json");
  fs.writeFileSync(file, JSON.stringify(out));
  console.log(`\nBacked up ${total} rows from ${Object.keys(out.tables).length} tables`);
  console.log("Source: " + out.source);
  console.log("Saved to: " + file);
}

async function restore(file) {
  const data = JSON.parse(fs.readFileSync(file, "utf8"));
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

(async () => {
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
