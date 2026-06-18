// Seed demo data (async, PostgreSQL). Safe to run repeatedly (idempotent reseed).
const { run, db } = require("./db");
const A = require("./auth");

const TID = "tenant-helios";
const RID = "reseller-solarsync";

async function seed() {
  await db(); // ensure schema migrated
  for (const t of ["resellers","tenants","users","clients","addons","tenant_addons","tester_tokens","report_templates","letterheads","reports","report_publications","invoices"])
    await run(`delete from ${t}`);

  await run("insert into resellers (id,name) values ($1,$2)", [RID, "SolarSync"]);
  await run("insert into tenants (id,reseller_id,name,domain,plan) values ($1,$2,$3,$4,$5)",
    [TID, RID, "Helios Solar", "portal.heliossolar.com.au", "Scale"]);

  // Users start with a PIN (123456) but NOT enrolled — first login shows the QR.
  const mk = (id, tenant, role, name) => run(
    "insert into users (id,tenant_id,app_role,display_name,pin_hash,totp_secret,totp_enrolled) values ($1,$2,$3,$4,$5,null,false)",
    [id, tenant, role, name, A.bcrypt.hashSync("123456", 10)]);
  await mk("u-reseller", null, "reseller", "SolarSync Admin");
  await mk("u-admin", TID, "tenant_admin", "Sarah Chen");
  await mk("u-contractor", TID, "contractor", "Dan Webb");
  await mk("u-client", TID, "client", "Adam Smith");

  await run("insert into clients (id,tenant_id,user_id,name,site_address,install_status,system_spec) values ($1,$2,$3,$4,$5,$6,$7)",
    ["c-adam", TID, "u-client", "Adam Smith", "42 Solar Ave, Brisbane QLD 4000", "installed",
     JSON.stringify({ systemKw: 6.6, panels: 16, panelModel: "Jinko Tiger Neo 440W", inverter: "Fronius Primo GEN24 5.0", battery: null, phone: "0412 345 678", email: "adam.smith@email.com" })]);

  for (const [k,n,p] of [["compliance-suite","Compliance Reports Suite",69],["vpp","VPP Enrollment Assistant",49],["document-library","Document Library",29]])
    await run("insert into addons (key,name,price) values ($1,$2,$3)", [k,n,p]);
  await run("insert into tester_tokens (token,scope,active) values ($1,$2,true)", ["TESTER-2026","compliance"]);

  const tpl = (k,t,b)=>run("insert into report_templates (key,category,title,body_html) values ($1,'compliance',$2,$3)", [k,t,b]);
  await tpl("rep-gridconnect","Grid-Connect Solar Installation — Compliance Report","<h1>Grid-Connect Solar Installation — Compliance Report</h1><p>AS/NZS 5033 · 4777.1 · 3000</p>");
  await tpl("rep-instmanual","Solar Installation Manual & Handover Pack","<h1>Solar Installation Manual & Handover Pack</h1><p>Full AS/NZS-compliant install procedure, photos, sign-off.</p>");

  await run("insert into invoices (id,tenant_id,client_id,number,amount,status) values ($1,$2,$3,$4,$5,'due')",
    ["inv-2048", TID, "c-adam", "INV-2048", 5880]);

  console.log("Seeded: reseller, Helios tenant, 4 users (PIN 123456), client, addons, 1 token, 2 templates, 1 due invoice.");
}

seed().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
