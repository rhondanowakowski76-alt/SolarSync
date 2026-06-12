// Seed demo data so the backend is testable/demonstrable immediately.
const { db, rid } = require("./db");
const A = require("./auth");

const TID = "tenant-helios";
const RID = "reseller-solarsync";

// Wipe (idempotent reseed)
for (const t of ["resellers","tenants","users","clients","addons","tenant_addons","tester_tokens","report_templates","letterheads","reports","report_publications","invoices"])
  db.prepare(`delete from ${t}`).run();

db.prepare("insert into resellers (id,name) values (?,?)").run(RID, "SolarSync");
db.prepare("insert into tenants (id,reseller_id,name,domain,plan) values (?,?,?,?,?)")
  .run(TID, RID, "Helios Solar", "portal.heliossolar.com.au", "Scale");

// Users start with a PIN (123456) but NOT enrolled — first login shows the
// authenticator setup key to add to Google Authenticator / Authy (real flow).
function mkUser(id, tenant, role, name) {
  db.prepare(`insert into users (id,tenant_id,app_role,display_name,pin_hash,totp_secret,totp_enrolled)
    values (?,?,?,?,?,?,0)`).run(id, tenant, role, name, A.bcrypt.hashSync("123456", 10), null);
}
mkUser("u-reseller", null, "reseller", "SolarSync Admin");
mkUser("u-admin", TID, "tenant_admin", "Sarah Chen");
mkUser("u-contractor", TID, "contractor", "Dan Webb");
mkUser("u-client", TID, "client", "Adam Smith");

db.prepare("insert into clients (id,tenant_id,user_id,name,site_address,install_status) values (?,?,?,?,?,?)")
  .run("c-adam", TID, "u-client", "Adam Smith", "42 Solar Ave, Brisbane QLD 4000", "installed");

// Add-ons + tester token
for (const [k,n,p] of [["compliance-suite","Compliance Reports Suite",69],["vpp","VPP Enrollment Assistant",49]])
  db.prepare("insert into addons (key,name,price) values (?,?,?)").run(k,n,p);
db.prepare("insert into tester_tokens (token,scope,active) values (?,?,1)").run("TESTER-2026","compliance");

// Report templates (subset; full HTML bodies come from the front-end bundle at wire-up)
const tpl = (k,t,b)=>db.prepare("insert into report_templates (key,category,title,body_html) values (?,?,?,?)").run(k,"compliance",t,b);
tpl("rep-gridconnect","Grid-Connect Solar Installation — Compliance Report","<h1>Grid-Connect Solar Installation — Compliance Report</h1><p>AS/NZS 5033 · 4777.1 · 3000</p>");
tpl("rep-instmanual","Solar Installation Manual & Handover Pack","<h1>Solar Installation Manual & Handover Pack</h1><p>Full AS/NZS-compliant install procedure, photos, sign-off.</p>");

// An unpaid invoice for the client (drives the report gate)
db.prepare("insert into invoices (id,tenant_id,client_id,number,amount,status) values (?,?,?,?,?,?)")
  .run("inv-2048", TID, "c-adam", "INV-2048", 5880, "due");

console.log("Seeded: reseller, Helios tenant, 4 users (PIN 123456), client, addons, 1 token, 2 templates, 1 due invoice.");
console.log("Users not yet enrolled — first login shows the authenticator setup key.");
