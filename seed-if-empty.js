// Seed the database only on first boot (so redeploys don't wipe live data).
const { db } = require("./db");
const n = db.prepare("select count(*) c from users").get().c;
if (n === 0) {
  console.log("Empty database — seeding initial data…");
  require("./seed.js");
} else {
  console.log(`Database already has ${n} users — skipping seed.`);
}
