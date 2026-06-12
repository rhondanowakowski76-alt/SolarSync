// Seed only on first boot (so redeploys never wipe live data).
const { one, db } = require("./db");

(async () => {
  await db();
  const r = await one("select count(*)::int as c from users");
  if (!r || r.c === 0) {
    console.log("Empty database — seeding initial data…");
    require("./seed.js");   // seeds then exits
  } else {
    console.log(`Database already has ${r.c} users — skipping seed.`);
    process.exit(0);
  }
})().catch(e => { console.error(e); process.exit(1); });
