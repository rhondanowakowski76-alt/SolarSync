# SolarSync — Fly.io removal (push these to `main`)

## Do these on your end
1. **DELETE** `fly.toml` from the repo root. (It's Fly-only; not used by DigitalOcean.)
2. **REPLACE** `Dockerfile` with the one in this folder.
3. **REPLACE** `README.md` with the one in this folder.

That's the complete Fly.io removal. Nothing else references Fly.

## Why this matters for your data / tabs
- `fly.toml` and the old `Dockerfile` set `DB_PATH=/data/solarsync.db`.
  `/data` was a **Fly volume** — it does NOT exist as persistent storage on
  DigitalOcean App Platform. On DO that folder is wiped on every deploy, so the
  database is empty/reset → tabs that read data show nothing.
- Proper fix: create a **DigitalOcean Managed Postgres** DB and point the app at
  it via an env var (the app already includes the `pg` Postgres driver).
  This needs a one-line change in `db.js`/`server.js` (see below) — I could not
  read those files remotely, so I can't hand them over yet.

## Still outstanding — needs me to read/edit the app code
These can't be fixed from a read-only view of the public repo. Connect the local
project folder (or authorize the GitHub connector) and I'll produce real files:

- **Blank screen:** repo has 3 mis-named entry files — `index.html.html`,
  `index (1).html`, `index.html (2).html` — and none named exactly `index.html`.
  The correct one needs to be identified and renamed to `index.html`.
- **Tabs not all functional:** requires reading the front-end tab code + the
  backend endpoints they call.
- **Tester/quoting shows one fake premise, no live address:** the quoting tester
  is using a hard-coded sample address instead of live address lookup — needs the
  quoting/tester code.
- **Base44 remnant:** the imported form/color-code from Base44 needs its Base44
  reference removed — needs the HTML file it lives in.
- **DB persistence:** switch `DB_PATH` file DB → DigitalOcean Managed Postgres.
