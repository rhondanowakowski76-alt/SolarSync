# SolarSync Portal

Self-contained app: Node/Express backend (PIN + TOTP auth, reports, billing gate)
serving the front-end. Multi-tenant reseller portal.

**Hosting:** DigitalOcean App Platform (deploys automatically from `main`).
**Document storage:** DigitalOcean Spaces — see `DEPLOY-SETUP.md` for the
required `SPACES_*` environment variables.

> Note: the container filesystem on App Platform is ephemeral (reset on each
> deploy). Use a DigitalOcean Managed Postgres database for persistent data and
> configure it via environment variables.
