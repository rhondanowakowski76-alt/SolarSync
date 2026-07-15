-- SolarSync — staff & contractor seats (multi-tenant)
-- Run once against your database. Safe/idempotent (IF NOT EXISTS).
-- ADJUST the table name "tenants" if yours differs (e.g. "reseller_tenants").

-- 1) Seat allowance per tenant (mirrors their subscription plan)
ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS staff_seat_limit INTEGER NOT NULL DEFAULT 3;

-- 2) Staff / contractor records, scoped to a tenant
CREATE TABLE IF NOT EXISTS tenant_staff (
  id            SERIAL PRIMARY KEY,
  tenant_id     INTEGER NOT NULL,
  name          TEXT    NOT NULL,
  email         TEXT,
  role          TEXT    NOT NULL DEFAULT 'staff',      -- 'staff' | 'admin'
  member_type   TEXT    NOT NULL DEFAULT 'employee',   -- 'employee' | 'contractor'
  counts_seat   BOOLEAN NOT NULL DEFAULT TRUE,         -- contractors can be set FALSE
  status        TEXT    NOT NULL DEFAULT 'active',      -- 'active' | 'suspended' | 'removed'
  pin_hash      TEXT,                                   -- optional: bcrypt PIN for login
  created_by    TEXT,                                   -- who added them
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT tenant_staff_email_unique UNIQUE (tenant_id, email)
);

CREATE INDEX IF NOT EXISTS idx_tenant_staff_tenant
  ON tenant_staff (tenant_id, status);
