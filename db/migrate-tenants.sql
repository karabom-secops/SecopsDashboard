-- ============================================================
-- migrate-tenants.sql
-- One-time migration: adds multi-tenant support to an existing
-- SecOps Dashboard database that already has the old schema
-- (users + vuln_scans without tenants).
--
-- Safe to re-run — each step uses IF NOT EXISTS / DO NOTHING.
--
-- Usage (on the Ubuntu server):
--   psql -U secops_user -d secops_db -h localhost -f db/migrate-tenants.sql
-- ============================================================

BEGIN;

-- ── 1. Create tenants table ───────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenants (
  id         SERIAL PRIMARY KEY,
  name       VARCHAR(100) UNIQUE NOT NULL,
  slug       VARCHAR(30)  UNIQUE NOT NULL,
  created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── 2. Seed the "Default Org" tenant ─────────────────────────────────────
--      (all pre-existing data will be assigned to this tenant)

INSERT INTO tenants (name, slug)
VALUES ('Default Org', 'default')
ON CONFLICT (slug) DO NOTHING;

-- ── 3. Add tenant_id column to users (nullable — superadmin stays NULL) ──

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL;

-- ── 4. Widen the role check to include 'superadmin' ──────────────────────

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_chk;

ALTER TABLE users
  ADD CONSTRAINT users_role_chk
    CHECK (role IN ('superadmin', 'admin', 'readonly'));

-- ── 5. Promote every existing 'admin' user to 'superadmin' ───────────────
--      Superadmins are org-agnostic — tenant_id stays NULL.

UPDATE users
SET role = 'superadmin', tenant_id = NULL
WHERE role = 'admin';

-- ── 6. Add tenant_id column to vuln_scans (start nullable) ───────────────

ALTER TABLE vuln_scans
  ADD COLUMN IF NOT EXISTS tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE;

-- ── 7. Assign all existing scans to the Default Org ──────────────────────

UPDATE vuln_scans
SET tenant_id = (SELECT id FROM tenants WHERE slug = 'default')
WHERE tenant_id IS NULL;

-- ── 8. Make tenant_id NOT NULL now that every row has a value ─────────────

ALTER TABLE vuln_scans
  ALTER COLUMN tenant_id SET NOT NULL;

-- ── 9. Replace the global UNIQUE on month_key with a per-tenant UNIQUE ───

ALTER TABLE vuln_scans
  DROP CONSTRAINT IF EXISTS vuln_scans_month_key_key;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'vuln_scans_tenant_month_key'
  ) THEN
    ALTER TABLE vuln_scans
      ADD CONSTRAINT vuln_scans_tenant_month_key UNIQUE (tenant_id, month_key);
  END IF;
END;
$$;

COMMIT;

-- ── Done ──────────────────────────────────────────────────────────────────
\echo 'Migration complete.'
\echo 'Existing admin users promoted to superadmin.'
\echo 'Existing vuln scans assigned to Default Org.'
