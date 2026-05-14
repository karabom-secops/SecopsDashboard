-- ============================================================
-- migrate-multi-tenant.sql
-- Adds the user_tenants junction table so a single user account
-- can be assigned to multiple tenants.
--
-- Safe to re-run — each step uses IF NOT EXISTS / ON CONFLICT DO NOTHING.
--
-- Usage (on the Ubuntu server):
--   psql -U secops_user -d secops_db -h localhost -f db/migrate-multi-tenant.sql
-- ============================================================

BEGIN;

-- ── 1. Create the junction table ────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS user_tenants (
  user_id   INT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
  tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  PRIMARY KEY (user_id, tenant_id)
);

-- ── 2. Backfill from existing users.tenant_id ───────────────────────────────
--      Every non-superadmin user already has a primary tenant; mirror it here.

INSERT INTO user_tenants (user_id, tenant_id)
SELECT id, tenant_id
FROM   users
WHERE  tenant_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- ── 3. Index for fast per-user lookups ──────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_user_tenants_user ON user_tenants (user_id);

COMMIT;
