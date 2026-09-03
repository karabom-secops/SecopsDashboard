-- ─────────────────────────────────────────────────────────────────────────────
-- The `analyst` role
--
-- SOC analysts are a distinct job function and this application already models
-- job functions as roles — sales, manager. Giving them the training portal by
-- role rather than by per-user grant means a new analyst gets access by being
-- an analyst, not by somebody remembering to tick a box on the Admin tab.
--
-- WHAT AN ANALYST IS
--
-- Read-only across the dashboard, plus the Training tab. The defaults live in
-- lib/pages.js (ROLE_DEFAULTS.analyst) — this migration only widens the
-- constraint so the role can be stored.
--
-- NOBODY IS MOVED BY THIS FILE. Existing analysts keep whatever role they have
-- and must be reassigned deliberately on the Admin tab. That is the safe
-- direction: nobody gains access by accident, and nobody gains it silently.
--
--   psql -d secops -f db/migrate-analyst-role.sql
--
-- Idiom follows db/migrate-client-role.sql and db/migrate-sales-role.sql.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_chk;
ALTER TABLE users ADD CONSTRAINT users_role_chk
  CHECK (role IN ('superadmin','admin','readonly','manager','sales','client','analyst'));

COMMENT ON COLUMN users.role IS
  'superadmin/admin/manager/sales/readonly/analyst are internal; client is external and confined to /api/portal by lib/portal-gate.js.';
