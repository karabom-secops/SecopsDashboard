-- Migration: add 'client' to the users role check constraint.
--
-- 'client' is the first role in this system that belongs to someone OUTSIDE
-- Reflex — a customer logging in to the client portal. It is deliberately NOT
-- a narrower version of 'readonly': readonly grants read on every tab
-- (lib/pages.js VIEWER_TABS), including Red Team findings and MDR pricing.
--
-- A client's page access is 'none' everywhere (lib/pages.js ROLE_DEFAULTS.client).
-- They never use the page catalog at all; they are confined to /api/portal/* by
-- requirePortalConfinement in lib/portal-gate.js. The empty access map is
-- belt-and-braces so that even a bypass of that confinement grants nothing.
--
-- Usage: psql -U secops_user -d secops_db -f db/migrate-client-role.sql
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_chk;
ALTER TABLE users ADD CONSTRAINT users_role_chk
  CHECK (role IN ('superadmin', 'admin', 'readonly', 'manager', 'sales', 'client'));
