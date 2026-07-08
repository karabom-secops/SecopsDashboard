-- Migration: add 'sales' to the users role check constraint.
-- Run against an existing deployment that already has the old constraint.
-- Usage: psql -U secops_user -d secops_db -f db/migrate-sales-role.sql

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_chk;
ALTER TABLE users ADD CONSTRAINT users_role_chk
  CHECK (role IN ('superadmin', 'admin', 'readonly', 'manager', 'sales'));
