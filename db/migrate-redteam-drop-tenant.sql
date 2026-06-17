-- Migration: remove tenant_id from redteam tables.
-- Red Team data is global (not tenant-scoped), like Operations.
-- Usage: psql -U secops_user -d secops_db -f db/migrate-redteam-drop-tenant.sql

ALTER TABLE redteam_tasks    DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE redteam_projects DROP COLUMN IF EXISTS tenant_id;

DROP INDEX IF EXISTS idx_rt_projects_tenant;
DROP INDEX IF EXISTS idx_rt_tasks_tenant;
