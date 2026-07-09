-- Link Red Team engagements to a SecOps tenant so findings can auto-populate
-- that tenant's Remediation Tracker.
-- Run once: psql -d secops -f db/migrate-redteam-tenant-link.sql

ALTER TABLE redteam_projects ADD COLUMN IF NOT EXISTS tenant_id INT REFERENCES tenants(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_redteam_projects_tenant ON redteam_projects(tenant_id);
