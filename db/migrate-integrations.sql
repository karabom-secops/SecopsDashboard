-- Integrations Migration
-- Run once: psql -d secops -f migrate-integrations.sql

CREATE TABLE IF NOT EXISTS integrations (
  id                 SERIAL PRIMARY KEY,
  tenant_id          INT          REFERENCES tenants(id) ON DELETE CASCADE,
  provider           VARCHAR(50)  NOT NULL,
  base_url           TEXT         NOT NULL,
  api_key_enc        TEXT         NOT NULL,
  api_key_iv         TEXT         NOT NULL,
  is_enabled         BOOLEAN      DEFAULT TRUE,
  last_synced_at     TIMESTAMPTZ,
  last_sync_status   VARCHAR(20),
  last_sync_message  TEXT,
  created_at         TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE(tenant_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_integrations_tenant ON integrations(tenant_id);

-- Provider-specific extra config (e.g. organizationUuid for Arctic Wolf)
ALTER TABLE integrations ADD COLUMN IF NOT EXISTS config_json JSONB DEFAULT '{}';
