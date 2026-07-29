-- Managed EDR (SentinelOne) Migration
-- Run once: psql -d secops -f migrate-edr.sql
--
-- Threats and activities are UPSERTed by their SentinelOne id, so the dashboard
-- keeps history beyond the provider's own retention window. Agents are a fleet
-- snapshot — also upserted, with stale rows pruned by the sync.

CREATE TABLE IF NOT EXISTS edr_threats (
  id                    SERIAL PRIMARY KEY,
  tenant_id             INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  threat_id             VARCHAR(64)  NOT NULL,
  threat_name           TEXT,
  classification        VARCHAR(120),
  classification_source VARCHAR(60),
  confidence_level      VARCHAR(30),   -- malicious | suspicious | n/a
  analyst_verdict       VARCHAR(30),   -- true_positive | false_positive | suspicious | undefined
  incident_status       VARCHAR(30),   -- unresolved | in_progress | resolved
  mitigation_status     VARCHAR(60),   -- mitigated | not_mitigated | marked_as_benign | active …
  detection_type        VARCHAR(60),   -- static | dynamic
  detection_engines     TEXT,
  endpoint_name         TEXT,
  endpoint_id           VARCHAR(64),
  os_name               TEXT,
  agent_version         TEXT,
  site_name             TEXT,
  group_name            TEXT,
  file_path             TEXT,
  file_hash             VARCHAR(128),
  initiated_by          VARCHAR(60),
  detected_at           TIMESTAMPTZ,
  mitigated_at          TIMESTAMPTZ,
  resolved_at           TIMESTAMPTZ,
  updated_at            TIMESTAMPTZ,
  raw_json              JSONB,
  synced_at             TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (tenant_id, threat_id)
);

CREATE INDEX IF NOT EXISTS idx_edr_threats_tenant_detected ON edr_threats(tenant_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_edr_threats_tenant_status   ON edr_threats(tenant_id, incident_status);

CREATE TABLE IF NOT EXISTS edr_activities (
  id                    SERIAL PRIMARY KEY,
  tenant_id             INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  activity_id           VARCHAR(64)  NOT NULL,
  activity_type         INT,
  activity_type_name    TEXT,
  primary_description   TEXT,
  secondary_description TEXT,
  endpoint_name         TEXT,
  endpoint_id           VARCHAR(64),
  site_name             TEXT,
  group_name            TEXT,
  user_name             TEXT,
  threat_id             VARCHAR(64),
  created_at            TIMESTAMPTZ,
  raw_json              JSONB,
  synced_at             TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (tenant_id, activity_id)
);

CREATE INDEX IF NOT EXISTS idx_edr_activities_tenant_created ON edr_activities(tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS edr_agents (
  id             SERIAL PRIMARY KEY,
  tenant_id      INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  agent_id       VARCHAR(64)  NOT NULL,
  computer_name  TEXT,
  os_name        TEXT,
  os_type        VARCHAR(40),
  agent_version  TEXT,
  machine_type   VARCHAR(40),
  domain         TEXT,
  site_name      TEXT,
  group_name     TEXT,
  is_active      BOOLEAN,
  is_infected    BOOLEAN,
  is_up_to_date  BOOLEAN,
  network_status VARCHAR(40),
  scan_status    VARCHAR(40),
  active_threats INT          DEFAULT 0,
  last_active_at TIMESTAMPTZ,
  registered_at  TIMESTAMPTZ,
  synced_at      TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (tenant_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_edr_agents_tenant ON edr_agents(tenant_id);
