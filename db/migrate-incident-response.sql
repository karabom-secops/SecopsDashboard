-- Incident Response Module Migration
-- Run once: psql -d secops -f migrate-incident-response.sql

CREATE TABLE IF NOT EXISTS ir_incidents (
  id          SERIAL PRIMARY KEY,
  tenant_id   INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title       VARCHAR(300) NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity    VARCHAR(20) NOT NULL DEFAULT 'medium'
                CHECK (severity IN ('low','medium','high','critical')),
  status      VARCHAR(20) NOT NULL DEFAULT 'open'
                CHECK (status IN ('open','contained','remediating','resolved','closed')),
  assigned_to VARCHAR(200) NOT NULL DEFAULT '',
  phase       VARCHAR(30) NOT NULL DEFAULT 'identification'
                CHECK (phase IN ('identification','containment','eradication','recovery','post-incident-analysis')),
  opened_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  closed_at   TIMESTAMPTZ,
  created_by  INT REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ir_incidents_tenant ON ir_incidents(tenant_id);

-- Idempotent for databases where this migration already ran before the phase tracker was added
ALTER TABLE ir_incidents ADD COLUMN IF NOT EXISTS phase VARCHAR(30) NOT NULL DEFAULT 'identification';
DO $$ BEGIN
  ALTER TABLE ir_incidents ADD CONSTRAINT ir_incidents_phase_check
    CHECK (phase IN ('identification','containment','eradication','recovery','post-incident-analysis'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS ir_activities (
  id          SERIAL PRIMARY KEY,
  incident_id INT NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
  entry       TEXT NOT NULL,
  assignee    VARCHAR(200) NOT NULL DEFAULT '',
  status      VARCHAR(20) NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending','in-progress','done')),
  logged_by   INT REFERENCES users(id) ON DELETE SET NULL,
  logged_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ir_activities_incident ON ir_activities(incident_id);
