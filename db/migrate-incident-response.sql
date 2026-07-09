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

-- Incident type, used to select the seeded playbook of phase tasks on creation
ALTER TABLE ir_incidents ADD COLUMN IF NOT EXISTS incident_type VARCHAR(40) NOT NULL DEFAULT 'other';
DO $$ BEGIN
  ALTER TABLE ir_incidents ADD CONSTRAINT ir_incidents_type_check
    CHECK (incident_type IN ('phishing','malware_ransomware','data_breach','insider_threat','ddos','unauthorized_access','other'));
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

-- Per-task phase + ordering, so playbook tiles can be dragged across phase columns
-- independently of the incident's own overall phase.
ALTER TABLE ir_activities ADD COLUMN IF NOT EXISTS phase VARCHAR(30) NOT NULL DEFAULT 'identification';
DO $$ BEGIN
  ALTER TABLE ir_activities ADD CONSTRAINT ir_activities_phase_check
    CHECK (phase IN ('identification','containment','eradication','recovery','post-incident-analysis'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
ALTER TABLE ir_activities ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0;

-- Timestamp recorded when a playbook step tile is marked done
ALTER TABLE ir_activities ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ;

-- Backfill: existing activities inherit their incident's current phase
UPDATE ir_activities a SET phase = i.phase
FROM ir_incidents i
WHERE a.incident_id = i.id AND a.phase = 'identification' AND i.phase != 'identification';
