-- Risk Register Module Migration
-- Run once: psql -d secops -f migrate-risk-register.sql

CREATE TABLE IF NOT EXISTS risks (
  id              SERIAL PRIMARY KEY,
  tenant_id       INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  title           VARCHAR(200) NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  category        VARCHAR(50) NOT NULL DEFAULT 'operational'
                    CHECK (category IN ('operational','financial','compliance','technical','reputational')),
  likelihood      SMALLINT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
  impact          SMALLINT NOT NULL CHECK (impact BETWEEN 1 AND 5),
  risk_score      SMALLINT NOT NULL,
  owner           VARCHAR(200) NOT NULL DEFAULT '',
  mitigation_plan TEXT NOT NULL DEFAULT '',
  stage           VARCHAR(20) NOT NULL DEFAULT 'identified'
                    CHECK (stage IN ('identified','assessing','mitigating','monitoring','closed')),
  start_date      DATE NOT NULL DEFAULT CURRENT_DATE,
  due_date        DATE,
  closed_at       TIMESTAMPTZ,
  created_by      INT REFERENCES users(id) ON DELETE SET NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_risks_tenant ON risks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_risks_tenant_stage ON risks(tenant_id, stage);

-- Idempotent for databases where this migration already ran before closed_at was added
ALTER TABLE risks ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ;
