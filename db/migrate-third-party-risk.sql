-- Third-Party Risk Management Module Migration
-- Run once: psql -d secops -f migrate-third-party-risk.sql

CREATE TABLE IF NOT EXISTS vendors (
  id                 SERIAL PRIMARY KEY,
  tenant_id          INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name               VARCHAR(200) NOT NULL,
  service            TEXT NOT NULL DEFAULT '',           -- what they do for us
  owner              VARCHAR(200) NOT NULL DEFAULT '',   -- internal relationship owner
  criticality        VARCHAR(20) NOT NULL DEFAULT 'medium'
                       CHECK (criticality IN ('critical','high','medium','low')),
  data_access        VARCHAR(20) NOT NULL DEFAULT 'none'
                       CHECK (data_access IN ('none','internal','confidential','pii','regulated')),
  network_access     BOOLEAN NOT NULL DEFAULT FALSE,
  assurance          VARCHAR(20) NOT NULL DEFAULT 'none'
                       CHECK (assurance IN ('none','questionnaire','soc2','iso27001','both')),
  assurance_expires  DATE,
  contract_start     DATE,
  contract_end       DATE,
  last_review_date   DATE,
  next_review_date   DATE,
  status             VARCHAR(20) NOT NULL DEFAULT 'active'
                       CHECK (status IN ('onboarding','active','under_review','offboarding','terminated')),
  -- Derived by lib/vendor-score.js on every write. Never client-supplied.
  inherent_score     SMALLINT NOT NULL DEFAULT 1,
  residual_score     SMALLINT NOT NULL DEFAULT 1,
  notes              TEXT NOT NULL DEFAULT '',
  created_by         INT REFERENCES users(id) ON DELETE SET NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_vendors_tenant ON vendors(tenant_id);

-- Manual link only: lets a register entry be attributed to a vendor. Nothing
-- ever sets this automatically (unlike risks.grc_question_id). ON DELETE SET
-- NULL so removing a vendor cannot delete the risk it raised.
ALTER TABLE risks ADD COLUMN IF NOT EXISTS vendor_id INT REFERENCES vendors(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_risks_vendor ON risks(vendor_id);
