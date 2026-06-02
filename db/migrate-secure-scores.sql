-- Migration: Add secure_scores table for historical tracking
-- This table is optional; scores can be calculated on-the-fly from existing data.
-- Use this if you want to track historical score snapshots.

CREATE TABLE IF NOT EXISTS secure_scores (
  id SERIAL PRIMARY KEY,
  tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE,
  score_date DATE DEFAULT CURRENT_DATE,
  composite_score INT CHECK (composite_score >= 0 AND composite_score <= 100),
  vuln_score INT CHECK (vuln_score >= 0 AND vuln_score <= 100),
  awareness_score INT CHECK (awareness_score >= 0 AND awareness_score <= 100),
  mdr_score INT CHECK (mdr_score >= 0 AND mdr_score <= 100),
  calculated_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(tenant_id, score_date)
);

CREATE INDEX IF NOT EXISTS idx_secure_scores_tenant_date 
  ON secure_scores(tenant_id, score_date DESC);
