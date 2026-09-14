-- Risk acceptances — a client formally accepting a finding, reviewed by staff.
--
-- A client submits from the portal; nothing about the finding or the Secure
-- Score changes until an analyst approves it. Approval sets the finding to
-- accepted (vulnerabilities) or risk-accepted (penetration test findings); the
-- expiry reopens it. See lib/risk-acceptance.js for the rules and why.
--
-- Safe to re-run.

CREATE TABLE IF NOT EXISTS risk_acceptances (
  id               SERIAL PRIMARY KEY,
  tenant_id        INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  source           VARCHAR(10)  NOT NULL CHECK (source IN ('vuln', 'pentest')),

  -- vuln_findings.id or pentest_findings.id AT THE TIME OF THE REQUEST. No
  -- foreign key: vulnerability rows are rewritten on every scan upload, and the
  -- acceptance must outlive the row it was raised against.
  finding_id       INT          NOT NULL,

  -- How a vulnerability is followed into later scans — the same
  -- plugin|host|port key the upload carry-forward uses. STAFF-ONLY: host and
  -- port are the perimeter detail the portal withholds. NULL for pentest.
  plugin_id        TEXT,
  host             TEXT,
  port             TEXT,

  -- Snapshots, so the register still reads correctly after the finding is gone.
  finding_title    TEXT         NOT NULL,
  finding_severity VARCHAR(20),

  approver_name    VARCHAR(120) NOT NULL CHECK (char_length(btrim(approver_name)) > 0),
  approver_role    VARCHAR(120) NOT NULL CHECK (char_length(btrim(approver_role)) > 0),
  justification    TEXT         NOT NULL CHECK (char_length(justification) BETWEEN 20 AND 2000),
  expires_on       DATE         NOT NULL,

  status           VARCHAR(12)  NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawn', 'expired')),

  requested_by     INT          REFERENCES users(id) ON DELETE SET NULL,
  requested_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  reviewed_by      INT          REFERENCES users(id) ON DELETE SET NULL,
  reviewed_at      TIMESTAMPTZ,
  -- Written TO the client: shown in the portal on approval or rejection.
  review_note      TEXT         CHECK (review_note IS NULL OR char_length(review_note) <= 1000),
  closed_at        TIMESTAMPTZ,

  -- An acceptance that has already expired on the day it was made is not one.
  CONSTRAINT risk_acceptances_expiry_future
    CHECK (expires_on > (requested_at AT TIME ZONE 'UTC')::date)
);

-- One live acceptance per finding. The application checks first so the client
-- gets a clear message; this is what holds under a double-submit race.
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_acceptances_live
  ON risk_acceptances (tenant_id, source, finding_id)
  WHERE status IN ('pending', 'approved');

CREATE INDEX IF NOT EXISTS idx_risk_acceptances_tenant_status
  ON risk_acceptances (tenant_id, status, requested_at DESC);

-- The daily expiry sweep.
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_expiry
  ON risk_acceptances (expires_on)
  WHERE status = 'approved';

COMMENT ON TABLE risk_acceptances IS
  'Client-requested risk acceptances. pending until staff approve; approval sets '
  'the finding accepted and removes it from the Secure Score; expiry reopens it. '
  'host/port/plugin_id are staff-only and must never be returned by the portal.';
