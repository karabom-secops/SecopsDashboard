-- Firewall finding categories
-- Run once: psql -d secops -f migrate-firewall-categories.sql
--
-- Findings are now grouped into the categories a client-facing firewall
-- assessment reports against — Risky Policy Conditions, Policy Attribute,
-- Risky Inbound Blanket, Risky Inbound Conditions, Risky Outbound Conditions —
-- plus the device-hardening groups those reports do not cover.
--
-- ══ WHY THERE IS NO DEFAULT AND NO CHECK CONSTRAINT ══
--
-- NULLABLE, and rows written before this migration stay NULL. That is correct:
-- a finding stored by the previous version was never categorised, and
-- back-filling it with a plausible category would be inventing data about an
-- audit nobody re-ran. lib/fortigate-score.js reports uncategorised findings
-- rather than bucketing them, so an old audit reads as "not categorised"
-- instead of quietly landing in the wrong group.
--
-- No CHECK constraint on the value, deliberately: the category list lives in
-- lib/fortigate-checks.js and will grow. A constraint here would mean every new
-- category needs a migration before the code that emits it can ship, and the
-- failure mode is an INSERT that rejects a finding — losing the finding to
-- protect a spelling.

ALTER TABLE firewall_findings ADD COLUMN IF NOT EXISTS category TEXT;

-- Findings are read grouped by category within an audit.
CREATE INDEX IF NOT EXISTS idx_firewall_findings_category
  ON firewall_findings (audit_id, category);

COMMENT ON COLUMN firewall_findings.category IS
  'Report grouping from lib/fortigate-checks.js CATEGORIES. NULL means the finding predates categorisation — not that it belongs nowhere.';
