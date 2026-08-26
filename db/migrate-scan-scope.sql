-- ─────────────────────────────────────────────────────────────────────────────
-- Scan scope: how many hosts a scan actually touched
--
-- The Secure Score's vulnerability component divides findings by the assets in
-- scope. It had no way to know what a scan covered, so it counted DISTINCT host
-- in vuln_findings — which counts HOSTS THAT HAD FINDINGS, not hosts scanned.
-- Informational rows are dropped at parse time (lib/vuln-parser.js), so a host
-- that came back clean leaves no trace in the database at all.
--
-- That inverted the measure: the cleaner an estate, the fewer hosts appeared,
-- and the worse its apparent scan coverage looked. A client who scanned 50
-- hosts and had findings on 10 read as 20% coverage.
--
-- The real figure is recovered at parse time now — Nessus emits an
-- informational row for every host it touched, and a .nessus file carries one
-- ReportHost element per host — and lands here.
--
-- NULL means "scope unknown", which the score treats as neutral. Scans uploaded
-- before this migration keep NULL: the host list was discarded on the way in
-- and CANNOT be reconstructed, so those scans go on being scored without a
-- coverage cap until they are re-uploaded. An Arctic Wolf Managed Risk export
-- is a risk register rather than a scan and never carries scope, so it stays
-- NULL permanently.
--
--   psql -d secops -f db/migrate-scan-scope.sql
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE vuln_scans ADD COLUMN IF NOT EXISTS scanned_hosts INT;

ALTER TABLE vuln_scans DROP CONSTRAINT IF EXISTS vuln_scans_scanned_hosts_chk;
ALTER TABLE vuln_scans ADD  CONSTRAINT vuln_scans_scanned_hosts_chk
  CHECK (scanned_hosts IS NULL OR scanned_hosts >= 0);

COMMENT ON COLUMN vuln_scans.scanned_hosts IS
  'Hosts the scan touched, clean ones included. NULL = scope unknown (pre-migration upload, or a format that cannot report it). Never derive this from vuln_findings.';
