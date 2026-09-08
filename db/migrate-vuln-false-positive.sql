-- ─────────────────────────────────────────────────────────────────────────────
-- A false-positive status for vulnerability findings
--
--   psql -d secops -f db/migrate-vuln-false-positive.sql
--
-- WHY
--
-- A scanner finding that is not real had nowhere to go. The available statuses
-- were open, in-progress, fixed and accepted, and every one of them is a lie
-- about a false positive:
--
--   open / in-progress   says the risk exists and someone is working on it
--   fixed                says we changed something. We did not — there was
--                        nothing to change
--   accepted             says the client has knowingly signed off a live risk.
--                        That is the worst of the four: it puts an imaginary
--                        risk on the acceptance register, and a board reviewing
--                        accepted risk is then reviewing something that was
--                        never there
--
-- So analysts left them open, and the score carried findings that do not exist.
--
-- WHAT IT DOES TO THE SCORE
--
-- A false positive leaves the active counts entirely, exactly like fixed. That
-- is not leniency — the finding was never a risk, so counting it was the error,
-- and removing it makes the score more accurate rather than more generous. See
-- computeVulnSummary() in lib/vuln-parser.js.
--
-- It is deliberately NOT the same as `accepted`, which stays a live risk
-- somebody signed off, and is reported separately so the two can never be read
-- as the same thing.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE vuln_findings
  DROP CONSTRAINT IF EXISTS vuln_findings_status_chk;

ALTER TABLE vuln_findings
  ADD CONSTRAINT vuln_findings_status_chk
  CHECK (status IN ('open', 'in-progress', 'fixed', 'accepted', 'false-positive'));

COMMENT ON COLUMN vuln_findings.status IS
  'open | in-progress | fixed | accepted | false-positive. '
  'open and in-progress are ACTIVE and count toward the Secure Score. '
  'fixed and false-positive leave the counts — one because the risk was closed, '
  'the other because it never existed. accepted also leaves the counts but is a '
  'live risk signed off by the client, and is reported separately.';
