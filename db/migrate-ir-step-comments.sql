-- ─────────────────────────────────────────────────────────────────────────────
-- Comments on incident response playbook steps
--
--   psql -d secops -f db/migrate-ir-step-comments.sql
--
-- THE PROBLEM
--
-- A playbook step had a status, an assignee and a completion time, and nowhere
-- to say anything. "Message trace run — 14 recipients, 2 submitted credentials"
-- is the most useful sentence in a phishing response, and it had to live in an
-- analyst's head, a chat thread, or the incident description, where it was
-- detached from the step it belonged to.
--
-- WHAT THIS RECORDS
--
-- A thread per step: who said what, and when. APPEND-ONLY, deliberately — no
-- edit and no delete route exists. An incident record is evidence; it can end
-- up in front of a client, an insurer or a regulator, and a note that can be
-- quietly rewritten after the fact is worth less than one that cannot. A
-- mistaken comment is corrected by a later comment, the same way the phase
-- trail (ir_phase_events) and training attempts are kept.
--
-- STAFF-ONLY. Playbook steps are an operator's working notes, and the client
-- portal already reads only phase, status and completed_at from ir_activities.
-- Nothing in lib/portal-routes.js reads this table, and the test suite asserts
-- that it stays that way.
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ir_activity_comments (
  id          SERIAL PRIMARY KEY,
  -- Deleting a step deletes its thread. A comment about a step that no longer
  -- exists would be an orphan nobody could find or read in context.
  activity_id INT NOT NULL REFERENCES ir_activities(id) ON DELETE CASCADE,
  -- Denormalised from the step so every step's thread loads in ONE query per
  -- incident, and so ownership is checked with the same WHERE-clause rule as
  -- the rest of the IR surface rather than through a chain of joins.
  incident_id INT NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
  tenant_id   INT REFERENCES tenants(id) ON DELETE CASCADE,
  body        TEXT NOT NULL,
  -- NULL once the author's account is removed. The comment survives: what was
  -- recorded during the response does not stop being true when someone leaves.
  author_id   INT REFERENCES users(id) ON DELETE SET NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Enforced here as well as in the route, so a blank or runaway comment cannot
-- reach the table by any path.
DO $$ BEGIN
  ALTER TABLE ir_activity_comments ADD CONSTRAINT ir_activity_comments_body_chk
    CHECK (char_length(btrim(body)) BETWEEN 1 AND 4000);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_ir_activity_comments_incident
  ON ir_activity_comments (incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_ir_activity_comments_activity
  ON ir_activity_comments (activity_id, created_at);

COMMENT ON TABLE ir_activity_comments IS
  'Append-only comment thread per IR playbook step. Staff-only: never read by the client portal. No edit or delete route exists; a correction is a later comment.';
COMMENT ON COLUMN ir_activity_comments.author_id IS
  'Who wrote it. SET NULL when the account is removed, so the comment outlives the account.';
