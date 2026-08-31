-- ─────────────────────────────────────────────────────────────────────────────
-- When an incident moved through each response phase
--
-- THE PROBLEM
--
-- ir_incidents.phase is updated IN PLACE. PATCH /api/ir/incidents/:id/phase
-- overwrites the column and bumps updated_at, so the record says where an
-- incident is now and nothing about how it got there. "Contained within four
-- hours, eradicated the next morning" is the story a client actually wants from
-- an incident, and it was not being kept.
--
-- ir_activities carries a per-task phase and completed_at, but those are
-- playbook checklist items — an operator's working notes. Ticking the last
-- containment task is not the same event as declaring the incident contained,
-- and inferring one from the other would put a time against a decision nobody
-- made.
--
-- WHAT THIS RECORDS
--
-- One row each time an incident ENTERS a phase. Append-only: a phase entered,
-- left, and re-entered (which happens — eradication often bounces back to
-- containment) produces three rows, and the trail shows that honestly rather
-- than pretending the response was linear.
--
--   psql -d secops -f db/migrate-ir-phase-history.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS ir_phase_events (
  id          SERIAL PRIMARY KEY,
  incident_id INT NOT NULL REFERENCES ir_incidents(id) ON DELETE CASCADE,
  -- Denormalised from the incident so a portal query can scope by tenant
  -- without a join, and so the same WHERE-clause ownership rule applies here
  -- as everywhere else on that surface.
  tenant_id   INT REFERENCES tenants(id) ON DELETE CASCADE,
  phase       VARCHAR(30) NOT NULL,
  entered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Who moved it. NULL for the backfilled opening row, and for anything a
  -- scheduled process does.
  changed_by  INT REFERENCES users(id) ON DELETE SET NULL
);

DO $$ BEGIN
  ALTER TABLE ir_phase_events ADD CONSTRAINT ir_phase_events_phase_check
    CHECK (phase IN ('identification','containment','eradication','recovery','post-incident-analysis'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_ir_phase_events_incident
  ON ir_phase_events (incident_id, entered_at);
CREATE INDEX IF NOT EXISTS idx_ir_phase_events_tenant
  ON ir_phase_events (tenant_id, entered_at DESC);

-- ── Backfill ────────────────────────────────────────────────────────────────
--
-- Every existing incident gets ONE row: identification, at opened_at. That is
-- the only transition we can honestly date — the incident demonstrably existed
-- then. Its CURRENT phase is known but the time it reached it is not, and
-- writing NOW() against it would claim an incident opened in April moved to
-- eradication on the day of the migration.
--
-- So historical incidents show one dated step and their current phase undated,
-- which is the truth. New transitions are recorded from here on.

INSERT INTO ir_phase_events (incident_id, tenant_id, phase, entered_at)
SELECT i.id, i.tenant_id, 'identification', i.opened_at
  FROM ir_incidents i
 WHERE NOT EXISTS (
   SELECT 1 FROM ir_phase_events e WHERE e.incident_id = i.id
 );

COMMENT ON TABLE ir_phase_events IS
  'Append-only record of each time an IR incident entered a response phase. Re-entering a phase adds another row; the trail is not assumed to be linear.';
COMMENT ON COLUMN ir_phase_events.entered_at IS
  'When the incident entered this phase. Backfilled rows carry opened_at for identification only — no other historical transition time is knowable.';
