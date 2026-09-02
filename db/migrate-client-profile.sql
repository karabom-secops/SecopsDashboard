-- ─────────────────────────────────────────────────────────────────────────────
-- Client profile: history, review dates, and the removal of a dead field
--
-- WHY
--
-- tenant_estate is a single overwriting row that silently drives up to about
-- forty-five points of a client-facing Secure Score. Someone edits a number,
-- the score in the next board pack moves, and there is no record of what it
-- was, who changed it, or what the change did. For a figure that goes in front
-- of a client's board, that is not a defensible place to keep it.
--
--   psql -d secops -f db/migrate-client-profile.sql
--
-- Depends on db/migrate-tenant-estate.sql and db/migrate-tenant-services.sql.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── History ──────────────────────────────────────────────────────────────────
--
-- ONE ROW PER SAVE, not per field.
--
-- A per-field table was the obvious shape and the wrong one: score_before and
-- score_after belong to the change as a WHOLE, and splitting them across field
-- rows would either duplicate them or need a second table to hang them on. The
-- diff is a handful of keys, so JSONB carries it without ceremony — the same
-- choice report_publications.sections already makes.
CREATE TABLE IF NOT EXISTS tenant_profile_events (
  id           SERIAL PRIMARY KEY,
  tenant_id    INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  changed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  changed_by   INT REFERENCES users(id) ON DELETE SET NULL,

  -- 'change' carries a non-empty diff. 'review' is somebody confirming the
  -- profile is still correct without editing it, and carries an empty one —
  -- which is why the diff is not constrained to be non-empty here.
  kind         TEXT NOT NULL DEFAULT 'change'
               CHECK (kind IN ('change', 'review')),

  -- { field: { from, to } }. Written ONLY when something actually changed:
  -- a save that alters nothing writes no row at all, so this table stays a
  -- record of events rather than of button presses.
  diff         JSONB NOT NULL,

  -- The composite Secure Score either side of the change. This is the whole
  -- reason the table exists: it turns "the score moved" into "this edit moved
  -- it, by this much".
  --
  -- A SNAPSHOT TAKEN AT SAVE TIME, not a recomputed history. Anything that
  -- displays these must say so, or an old row reads as an authoritative past
  -- score. NULL when the score could not be computed — which must never be
  -- allowed to fail the save.
  score_before INT,
  score_after  INT,

  note         TEXT
);

CREATE INDEX IF NOT EXISTS idx_tenant_profile_events_tenant
  ON tenant_profile_events (tenant_id, changed_at DESC);

COMMENT ON TABLE tenant_profile_events IS
  'Append-only history of client profile (estate + services) changes, with the score movement each one caused.';
COMMENT ON COLUMN tenant_profile_events.score_after IS
  'Composite score as computed at save time. A snapshot, not a recomputed history — label it as such wherever shown.';

-- ── Review date ──────────────────────────────────────────────────────────────
--
-- Distinct from updated_at so "I checked, it is still correct" is expressible
-- without faking an edit. It is what clears a staleness flag; the flag itself
-- is advisory only and never changes a score — see the header of lib/estate.js.
ALTER TABLE tenant_estate ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

COMMENT ON COLUMN tenant_estate.reviewed_at IS
  'Last time someone confirmed the estate is still accurate, edit or no edit. Drives the staleness flag only.';

-- ── Removing endpoints_patched ───────────────────────────────────────────────
--
-- THIS IS THE ONE IRREVERSIBLE STEP IN THIS FILE.
--
-- The column was validated on the way in, clamped against its population,
-- stored, and read back to the admin who typed it — and no scoring path ever
-- looked at it. Endpoint patch state is measured from the EDR feed by
-- scoreEndpoints() in lib/secure-score.js, which is better evidence than a
-- typed count and has always been what the endpoint yardstick actually uses.
--
-- If anyone has entered values here, they are lost. Check before running:
--
--   SELECT tenant_id, endpoints_patched FROM tenant_estate
--    WHERE endpoints_patched IS NOT NULL;
ALTER TABLE tenant_estate DROP COLUMN IF EXISTS endpoints_patched;
