-- ─────────────────────────────────────────────────────────────────────────────
-- Link a client to their Arctic Wolf organisation
--
--   psql -d secops -f db/migrate-arctic-wolf-org.sql
--
-- Depends on db/migrate-tenant-estate.sql.
--
-- WHY
--
-- The Secure Score's `coverage` figure credits the FULL MDR weight to any
-- client recorded as buying MDR, however much of their estate Arctic Wolf can
-- actually see. Arctic Wolf publishes a per-org Coverage Score saying exactly
-- that — it arrives in the weekly report and is already shown on the Operations
-- tab — so a client onboarded across 70% of their estate had roughly a third of
-- their MDR weight reported to their board as covered when the vendor's own
-- number said otherwise.
--
-- This column is the missing link between the two: the weekly report knows the
-- client only by an organisation NAME, and nothing in the database did.
--
-- WHY A NAME AND NOT A FOREIGN KEY
--
-- There is nothing to reference. The weekly report lives in data/weeks.json, a
-- flat file, and is deliberately NOT migrated into Postgres — see the header of
-- lib/arctic-wolf-coverage.js. The value is somebody else's identifier, so we
-- do not own its shape and impose no format on it beyond a length bound.
--
-- NULL MEANS NOT LINKED
--
-- No discount is applied, and the Secure Score says so rather than showing a
-- silent gap. Empty string is rejected below so "not linked" has exactly one
-- representation and cannot sit in the column looking like a link that resolves
-- to nothing.
--
-- WHAT THIS DOES NOT DO
--
-- It does not move the composite score. The Arctic Wolf figure adjusts how much
-- of the posture the MDR service is credited with REACHING; it never changes
-- what any component SCORES — the same rule tenant_estate.awareness_program
-- already follows. So a tenant_profile_events row recording a change to this
-- field will have score_before = score_after, and that is correct, not a bug to
-- be fixed by feeding coverage into the composite.
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE tenant_estate
  ADD COLUMN IF NOT EXISTS arctic_wolf_org TEXT;

-- Dropped first so the migration is re-runnable, matching the awareness_program
-- constraint immediately above it in db/migrate-tenant-estate.sql.
ALTER TABLE tenant_estate
  DROP CONSTRAINT IF EXISTS tenant_estate_aw_org_len;

ALTER TABLE tenant_estate
  ADD CONSTRAINT tenant_estate_aw_org_len
  CHECK (arctic_wolf_org IS NULL OR char_length(arctic_wolf_org) BETWEEN 1 AND 200);

COMMENT ON COLUMN tenant_estate.arctic_wolf_org IS
  'Exact orgName as it appears in the Arctic Wolf weekly report (data/weeks.json). '
  'NULL means not linked: no MDR coverage discount is applied to the Secure Score '
  'and the page states that. Never a foreign key — the org list is not in this database.';
