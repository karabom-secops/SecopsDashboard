-- Client logos — uploaded on the Client Profile tab during onboarding.
--
-- WHY THE BYTES LIVE IN THE DATABASE
--
-- The same choice as pentest evidence screenshots (migrate-redteam-report.sql),
-- and the opposite of published report decks (migrate-report-archive.sql). A
-- logo is small and bounded, there is at most one per client, and it must be
-- there whenever the portal renders. Putting it on disk would add a second
-- thing to back up, to mount into every container, and to keep in step with the
-- row that points at it — for a file of a few tens of kilobytes.
--
-- WHY NOT SVG
--
-- An SVG is a script-bearing document. Served from our own origin it would run
-- in the client's session, so the upload route accepts raster images only. The
-- mime is stored and echoed back on read, never sniffed from the bytes.
--
-- Columns are nullable and added IF NOT EXISTS: a deployment that has not run
-- this migration shows no logo rather than failing, which is how every other
-- optional column in this schema behaves.
--
-- Safe to re-run.

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_mime       VARCHAR(40);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_data       BYTEA;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_filename   VARCHAR(200);
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_updated_at TIMESTAMPTZ;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS logo_updated_by INT;

-- Only the raster types the upload route accepts. A row that satisfies this
-- constraint is a row the serve route can hand back with a fixed Content-Type.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenants_logo_mime_allowed') THEN
    ALTER TABLE tenants ADD CONSTRAINT tenants_logo_mime_allowed
      CHECK (logo_mime IS NULL OR logo_mime IN ('image/png', 'image/jpeg', 'image/webp'));
  END IF;
END
$$;

-- The bytes and the type travel together: one without the other cannot be served.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'tenants_logo_complete') THEN
    ALTER TABLE tenants ADD CONSTRAINT tenants_logo_complete
      CHECK ((logo_mime IS NULL AND logo_data IS NULL) OR (logo_mime IS NOT NULL AND logo_data IS NOT NULL));
  END IF;
END
$$;

COMMENT ON COLUMN tenants.logo_data IS
  'Client logo bytes (raster only; never SVG — it would execute in the client''s session). '
  'Served by GET /api/client-profile/logo for staff and GET /api/portal/logo for the client.';
