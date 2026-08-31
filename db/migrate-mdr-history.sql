-- ─────────────────────────────────────────────────────────────────────────────
-- MDR ticket identity and history
--
-- THE PROBLEM
--
-- writeMdrTickets() ran `DELETE FROM mdr_uploads WHERE tenant_id = $1` and
-- re-inserted every ticket on each integration sync. mdr_tickets.upload_id has
-- ON DELETE CASCADE, so every ticket row was destroyed and recreated with a new
-- primary key several times a day.
--
-- A ticket therefore had no stable identity and no history. Nothing recorded
-- that it moved from open to resolved, or that its severity was raised. That is
-- survivable for an internal snapshot panel and fatal for a client portal whose
-- entire promise is "track your incidents": the row a client was watching would
-- vanish and reappear under a different id.
--
-- THE SHAPE OF THE FIX
--
-- Separate IDENTITY from SNAPSHOT MEMBERSHIP.
--
--   identity            = (tenant_id, ticket_number), a real unique index
--   snapshot membership = upload_id, re-pointed at the newest upload on every
--                         sync for every ticket the feed still returns
--
-- That second half is what makes this safe. "Tickets belonging to the latest
-- upload_id" still means "tickets present in the last sync", so GET /api/mdr,
-- /api/mdr/trends, loadIncidentRate() and the mdr_tickets JOIN mdr_uploads in
-- /api/reports/metrics all keep returning identical results with NO query
-- changes. Tickets that age out of the vendor's window keep a stale upload_id
-- and drop out of the internal panel exactly as they do today — but they now
-- survive in the table, and the portal reads by tenant_id, so the client's
-- history is complete.
--
-- mdr_uploads keeps its current meaning and keeps feeding calculateMdrScore.
-- Its total/resolved/avg columns are computed by calcMdrStats() from the
-- INCOMING FEED, not from the table, so persisting tickets cannot inflate them.
--
--   psql -d secops -f db/migrate-mdr-history.sql
-- ─────────────────────────────────────────────────────────────────────────────

BEGIN;

-- ── 1. Columns ──────────────────────────────────────────────────────────────

-- Tenancy without the upload_id hop. The portal filters on this and nothing
-- else, so a ticket orphaned from its upload is still correctly scoped.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS tenant_id INT REFERENCES tenants(id) ON DELETE CASCADE;

-- When WE first saw it, which is not the vendor's created_at: a back-dated
-- ticket imported today was not open for three weeks on our watch.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS first_seen_at     TIMESTAMPTZ;
-- Last sync that still returned it. Staleness = upstream stopped reporting.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS last_seen_at      TIMESTAMPTZ;
-- Cheap ageing without a correlated subquery into the events table on every
-- row of a 500-row list.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMPTZ;
-- Staff kill-switch for a ticket that should not reach the client.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS portal_visible    BOOLEAN NOT NULL DEFAULT TRUE;
-- Which feed produced it; free when a second MDR provider appears.
ALTER TABLE mdr_tickets ADD COLUMN IF NOT EXISTS source            TEXT;

-- ── 2. Backfill BEFORE any constraint, so it cannot fail on live data ───────

UPDATE mdr_tickets t
   SET tenant_id = u.tenant_id
  FROM mdr_uploads u
 WHERE u.id = t.upload_id
   AND t.tenant_id IS NULL;

-- COALESCE order matters: prefer the vendor's own timestamps over NOW(), or
-- every historical ticket would look like it appeared the day of the migration.
UPDATE mdr_tickets
   SET first_seen_at     = COALESCE(first_seen_at,     created_at, updated_at, NOW()),
       last_seen_at      = COALESCE(last_seen_at,      updated_at, created_at, NOW()),
       status_changed_at = COALESCE(status_changed_at, updated_at, created_at, NOW())
 WHERE first_seen_at IS NULL
    OR last_seen_at IS NULL
    OR status_changed_at IS NULL;

UPDATE mdr_tickets SET source = 'arctic_wolf' WHERE source IS NULL;

-- ── 3. Dedupe before the unique index ───────────────────────────────────────
-- In principle the old DELETE+CASCADE left one upload per tenant, so there can
-- be no duplicates. In practice that DELETE was added later than the table, and
-- a deployment upgraded across that change can carry them. Keep the newest row
-- per key; ties break on id, which is monotonic.

DELETE FROM mdr_tickets a
 USING mdr_tickets b
 WHERE a.tenant_id IS NOT NULL
   AND a.tenant_id     = b.tenant_id
   AND a.ticket_number = b.ticket_number
   AND (COALESCE(a.upload_id, 0), a.id) < (COALESCE(b.upload_id, 0), b.id);

-- ── 4. Identity ─────────────────────────────────────────────────────────────
-- PARTIAL, because mdr_uploads.tenant_id is explicitly nullable (see
-- db/migrate-mdr-tickets.sql, which drops NOT NULL for "system-wide uploads").
-- Legacy rows with no tenant cannot participate in a per-tenant key, and the
-- portal never sees them because every portal query carries AND tenant_id = $1.
CREATE UNIQUE INDEX IF NOT EXISTS mdr_tickets_tenant_number_uidx
  ON mdr_tickets (tenant_id, ticket_number) WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_mdr_tickets_tenant_created
  ON mdr_tickets (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mdr_tickets_tenant_lastseen
  ON mdr_tickets (tenant_id, last_seen_at DESC);

-- ── 5. Break the cascade ────────────────────────────────────────────────────
-- THE single change that stops the data loss. With ON DELETE SET NULL, pruning
-- an old snapshot row detaches its tickets instead of destroying them.
ALTER TABLE mdr_tickets ALTER COLUMN upload_id DROP NOT NULL;
ALTER TABLE mdr_tickets DROP CONSTRAINT IF EXISTS mdr_tickets_upload_id_fkey;
ALTER TABLE mdr_tickets ADD  CONSTRAINT mdr_tickets_upload_id_fkey
  FOREIGN KEY (upload_id) REFERENCES mdr_uploads(id) ON DELETE SET NULL;

-- ── 6. History ──────────────────────────────────────────────────────────────
-- A column answers "when did it last move". The client-facing promise is a
-- TRAIL — raised 3 Sep, escalated to HIGH 4 Sep, resolved 6 Sep — which needs
-- ordered per-field rows. Both are kept: the column so a list render is one
-- query, the table so a detail view can show the story.
--
-- Rows are written ONLY on an actual diff, so a daily sync over 500 unchanged
-- tickets writes nothing at all.
CREATE TABLE IF NOT EXISTS mdr_ticket_events (
  id         BIGSERIAL PRIMARY KEY,
  ticket_id  INT  NOT NULL REFERENCES mdr_tickets(id) ON DELETE CASCADE,
  tenant_id  INT  REFERENCES tenants(id) ON DELETE CASCADE,
  event_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  event_type TEXT NOT NULL,           -- 'created' | 'changed'
  field      TEXT,                    -- 'status' | 'severity' | 'assigned_to' | 'resolved_at'
  old_value  TEXT,
  new_value  TEXT,
  source     TEXT NOT NULL DEFAULT 'sync'
);
CREATE INDEX IF NOT EXISTS idx_mdr_ticket_events_ticket ON mdr_ticket_events (ticket_id, event_at);
CREATE INDEX IF NOT EXISTS idx_mdr_ticket_events_tenant ON mdr_ticket_events (tenant_id, event_at DESC);

COMMENT ON TABLE mdr_ticket_events IS
  'Append-only per-field change trail for MDR tickets. Written only on a real diff.';
COMMENT ON COLUMN mdr_tickets.upload_id IS
  'The most recent sync that still returned this ticket. A stale value means the vendor no longer reports it. NULL means its snapshot row was pruned.';
COMMENT ON COLUMN mdr_tickets.portal_visible IS
  'FALSE hides the ticket from the client portal. Staff-only kill switch; does not affect internal views.';

COMMIT;
