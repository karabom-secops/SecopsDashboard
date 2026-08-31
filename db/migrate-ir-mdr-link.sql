-- ─────────────────────────────────────────────────────────────────────────────
-- Link an IR incident to the MDR ticket it was escalated from
--
-- WHY
--
-- The product has two incident concepts that share no key: mdr_tickets (what
-- Arctic Wolf raised) and ir_incidents (what we formally opened and worked).
-- An event that was escalated exists in both, and nothing connects them — which
-- is why the dashboard can show two different "incident counts" for the same
-- client.
--
-- The client portal shows one merged list, so it needs a join. This is that
-- join, and it is deliberately MANUAL: an operator sets it when they open an IR
-- incident from a ticket.
--
-- NOT fuzzy-matched on subject and timestamp. Automatic matching would silently
-- merge two unrelated events into one record, and a client who is shown one
-- incident where there were two has been misinformed in a way nobody can see.
-- A visible duplicate is a worse-looking, better outcome.
--
-- Consequence to be explicit about: until staff link them, an escalated event
-- appears twice in the portal.
--
--   psql -d secops -f db/migrate-ir-mdr-link.sql
-- ─────────────────────────────────────────────────────────────────────────────

-- Text rather than a foreign key to mdr_tickets(id): the ticket NUMBER is the
-- stable business identifier, and an operator may well link a ticket before the
-- next sync has created its row. A dangling reference resolves to nothing and
-- the incident simply shows unlinked, which is the right failure.
ALTER TABLE ir_incidents ADD COLUMN IF NOT EXISTS mdr_ticket_number TEXT;

CREATE INDEX IF NOT EXISTS idx_ir_incidents_mdr
  ON ir_incidents (tenant_id, mdr_ticket_number)
  WHERE mdr_ticket_number IS NOT NULL;

COMMENT ON COLUMN ir_incidents.mdr_ticket_number IS
  'Optional link to mdr_tickets.ticket_number within the same tenant. Set by an operator; never inferred. Deduplicates the merged portal incident list.';
