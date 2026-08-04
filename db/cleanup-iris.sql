-- Cleanup: remove data left behind by the retired DFIR-IRIS integration.
--
-- DESTRUCTIVE — run manually and only once you are sure the IRIS integration
-- is no longer wanted:  psql -d secops -f cleanup-iris.sql
--
-- Notes:
--   * mdr_uploads rows are SHARED with the Arctic Wolf ticket integration, so
--     they are deliberately left alone here. Deleting IRIS tickets will leave
--     the upload-level counters (total_tickets, resolved_count, …) stale.
--     Refresh them by re-running an Arctic Wolf sync from Admin → Integrations,
--     which rewrites mdr_uploads for the tenant from scratch.
--   * IRIS tickets are identifiable two ways: ticket_type = 'dfir_case' (set by
--     the adapter) and ticket_number LIKE 'IRIS-%'. Both are matched below so a
--     partial/older sync is still caught.

BEGIN;

DELETE FROM mdr_tickets
 WHERE ticket_type = 'dfir_case'
    OR ticket_number LIKE 'IRIS-%';

DELETE FROM integrations
 WHERE provider = 'iris_dfir';

COMMIT;
