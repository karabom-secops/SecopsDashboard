-- ============================================================
-- migrate-page-access.sql
-- Adds per-user page access overrides on top of the role defaults
-- defined in lib/pages.js.
--
-- A row here overrides whatever the user's role would grant for that
-- page. No row means "inherit from role", so this migration changes
-- nothing for existing users until an admin sets an override.
--
-- Safe to re-run — uses IF NOT EXISTS.
--
-- Usage (on the Ubuntu server):
--   psql -U secops_user -d secops_db -h localhost -f db/migrate-page-access.sql
-- ============================================================

BEGIN;

CREATE TABLE IF NOT EXISTS user_page_access (
  user_id  INT         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  page_key VARCHAR(40) NOT NULL,
  access   VARCHAR(10) NOT NULL
             CONSTRAINT user_page_access_level_chk CHECK (access IN ('none', 'read', 'write')),
  PRIMARY KEY (user_id, page_key)
);

CREATE INDEX IF NOT EXISTS idx_user_page_access_user ON user_page_access (user_id);

COMMIT;
