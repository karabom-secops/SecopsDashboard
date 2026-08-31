-- ─────────────────────────────────────────────────────────────────────────────
-- Published report archive
--
-- THE PROBLEM
--
-- Board reports are assembled entirely in the browser (tab-reports.js
-- assembleDeck) and the .pptx is streamed by lib/report-pptx-route.js and
-- discarded. Nothing is stored. There is no record of what was sent to a client
-- or when, and no artefact a client could come back for.
--
-- The portal promises "download your reports", which needs the report to exist
-- somewhere after the tab that made it is closed.
--
-- WHAT IS STORED, AND WHERE
--
-- The row is the index; the .pptx lives on the filesystem under
-- REPORT_ARCHIVE_DIR. Deliberately not bytea: a 1-20MB deck per client per
-- month lands in every pg_dump, and node-postgres has no chunked read, so each
-- download would materialise the whole buffer in the Node heap twice. A read
-- stream is constant memory. Not object storage either — no S3 dependency, and
-- this is a single-node self-hosted app.
--
-- deck_html is stored IN the row. It is what makes the report readable without
-- PowerPoint, and it is the evidence of what was actually published: a pptx
-- regenerated later from `sections` is a reconstruction, not the artefact.
--
-- IMMUTABILITY
--
-- Rows are append-only. Republishing a period inserts version+1; nothing is
-- overwritten and no file is ever reopened for write. Withdrawal is a state
-- transition, not an edit. client_name and period_label are frozen at publish,
-- because renaming a tenant must not rewrite what was sent last March.
--
--   psql -d secops -f db/migrate-report-archive.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS report_publications (
  id            SERIAL PRIMARY KEY,
  tenant_id     INT      NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  period        CHAR(7)  NOT NULL,               -- 'YYYY-MM'
  version       INT      NOT NULL,               -- 1..n per (tenant, period)

  -- Frozen at publish. A tenant rename must not retroactively alter history.
  title         TEXT     NOT NULL DEFAULT '',
  client_name   TEXT     NOT NULL DEFAULT '',
  period_label  TEXT     NOT NULL DEFAULT '',
  author        TEXT     NOT NULL DEFAULT '',
  cover_note    TEXT     NOT NULL DEFAULT '',    -- staff message shown to the client

  status        VARCHAR(12) NOT NULL DEFAULT 'published'
                  CONSTRAINT report_pub_status_chk CHECK (status IN ('published', 'withdrawn')),

  published_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  published_by  INT REFERENCES users(id) ON DELETE SET NULL,
  withdrawn_at  TIMESTAMPTZ,
  withdrawn_by  INT REFERENCES users(id) ON DELETE SET NULL,
  withdraw_reason TEXT,

  pptx_path     TEXT,                            -- relative to REPORT_ARCHIVE_DIR; NULL once purged
  pptx_bytes    INT,
  pptx_sha256   CHAR(64),                        -- lets staff prove which artefact was sent
  slide_count   INT,

  deck_html     TEXT,                            -- the human-readable artefact
  html_bytes    INT,

  -- The machine-readable source, kept alongside deck_html so a future PDF or
  -- DOCX export does not need the browser that produced the original.
  sections      JSONB NOT NULL DEFAULT '[]'::jsonb,
  ctx           JSONB NOT NULL DEFAULT '{}'::jsonb,

  purged_at     TIMESTAMPTZ,                     -- bytes gone, row kept as the audit trail
  download_count INT NOT NULL DEFAULT 0,
  last_downloaded_at TIMESTAMPTZ,

  UNIQUE (tenant_id, period, version)
);

CREATE INDEX IF NOT EXISTS idx_report_pub_tenant
  ON report_publications (tenant_id, published_at DESC);
CREATE INDEX IF NOT EXISTS idx_report_pub_period
  ON report_publications (tenant_id, period, version DESC);

COMMENT ON TABLE report_publications IS
  'Append-only archive of board reports published to clients. One row per publish; republishing inserts a new version.';
COMMENT ON COLUMN report_publications.pptx_path IS
  'Path relative to REPORT_ARCHIVE_DIR. Always generated server-side, never client input, and re-validated on every read.';
COMMENT ON COLUMN report_publications.purged_at IS
  'When retention removed the file. The row survives so the record of what was sent to whom outlives the bytes.';
