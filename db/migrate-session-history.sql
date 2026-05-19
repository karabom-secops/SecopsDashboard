-- ── Migration: Session History awareness support ──────────────────────────
-- Run once against your database.
-- Adds upload_type column to awareness_uploads and creates
-- the awareness_sessions table for per-row session history data.

ALTER TABLE awareness_uploads
  ADD COLUMN IF NOT EXISTS upload_type TEXT NOT NULL DEFAULT 'summary';

CREATE TABLE IF NOT EXISTS awareness_sessions (
  id                 SERIAL PRIMARY KEY,
  upload_id          INT          NOT NULL REFERENCES awareness_uploads(id) ON DELETE CASCADE,
  user_first_name    TEXT,
  user_last_name     TEXT,
  user_email         TEXT,
  manager_first_name TEXT,
  manager_last_name  TEXT,
  manager_email      TEXT,
  sent_date          TIMESTAMPTZ,
  session_type       TEXT,   -- 'Awareness Session' | 'Quiz' | 'Phishing Simulation' | 'Phishing Remediation Session'
  title              TEXT,
  status             TEXT,   -- 'Not Started' | 'Complete' | 'N/A'
  completed_date     TIMESTAMPTZ,
  elapsed_seconds    INT,
  clicked_at         TIMESTAMPTZ,
  quiz_score         NUMERIC
);

CREATE INDEX IF NOT EXISTS idx_awareness_sessions_upload ON awareness_sessions(upload_id);
CREATE INDEX IF NOT EXISTS idx_awareness_sessions_email  ON awareness_sessions(user_email);
