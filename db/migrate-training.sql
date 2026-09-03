-- ─────────────────────────────────────────────────────────────────────────────
-- SOC analyst training: progress and attempts
--
-- The curriculum itself is NOT here. Modules, lessons and the question bank
-- live in lib/training/ and are versioned with the code, reviewed like code,
-- and deployed with it. These two tables hold only what cannot be a file: what
-- a particular person has done.
--
-- THIS IS THE FIRST USER-SCOPED DATA IN THE APPLICATION. Everything else is
-- tenant-scoped through a resolve*Tenant helper. Training belongs to a person,
-- so both tables key on user_id and every query carries it in the WHERE clause
-- — see resolveTrainingUser in server.js, which reads the session and nothing
-- else.
--
--   psql -d secops -f db/migrate-training.sql
--
-- Depends on db/migrate-analyst-role.sql only for who can reach the routes.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Progress ────────────────────────────────────────────────────────────────
--
-- One row per person per item, updated in place. Progress is a CURRENT STATE
-- ("I have done this") and there is nothing to learn from its history, which is
-- what separates it from the attempts table below.
--
-- item_key is namespaced — 'module:phishing-response', and later
-- 'lesson:phishing-response/first-moves' — so lesson-level tracking can be
-- added without a migration. Validated against the real catalogue by
-- isValidProgressKey() in lib/training.js before anything is written, so this
-- column cannot quietly become a place to store whatever a browser sends.
CREATE TABLE IF NOT EXISTS training_progress (
  user_id      INT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  item_key     TEXT NOT NULL,
  status       TEXT NOT NULL
                 CONSTRAINT training_progress_status_chk
                 CHECK (status IN ('started', 'completed')),
  started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  PRIMARY KEY (user_id, item_key)
);

CREATE INDEX IF NOT EXISTS idx_training_progress_user
  ON training_progress (user_id);

-- ── Attempts ────────────────────────────────────────────────────────────────
--
-- APPEND-ONLY. A retake inserts a new row; it never updates an old one.
--
-- Overwriting would keep only the best attempt, which is precisely the thing a
-- training record exists to show. "Passed on the fourth try" and "passed first
-- time" are different facts about an analyst's grasp of the material, and a
-- table that cannot tell them apart is a table that flatters everybody equally.
--
-- The same reasoning as report_publications and tenant_profile_events: history
-- is kept because the current state is not the whole story.
CREATE TABLE IF NOT EXISTS training_attempts (
  id           SERIAL PRIMARY KEY,
  user_id      INT  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  module_id    TEXT NOT NULL,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- Graded on the SERVER, from the key in lib/training/questions.js. The
  -- browser never receives the answers before submitting, so these numbers
  -- describe what somebody knew rather than what they were able to read out of
  -- a downloaded script.
  score        INT  NOT NULL CHECK (score >= 0),
  total        INT  NOT NULL CHECK (total > 0),
  passed       BOOLEAN NOT NULL,

  -- What was submitted, for reviewing which questions a cohort gets wrong.
  -- The question bank is versioned in git, so a stored answer index can be
  -- resolved back to the question it belonged to at the time.
  answers      JSONB,

  CONSTRAINT training_attempts_score_chk CHECK (score <= total)
);

CREATE INDEX IF NOT EXISTS idx_training_attempts_user
  ON training_attempts (user_id, module_id, attempted_at DESC);

COMMENT ON TABLE training_attempts IS
  'Append-only. A retake is a new row — a prior failure must survive a later pass.';
COMMENT ON COLUMN training_attempts.score IS
  'Graded server-side against lib/training/questions.js; the answer key is never sent to the browser.';
