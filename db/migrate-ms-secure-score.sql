-- Microsoft Secure Score Migration
-- Run once: psql -d secops -f migrate-ms-secure-score.sql
--
-- ══ WHY THIS IS NOT THE secure_scores TABLE ══
--
-- `secure_scores` holds OUR composite — vuln, awareness and MDR, weighted by
-- lib/secure-score.js, on a fixed 0-100 scale we define and can defend line by
-- line. Microsoft Secure Score is a different number computed by somebody else
-- against a denominator that MOVES: maxScore changes whenever Microsoft adds a
-- control or the tenant changes licence tier, and it changes retroactively for
-- nobody — only from that day forward.
--
-- Storing Microsoft's number in our table would mean one of two bad things:
--
--   * folding it into the composite, which makes our score unauditable. A drop
--     caused by Microsoft publishing four new Defender controls would read on a
--     board pack as the client's posture having degraded, which is false, and
--     we would have no way to show otherwise; or
--
--   * storing it as a bare percentage, which throws away the denominator and
--     makes the trend a lie the moment maxScore moves. 210/400 and 210/300 are
--     both "210 points" and are not the same security position.
--
-- So it lives here, current AND max preserved on every row, and it is reported
-- ALONGSIDE our composite rather than inside it. See lib/integrations/ms-graph.js.

CREATE TABLE IF NOT EXISTS ms_secure_scores (
  id                SERIAL PRIMARY KEY,
  tenant_id         INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- The date of Microsoft's snapshot (createdDateTime), NOT the day we synced.
  -- Graph publishes roughly one snapshot per day and backfills about 90 days,
  -- so a first sync lands three months of history at once and a re-sync of an
  -- already-held day must overwrite rather than duplicate.
  score_date        DATE         NOT NULL,

  -- BOTH halves, always. See the header: a percentage alone cannot be trended
  -- across a maxScore change, and every read path recomputes from this pair.
  current_score     NUMERIC(10,3),
  max_score         NUMERIC(10,3),

  -- Microsoft's own tenant identifier, kept so a mis-scoped credential is
  -- detectable after the fact: two dashboard tenants showing the same
  -- azure_tenant_id means one of them is reading the other's posture.
  azure_tenant_id   VARCHAR(64),

  active_user_count   INT,
  licensed_user_count INT,

  -- enabledServices tells you WHY a max score moved — a tenant that switched on
  -- Defender for Identity gains controls and loses percentage overnight without
  -- anything having got worse.
  enabled_services  JSONB DEFAULT '[]',

  -- averageComparativeScores: Microsoft's peer benchmarks (by seat band and by
  -- industry). Stored verbatim because the shape is Microsoft's to change.
  comparative_json  JSONB DEFAULT '[]',

  raw_json          JSONB,
  synced_at         TIMESTAMPTZ  DEFAULT NOW(),

  UNIQUE (tenant_id, score_date)
);

CREATE INDEX IF NOT EXISTS idx_ms_secure_scores_tenant_date
  ON ms_secure_scores (tenant_id, score_date DESC);

-- ══ PER-CONTROL DETAIL ══
--
-- This is the half that earns the integration its keep: every control carries a
-- point value and a remediation string, so the newest snapshot is a prioritised,
-- externally-scored backlog rather than another gauge.
--
-- Rows are written for the NEWEST snapshot only. Retaining per-control history
-- for 90 days x ~200 controls x every tenant buys a table nobody queries; the
-- headline trend in ms_secure_scores is what the board pack plots.

CREATE TABLE IF NOT EXISTS ms_secure_score_controls (
  id                  SERIAL PRIMARY KEY,
  tenant_id           INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  score_date          DATE         NOT NULL,

  -- Microsoft's stable key for the control, e.g. 'MFARegistrationV2'.
  control_name        VARCHAR(255) NOT NULL,

  -- ── From the snapshot's controlScores[] ──
  control_category    VARCHAR(64),   -- Identity | Data | Device | Apps | Infrastructure
  score               NUMERIC(10,3), -- points earned; NULL means Microsoft did not say
  score_in_percentage NUMERIC(6,2),
  implementation_status TEXT,
  description         TEXT,

  -- ── From secureScoreControlProfiles ──
  --
  -- Profile metadata is a SEPARATE Graph call and can legitimately be missing:
  -- Microsoft retires profiles while old snapshots still reference the control.
  -- Every column here is therefore nullable, and the UI must render a control
  -- whose profile never arrived rather than dropping it — a control missing
  -- from a remediation list is a gap nobody sees.
  title               TEXT,
  max_score           NUMERIC(10,3),
  rank                INT,           -- Microsoft's own priority ordering
  tier                VARCHAR(64),   -- Core | Defense in Depth | Advanced
  service             VARCHAR(64),
  action_type         VARCHAR(64),
  action_url          TEXT,
  remediation         TEXT,
  remediation_impact  TEXT,
  user_impact         VARCHAR(64),
  implementation_cost VARCHAR(64),
  threats             JSONB DEFAULT '[]',
  deprecated          BOOLEAN DEFAULT FALSE,

  /*
   * The tenant's own disposition of the control, from the profile's
   * controlStateUpdates[]: 'Default', 'Ignored', 'ThirdParty', 'Reviewed'.
   *
   * This MUST NOT be collapsed into the score. A control marked ThirdParty is
   * one the client covers with a non-Microsoft product — CrowdStrike instead of
   * Defender, say — and Microsoft still scores it zero. Presenting that zero as
   * a remediation item tells a client to buy something they have already bought,
   * which is the fastest way to lose the room in a board review.
   *
   * 'Ignored' is the opposite trap: it is a risk ACCEPTANCE, and it belongs in
   * the risk register, not silently removed from the report.
   */
  control_state       VARCHAR(32),

  raw_json            JSONB,
  synced_at           TIMESTAMPTZ  DEFAULT NOW(),

  UNIQUE (tenant_id, score_date, control_name)
);

CREATE INDEX IF NOT EXISTS idx_ms_ss_controls_tenant_date
  ON ms_secure_score_controls (tenant_id, score_date DESC);

-- The remediation list is "worst gaps first, for the newest snapshot", so the
-- ordering columns are worth an index of their own on larger estates.
CREATE INDEX IF NOT EXISTS idx_ms_ss_controls_gap
  ON ms_secure_score_controls (tenant_id, score_date DESC, rank);
