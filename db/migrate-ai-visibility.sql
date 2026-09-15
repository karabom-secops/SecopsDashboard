-- AI Visibility — the DNSFilter MSP key, and the sanctioned-app register.
--
-- Safe to re-run.

-- ── MSP-level integrations ──────────────────────────────────────────────────
--
-- The integrations table is per client. DNSFilter is reached with ONE MSP key
-- that sees every client organisation, so the key does not belong to any
-- client row: storing it on one would make it that client's to remove, and
-- would copy it into every client that needed it. It lives here, once,
-- encrypted exactly like every other credential (api_key_enc / api_key_iv),
-- and only a superadmin route reads or writes it.
--
-- Each client's own `integrations` row (provider 'dnsfilter') holds only its
-- DNSFilter organisation id and time zone.
CREATE TABLE IF NOT EXISTS msp_integrations (
  provider      VARCHAR(50)  PRIMARY KEY,
  base_url      TEXT         NOT NULL,
  api_key_enc   TEXT         NOT NULL,
  api_key_iv    TEXT         NOT NULL,
  -- Not secret: verification results (organisations seen, AI category id).
  config_json   JSONB        NOT NULL DEFAULT '{}'::jsonb,
  updated_by    INT          REFERENCES users(id) ON DELETE SET NULL,
  updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE msp_integrations IS
  'MSP-wide credentials (one row per provider). Keys encrypted; never returned by any route.';

-- ── Sanctioned AI applications ──────────────────────────────────────────────
--
-- A client's decision about each AI tool seen in their DNS traffic. No row
-- means UNREVIEWED, which is not the same as sanctioned — see lib/ai-visibility.js.
CREATE TABLE IF NOT EXISTS ai_app_decisions (
  id          SERIAL PRIMARY KEY,
  tenant_id   INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  -- lib/integrations/dnsfilter.js keys: 'app:<id>' or 'domain:<registered domain>'
  app_key     VARCHAR(130) NOT NULL CHECK (app_key ~ '^(app|domain):[a-z0-9._-]{1,120}$'),
  app_name    VARCHAR(200),
  status      VARCHAR(14)  NOT NULL CHECK (status IN ('sanctioned', 'unsanctioned', 'under_review')),
  note        TEXT         CHECK (note IS NULL OR char_length(note) <= 1000),
  decided_by  INT          REFERENCES users(id) ON DELETE SET NULL,
  decided_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  CONSTRAINT ai_app_decisions_uniq UNIQUE (tenant_id, app_key)
);

CREATE INDEX IF NOT EXISTS idx_ai_app_decisions_tenant ON ai_app_decisions (tenant_id);
