-- ─────────────────────────────────────────────────────────────────────────────
-- Tenant estate profile
--
-- The Secure Score's vulnerability component needs to know how big a client's
-- estate is, and what kind of estate it is. Without it the score judged every
-- client against an absolute count of findings, which punished small clients
-- for not running scans they had little reason to run, and saturated to zero
-- for anyone large enough to have real numbers.
--
-- Endpoints are derivable from edr_agents and scanned hosts from the scan
-- itself, so both are optional here — a value entered on this table is an
-- OVERRIDE, asserting something the telemetry cannot see (an unmanaged server,
-- a site behind a CDN). Servers, public-facing assets and cloud tenancies are
-- not recorded anywhere else and can only be declared.
--
-- NULL means "not recorded" and 0 means "declared as none". They are different
-- claims: 0 servers is what makes a client endpoint-only and moves them onto
-- the patch-currency yardstick, while NULL leaves the estate unknown.
--
--   psql -d secops -f db/migrate-tenant-estate.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tenant_estate (
  tenant_id        INT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

  servers          INT,          -- physical/virtual servers in scope
  public_assets    INT,          -- internet-facing assets and applications
  endpoints        INT,          -- override; derived from edr_agents when NULL
  cloud_tenancies  INT,          -- cloud subscriptions/accounts in scope

  notes            TEXT,
  updated_by       INT REFERENCES users(id) ON DELETE SET NULL,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  -- A negative asset count is always a data-entry error, and one that would
  -- silently invert the density calculation.
  CONSTRAINT tenant_estate_non_negative CHECK (
    COALESCE(servers, 0)         >= 0 AND
    COALESCE(public_assets, 0)   >= 0 AND
    COALESCE(endpoints, 0)       >= 0 AND
    COALESCE(cloud_tenancies, 0) >= 0
  )
);

COMMENT ON TABLE  tenant_estate IS
  'Declared estate size per client; drives the Secure Score vulnerability yardstick.';
COMMENT ON COLUMN tenant_estate.servers IS
  'NULL = not recorded, 0 = declared none. 0 across all infra columns makes the client endpoint-only.';
COMMENT ON COLUMN tenant_estate.endpoints IS
  'Override only. Left NULL, the score uses COUNT(*) FROM edr_agents.';
