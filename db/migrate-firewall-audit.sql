-- ─────────────────────────────────────────────────────────────────────────────
-- FortiGate configuration audit
--
-- A client takes a backup from the device (admin menu → Configuration → Backup
-- → Local PC → File format: YAML), uploads it, and gets a scored posture review
-- with named findings.
--
-- ══ THE CONFIGURATION IS NOT STORED. ANYWHERE. ══
--
-- There is no column below that a config could go in — not bytea, not text,
-- not "just the interesting bits". It is parsed in memory by
-- lib/fortigate-parser.js, audited, and dropped when the request ends.
--
-- Unmasked, a FortiGate backup contains administrator password hashes, IPsec
-- pre-shared keys, SNMP community strings, LDAP and RADIUS bind credentials and
-- certificate private keys. "Password mask" on that backup screen is optional,
-- so unmasked files WILL arrive. Storing them would turn this dashboard into a
-- repository of its clients' firewall credentials, and a single compromise here
-- into a compromise of every perimeter we audit.
--
-- If a future change needs the config kept, that is a decision to take
-- deliberately and in the open — not by adding a column.
--
--   psql -d secops -f db/migrate-firewall-audit.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS firewall_audits (
  id           SERIAL PRIMARY KEY,
  tenant_id    INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  uploaded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  uploaded_by  INT REFERENCES users(id) ON DELETE SET NULL,

  -- Read from config-version and system.global.hostname. Identifying the
  -- device, not its contents.
  device_name    TEXT,
  model          TEXT,
  firmware       TEXT,
  config_version TEXT,

  -- TRI-STATE, so NULL is meaningful: TRUE appeared masked, FALSE appeared
  -- unmasked, NULL could not be determined. It is a heuristic over how the
  -- device writes secret fields, so it advises and never scores. An analyst who
  -- has just uploaded an unmasked config needs to be told to rotate what was in
  -- it, and a guess presented as a fact would either cause needless rotation or
  -- wrongly reassure.
  appeared_masked BOOLEAN,

  -- NULL, not 0, when nothing could be assessed. A firewall we could not read
  -- did not fail everything.
  score           INT CHECK (score IS NULL OR score BETWEEN 0 AND 100),
  total_checks    INT,
  assessed        INT,
  passed          INT,
  failed          INT,
  not_assessable  INT,

  -- What share of the benchmark this config actually answered. A high score at
  -- low coverage is not a good result and the page has to be able to say so.
  coverage        INT CHECK (coverage IS NULL OR coverage BETWEEN 0 AND 100),

  severity_counts JSONB,
  -- Sections present in the file that the parser does not claim to understand.
  -- Named so an audit can never quietly score a config it barely read.
  unread_sections JSONB
);

CREATE INDEX IF NOT EXISTS idx_firewall_audits_tenant
  ON firewall_audits (tenant_id, uploaded_at DESC);

CREATE TABLE IF NOT EXISTS firewall_findings (
  id        SERIAL PRIMARY KEY,
  audit_id  INT NOT NULL REFERENCES firewall_audits(id) ON DELETE CASCADE,
  -- Denormalised from the audit so the portal can scope by tenant without a
  -- join, and so the same WHERE-clause ownership rule applies here as on every
  -- other client-facing surface.
  tenant_id INT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  check_id  TEXT NOT NULL,
  severity  TEXT NOT NULL
              CONSTRAINT firewall_findings_severity_chk
              CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  -- 'not-assessable' is a first-class outcome, not a flavour of failure. See
  -- the header of lib/fortigate-score.js for why it leaves the denominator.
  status    TEXT NOT NULL
              CONSTRAINT firewall_findings_status_chk
              CHECK (status IN ('pass', 'fail', 'not-assessable')),

  title       TEXT,
  detail      TEXT,
  rationale   TEXT,
  remediation TEXT,
  cis_ref     TEXT,
  source      TEXT,      -- 'cis' or 'reflex', so ours is not dressed up as a standard

  -- Identifiers and counts ONLY: policy ids, interface names, tunnel names.
  -- NEVER a secret value. Checks are written not to put one here, and
  -- lib/fortigate-parser.js redact() is the net under that.
  --
  -- Withheld from the client-facing projection (publicFinding in
  -- lib/fortigate-score.js): together these are a working map of where a
  -- client's firewall is weakest, which is the same reason the portal
  -- withholds the vulnerability finding list.
  evidence  JSONB
);

CREATE INDEX IF NOT EXISTS idx_firewall_findings_audit
  ON firewall_findings (audit_id);
CREATE INDEX IF NOT EXISTS idx_firewall_findings_tenant
  ON firewall_findings (tenant_id, status);

COMMENT ON TABLE firewall_audits IS
  'One FortiGate config audit. The configuration itself is never stored — parsed in memory and discarded.';
COMMENT ON COLUMN firewall_audits.appeared_masked IS
  'Heuristic tri-state: TRUE appeared masked, FALSE appeared unmasked, NULL undetermined. Advisory only, never scored.';
COMMENT ON COLUMN firewall_findings.evidence IS
  'Identifiers and counts only. Never a secret value. Withheld from client-facing views.';
