-- Managed Email Security (Acronis) Migration
-- Run once: psql -d secops -f migrate-email-security.sql
--
-- Alerts are UPSERTed by their Acronis alert id, so the dashboard keeps history
-- beyond the provider's own retention window and a re-sync of a changed alert
-- (dismissed, reclassified) overwrites its stored row rather than duplicating it.
--
-- ══ WHAT IS STORED, AND WHY IT IS PERSONAL DATA ══
--
-- These rows name the mailbox that was targeted, in full. That is a deliberate
-- decision, taken so the tab can answer the question the service exists to
-- answer: who is repeatedly attacked, and therefore who needs training. It also
-- means this table holds personal data under POPIA — recipient addresses,
-- sender addresses and subject lines — for every client on the service.
--
-- Consequences worth stating rather than discovering:
--   * it belongs in the client agreement and the data inventory;
--   * ON DELETE CASCADE below means removing a tenant removes their mail data;
--   * there is no retention sweep. If a retention period is agreed, it needs a
--     scheduled DELETE — this schema does not impose one.

CREATE TABLE IF NOT EXISTS email_alerts (
  id               SERIAL PRIMARY KEY,
  tenant_id        INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

  -- The provider's own id. Uniqueness is per tenant, not global: two clients
  -- with separate Acronis tenants can legitimately mint the same id.
  alert_id         VARCHAR(128) NOT NULL,

  -- Verbatim from the provider, never normalised away. The classifier below
  -- reads these; keeping them means a misclassification can be corrected from
  -- stored rows instead of a re-sync.
  alert_type       TEXT,
  category         TEXT,
  severity         VARCHAR(30),

  -- Our classification. NULL means "the classifier did not recognise it",
  -- which is NOT the same as 'other' — see lib/integrations/acronis.js.
  threat_class     VARCHAR(30),

  -- What happened to the message: blocked | quarantined | delivered |
  -- remediated | unknown. NULL where the alert did not say.
  disposition      VARCHAR(30),

  recipient        TEXT,
  recipient_domain TEXT,
  sender           TEXT,
  sender_domain    TEXT,
  subject          TEXT,

  -- Provider timestamps. created_at is when Acronis raised the alert, which is
  -- the closest thing to "when the message arrived" the alert API offers.
  created_at       TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ,
  received_at      TIMESTAMPTZ,
  resolved_at      TIMESTAMPTZ,
  alert_status     VARCHAR(30),

  raw_json         JSONB,
  synced_at        TIMESTAMPTZ  DEFAULT NOW(),

  UNIQUE (tenant_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_email_alerts_tenant_created
  ON email_alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_alerts_tenant_class
  ON email_alerts (tenant_id, threat_class);
CREATE INDEX IF NOT EXISTS idx_email_alerts_tenant_recipient
  ON email_alerts (tenant_id, recipient);

/*
 * Every alert TYPE the sync has ever seen, and whether we recognised it as
 * email security.
 *
 * This exists for the same reason the FortiGate parser reports `unread`
 * sections: a classifier that silently drops what it does not recognise will
 * one day show a client a clean email-security dashboard built on alerts nobody
 * read. Acronis raises alerts for backup, DR, patching and endpoint protection
 * through the same API, so "not email" is the common and correct outcome — but
 * it has to be visible, and it has to be countable, or a new Advanced Email
 * Security alert type shipped by Acronis silently becomes zero on a chart.
 *
 * Deliberately NOT a copy of the alerts themselves: this is a ledger of type
 * names and counts, so recognising a new type later costs one classifier line
 * and a re-sync, not a table full of another product's data.
 */
CREATE TABLE IF NOT EXISTS email_alert_types_seen (
  id            SERIAL PRIMARY KEY,
  tenant_id     INT          NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_type    TEXT         NOT NULL,
  category      TEXT,
  is_email      BOOLEAN      NOT NULL,
  seen_count    INT          NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ  DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ  DEFAULT NOW(),
  UNIQUE (tenant_id, alert_type)
);

CREATE INDEX IF NOT EXISTS idx_email_types_seen_tenant
  ON email_alert_types_seen (tenant_id, is_email);

COMMENT ON TABLE email_alerts IS
  'Acronis email-security alerts. Contains personal data (recipient/sender addresses, subject lines) — see POPIA note in db/migrate-email-security.sql.';
COMMENT ON COLUMN email_alerts.threat_class IS
  'Our classification. NULL means unrecognised by the classifier, which is not the same as ''other''.';
COMMENT ON COLUMN email_alerts.disposition IS
  'What happened to the message. NULL where the alert did not say — never assume blocked.';
COMMENT ON TABLE email_alert_types_seen IS
  'Every Acronis alert type encountered and whether it was read as email security. Makes silent classifier gaps visible.';
