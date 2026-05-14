-- TOTP MFA migration
-- Run: PGPASSWORD='...' psql -h 127.0.0.1 -U secops_user -d secops_db -f db/migrate-totp.sql

BEGIN;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS totp_secret   TEXT,
  ADD COLUMN IF NOT EXISTS totp_enabled  BOOLEAN NOT NULL DEFAULT FALSE,
  -- FALSE for existing rows = grace period (they log in normally but see a banner).
  -- New superadmins get TRUE set by the application on creation.
  ADD COLUMN IF NOT EXISTS totp_required BOOLEAN NOT NULL DEFAULT FALSE;

COMMIT;
