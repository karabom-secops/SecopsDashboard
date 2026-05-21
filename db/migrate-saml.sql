-- db/migrate-saml.sql
-- Run once on an EXISTING deployment to add SAML / SSO support.
-- Safe to re-run (uses IF NOT EXISTS / IF EXISTS guards).

-- Allow SAML users who have no password
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- Support UPN/email addresses as usernames (e.g. user@domain.com)
ALTER TABLE users ALTER COLUMN username TYPE VARCHAR(254);

-- Track authentication type: 'local' (password) or 'saml' (SSO)
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_type VARCHAR(10) NOT NULL DEFAULT 'local';

-- Store the SAML NameID for fast lookup on callback
ALTER TABLE users ADD COLUMN IF NOT EXISTS saml_nameid TEXT;

-- Enforce uniqueness only on non-NULL nameIDs
CREATE UNIQUE INDEX IF NOT EXISTS users_saml_nameid_unique
  ON users(saml_nameid)
  WHERE saml_nameid IS NOT NULL;
