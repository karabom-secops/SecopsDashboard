-- Migration: account lifecycle columns on users.
--
-- WHY
--
-- These are survivable gaps for internal staff and unacceptable for external
-- client accounts:
--
--   * There is no way to SUSPEND a user. The only revocation available today is
--     DELETE (server.js DELETE /api/users/:id), which destroys the account
--     rather than disabling it. For a client whose contract has lapsed, or a
--     departing employee at a client, we need to close the door without
--     erasing who had access to what.
--
--   * A password set by an MSP admin can never be changed by the person using
--     it. There is no self-service change-password route and no way to flag an
--     account as needing one, so a provisioned credential stays whatever an
--     admin typed and read out over the phone, forever.
--
-- is_active is enforced in requireAuth (lib/auth-middleware.js) as well as at
-- login, so suspending someone takes effect on their NEXT REQUEST rather than
-- when their 8-hour session expires. Role and tenant are still snapshotted on
-- the session at login — that remains true and is noted as a known limitation.
--
-- Usage: psql -U secops_user -d secops_db -f db/migrate-user-lifecycle.sql
-- ─────────────────────────────────────────────────────────────────────────────

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active            BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at  TIMESTAMPTZ;

-- Existing accounts predate the column, so their password age is unknown rather
-- than "now" — recording a fabricated timestamp would make a five-year-old
-- password look freshly rotated. NULL means "never recorded".
COMMENT ON COLUMN users.password_changed_at IS
  'When the user last set their own password. NULL = unknown (predates this column, or set by an admin).';
COMMENT ON COLUMN users.is_active IS
  'FALSE suspends the account: login is refused and existing sessions are rejected on their next request.';
COMMENT ON COLUMN users.must_change_password IS
  'TRUE forces a password change before any other action. Set when an admin provisions or resets an account.';

-- Suspended accounts are looked up on every authenticated request.
CREATE INDEX IF NOT EXISTS idx_users_active ON users (id) WHERE is_active = FALSE;
