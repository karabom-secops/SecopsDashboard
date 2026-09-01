-- migrate-awareness-clicked.sql
--
-- Separates "did they click" from "when did they click".
--
-- WHY
--
-- awareness_sessions had only clicked_at TIMESTAMPTZ, and every consumer read
-- a click as `!!clicked_at`. That works for an export whose Clicked column is
-- a timestamp and fails badly for one whose Clicked column is a yes/no flag:
-- the parser fed the flag to new Date(), which accepts a bare integer as a
-- YEAR, so '1' became 2001 and '0' became 2000. Every row came back with a
-- date attached, including the ones that meant "did not click", and the
-- phishing click rate read ~99%.
--
-- The parser no longer coerces a number into a date. This column is what lets
-- a flag-only export still report a real click rate instead of a flawless and
-- equally wrong 0%.
--
-- NULL is meaningful and is the default: it means the export carried no click
-- signal for this row. A reporting gap must not read as a clean result.

ALTER TABLE awareness_sessions
  ADD COLUMN IF NOT EXISTS clicked BOOLEAN;

COMMENT ON COLUMN awareness_sessions.clicked IS
  'TRUE clicked, FALSE did not, NULL not reported by the source export. '
  'clicked_at carries the time when the source gave one; a flag-only export '
  'sets clicked without clicked_at rather than inventing a timestamp.';

-- Backfill, carefully.
--
-- An existing clicked_at CANNOT simply be trusted: the rows this migration
-- exists to fix are exactly the ones carrying a manufactured timestamp. So the
-- backfill uses the one invariant that separates a real click from a fabricated
-- one without guessing at a cutoff date:
--
--   a click cannot happen before the mail was sent.
--
-- '0' parsed to the year 2000 and '1' to 2001, both of which precede every
-- real send, so the fabricated rows fail this test while genuine ones pass.
UPDATE awareness_sessions
   SET clicked = TRUE
 WHERE clicked IS NULL
   AND clicked_at IS NOT NULL
   AND sent_date IS NOT NULL
   AND clicked_at >= sent_date;

-- Everything else is left NULL — "not reported" — rather than FALSE.
--
-- Under the old parser a genuine non-click, an unreadable cell and a
-- fabricated date all ended up indistinguishable, so calling any of them
-- "did not click" would launder the bug into confident-looking data. Re-upload
-- the export to get a real answer; until then the UI says the rate is not
-- available instead of showing a reassuring zero.


CREATE INDEX IF NOT EXISTS idx_awareness_sessions_clicked
  ON awareness_sessions (upload_id, clicked)
  WHERE clicked IS TRUE;
