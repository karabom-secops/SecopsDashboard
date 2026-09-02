-- migrate-tenant-services.sql
--
-- Records which services each client actually consumes, so the board report can
-- default to the sections that apply to them.
--
-- Run once: psql -d secops -f db/migrate-tenant-services.sql
--
-- NULLABLE ON PURPOSE, AND WITHOUT A DEFAULT.
--
--   NULL   nobody has recorded this client's services yet. The report offers
--          every section, exactly as it did before this column existed.
--   '{}'   somebody recorded "none". Only the always-on sections are offered.
--
-- Those two must stay distinguishable. Defaulting the column to '{}' would say
-- every existing client buys nothing, and would silently strip most sections
-- out of every report the moment this shipped — the failure nobody notices,
-- because a missing section leaves no mark on the page.
--
-- Valid keys are defined in lib/services.js and validated there on write. They
-- are deliberately NOT constrained here: adding a service to the catalogue
-- should not require a migration, and a CHECK constraint would reject rows the
-- application considers valid until someone remembers to alter it.

ALTER TABLE tenants
  ADD COLUMN IF NOT EXISTS services TEXT[];

COMMENT ON COLUMN tenants.services IS
  'Service keys from lib/services.js that this client consumes. '
  'NULL means not yet recorded (report offers everything); '
  'an empty array means explicitly none.';

-- Answers "which clients have MDR" without scanning the table.
CREATE INDEX IF NOT EXISTS idx_tenants_services
  ON tenants USING GIN (services);
