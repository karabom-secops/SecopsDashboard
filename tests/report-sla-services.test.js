'use strict';

/**
 * The resolution SLA, and which report sections a client is offered.
 *
 * Both are driven behaviourally: report-sections.js is loaded into a VM and its
 * real functions are called. Only the wiring that has no callable seam is
 * asserted statically.
 *
 *   node tests/report-sla-services.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('report-sla-services');

const sandbox = { console };
sandbox.window = sandbox;
vm.createContext(sandbox);
for (const f of ['report-shell.js', 'report-deck.js', 'report-sections.js']) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'public', 'js', f), 'utf8'), sandbox);
}
const S = sandbox.window.ReportSections;

/* ── SLA ──────────────────────────────────────────────────────────────────── */

section('security runs 24/7, so the clock does too');

check('the targets are the contracted ones',
  S.IR_SLA_HOURS.CRITICAL === 8 && S.IR_SLA_HOURS.HIGH === 24 &&
  S.IR_SLA_HOURS.MEDIUM === 48 && S.IR_SLA_HOURS.LOW === 72,
  JSON.stringify(S.IR_SLA_HOURS));

/*
 * THE CASE THAT WAS WRONG.
 *
 * Under the old business-hours model (08:00–17:00, Mon–Fri) a ticket raised
 * Friday 17:05 and closed Monday 09:00 accrued about one hour, because nights
 * and weekends did not count. A 24/7 service cannot claim that: the client was
 * exposed for 64 hours and the report said one.
 */
const fri1705 = '2026-03-06T17:05:00+02:00';   // Friday
const mon0900 = '2026-03-09T09:00:00+02:00';   // Monday
const weekend = S.elapsedHoursBetween(fri1705, mon0900);
check('a weekend is counted, not skipped', Math.round(weekend) === 64, weekend);
check('and that fails the 48-hour Medium target',
  weekend > S.IR_SLA_HOURS.MEDIUM, weekend + 'h vs ' + S.IR_SLA_HOURS.MEDIUM + 'h');
check('while still meeting the 72-hour Low target',
  weekend <= S.IR_SLA_HOURS.LOW, weekend + 'h vs ' + S.IR_SLA_HOURS.LOW + 'h');

const overnight = S.elapsedHoursBetween('2026-03-03T22:00:00Z', '2026-03-04T06:00:00Z');
check('an overnight ticket accrues its 8 hours', overnight === 8, overnight);

section('a missing timestamp is refused, not measured from 1970');

// new Date(null) is the epoch, not an invalid date. Measuring from it reports
// half a million hours and destroys the mean.
check('a null start is null', S.elapsedHoursBetween(null, mon0900) === null);
check('a null end is null', S.elapsedHoursBetween(fri1705, null) === null);
check('an empty string is null', S.elapsedHoursBetween('', mon0900) === null);
check('unparseable is null', S.elapsedHoursBetween('not a date', mon0900) === null);
check('a resolution before the raise is null',
  S.elapsedHoursBetween(mon0900, fri1705) === null);
check('but zero elapsed is a legitimate answer',
  S.elapsedHoursBetween(fri1705, fri1705) === 0);

section('severities map to their contracted target');

check('Critical is 8 hours', S.slaTargetFor('CRITICAL') === 8);
check('case does not matter', S.slaTargetFor('high') === 24);
check('whitespace does not matter', S.slaTargetFor(' Medium ') === 48);
check('Low is 72 hours', S.slaTargetFor('LOW') === 72);
// Defaulting an unknown severity to MEDIUM would invent a commitment and then
// grade the service against it.
check('an unknown severity has NO target rather than a guessed one',
  S.slaTargetFor('INFORMATIONAL') === null, S.slaTargetFor('INFORMATIONAL'));
check('and neither does a missing one', S.slaTargetFor(null) === null);

section('the business-hours model is gone, not merely unused');

const src = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');
check('no business-hours measurement remains', !/businessHoursBetween/.test(src));
check('nor its service-window config', !/BUSINESS_HOURS/.test(src));
// Two places computed an SLA figure. Leaving one on the old measure put two
// different numbers for the same month on two slides of the same deck.
check('every SLA computation uses elapsed hours',
  (src.match(/elapsedHoursBetween\(/g) || []).length >= 3,
  (src.match(/elapsedHoursBetween\(/g) || []).length);
check('and every one reads the target from the same table',
  (src.match(/slaTargetFor\(/g) || []).length >= 3,
  (src.match(/slaTargetFor\(/g) || []).length);
check('the note tells the reader it is 24/7', /24\/7/.test(src));
check('and states the targets rather than hard-coding prose',
  /slaTargetLabel\(\)/.test(src));

/* ── Services ─────────────────────────────────────────────────────────────── */

section('every section declares who it is for');

const missing = [];
S.forEach(function (sec) {
  if (!Object.prototype.hasOwnProperty.call(sec, 'services')) missing.push(sec.id);
});
check('no section is left unassigned', missing.length === 0, missing.join(', '));
check('there are still fifteen sections', S.length === 15, S.length);

const on = (svc) => {
  const d = S.defaultSectionsFor(svc);
  return Object.keys(d).filter(k => d[k]);
};

section('an unrecorded client is offered everything');

/*
 * The case that decides whether this feature is safe to ship. Every existing
 * client is unrecorded on day one, and treating that as "buys nothing" would
 * silently cut their reports to four sections — the failure nobody notices,
 * because a missing slide leaves no mark on the page.
 */
check('null means all fifteen', on(null).length === 15, on(null).length);
check('and so does a non-array', on(undefined).length === 15, on(undefined).length);

section('an explicit empty list is NOT the same as unrecorded');

const none = on([]);
check('recording "none" offers only the always-on sections', none.length === 4, none.length);
check('and those are the client-agnostic ones',
  ['execSummary', 'assuranceDashboard', 'assurance', 'recommendations']
    .every(id => none.indexOf(id) >= 0), none.join(', '));

section('a single-service client gets their own report');

const aware = on(['awareness']);
check('awareness-only includes the human risk dashboard',
  aware.indexOf('humanRisk') >= 0);
check('and NOT the vulnerability dashboard they never bought',
  aware.indexOf('vulnDashboard') < 0, aware.join(', '));

const vuln = on(['vuln']);
check('vuln-only includes the vulnerability dashboard',
  vuln.indexOf('vulnDashboard') >= 0);
check('and not the human risk dashboard', vuln.indexOf('humanRisk') < 0);

const mdr = on(['mdr']);
check('MDR-only includes the threat landscape', mdr.indexOf('threatLandscape') >= 0);
check('and resilience', mdr.indexOf('resilience') >= 0);
check('but not vulnerabilities or awareness',
  mdr.indexOf('vulnDashboard') < 0 && mdr.indexOf('humanRisk') < 0);

section('vCISO covers governance AND the managed-service views');

const vciso = on(['vciso']);
['heatMap', 'topRisks', 'execRisk', 'businessImpact', 'thirdParty', 'compliance']
  .forEach(id => check('vCISO includes ' + id, vciso.indexOf(id) >= 0));
['threatLandscape', 'identityRisk', 'resilience']
  .forEach(id => check('vCISO also includes ' + id, vciso.indexOf(id) >= 0));
// vCISO is governance and oversight, not the scanning or training subscriptions.
check('but vCISO alone does not include the vulnerability dashboard',
  vciso.indexOf('vulnDashboard') < 0);
check('nor the human risk dashboard', vciso.indexOf('humanRisk') < 0);

section('services combine, they do not compete');

const both = on(['awareness', 'vuln']);
check('two services yield the union',
  both.indexOf('humanRisk') >= 0 && both.indexOf('vulnDashboard') >= 0);
const all = on(['mdr', 'vuln', 'awareness', 'edr', 'ndr', 'identity', 'pentest', 'vciso']);
check('the full stack yields every section', all.length === 15, all.length);

section('the catalogue validates what it stores');

const svcLib = require(path.join(ROOT, 'lib', 'services.js'));
check('null round-trips as null, not as an empty list',
  svcLib.normaliseServices(null) === null);
check('an unknown key is dropped rather than stored',
  JSON.stringify(svcLib.normaliseServices(['mdr', 'wat'])) === JSON.stringify(['mdr']));
check('duplicates collapse',
  JSON.stringify(svcLib.normaliseServices(['mdr', 'mdr'])) === JSON.stringify(['mdr']));
check('order is the catalogue order, not the click order',
  JSON.stringify(svcLib.normaliseServices(['vciso', 'mdr'])) === JSON.stringify(['mdr', 'vciso']));
check('an empty list stays an empty list',
  JSON.stringify(svcLib.normaliseServices([])) === JSON.stringify([]));
check('every catalogue key is one the report knows about',
  svcLib.SERVICE_KEYS.every(k => k === 'pentest' ||
    S.some(sec => sec.services && sec.services.indexOf(k) >= 0)),
  svcLib.SERVICE_KEYS.join(','));

section('the wiring that has no seam');

const rptJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-reports.js'), 'utf8');
// The toggles pre-select from the tenant list, so the tenant list has to be
// loaded first. It was not: renderSectionToggles ran before populateClients,
// so every client looked unrecorded on the first paint.
// Anchored on the CALL, not the `function renderSectionToggles(prefs) {`
// declaration — which contains the same substring and sits earlier in the file,
// so the loose version passed no matter what the order was.
const populateAt = rptJs.indexOf('await populateClients(prefs);');
const togglesAt  = rptJs.indexOf('\n      renderSectionToggles(prefs);');
check('the init call sites were both found', populateAt > -1 && togglesAt > -1,
  'populate@' + populateAt + ' toggles@' + togglesAt);
check('clients are loaded before the section toggles render',
  populateAt > -1 && togglesAt > -1 && populateAt < togglesAt,
  'populate@' + populateAt + ' toggles@' + togglesAt);
check('a saved choice still beats the service default',
  /saved !== null \? saved : suggested/.test(rptJs));
check('and the analyst is told what was decided for them',
  /not subscribed/.test(rptJs) && /rpt-sections-note/.test(rptJs));

const serverJs = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
check('the tenant list carries services',
  /\$\{servicesCol\}/.test(serverJs) && /NULL::text\[\] AS services/.test(serverJs));
check('an un-migrated database reports null, not an empty list',
  /hasTenantServicesColumn\(\)\s*\?\s*'t\.services'\s*:\s*'NULL::text\[\] AS services'/.test(serverJs));

const pagesJs = fs.readFileSync(path.join(ROOT, 'lib', 'pages.js'), 'utf8');
// Without this, a write to /api/tenants fell through pageGate's no-mapping
// branch and was reachable by any authenticated staff user.
check('writes to /api/tenants are gated on the admin page',
  /tenants:\s*'admin'/.test(pagesJs));

done();
