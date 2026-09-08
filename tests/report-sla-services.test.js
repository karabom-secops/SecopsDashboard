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

// Read once, up front. These were declared beside the sections that used them,
// which put one of them in a temporal dead zone for an earlier section and
// crashed the suite on load — a crash a `grep FAIL` does not show.
const src      = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');
const rptJs    = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-reports.js'), 'utf8');
const authJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'auth.js'), 'utf8');
const serverJs = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const pagesJs  = fs.readFileSync(path.join(ROOT, 'lib', 'pages.js'), 'utf8');

/**
 * Source with comments removed.
 *
 * Every "this no longer appears" check in this suite has to run against code,
 * not prose. A comment explaining why something was removed necessarily
 * contains the thing that was removed, so the naive version of these checks
 * fails on its own documentation — which happened twice while writing them.
 */
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const srcCode = codeOnly(src);

/* ── SLA ──────────────────────────────────────────────────────────────────── */

section('security runs 24/7, so the clock does too');

/*
 * THE CASE THAT WAS WRONG.
 *
 * Under the old business-hours model (08:00–17:00, Mon–Fri) a ticket raised
 * Friday 17:05 and closed Monday 09:00 accrued about one hour, because nights
 * and weekends did not count. A 24/7 service cannot claim that: the client was
 * exposed for 64 hours and the report said one.
 *
 * The deck no longer GRADES durations — the incident SLA was removed from both
 * the KPI table and the Executive Summary — but it still reports them, so how
 * they are measured still matters.
 */
const fri1705 = '2026-03-06T17:05:00+02:00';   // Friday
const mon0900 = '2026-03-09T09:00:00+02:00';   // Monday
const weekend = S.elapsedHoursBetween(fri1705, mon0900);
check('a weekend is counted, not skipped', Math.round(weekend) === 64, weekend);

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

/*
 * ── The incident SLA is gone from the deck ────────────────────────────────
 *
 * Removed on request from the KPI table first, then from the Executive
 * Summary. Nothing was left reading IR_SLA_HOURS or slaTargetFor, so both were
 * deleted rather than kept: a table of contracted SLA targets sitting in the
 * report module reads as a policy the deck enforces, and the next person to
 * find it would reasonably assume a client is graded against it somewhere.
 *
 * codeOnly throughout — this file documents its own removals, so the comment
 * explaining each one necessarily names the thing that went.
 */
section('the incident SLA is gone, not merely unused');

const srcNoComments = codeOnly(src);

check('the target table is deleted', !/IR_SLA_HOURS/.test(srcNoComments));
check('and its lookup with it', !/slaTargetFor/.test(srcNoComments));
check('and the attainment threshold', !/SLA_TARGET_PCT/.test(srcNoComments));
check('and the targets label', !/slaTargetLabel/.test(srcNoComments));
// Exported seams too — a module that still hands these out invites a caller.
check('nothing is exported for them',
  !/SECTIONS\.IR_SLA_HOURS/.test(srcNoComments) &&
  !/SECTIONS\.slaTargetFor/.test(srcNoComments));
check('and the browser module really has dropped them',
  S.IR_SLA_HOURS === undefined && S.slaTargetFor === undefined);

// What SURVIVES: duration is still measured and reported. Removing the grading
// must not take the measurement with it.
check('elapsed-hours measurement survives',
  typeof S.elapsedHoursBetween === 'function');
check('and the KPI table still uses it',
  (srcNoComments.match(/elapsedHoursBetween\(/g) || []).length >= 2,
  (srcNoComments.match(/elapsedHoursBetween\(/g) || []).length);

section('the business-hours model is gone, not merely unused');

check('no business-hours measurement remains', !/businessHoursBetween/.test(src));
check('nor its service-window config', !/BUSINESS_HOURS/.test(src));
check('the note tells the reader it is 24/7', /24\/7/.test(src));

/* ── The KPI table ─────────────────────────────────────────────────────────
 *
 * "Resolved within SLA" was removed from this table on request. Nothing here
 * tested the table's contents at all — a row AND a whole column could be
 * deleted with all 243 checks still green, which is how a section quietly
 * stops saying what everyone assumes it says.
 *
 * Rendered for real and read back.
 */
section('the resolution KPI table');

const kpiSec = S.filter(x => x.id === 'assuranceDashboard')[0];

function kpiHtml(tickets) {
  return kpiSec.render({
    period: '2026-08', periodLabel: 'August 2026', comments: {},
    data: { mdr: { tickets: tickets }, secureScore: {} },
  }) || '';
}

const kpi = kpiHtml([
  // 12h HIGH — inside every target. 96h CRITICAL — outside all of them.
  { createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-02T20:00:00Z', severity: 'HIGH' },
  { createdAt: '2026-08-05T08:00:00Z', resolvedAt: '2026-08-09T08:00:00Z', severity: 'CRITICAL' },
  { createdAt: '2026-08-06T08:00:00Z', resolvedAt: '2026-08-06T12:00:00Z', severity: 'WEIRD' },
]);
const kpiText = kpi.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

check('the table renders', /Incident resolution/.test(kpi));
check('and still reports what it measures',
  /Mean time to resolve/.test(kpiText) && /Median time to resolve/.test(kpiText) &&
  /Tickets raised this period/.test(kpiText) && /Tickets resolved this period/.test(kpiText));

// The removal, asserted on the rendered output rather than the source — the
// source still discusses the SLA in comments and in the exec-summary tile.
check('no SLA row', !/Resolved within SLA/.test(kpiText), kpiText.slice(0, 90));
check('no SLA attainment target', !/95\s*%/.test(kpiText));
// The column went with the row: every remaining KPI is a measurement with no
// contracted target, and a "Target" column of em-dashes reads as missed
// commitments.
check('no Target column', !/\bTarget\b/.test(kpiText), kpiText.slice(0, 120));
// This row existed only to qualify a partial SLA figure.
check('no ungraded-severity row', !/Not graded/.test(kpiText));
// The targets sentence stated a commitment the table no longer reports on.
check('the note no longer recites the targets',
  !/Resolution targets/.test(kpiText) && !/Critical 24 h/.test(kpiText));
check('but still explains the 24/7 clock', /24\/7/.test(kpiText));

/*
 * The measurements themselves must survive the removal — pinned to exact
 * values, because "contains hrs" would pass on any number at all.
 *
 * Elapsed hours: 12, 96 and 4. Mean 112/3 = 37.3; median of [4,12,96] = 12.
 * The unrecognised severity is counted in both, as it always was: it has no
 * contracted target, but it does have a duration.
 */
check('the mean is computed over every resolved ticket',
  /37\.3 hrs/.test(kpiText), kpiText.slice(0, 110));
check('and the median is the middle duration',
  /Median time to resolve 12 hrs/.test(kpiText), kpiText.slice(0, 140));
check('a ticket with an unrecognised severity is still timed',
  /Tickets resolved this period 3/.test(kpiText));

// Backlog change appears only when the two counts differ — the fixture above
// has three of each, so its absence there is correct, not a regression.
check('no backlog row when raised and resolved match',
  !/Backlog change/.test(kpiText));
const backlogText = kpiHtml([
  { createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-02T20:00:00Z', severity: 'HIGH' },
  { createdAt: '2026-08-04T08:00:00Z', severity: 'HIGH' },
  { createdAt: '2026-08-05T08:00:00Z', severity: 'LOW' },
]).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
check('and it reports the growth when they differ',
  /Backlog change 2 more open/.test(backlogText), backlogText.slice(0, 200));

// The helpers that existed only for the removed row are gone from the code —
// a constant named SLA_TARGET_PCT left behind reads as a policy in force.
check('SLA_TARGET_PCT is gone', !/SLA_TARGET_PCT/.test(codeOnly(src)));
check('slaTargetLabel is gone', !/slaTargetLabel/.test(codeOnly(src)));

section('the table reports resolution, and nothing it cannot measure');

/*
 * The block used to lead with "Mean time to respond (MTTR)" and "Median time
 * to respond", both of which were measuring creation to RESOLUTION. The ticket
 * feed carries no acknowledgement stamp, so a response time cannot be derived
 * at all — the labels described a metric the data cannot produce, directly
 * above a row about resolution.
 */
// Scoped to the row LABELS, not the whole file: the comment explaining why
// these were removed necessarily contains the words, and the loose version of
// this check failed on its own documentation.
const kpiLabels = (src.match(/kpi: '[^']+'/g) || []).join(' | ');
check('the KPI labels were found', kpiLabels.length > 40, kpiLabels);
check('no metric claims to measure response time',
  !/time to respond/i.test(kpiLabels), kpiLabels);
check('nor mean time to mitigate, which came off a different platform clock',
  !/time to mitigate/i.test(kpiLabels));
check('the timings are labelled resolution',
  /Mean time to resolve/.test(src) && /Median time to resolve/.test(src));

/*
 * "Resolution rate" divided tickets resolved in the month by tickets raised in
 * the month — two different cohorts, since a ticket resolved in March may have
 * been raised in January. Clearing a backlog produced 125.2%, which is not a
 * rate and cannot be read as one.
 */
check('the >100% "resolution rate" is gone', !/resRate/.test(src));
check('and the two counts are shown without a fabricated ratio between them',
  /Tickets raised this period/.test(src) && /Tickets resolved this period/.test(src));
check('a backlog change is stated in tickets, not as a percentage',
  /Backlog change/.test(src) && /fewer open/.test(src) && /more open/.test(src));
check('the note warns the two counts are different sets',
  /different sets/.test(src));

/* ── Vulnerability remediation SLA ────────────────────────────────────────── */

section('one remediation SLA, not four');

/*
 * lib/vuln-parser.js computes the due_date stored on every finding, so it is
 * the authority. Four browser modules kept their own literal and the board
 * report's had drifted to 7/30/90/180 — a 20-day-old High was flagged overdue
 * on the Vulnerabilities tab and reported to the board as within SLA, from the
 * same database row. The report also contradicted its own prose, which said
 * "High 2 weeks" two hundred lines below the table allowing thirty days.
 */
const parser = require(path.join(ROOT, 'lib', 'vuln-parser.js'));

check('the parser still owns the numbers',
  parser.SLA_DAYS.Critical === 7 && parser.SLA_DAYS.High === 14 &&
  parser.SLA_DAYS.Medium === 30 && parser.SLA_DAYS.Low === 60,
  JSON.stringify(parser.SLA_DAYS));

check('the server ships them to the browser',
  /vulnSlaDays:\s*vulnParserLib\.SLA_DAYS/.test(serverJs));
check('and auth.js takes them from the response',
  /window\.VULN_SLA_DAYS = user\.vulnSlaDays/.test(authJs));

// The literal in auth.js is only what applies before /api/auth/me returns.
// It still has to agree, or the page renders one policy and then swaps to
// another mid-load.
const fallback = (authJs.match(/window\.VULN_SLA_DAYS = (\{[^}]*\})/) || [])[1];
check('the pre-session fallback was found', !!fallback, fallback);
check('and it matches the parser exactly',
  !!fallback && JSON.parse(fallback.replace(/(\w+):/g, '"$1":')).Critical === parser.SLA_DAYS.Critical &&
  JSON.parse(fallback.replace(/(\w+):/g, '"$1":')).High === parser.SLA_DAYS.High &&
  JSON.parse(fallback.replace(/(\w+):/g, '"$1":')).Medium === parser.SLA_DAYS.Medium &&
  JSON.parse(fallback.replace(/(\w+):/g, '"$1":')).Low === parser.SLA_DAYS.Low,
  fallback);

section('no module keeps a private copy any more');

const consumers = ['report-sections.js', 'tab-vulns.js', 'tab-remediation-tracker.js'];
consumers.forEach(function (f) {
  const js = fs.readFileSync(path.join(ROOT, 'public', 'js', f), 'utf8');
  check(f + ' declares no SLA table of its own',
    !/(VULN_)?SLA_DAYS\s*=\s*\{/.test(js));
  check(f + ' reads the shared one',
    /vulnSlaDays\s*\(/.test(js) || /window\.vulnSlaDays/.test(js));
});

// A module-level capture would freeze the fallback before the session response
// lands, which defeats the whole exercise.
check('the report resolves the SLA at use time, not at load',
  /function vulnSlaDays\(severity\)/.test(src) && !/var VULN_SLA_DAYS\s*=/.test(src));

section('the report no longer states an SLA it is not applying');

check('the prose is built from the live table',
  /VULN_SLA_SEVERITIES\.map/.test(src));
check('and no longer hard-codes "2 weeks" in any rendered string',
  !/High 2 weeks/.test(srcCode) && !/Medium 1 month/.test(srcCode));

section('the shared accessor normalises case');

// The tabs hold severities lowercase, the report capitalised, the parser
// capitalised. One accessor has to serve all three.
/*
 * auth.js is run WHOLE, with a stubbed document rather than its tail chopped
 * off. Cutting the file at a regex left unbalanced braces and a SyntaxError,
 * which the runner reported as a crashed suite rather than a failed check.
 *
 * readyState 'loading' makes the IIFE register a DOMContentLoaded listener and
 * return, so init() never runs and nothing is fetched — but everything defined
 * above it, including the SLA accessor, is real.
 */
const authSandbox = {
  console,
  document: {
    readyState: 'loading',
    addEventListener() {},
    querySelector() { return null; },
    getElementById() { return null; },
    querySelectorAll() { return []; },
  },
  fetch() { return Promise.reject(new Error('not used')); },
  location: { replace() {}, pathname: '/' },
};
authSandbox.window = authSandbox;
vm.createContext(authSandbox);
vm.runInContext(authJs, authSandbox, { filename: 'auth.js' });
const A = authSandbox.window;
check('lowercase resolves', A.vulnSlaDays('high') === 14, A.vulnSlaDays('high'));
check('capitalised resolves', A.vulnSlaDays('High') === 14);
check('padded resolves', A.vulnSlaDays(' HIGH ') === 14);
check('Info has no SLA', A.vulnSlaDays('Info') === null, A.vulnSlaDays('Info'));
check('and neither does nothing', A.vulnSlaDays(null) === null);

/* ── Services ─────────────────────────────────────────────────────────────── */

section('every section declares who it is for');

const missing = [];
S.forEach(function (sec) {
  if (!Object.prototype.hasOwnProperty.call(sec, 'services')) missing.push(sec.id);
});
check('no section is left unassigned', missing.length === 0, missing.join(', '));
// Deliberately not a magic number: adding a section should not require
// editing this suite, only deciding who the section is for.
check('the registry is non-trivial', S.length >= 15, S.length);

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
check('null offers every section', on(null).length === S.length, on(null).length + '/' + S.length);
check('and so does a non-array', on(undefined).length === S.length, on(undefined).length);

section('an explicit empty list is NOT the same as unrecorded');

const none = on([]);
const alwaysOn = S.filter(function (x) { return !x.services; }).map(function (x) { return x.id; });
check('recording "none" offers only the always-on sections',
  none.length === alwaysOn.length, none.join(', '));
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

section('vISO covers governance AND the managed-service views');

const viso = on(['viso']);
['heatMap', 'topRisks', 'execRisk', 'businessImpact', 'thirdParty', 'compliance']
  .forEach(id => check('vISO includes ' + id, viso.indexOf(id) >= 0));
['threatLandscape', 'identityRisk', 'resilience']
  .forEach(id => check('vISO also includes ' + id, viso.indexOf(id) >= 0));
// vISO is governance and oversight, not the scanning or training subscriptions.
check('but vISO alone does not include the vulnerability dashboard',
  viso.indexOf('vulnDashboard') < 0);
check('nor the human risk dashboard', viso.indexOf('humanRisk') < 0);

section('services combine, they do not compete');

const both = on(['awareness', 'vuln']);
check('two services yield the union',
  both.indexOf('humanRisk') >= 0 && both.indexOf('vulnDashboard') >= 0);
/*
 * Derived from the catalogue, not written out by hand.
 *
 * This listed the eight service keys literally and broke the moment a ninth was
 * added — reporting that the full stack no longer yields every section, when
 * what had actually happened was that the test did not know about a service.
 * The claim being made is "a client who buys everything is offered everything",
 * and that claim has to read the real catalogue to mean anything.
 */
const ALL_SERVICE_KEYS = require(path.join(ROOT, 'lib', 'services.js')).SERVICE_KEYS;
const all = on(ALL_SERVICE_KEYS);
check('the full stack yields every section',
  all.length === S.length, all.length + '/' + S.length +
  ' over ' + ALL_SERVICE_KEYS.length + ' services');

section('MDR includes endpoint, network and identity');

/*
 * A client on MDR is not asked to buy Managed EDR, NDR or Identity separately,
 * so they must not be reported as lacking them. Before this they showed three
 * coverage gaps for capabilities they were already paying for, and the deck
 * withheld the endpoint and identity sections their MDR service produces.
 *
 * The implication is applied on READ. tenants.services stays a record of what
 * was sold; what that entitles them to is derived, because the two change for
 * different reasons.
 */
const svcLib0 = require(path.join(ROOT, 'lib', 'services.js'));

check('MDR expands to the three it includes',
  JSON.stringify(svcLib0.effectiveServices(['mdr'])) ===
  JSON.stringify(['mdr', 'edr', 'ndr', 'identity']),
  JSON.stringify(svcLib0.effectiveServices(['mdr'])));
check('buying them explicitly changes nothing',
  JSON.stringify(svcLib0.effectiveServices(['mdr', 'edr', 'ndr', 'identity'])) ===
  JSON.stringify(svcLib0.effectiveServices(['mdr'])));
check('and EDR alone does NOT imply MDR',
  svcLib0.effectiveServices(['edr']).indexOf('mdr') < 0);
check('unrecorded survives expansion as unrecorded',
  svcLib0.effectiveServices(null) === null);

// The stored record must keep saying what was sold.
check('expansion does not leak into what gets stored',
  JSON.stringify(svcLib0.normaliseServices(['mdr'])) === JSON.stringify(['mdr']),
  JSON.stringify(svcLib0.normaliseServices(['mdr'])));
check('and an implied service is identifiable as implied',
  svcLib0.isImplied(['mdr'], 'edr') === true &&
  svcLib0.isImplied(['edr'], 'edr') === false);

// Coverage: MDR supplies the endpoint yardstick but not an external scan.
/*
 * Coverage is the three core services and nothing else. Managed EDR used to
 * cover the vulnerabilities component whenever the engine scored an
 * endpoint-only estate on patch currency — defensible arithmetic, wrong answer
 * commercially: it credited an MDR client with vulnerability coverage they had
 * not bought, and put "Endpoint Patch Currency" in their board report.
 */
check('MDR does not cover vulnerabilities on any estate',
  svcLib0.coversComponent(['mdr'], 'vulnerabilities', 'endpoint') === false &&
  svcLib0.coversComponent(['mdr'], 'vulnerabilities', 'infrastructure') === false);
check('only Vulnerability Management does',
  svcLib0.coversComponent(['vuln'], 'vulnerabilities', 'endpoint') === true);
check('and Managed EDR covers no scored component at all',
  JSON.stringify(svcLib0.SERVICE_COVERS.edr) === '[]');

// Report sections follow the same expansion.
const mdrSections = on(svcLib0.effectiveServices(['mdr']));
const bundleSections = on(svcLib0.effectiveServices(['mdr', 'edr', 'ndr', 'identity']));
check('MDR alone offers the same sections as buying the bundle',
  JSON.stringify(mdrSections) === JSON.stringify(bundleSections),
  mdrSections.join(', '));
check('including the identity dashboard MDR delivers',
  mdrSections.indexOf('identityRisk') >= 0, mdrSections.join(', '));

// And the report gates read the effective set rather than re-deriving it.
check('serviceInScope reads the effective list',
  /scope\.effectiveServices \|\| scope\.services/.test(src));
check('the score ships the effective list to the browser',
  /effectiveServices: servicesLib\.effectiveServices\(services\)/.test(
    fs.readFileSync(path.join(ROOT, 'lib', 'secure-score.js'), 'utf8')));
check('the tenant list ships it too',
  /effectiveServices: servicesLib\.effectiveServices\(r\.services\)/.test(serverJs));
check('and the Reports tab prefers it',
  /Array\.isArray\(t\.effectiveServices\) \? t\.effectiveServices : t\.services/.test(rptJs));

section('vCISO is now vISO');

check('the catalogue uses the new key',
  svcLib0.SERVICE_KEYS.indexOf('viso') >= 0 && svcLib0.SERVICE_KEYS.indexOf('vciso') < 0,
  svcLib0.SERVICE_KEYS.join(','));
check('and the new label', svcLib0.serviceLabel('viso') === 'vISO',
  svcLib0.serviceLabel('viso'));
// Cheap insurance: a stored value outliving a rename is expensive to diagnose.
check('a stored legacy key is migrated on read',
  JSON.stringify(svcLib0.normaliseServices(['vciso'])) === JSON.stringify(['viso']),
  JSON.stringify(svcLib0.normaliseServices(['vciso'])));
check('no section still points at the old key',
  !S.some(x => (x.services || []).indexOf('vciso') >= 0));

section('the catalogue validates what it stores');

const svcLib = require(path.join(ROOT, 'lib', 'services.js'));
check('null round-trips as null, not as an empty list',
  svcLib.normaliseServices(null) === null);
check('an unknown key is dropped rather than stored',
  JSON.stringify(svcLib.normaliseServices(['mdr', 'wat'])) === JSON.stringify(['mdr']));
check('duplicates collapse',
  JSON.stringify(svcLib.normaliseServices(['mdr', 'mdr'])) === JSON.stringify(['mdr']));
check('order is the catalogue order, not the click order',
  JSON.stringify(svcLib.normaliseServices(['viso', 'mdr'])) === JSON.stringify(['mdr', 'viso']));
check('an empty list stays an empty list',
  JSON.stringify(svcLib.normaliseServices([])) === JSON.stringify([]));
check('every catalogue key is one the report knows about',
  svcLib.SERVICE_KEYS.every(k => k === 'pentest' ||
    S.some(sec => sec.services && sec.services.indexOf(k) >= 0)),
  svcLib.SERVICE_KEYS.join(','));

/* ── Coverage and the three scores ────────────────────────────────────────── */

const SS = require(path.join(ROOT, 'lib', 'secure-score.js'));

// A client with real infrastructure, a good awareness result, no scan on file
// and no MDR feed. The awareness result is genuinely 100; the question is what
// the other two components should do to the headline.
// Built through estateLib, not as a literal. resolveEstate() derives the
// fields the weighting curve reads; a hand-written object leaves `exposure`
// null and silently falls back to the flat 40/35/25, which made an earlier
// version of the exposure check below compare two identical numbers and pass
// for the wrong reason.
const estateLib = require(path.join(ROOT, 'lib', 'estate.js'));
const mkEstate = (d) => estateLib.resolveEstate(d, {});

const estate = mkEstate({
  servers: 12, publicAssets: 8, endpoints: 240, cloudTenancies: 2,
  users: 242, trainedUsers: 242, awarenessProgram: 'platform',
});
const awarenessData = { upload: { total_users: 242 }, completionRate: 88 };
const score = (services) =>
  SS.calculateSecureScore(null, awarenessData, null, { estate, services });

section('a client is not scored on services they never bought');

const awarenessOnly = score(['awareness']);
check('their awareness result is intact',
  awarenessOnly.awarenessScore === 100, awarenessOnly.awarenessScore);
// This is the whole point. The composite sits well below 100 because two
// controls they do not buy score zero; the in-scope score says they are doing
// what they pay for.
check('the in-scope score reflects what they buy',
  awarenessOnly.serviceScore === 100, awarenessOnly.serviceScore);
/*
 * EXACTLY 50, and the arithmetic is worth writing down because the number moved
 * with the weighting change: an awareness-only client now weights awareness at
 * 0.50 (it was 0.35 under the estate-driven curve, which is why this used to
 * read 35 and the check was "< 50").
 *
 *   awareness      100 x 0.50 = 50
 *   vulnerabilities  0 x 0.25 =  0   (not bought, unmeasured)
 *   incident resp.   0 x 0.25 =  0   (not bought, unmeasured)
 *
 * Asserted as an equality rather than a threshold so a future weighting change
 * has to come back through this comment instead of sliding under an inequality.
 */
check('while the overall still counts the gaps',
  awarenessOnly.overall === 50, awarenessOnly.overall);
check('and the overall is below the in-scope score, which is the gap',
  awarenessOnly.overall < awarenessOnly.serviceScore,
  awarenessOnly.overall + ' < ' + awarenessOnly.serviceScore);
check('and the two are reported separately, not merged',
  awarenessOnly.serviceScore !== awarenessOnly.overall);

section('coverage is sized to the client, not counted in services');

/*
 * Coverage is the SUM OF THE COMPONENT WEIGHTS in scope, and those weights are
 * derived from the estate. So the same missing service costs a heavily exposed
 * client more coverage than a client with nothing facing the internet — which
 * is the right answer and is not asserted anywhere, it falls out of
 * resolveWeights().
 */
const exposed = SS.calculateSecureScore(null, awarenessData, null, {
  estate: mkEstate({ servers: 40, publicAssets: 60, endpoints: 240,
    cloudTenancies: 4, users: 242, trainedUsers: 242, awarenessProgram: 'platform' }),
  services: ['awareness'],
});
const sheltered = SS.calculateSecureScore(null, awarenessData, null, {
  estate: mkEstate({ servers: 1, publicAssets: 1, endpoints: 240,
    cloudTenancies: 0, users: 242, trainedUsers: 242, awarenessProgram: 'platform' }),
  services: ['awareness'],
});
/*
 * THESE TWO ASSERTIONS INVERTED, AND THAT IS THE POINT OF THE CHANGE.
 *
 * They used to check that a big estate and a small one weighted DIFFERENTLY —
 * the estate-driven exposure curve. That curve is gone: it meant a typed number
 * moved a board-reported score by up to fourteen points, and merely starting to
 * fill the form moved it nine. Weights now follow the SERVICE MIX, so two
 * clients on the same services weight identically however different their
 * estates, and that is the property worth pinning.
 *
 * Reframed rather than deleted: the fixtures still differ by a lot of estate,
 * so a regression that reintroduced estate-driven weighting would fail here.
 */
check('two estates on the same services weight IDENTICALLY',
  JSON.stringify(exposed.weights) === JSON.stringify(sheltered.weights),
  exposed.weights.vulnerabilities.toFixed(3) + ' vs ' + sheltered.weights.vulnerabilities.toFixed(3));
check('and their coverage is identical too — it follows the mix, not the estate',
  exposed.coverage === sheltered.coverage && exposed.coverage === 50,
  'exposed ' + exposed.coverage + '% vs sheltered ' + sheltered.coverage + '%');

check('full service cover reaches 100%',
  score(['vuln', 'awareness', 'mdr']).coverage === 100,
  score(['vuln', 'awareness', 'mdr']).coverage);

section('unrecorded services change nothing at all');

const unrecorded = score(null);
const before = SS.calculateSecureScore(null, awarenessData, null, { estate });
check('coverage is null, not zero', unrecorded.coverage === null, unrecorded.coverage);
check('the in-scope score is null, not zero',
  unrecorded.serviceScore === null, unrecorded.serviceScore);
// The regression that would have hit every existing client on day one.
check('and the composite is untouched',
  unrecorded.composite === before.composite, unrecorded.composite);
check('nothing is reported as uncovered',
  unrecorded.scope.uncovered.length === 0);

section('bought-but-no-data is not the same as never-bought');

const buysVuln = score(['vuln', 'awareness']);
// They pay for vulnerability management and we have no scan. That is a zero
// they are entitled to see inside their in-scope score.
check('a purchased control with no data stays IN scope',
  buysVuln.scope.covered.indexOf('vulnerabilities') >= 0);
check('and drags the in-scope score down',
  buysVuln.serviceScore < awarenessOnly.serviceScore,
  buysVuln.serviceScore + ' vs ' + awarenessOnly.serviceScore);
check('an unpurchased control is marked out of scope instead',
  awarenessOnly.unmeasured.some(u => u.key === 'vulnerabilities' && u.outOfScope === true));
check('with a reason a client can act on',
  awarenessOnly.unmeasured.some(u => u.reason === 'service not subscribed'));

section('a commercial gap is distinguished from a blind spot');

/*
 * A client who runs their own awareness programme and shows us the results is
 * MEASURED but not COVERED. Reporting that as the same kind of gap as a
 * control nobody is looking at turns a security finding into a sales line.
 */
const mdrOnly = score(['mdr']);
const awGap   = mdrOnly.scope.uncovered.filter(u => u.key === 'awareness')[0];
const vulnGap = mdrOnly.scope.uncovered.filter(u => u.key === 'vulnerabilities')[0];
// 'measured', not 'client-supplied': the evidence is not always the client's
// — an MDR client's endpoint data comes from our own EDR feed.
check('a measured-but-uncovered control is flagged as measured',
  awGap && awGap.evidence === 'measured', awGap && awGap.evidence);
check('the unmeasured one is flagged as a blind spot',
  vulnGap && vulnGap.evidence === 'none', vulnGap && vulnGap.evidence);
check('and only the blind spot counts toward blindSpotPoints',
  mdrOnly.scope.blindSpotPoints === vulnGap.pointsForfeited,
  mdrOnly.scope.blindSpotPoints + ' vs ' + vulnGap.pointsForfeited);

// The tidy formula overall = serviceScore x coverage is FALSE, and an earlier
// version of this engine claimed it. It holds only when everything uncovered is
// also unmeasured; a client-run control breaks it, as here.
check('overall is NOT derived from serviceScore x coverage',
  Math.abs(mdrOnly.overall - (mdrOnly.serviceScore * mdrOnly.coverage / 100)) > 5,
  'overall ' + mdrOnly.overall + ' vs product ' +
  Math.round(mdrOnly.serviceScore * mdrOnly.coverage / 100));

section('nothing in scope is not a zero');

const vcisoOnly = score(['viso']);
// vISO is governance; it does not scan a host or work a ticket. Dividing by a
// zero in-scope weight would produce NaN, and reporting 0 would say they are
// failing at services they were never sold.
check('vISO alone covers none of the scored components',
  vcisoOnly.coverage === 0, vcisoOnly.coverage);
check('and the in-scope score is null rather than 0 or NaN',
  vcisoOnly.serviceScore === null, vcisoOnly.serviceScore);
check('the overall score still stands on its own evidence',
  vcisoOnly.overall === before.composite, vcisoOnly.overall);

section('the coverage section is offered to everyone and self-disables');

const covSec = S.filter(x => x.id === 'serviceCoverage')[0];
check('the section exists', !!covSec);
check('it is always offered, whatever the client buys', covSec && !covSec.services);
check('it needs the secure score', covSec && covSec.requires.indexOf('secureScore') >= 0);
check('it renders nothing when no services are recorded',
  covSec && covSec.render({ data: { secureScore: { scope: { recorded: false } } } }) === null);
check('and nothing when the payload predates the feature',
  covSec && covSec.render({ data: { secureScore: {} } }) === null);

const rendered = covSec.render({ data: { secureScore: {
  serviceScore: 100, coverage: 35, overall: 35,
  scope: { recorded: true, blindSpotPoints: 65, uncovered: [
    { key: 'vulnerabilities', label: 'Vulnerability management', weight: 0.4,
      pointsForfeited: 40, evidence: 'none', closedBy: ['Vulnerability Management'] },
  ] },
} } });
check('it renders all three numbers', /100/.test(rendered) && /35 %/.test(rendered));
check('it names what would close the gap', /Vulnerability Management/.test(rendered));
check('it says a blind spot is unmeasured, not weak',
  /unmeasured/.test(rendered));
check('and it does not invite the reader to multiply',
  !/serviceScore ×/.test(rendered) && /independent/.test(rendered));

section('the exec summary reports the engagement, not the gaps');

/*
 * The headline used to be the overall composite, which counts controls the
 * client never bought as zero. An awareness-only client opened their board
 * pack on "Secure Score 35" when the service they pay for scored 100.
 *
 * Rendered for real, then read back out of the HTML.
 */
const execSec = S.filter(x => x.id === 'execSummary')[0];

function execCtx(services) {
  const sc = SS.calculateSecureScore(
    { vulns: [{ risk: 'Critical', status: 'open', firstSeenAt: '2026-06-01' }],
      risks: [{ stage: 'open', risk_score: 20 }], incidents: [] },
    awarenessData,
    { tickets: [{ createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-02T20:00:00Z', severity: 'HIGH' }] },
    { estate, services });

  return {
    period: '2026-08', periodLabel: 'August 2026', execSummary: '', comments: {},
    data: {
      secureScore: {
        score: sc.composite, serviceScore: sc.serviceScore,
        coverage: sc.coverage, overall: sc.overall, scope: sc.scope,
        components: {
          vulnerabilities:  { score: sc.vulnScore,      measured: sc.measured.vulnerabilities },
          awareness:        { score: sc.awarenessScore, measured: sc.measured.awareness },
          incidentResponse: { score: sc.mdrScore,       measured: sc.measured.incidentResponse },
        },
      },
      vulnFindings: { vulns: [{ risk: 'Critical', status: 'open', firstSeenAt: '2026-06-01' }],
                      risks: [{ stage: 'open', risk_score: 20 }], incidents: [] },
      awareness: awarenessData,
      mdr: { tickets: [{ createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-02T20:00:00Z', severity: 'HIGH' }] },
    },
  };
}

/* ── One Secure Score per deck ─────────────────────────────────────────────
 *
 * The Overview tile derived from `secureScore.score` — the overall composite —
 * while the Executive Summary reported the in-scope score. One payload, two
 * different Secure Scores in the same deck (55 and 47), with nothing on either
 * saying which was which. The analyst's only recourse was to retype it.
 *
 * headlineScore() is now the single copy of the rule, and both read it.
 */
section('the Overview tile and the Executive Summary agree');

const scopedPayload = {
  score: 55, overall: 55, rating: 'Fair',
  serviceScore: 47, serviceRating: 'Poor',
  scope: { recorded: true, services: ['mdr'] },
};
const unscopedPayload = { score: 55, overall: 55, rating: 'Fair',
                          serviceScore: null, scope: { recorded: false } };

check('headlineScore is exported', typeof S.headlineScore === 'function');

const scopedHead = S.headlineScore(scopedPayload);
check('a scoped client gets the in-scope score, not the overall',
  scopedHead.score === 47, scopedHead.score);
check('and it is flagged as scoped', scopedHead.scoped === true);
check('with the matching rating', scopedHead.rating === 'Poor', scopedHead.rating);

const plainHead = S.headlineScore(unscopedPayload);
check('an unrecorded client falls back to the overall',
  plainHead.score === 55, plainHead.score);
check('and is not flagged as scoped', plainHead.scoped === false);
check('with the overall rating', plainHead.rating === 'Fair', plainHead.rating);

// A recorded service mix that produced no in-scope score must not silently
// report null — the overall is still the honest answer there.
const noServiceScore = S.headlineScore(
  { score: 55, overall: 55, serviceScore: null, scope: { recorded: true } });
check('a recorded mix with no in-scope score still reports the overall',
  noServiceScore.score === 55 && noServiceScore.scoped === false, noServiceScore.score);

check('the reports tab asks for the rule rather than deriving its own',
  /R\.headlineScore\(secureScore\)/.test(rptJs));
check('and no longer reads the overall composite for the tile',
  !/secureScore\.score != null/.test(codeOnly(rptJs)));

/*
 * THE INVARIANT, end to end: the number the tile derives and the number the
 * Executive Summary prints, from ONE payload, must be the same. Asserting each
 * against a literal would let both drift together; this compares them.
 */
const agreeCtx = execCtx(['mdr']);
agreeCtx.data.secureScore = Object.assign({}, agreeCtx.data.secureScore, scopedPayload);
const agreeHtml = execSec.render(agreeCtx);
const printed = (agreeHtml.match(/(\d+)\/100/) || [])[1];
check('the Executive Summary prints the same score the tile derives',
  printed === String(S.headlineScore(scopedPayload).score),
  'summary=' + printed + ' tile=' + S.headlineScore(scopedPayload).score);
check('and it is the in-scope one, not the overall',
  printed === '47', printed);

// The tile must SAY it is the scoped figure. Without that, 47 in the report
// editor beside 55 on the Secure Score tab reads as a fault, and the fix an
// analyst reaches for is the override box — which is how a hand-typed number
// ends up in a board pack.
check('the tile carries the scoped flag through to the view',
  /t\.scoped\s*=\s*head\.scoped/.test(rptJs));
check('and the view renders a qualifier when it is set',
  /info\.scoped\s*\?[\s\S]{0,120}services in scope/.test(rptJs));

const tileLabels = (html) =>
  [...String(html || '').matchAll(/<div class="bi-l">([\s\S]*?)<\/div>/g)]
    .map(m => m[1].replace(/&middot;/g, '·').replace(/&amp;/g, '&').trim());

const awExec  = execSec.render(execCtx(['awareness']));
const awTiles = tileLabels(awExec);

check('the headline is the in-scope score, not the overall',
  /100\/100/.test(awExec) && !/>35\/100</.test(awExec), awTiles[0]);
check('and it says which score it is',
  /services in scope/.test(awTiles[0] || ''), awTiles[0]);
check('coverage sits beside it',
  awTiles.some(l => /Service coverage/.test(l)), awTiles.join(' | '));

section('a service the client does not buy appears nowhere');

// Not as a zero, not as "No data" — an empty tile on a board pack reads as a
// control that failed rather than one never purchased.
check('no vulnerability tile for an awareness-only client',
  !awTiles.some(l => /vulnerabilit/i.test(l)), awTiles.join(' | '));
check('no incident tile', !awTiles.some(l => /incident/i.test(l)));
check('no resolution SLA tile', !awTiles.some(l => /SLA/i.test(l)));
check('no risk-register tile', !awTiles.some(l => /risks above appetite/i.test(l)));
check('but the service they DO buy is reported',
  awTiles.some(l => /Awareness completion/.test(l)), awTiles.join(' | '));

const mdrTiles = tileLabels(execSec.render(execCtx(['mdr'])));
check('an MDR-only client gets incident tiles',
  mdrTiles.some(l => /incident/i.test(l)));
check('and no awareness tile',
  !mdrTiles.some(l => /Awareness completion/.test(l)), mdrTiles.join(' | '));

const allTiles = tileLabels(execSec.render(execCtx(['vuln', 'mdr', 'awareness', 'edr', 'viso'])));
check('a full-service client still gets everything',
  allTiles.length >= 6, allTiles.join(' | '));

/* ── The Executive Summary no longer grades resolution ────────────────────
 *
 * A "Resolution SLA met" tile sat beside the incident count and was removed on
 * request. It is checked across the same three months that used to distinguish
 * its empty states — quiet, ungradeable, and graded — because a removal that
 * only holds for one of them is not a removal.
 */
section('no resolution SLA tile in the executive summary');

const tilePairs = (html) =>
  [...String(html || '').matchAll(
    /<div class="bi-v( nd)?">([\s\S]*?)<\/div><div class="bi-l">([\s\S]*?)<\/div>/g)]
    .map(m => ({ nd: !!m[1],
                 v: m[2].trim(),
                 l: m[3].replace(/&middot;/g, '·').replace(/&amp;/g, '&').trim() }));

function mdrExecWith(tickets) {
  const c = execCtx(['mdr']);
  c.data.mdr = { tickets };
  return execSec.render(c);
}

const quietHtml = mdrExecWith([]);
const ungradedHtml = mdrExecWith([
  { createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-03T08:00:00Z', severity: 'WEIRD' },
]);
const gradedHtml = mdrExecWith([
  { createdAt: '2026-08-02T08:00:00Z', resolvedAt: '2026-08-02T20:00:00Z', severity: 'HIGH' },
]);

[['a quiet month', quietHtml], ['an ungradeable month', ungradedHtml],
 ['a fully graded month', gradedHtml]].forEach(([label, html]) => {
  const tiles = tilePairs(html);
  check('no SLA tile in ' + label,
    !tiles.some(t => /SLA/i.test(t.l)), tiles.map(t => t.l).join(' | '));
});

// The wording that supported it is gone too — an "n/a · nothing to resolve
// this period" left behind would be a caption with nothing above it.
check('and none of its empty-state wording survives',
  !/nothing to resolve this period/.test(codeOnly(src)));

// What MUST survive: the incident count. It reports activity, not attainment,
// and dropping it with the SLA tile would take the whole MDR statement out.
check('the incident count is untouched',
  tilePairs(gradedHtml).some(t => /Security incidents this period/.test(t.l)),
  tilePairs(gradedHtml).map(t => t.l).join(' | '));

section('an unconfigured client sees the report they always saw');

const plainExec  = execSec.render(execCtx(null));
const plainTiles = tileLabels(plainExec);
check('the headline falls back to the overall score',
  /35\/100/.test(plainExec), plainTiles[0]);
check('with no in-scope wording', !/services in scope/.test(plainTiles[0] || ''));
check('no coverage tile is invented',
  !plainTiles.some(l => /Service coverage/.test(l)), plainTiles.join(' | '));
// Named rather than counted. A bare `length >= 6` was here and it went stale
// the moment the SLA tile was removed — a count tells you something changed
// but not whether the right thing changed, and the obvious repair is to edit
// the number until it passes.
const plainSet = plainTiles.join(' | ');
check('the score is shown', /Secure Score/.test(plainSet), plainSet);
check('vulnerabilities are shown', /vulnerabilities open/i.test(plainSet));
check('incidents are shown', /Security incidents this period/.test(plainSet));
check('awareness is shown', /Awareness completion/.test(plainSet));
check('risks above appetite are shown', /risks above appetite/i.test(plainSet));
check('and nothing grades resolution', !/SLA/i.test(plainSet), plainSet);

section('the blocks behind the tiles are gated too');

// Gating the tile but not the block behind it would drop the headline number
// and keep the whole dashboard it came from.
const gateCode = codeOnly(src);
/*
 * Each block is gated on the thing that actually feeds it.
 *
 * vulnExposureBlock is SCAN data, so it follows the Vulnerability Management
 * SERVICE — not the vulnerabilities score component, which an MDR client
 * satisfies through endpoint patch currency without buying a scan. Gating it
 * on the component put an empty tile in an MDR client's board pack.
 */
[['awarenessBlock', "componentInScope\\(ctx, 'awareness'\\)"],
 ['vulnExposureBlock', "serviceInScope\\(ctx, 'vuln'\\)"],
 ['irKpiBlock', "componentInScope\\(ctx, 'incidentResponse'\\)"]].forEach(function (pair) {
  const fn = gateCode.slice(gateCode.indexOf('function ' + pair[0] + '(ctx)'));
  check(pair[0] + ' returns nothing when out of scope',
    new RegExp(pair[1]).test(fn.slice(0, 400)), pair[1]);
});
// The distinction that caused the bug, pinned so it cannot be undone.
check('the vulnerability tile follows the scanning service, not the component',
  /if \(serviceInScope\(ctx, 'vuln'\)\) \{[\s\S]{0,200}vulnerabilities open/.test(src));
check('endpoint coverage is gated on Managed EDR',
  /serviceInScope\(ctx, 'edr'\)/.test(gateCode));
check('the maturity table drops out-of-scope domains',
  /d\.key === 'overall'\) return !scoped/.test(gateCode) &&
  /return componentInScope\(ctx, d\.key\)/.test(gateCode));
check('all three gates default to in-scope when nothing is recorded',
  /if \(!scope \|\| !scope\.recorded\) return true;/.test(gateCode));

section('advice is only ever about services the client buys');

/*
 * "Reduce critical and high-severity findings" for a client who does not buy
 * vulnerability management appears under Executive Decisions in their board
 * pack as a failing of theirs — when nobody was ever engaged to scan. The
 * coverage section is where that gap is stated, once.
 */
const recEstate = mkEstate({
  servers: 12, publicAssets: 8, endpoints: 240, cloudTenancies: 2,
  users: 242, trainedUsers: 120, awarenessProgram: 'platform',
});
const recMeasured = { vulnerabilities: false, awareness: true, incidentResponse: false };
const recDetail = { basis: 'infrastructure', measured: false };
const recs = (services) => SS.generateRecommendations(
  10, 55, 0, recMeasured, recDetail, recEstate, { services })
  .map(r => r.area);

const recAll = recs(null);
check('an unrecorded client still gets the full advice',
  recAll.length >= 4, recAll.join(', '));

const recAware = recs(['awareness']);
check('an awareness-only client gets awareness advice',
  recAware.indexOf('Security Awareness') >= 0, recAware.join(', '));
check('and no vulnerability advice',
  !recAware.some(a => /Vulnerabilit|Scan Coverage|Asset Inventory|Internal Infrastructure|Patch Management|Endpoint/.test(a)),
  recAware.join(', '));
check('and no incident-response advice',
  recAware.indexOf('Incident Response') < 0, recAware.join(', '));

const recVuln = recs(['vuln']);
check('a vuln-only client gets vulnerability advice',
  recVuln.some(a => /Vulnerabilit|Internal Infrastructure/.test(a)), recVuln.join(', '));
check('and no awareness advice',
  recVuln.indexOf('Security Awareness') < 0, recVuln.join(', '));

check('an MDR client gets incident-response advice',
  recs(['mdr']).indexOf('Incident Response') >= 0);

/*
 * The map is the enforcement. An area missing from it keeps its
 * recommendation — failing open loses no advice — so the only thing stopping a
 * new area going unmapped is this check.
 */
const ssSrc = fs.readFileSync(path.join(ROOT, 'lib', 'secure-score.js'), 'utf8');
const areasInFile = [...new Set((ssSrc.match(/area: '[^']+'/g) || [])
  .map(s => s.slice(7, -1)))];
const unmapped = areasInFile.filter(a => !(a in SS.AREA_COMPONENT));
check('every recommendation area is mapped to a component',
  areasInFile.length > 5 && unmapped.length === 0,
  areasInFile.length + ' areas, unmapped: ' + (unmapped.join(', ') || 'none'));
check('and "Overall" advice applies whatever they buy',
  SS.AREA_COMPONENT.Overall === null);
check('the route passes the services through',
  /generateRecommendations\([\s\S]{0,200}\{ services: tenantServices \}\)/.test(serverJs));

section('the Secure Score tab shows all three figures');

// renderScopeStrip is a pure function of its arguments — no DOM needed beyond
// an object with `hidden` and `innerHTML`.
const tabSandbox = { console, window: {} };
tabSandbox.window.window = tabSandbox.window;
tabSandbox.document = { getElementById() { return null; }, addEventListener() {} };
tabSandbox.window.document = tabSandbox.document;
vm.createContext(tabSandbox);
vm.runInContext(
  fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8'),
  tabSandbox, { filename: 'tab-secure-score.js' });
const Tab = tabSandbox.window.SecureScoreTab;

check('the tab exposes the scope strip', Tab && typeof Tab.renderScopeStrip === 'function');

function strip(services) {
  const s = SS.calculateSecureScore(null, awarenessData, null, { estate, services });
  const el = { hidden: true, innerHTML: '' };
  Tab.renderScopeStrip(el, {
    score: s.composite, overall: s.overall,
    serviceScore: s.serviceScore, coverage: s.coverage, scope: s.scope,
  });
  return el;
}

const stripAware = strip(['awareness']);
check('it renders for a scoped client', stripAware.hidden === false);
check('showing the in-scope score', /Secure Score — services in scope/.test(stripAware.innerHTML));
check('the coverage score', /Service coverage of posture/.test(stripAware.innerHTML));
check('and the overall score', /Overall Secure Score/.test(stripAware.innerHTML));
check('with the gaps named', /Vulnerability management/.test(stripAware.innerHTML));
check('and what would close them',
  /Covered by Vulnerability Management/.test(stripAware.innerHTML));

// A control the client runs themselves is a commercial gap, not a blind spot.
const stripMdr = strip(['mdr']);
check('a measured-but-uncovered control is not called a blind spot',
  /measured, outside this engagement/.test(stripMdr.innerHTML));
check('while an unmeasured one is',
  /ss-scope-blind/.test(stripMdr.innerHTML));

// The regression that would hit every unconfigured client.
const stripNone = strip(null);
check('the strip is hidden when no services are recorded', stripNone.hidden === true);
check('and renders nothing at all', stripNone.innerHTML === '');

// The gauge must not compare an in-scope score against a stored composite.
const tabSrc = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');
check('the gauge shows the in-scope score when scoped',
  /const gaugeValue = scoped \? scoreData\.serviceScore : scoreData\.score;/.test(tabSrc));
check('and drops the trend delta rather than comparing two measures',
  /renderScoreGauge\(gaugeContainer, gaugeValue, scoped \? null : delta\)/.test(tabSrc));

section('no section anywhere in the deck shows an unbought service');

/*
 * THE WHOLE-DECK AUDIT.
 *
 * Gating sections by their declared services was not enough, because sections
 * draw ACROSS service boundaries. Cyber Risk Heat Map, Top Cyber Risks and
 * Business Impact are vISO deliverables built from VULNERABILITY findings;
 * Threat Landscape mixes vulnerability and MDR data; Risk Appetite pulls EDR,
 * identity and vulnerability. A vISO-only client would have received a
 * business-impact analysis built entirely from scan data they do not buy.
 *
 * The fix is to withhold the data at source rather than filter it at each of a
 * dozen render functions, so this renders every section for real with the
 * out-of-scope sources removed exactly as tab-reports.js removes them, and
 * greps the output for fingerprints only that service's data could produce.
 */
/*
 * The withholding rule comes from tab-reports.js itself.
 *
 * An earlier version of this audit carried its OWN copy of the source→service
 * map and its own withholding flag. It passed with a green tick while the real
 * withholding in tab-reports.js was disabled — it was testing its own
 * reimplementation. Two mutations went uncaught before that showed up.
 */
const rptSandbox = { console };
rptSandbox.window = rptSandbox;
rptSandbox.document = { getElementById() { return null; }, addEventListener() {},
                        querySelectorAll() { return []; }, createElement() { return {}; } };
rptSandbox.localStorage = { getItem() { return null; }, setItem() {} };
rptSandbox.fetch = () => Promise.reject(new Error('not used'));
vm.createContext(rptSandbox);
for (const f of ['report-shell.js', 'report-deck.js', 'report-sections.js', 'tab-reports.js']) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'public', 'js', f), 'utf8'),
    rptSandbox, { filename: f });
}
const RT = rptSandbox.window.ReportsTab;
const SOURCE_SERVICE = RT && RT.SOURCE_SERVICE;

check('the real withholding rule is reachable',
  !!(RT && typeof RT.sourceInScope === 'function' && SOURCE_SERVICE));
// Drive it directly, so the rule itself is under test rather than a restatement.
check('a vuln source is withheld from an awareness-only client',
  RT.sourceInScope('vulnFindings', ['awareness'], true) === false);
check('an MDR source is withheld from an awareness-only client',
  RT.sourceInScope('mdr', ['awareness'], true) === false);
check('the source they DO buy is fetched',
  RT.sourceInScope('awareness', ['awareness'], true) === true);
// MDR includes endpoint detection, so its data must not be withheld.
check('an MDR client still gets endpoint data',
  RT.sourceInScope('edr', svcLib0.effectiveServices(['mdr']), true) === true);
check('nothing is withheld when services are unrecorded',
  RT.sourceInScope('vulnFindings', null, false) === true);
// Withholding these would take the scope object with it and disable every gate.
check('the secure score is never withheld',
  RT.sourceInScope('secureScore', ['awareness'], true) === true);
check('nor the metrics payload',
  RT.sourceInScope('metrics', ['awareness'], true) === true);
const FINGERPRINT = {
  vuln: /ZZVULNZZ/, mdr: /ZZMDRZZ/, awareness: /ZZAWARENESSZZ/,
  identity: /ZZIDENTITYZZ/, edr: /ZZEDRZZ/, viso: /ZZVENDORZZ/,
};

/**
 * Tile labels that belong to a service, matched against the rendered captions.
 *
 * "Critical & high vulnerabilities open" is scan data even when the
 * vulnerabilities SCORE COMPONENT is in scope — an MDR client is scored on
 * endpoint patch currency and buys no scan, so the tile must not appear.
 * That distinction is why these are keyed on the service, not the component.
 */
const TILE_SERVICE = {
  vuln:      /vulnerabilities open/i,
  mdr:       /Security incidents this period|Resolution SLA met/i,
  awareness: /Awareness completion/i,
  viso:      /risks above appetite/i,
};

function allSourceData() {
  return {
    vulnFindings: { vulns: [{ name: 'ZZVULNZZ finding', risk: 'Critical', status: 'open',
                              firstSeenAt: '2026-05-01', host: 'h1' }],
                    risks: [{ title: 'ZZVULNZZ risk', stage: 'open', risk_score: 20 }],
                    pentest: [], incidents: [] },
    vulnSummary: { critical: 1, high: 2, medium: 3, low: 4, hosts: 5, name: 'ZZVULNZZ' },
    vulnTrends: { months: [{ period: '2026-08', critical: 1, high: 2, medium: 0, low: 0 }] },
    mdr: { tickets: [{ ticketNumber: 'ZZMDRZZ-1', subject: 'ZZMDRZZ ticket', severity: 'HIGH',
                       status: 'Resolved', createdAt: '2026-08-02T08:00:00Z',
                       resolvedAt: '2026-08-02T20:00:00Z' }] },
    edr: { threats: { total: 1, mttmHours: 2, ZZEDRZZ: 1 },
           agents: { total: 10, healthy: 9, label: 'ZZEDRZZ' } },
    o365: { signIns: { total: 5, risky: 1, label: 'ZZIDENTITYZZ' }, mfa: { enforced: 4, total: 5 } },
    awareness: { upload: { total_users: 242 },
                 sessions: [{ session_type: 'Awareness Session', status: 'Complete',
                              user_email: 'ZZAWARENESSZZ@x', sent_date: '2026-08-01' }] },
    vendors: [{ name: 'ZZVENDORZZ', tier: 'critical', score: 40 }],
    grcAssessment: { total: 55, frameworks: {}, sections: [{ name: 'ZZVENDORZZ', score: 50 }] },
    grcQuestions: [],
    metrics: { tiles: {} },
  };
}

/*
 * An endpoint-only estate, which is where the reported bug lived.
 *
 * With no servers, public assets or cloud, the vulnerability component is
 * scored on ENDPOINT PATCH CURRENCY rather than a scan — so for an MDR client
 * (MDR includes EDR) the component is in scope while the scanning service is
 * not. Every audit case ran against an infrastructure estate, where the
 * component is out of scope too, so the distinction never arose and the empty
 * "Critical & high vulnerabilities open" tile went unnoticed.
 */
const endpointEstate = mkEstate({
  servers: 0, publicAssets: 0, cloudTenancies: 0,
  endpoints: 240, users: 242, trainedUsers: 242, awarenessProgram: 'platform',
});

/** Renders the deck for one service mix and returns any leaked service keys. */
function auditDeck(services, opts) {
  const withhold = !(opts && opts.withholdNothing);
  const est = (opts && opts.estate) || estate;
  const sc = SS.calculateSecureScore(null, { upload: { total_users: 242 } }, null,
    { estate: est, services });
  const eff = svcLib0.effectiveServices(services);

  const full = allSourceData();
  const data = { secureScore: {
    score: sc.composite, overall: sc.overall, serviceScore: sc.serviceScore,
    coverage: sc.coverage, scope: sc.scope, recommendations: [],
    components: {
      vulnerabilities:  { score: sc.vulnScore, measured: sc.measured.vulnerabilities },
      awareness:        { score: sc.awarenessScore, measured: sc.measured.awareness },
      incidentResponse: { score: sc.mdrScore, measured: sc.measured.incidentResponse },
    },
  } };
  // The REAL rule decides what arrives, so disabling it in tab-reports.js
  // shows up here as a leak rather than passing silently.
  Object.keys(full).forEach((k) => {
    if (!withhold || RT.sourceInScope(k, eff, !!eff)) data[k] = full[k];
  });

  const ctx = { period: '2026-08', periodLabel: 'August 2026', clientName: 'Acme',
                execSummary: '', narrative: '', assurance: '', comments: {}, data };

  const leaks = [];
  const rendered = [];
  S.forEach((sec) => {
    if (eff && sec.services && !sec.services.some(k => eff.indexOf(k) >= 0)) return;
    if ((sec.requires || []).some(k => ctx.data[k] == null)) return;
    let html = null;
    try { html = sec.render(ctx); } catch (e) { html = 'ERR ' + e.message; }
    if (!html) return;
    rendered.push(sec.id);
    if (!eff) return;

    // A) Data from a service they do not buy appearing in the output.
    Object.keys(FINGERPRINT).forEach((svc) => {
      if (eff.indexOf(svc) >= 0) return;
      if (FINGERPRINT[svc].test(String(html))) leaks.push(sec.id + '/' + svc);
    });

    /*
     * B) An EMPTY tile for a service they do not buy.
     *
     * The first version of this audit only looked for leaked content, so an
     * MDR client's "Critical & high vulnerabilities open — No data" sailed
     * through: the data WAS correctly withheld, and the tile rendered anyway.
     * On a board pack an empty tile reads as a control that failed, which is
     * the exact harm this whole exercise exists to prevent — so a tile whose
     * subject is out of scope is a leak whether or not it carries a number.
     */
    const labels = [...String(html).matchAll(/<div class="bi-l">([\s\S]*?)<\/div>/g)]
      .map(m => m[1].replace(/&amp;/g, '&').replace(/&middot;/g, '·'));
    labels.forEach((label) => {
      Object.keys(TILE_SERVICE).forEach((svc) => {
        if (eff.indexOf(svc) >= 0) return;
        if (TILE_SERVICE[svc].test(label)) {
          leaks.push(sec.id + '/tile "' + label.trim() + '" (' + svc + ')');
        }
      });
    });
  });
  return { leaks, rendered };
}

[['awareness only', ['awareness']],
 ['vulnerability only', ['vuln']],
 ['MDR only', ['mdr']],
 ['vISO only', ['viso']],
 ['vuln + awareness', ['vuln', 'awareness']],
 ['explicitly none', []],
].forEach(function (pair) {
  const r = auditDeck(pair[1]);
  check(pair[0] + ' shows nothing from an unbought service',
    r.leaks.length === 0, r.leaks.join(', ') || r.rendered.join(', '));
});

check('an unrecorded client still gets the full deck',
  auditDeck(null).rendered.length >= 8, auditDeck(null).rendered.join(', '));

/*
 * THE REPORTED CASE. An MDR client on an endpoint-only estate: scored on
 * endpoint patch currency, buys no scan. The component is in scope, the
 * scanning service is not, and the deck must show nothing scan-derived.
 */
const endpointMdr = auditDeck(['mdr'], { estate: endpointEstate });
check('an MDR client on an endpoint estate is scored on endpoints',
  SS.calculateSecureScore(null, { upload: { total_users: 242 } }, null,
    { estate: endpointEstate, services: ['mdr'] }).vulnDetail.basis === 'endpoint');
check('and sees no scan-derived tile anywhere',
  endpointMdr.leaks.length === 0, endpointMdr.leaks.join(', '));

/*
 * Endpoint patch currency is a real measurement of something no contracted
 * service covers. It reached the deck three ways — a maturity row, a component
 * card captioned "Endpoint Hygiene", and a coverage gap labelled "Endpoint
 * patch currency" — and none of them belongs in a client report.
 */
const endpointHtml = (function () {
  const sc = SS.calculateSecureScore(null, { upload: { total_users: 242 } }, null,
    { estate: endpointEstate, services: ['mdr'] });
  const ctx = { period: '2026-08', periodLabel: 'August 2026', clientName: 'Acme',
    execSummary: '', comments: {},
    data: { secureScore: {
      score: sc.composite, overall: sc.overall, serviceScore: sc.serviceScore,
      coverage: sc.coverage, scope: sc.scope, recommendations: [],
      components: {
        vulnerabilities:  { score: sc.vulnScore, measured: sc.measured.vulnerabilities,
                            basis: sc.vulnDetail.basis, detail: sc.vulnDetail },
        awareness:        { score: sc.awarenessScore, measured: sc.measured.awareness },
        incidentResponse: { score: sc.mdrScore, measured: sc.measured.incidentResponse },
      },
    } } };
  return S.filter(x => ['execSummary', 'assuranceDashboard', 'serviceCoverage'].indexOf(x.id) >= 0)
    .map(x => { try { return x.render(ctx) || ''; } catch (e) { return ''; } }).join('\n');
})();

check('the phrase "Endpoint Patch Currency" is not in the deck',
  !/endpoint patch currency/i.test(endpointHtml));
check('nor "Endpoint Hygiene"', !/endpoint hygiene/i.test(endpointHtml), );
check('nor any endpoint caption at all',
  !/endpoints patched/i.test(endpointHtml));
// The coverage gap is named for the service, not the yardstick.
check('the coverage gap is named "Vulnerability management"',
  /Vulnerability management/.test(endpointHtml));

/*
 * The Secure Score tab's printable Executive Report is ALSO client-facing, and
 * had its own copy of the endpoint caption. Grepping only the deck would have
 * missed it — it lives in tab-secure-score.js, not report-sections.js.
 */
const tabJs2 = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');
const a4 = tabJs2.slice(tabJs2.indexOf('Security Posture Breakdown') - 3000,
                        tabJs2.indexOf('Security Posture Breakdown') + 1200);
check('the printable report drops the endpoint caption',
  !/Endpoint Hygiene/.test(a4) && !/vulnLabel/.test(a4), 'endpoint caption still in the A4 report');
check('and shows a component card only when the service covers it',
  /a4Covered\('vulnerabilities'\) \?/.test(a4) &&
  /a4Covered\('awareness'\) \?/.test(a4) &&
  /a4Covered\('incidentResponse'\) \?/.test(a4));
// Both halves of the gate, asserted separately. A check that matched only the
// "unrecorded" clause passed while the clause that actually decides coverage
// was replaced with `true`.
check('the A4 gate consults the covered list',
  /\(a4Scope\.covered \|\| \[\]\)\.indexOf\(key\) >= 0/.test(tabJs2));
check('and defaults to in-scope when unrecorded',
  /!a4Scope \|\| !a4Scope\.recorded/.test(tabJs2));

[['awareness', ['awareness']], ['vISO', ['viso']], ['none', []]].forEach(function (p) {
  const r = auditDeck(p[1], { estate: endpointEstate });
  check('nor does an ' + p[0] + '-only client on an endpoint estate',
    r.leaks.length === 0, r.leaks.join(', '));
});

/*
 * The audit has to be able to FAIL, or it proves nothing. Feeding every source
 * regardless of scope must produce a leak — and it does, through exactly the
 * path section-level gating misses: Top Cyber Risks is declared a vISO section
 * and built from vulnerability findings.
 */
const unguarded = auditDeck(['viso'], { withholdNothing: true });
check('the audit detects a leak when data is not withheld',
  unguarded.leaks.length > 0, unguarded.leaks.join(', '));

section('the deck refuses to build an unsubscribed section');

// The rule itself is exercised behaviourally above; this only pins that
// fetchNeeded actually consults it, which no unit call can show.
check('fetchNeeded consults the withholding rule',
  /if \(!sourceInScope\(k\)\) \{/.test(rptJs) && /_withheldSources = withheld;/.test(rptJs));
check('and skips sections whose services are all out of scope',
  /notSubscribed\.push\(s\.label\)/.test(rptJs));
check('saying why, so nobody hunts for a missing upload',
  /service not consumed by this client/.test(rptJs));
// A toggle that assembleDeck ignores is worse than no toggle.
check('the toggle for such a section is disabled, not merely tagged',
  /\(offByService \? ' disabled' : ''\)/.test(rptJs));
check('services are re-read before anything is fetched',
  rptJs.indexOf('readTenantServices();') < rptJs.indexOf('var notSubscribed = []'));
// Withholding secureScore would take the scope object with it and disable the
// gates that depend on it.
check('the score and metrics are never withheld',
  /secureScore:        null/.test(rptJs) && /metrics:            null/.test(rptJs));

section('the wiring that has no seam');

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


check('the tenant list carries services',
  /\$\{servicesCol\}/.test(serverJs) && /NULL::text\[\] AS services/.test(serverJs));
check('an un-migrated database reports null, not an empty list',
  /hasTenantServicesColumn\(\)\s*\?\s*'t\.services'\s*:\s*'NULL::text\[\] AS services'/.test(serverJs));

// Without this, a write to /api/tenants fell through pageGate's no-mapping
// branch and was reachable by any authenticated staff user.
check('writes to /api/tenants are gated on the admin page',
  /tenants:\s*'admin'/.test(pagesJs));

done();
