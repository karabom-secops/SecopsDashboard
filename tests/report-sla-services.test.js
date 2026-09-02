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
check('the full stack yields every section', all.length === S.length, all.length + '/' + S.length);

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
// This is the whole point. The composite says 35 because two controls they do
// not buy score zero; the in-scope score says they are doing what they pay for.
check('the in-scope score reflects what they buy',
  awarenessOnly.serviceScore === 100, awarenessOnly.serviceScore);
check('while the overall still counts the gaps',
  awarenessOnly.overall < 50, awarenessOnly.overall);
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
// Guard against the fixture silently losing its exposure again: if both fall
// back to the default weights the comparison below is vacuous.
check('the two estates really do weight differently',
  exposed.weights.vulnerabilities !== sheltered.weights.vulnerabilities,
  exposed.weights.vulnerabilities.toFixed(3) + ' vs ' + sheltered.weights.vulnerabilities.toFixed(3));
check('an exposed client loses more coverage to a missing vuln service',
  exposed.coverage < sheltered.coverage,
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
check('the client-run control is flagged as evidenced',
  awGap && awGap.evidence === 'client-supplied', awGap && awGap.evidence);
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

const vcisoOnly = score(['vciso']);
// vCISO is governance; it does not scan a host or work a ticket. Dividing by a
// zero in-scope weight would produce NaN, and reporting 0 would say they are
// failing at services they were never sold.
check('vCISO alone covers none of the scored components',
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
