'use strict';

/**
 * Arctic Wolf coverage → the MDR weight discount.
 *
 * WHAT THIS IS FOR
 *
 * The Secure Score's `coverage` figure credited the FULL MDR weight to any
 * client recorded as buying MDR, however much of their estate Arctic Wolf could
 * actually see. A client at 70% sensor reach had roughly a third of their MDR
 * weight in estate the service never touched, reported to their board as fully
 * covered.
 *
 * THE PROPERTIES THIS SUITE EXISTS TO PROTECT
 *
 *   unavailable is never zero      a mistyped org name must cost the client
 *                                  NOTHING — the MDR weight stays whole
 *   a reported 0 IS a score        and does discount, fully
 *   matching is exact             never fuzzy; a loose match puts one client's
 *                                  posture in another client's board report
 *   weights are never mutated      the sum-to-1 invariant survives
 *   only coverage moves            serviceScore, maxAchievable, composite,
 *                                  overall and uncovered are byte-identical
 *   a discounted client is not
 *     an uncovered one             they buy MDR; telling them to buy it again
 *                                  is how a board review is lost
 *   absent input is a no-op        every existing client scores exactly as
 *                                  before this feature existed
 *
 *   node tests/arctic-wolf-coverage.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('arctic-wolf-coverage');

const aw = require(path.join(ROOT, 'lib', 'arctic-wolf-coverage'));
const secureScore = require(path.join(ROOT, 'lib', 'secure-score'));

const serverJs = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const portalJs = fs.readFileSync(path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const srvCode = codeOnly(serverJs);

// ── Fixtures ───────────────────────────────────────────────────────────────

const NOW = new Date('2026-05-06T00:00:00Z');   // one week after 2026-04-29

const WEEKS = {
  '2026-04-22': {
    weekKey: '2026-04-22', weekCommencing: '22 April 2026',
    orgs: [
      { orgName: 'Reflex Solutions (Pty) Ltd', coverageScore: 55, irPlan: true },
      { orgName: 'Blank Co', coverageScore: 88, irPlan: true },
    ],
  },
  '2026-04-29': {
    weekKey: '2026-04-29', weekCommencing: '29 April 2026',
    orgs: [
      { orgName: 'Reflex Solutions (Pty) Ltd', coverageScore: 70, irPlan: true },
      { orgName: 'Zero Co',  coverageScore: 0,    irPlan: true },
      { orgName: 'Blank Co', coverageScore: null, irPlan: true },
    ],
  },
};

// ── The read ───────────────────────────────────────────────────────────────

section('the read — every "no" is its own reason, and none of them is zero');

const notLinked = aw.coverageForOrg(WEEKS, null, { now: NOW });
check('no org name -> not_linked', notLinked.reason === aw.REASONS.NOT_LINKED, notLinked.reason);
check('and linked is false', notLinked.linked === false, String(notLinked.linked));
check('and credit is NULL, not 0', notLinked.credit === null, String(notLinked.credit));
check('blank string is the same as absent',
  aw.coverageForOrg(WEEKS, '   ', { now: NOW }).reason === aw.REASONS.NOT_LINKED, 'not_linked');

const noReport = aw.coverageForOrg({}, 'Reflex Solutions (Pty) Ltd', { now: NOW });
check('no weeks -> no_report', noReport.reason === aw.REASONS.NO_REPORT, noReport.reason);
check('but it IS linked', noReport.linked === true, String(noReport.linked));
check('and credit is null', noReport.credit === null, String(noReport.credit));

const notFound = aw.coverageForOrg(WEEKS, 'Reflex', { now: NOW });
check('a PREFIX does not match — matching is never fuzzy',
  notFound.reason === aw.REASONS.ORG_NOT_FOUND, notFound.reason);
check('and the near name is offered so a human can fix it',
  notFound.candidates.indexOf('Reflex Solutions (Pty) Ltd') >= 0,
  JSON.stringify(notFound.candidates));
check('credit is null, so the MDR weight stays whole',
  notFound.credit === null, String(notFound.credit));

const noScore = aw.coverageForOrg(
  { '2026-04-29': WEEKS['2026-04-29'] }, 'Blank Co', { now: NOW });
check('org present with a null score -> no_score_in_report',
  noScore.reason === aw.REASONS.NO_SCORE_IN_REPORT, noScore.reason);
check('a null coverageScore is NEVER read as 0',
  noScore.score === null && noScore.credit === null,
  noScore.score + '/' + noScore.credit);

section('a reported zero is a real score');

const zero = aw.coverageForOrg(WEEKS, 'Zero Co', { now: NOW });
check('coverageScore 0 is available', zero.available === true, String(zero.available));
check('score is 0', zero.score === 0, String(zero.score));
check('credit is 0 — it discounts fully', zero.credit === 0, String(zero.credit));
check('and it is banded low', zero.band === 'low', String(zero.band));

section('week selection and matching');

const hit = aw.coverageForOrg(WEEKS, 'Reflex Solutions (Pty) Ltd', { now: NOW });
check('the newest scored week wins', hit.weekKey === '2026-04-29', hit.weekKey);
check('score 70', hit.score === 70, String(hit.score));
check('credit is score/100', hit.credit === 0.7, String(hit.credit));
check('the week commencing travels for attribution',
  hit.weekCommencing === '29 April 2026', hit.weekCommencing);
check('age is measured from the week the report covers',
  hit.ageDays === 7, String(hit.ageDays));
check('a week-old figure is not stale', hit.stale === false, String(hit.stale));
check('band 70 -> low', hit.band === 'low', hit.band);
check('the vendor is named on the result', hit.source === 'Arctic Wolf', hit.source);

const folded = aw.coverageForOrg(WEEKS, '  reflex   SOLUTIONS (pty) ltd ', { now: NOW });
check('case and whitespace differences still match',
  folded.available === true && folded.score === 70, JSON.stringify(folded.score));
check('and the match is flagged as folded, not exact',
  folded.matchedBy === 'name-folded', folded.matchedBy);
check('the report\'s own spelling is returned, not what was typed',
  folded.matchedOrg === 'Reflex Solutions (Pty) Ltd', folded.matchedOrg);

/*
 * A blank column this week must not silently remove a discount that last
 * week's dated, attributed figure still supports — so the search falls through
 * to the older week, and the week it used is always reported.
 */
const fellBack = aw.coverageForOrg(WEEKS, 'Blank Co', { now: NOW });
check('a blank score falls back to the last week that had one',
  fellBack.available === true && fellBack.score === 88, String(fellBack.score));
check('and reports the older week it actually used',
  fellBack.weekKey === '2026-04-22', fellBack.weekKey);

const old = aw.coverageForOrg(WEEKS, 'Reflex Solutions (Pty) Ltd',
  { now: new Date('2026-07-01T00:00:00Z') });
check('an old figure is flagged stale but still applied',
  old.stale === true && old.available === true && old.credit === 0.7,
  old.ageDays + ' days');

section('field normalisation');

check('orgNameField trims and collapses whitespace',
  aw.orgNameField('  A   B  ') === 'A B', JSON.stringify(aw.orgNameField('  A   B  ')));
check('blank becomes null, so "not linked" has one representation',
  aw.orgNameField('   ') === null, String(aw.orgNameField('   ')));
check('an over-long name is rejected rather than silently truncated',
  aw.orgNameField('x'.repeat(aw.MAX_ORG_NAME + 1)) === null, 'null');
check('orgNamesInLatest lists the newest week for the form',
  aw.orgNamesInLatest(WEEKS).length === 3, JSON.stringify(aw.orgNamesInLatest(WEEKS)));

// ── The engine ─────────────────────────────────────────────────────────────

section('the discount — only coverage moves');

const VULN = { total: 4, critical: 0, high: 1, medium: 2, low: 1 };
const AWARE = { upload: { total_users: 100, total_incomplete: 10 } };
const MDR = { total_tickets: 40, resolved_count: 38, avg_resolution_hours: 5 };
const ESTATE = { servers: 10, publicAssets: 4, endpoints: 200, cloudTenancies: 1, users: 100 };
const SERVICES = ['mdr', 'vuln', 'awareness'];

function run(mdrCoverage, services) {
  return secureScore.calculateSecureScore(VULN, AWARE, MDR, {
    estate: ESTATE,
    services: services === undefined ? SERVICES : services,
    mdrCoverage,
  });
}

const base = run(undefined);
const linked = run(hit);           // credit 0.70

check('with no vendor input, coverage equals nominal',
  base.coverage === base.coverageNominal,
  base.coverage + '/' + base.coverageNominal);
check('and nothing is discounted',
  base.scope.discountedPoints === 0 && base.scope.discounts.length === 0, 'clean');

check('a 70% reach lowers coverage',
  linked.coverage < linked.coverageNominal,
  linked.coverage + ' < ' + linked.coverageNominal);
check('nominal is unchanged by the discount',
  linked.coverageNominal === base.coverageNominal,
  linked.coverageNominal + ' vs ' + base.coverageNominal);
check('discountedPoints reconciles with the two printed integers',
  linked.scope.discountedPoints === linked.coverageNominal - linked.coverage,
  String(linked.scope.discountedPoints));

/*
 * The arithmetic, checked against the weights the engine actually chose rather
 * than a hardcoded expectation — the weighting is estate-driven and is allowed
 * to change without this test becoming a lie.
 */
const w = linked.weights;
const expected = Math.round((w.vulnerabilities + w.awareness + w.incidentResponse * 0.7) * 100);
check('coverage = round(Σ covered weight, MDR credited at 0.70)',
  linked.coverage === expected, linked.coverage + ' expected ' + expected);

section('everything else is byte-identical');

check('serviceScore is NOT discounted',
  linked.serviceScore === base.serviceScore,
  linked.serviceScore + ' vs ' + base.serviceScore);
check('maxAchievable is untouched — reach is not measurement',
  linked.maxAchievable === base.maxAchievable,
  linked.maxAchievable + ' vs ' + base.maxAchievable);
check('the composite does not move',
  linked.composite === base.composite, linked.composite + ' vs ' + base.composite);
check('nor does overall',
  linked.overall === base.overall, linked.overall + ' vs ' + base.overall);
check('component scores are unchanged',
  linked.vulnScore === base.vulnScore && linked.awarenessScore === base.awarenessScore &&
  linked.mdrScore === base.mdrScore, 'all three');

check('the weights object is not mutated',
  JSON.stringify(linked.weights) === JSON.stringify(base.weights),
  JSON.stringify(linked.weights));
check('and still sums to exactly 1',
  Math.abs((w.vulnerabilities + w.awareness + w.incidentResponse) - 1) < 1e-9,
  String(w.vulnerabilities + w.awareness + w.incidentResponse));

check('uncovered is identical',
  JSON.stringify(linked.scope.uncovered) === JSON.stringify(base.scope.uncovered),
  JSON.stringify(linked.scope.uncovered));
check('blindSpotPoints is identical',
  linked.scope.blindSpotPoints === base.scope.blindSpotPoints, 'same');
check('a discounted MDR client never appears as UNCOVERED',
  !linked.scope.uncovered.some(u => u.key === 'incidentResponse'),
  'absent — they buy MDR');

section('the discount record');

const d = linked.scope.discounts[0];
check('one discount is recorded', linked.scope.discounts.length === 1, 'one');
check('it names the component', d.key === 'incidentResponse', d.key);
check('it carries the vendor and metric',
  d.source === 'Arctic Wolf' && d.metric === 'Coverage Score', d.source + '/' + d.metric);
check('it carries the org and the week, so the figure is attributable',
  d.orgName === 'Reflex Solutions (Pty) Ltd' && d.weekKey === '2026-04-29',
  d.orgName + ' @ ' + d.weekKey);
check('it carries the undiscounted weight, matching the weights object',
  d.weight === w.incidentResponse, String(d.weight));
check('the vendor result is echoed on scope for the page',
  linked.scope.mdrCoverage && linked.scope.mdrCoverage.score === 70,
  JSON.stringify(linked.scope.mdrCoverage && linked.scope.mdrCoverage.score));

section('unavailable and invalid inputs are no-ops');

aw.REASON_LIST.forEach((reason) => {
  const inert = run({ available: false, credit: null, reason });
  check('reason "' + reason + '" leaves coverage at nominal',
    inert.coverage === inert.coverageNominal, inert.coverage + '/' + inert.coverageNominal);
});

[[1.4, 'above 1'], [-0.1, 'below 0'], [NaN, 'NaN'], ['0.7', 'a string'], [null, 'null']]
  .forEach(([credit, label]) => {
    const bad = run({ available: true, credit });
    check('a credit that is ' + label + ' is ignored',
      bad.coverage === bad.coverageNominal, bad.coverage + '/' + bad.coverageNominal);
  });

const zeroCredit = run({ available: true, credit: 0, source: 'Arctic Wolf', metric: 'Coverage Score' });
check('a credit of 0 IS applied — a real zero discounts fully',
  zeroCredit.coverage < zeroCredit.coverageNominal,
  zeroCredit.coverage + ' < ' + zeroCredit.coverageNominal);

section('scope rules survive');

const noMdr = run(hit, ['vuln', 'awareness']);
check('no discount when the client does not buy MDR',
  noMdr.coverage === noMdr.coverageNominal,
  noMdr.coverage + '/' + noMdr.coverageNominal);
check('and no discount is recorded', noMdr.scope.discounts.length === 0, 'none');

const unrecorded = run(hit, null);
check('services unrecorded -> coverage stays NULL',
  unrecorded.coverage === null, String(unrecorded.coverage));
check('and nominal is null too — not recorded is still not none',
  unrecorded.coverageNominal === null, String(unrecorded.coverageNominal));
check('and no discount is claimed', unrecorded.scope.discounts.length === 0, 'none');

// ── Wiring ─────────────────────────────────────────────────────────────────

section('wiring (source-level — Postgres is unreachable here)');

check('server.js requires the module',
  /require\('\.\/lib\/arctic-wolf-coverage'\)/.test(srvCode), 'required');
check('and reads coverage inside loadScoreInputs',
  /coverageForOrg\(/.test(srvCode), 'called');
check('and passes mdrCoverage into the engine',
  /mdrCoverage/.test(srvCode), 'passed');

/*
 * Staff-only, by decision. The weekly report is a global file holding every
 * org's figures, so a portal route that reached it would serve one client
 * another client's operational data.
 */
check('the client portal does NOT reference the module',
  !/arctic-wolf-coverage/.test(portalJs), 'absent from portal-routes.js');
check('nor the org column',
  !/arctic_wolf_org/.test(portalJs), 'absent');

check('the estate column read is guarded by a migration probe',
  /hasEstateArcticWolfColumn/.test(srvCode),
  'unguarded, loadEstate degrades to no-estate and zeroes every client\'s vuln score');

/*
 * BOTH estate SELECTs, not just one. loadEstate feeds the score; the second in
 * buildClientProfile feeds the form. Either naming an unmigrated column takes
 * the whole SELECT down into a catch that reports "no estate declared".
 */
check('both tenant_estate reads use the guard',
  (srvCode.match(/arctic_wolf_org' : 'NULL::text AS arctic_wolf_org/g) || []).length === 2,
  String((srvCode.match(/NULL::text AS arctic_wolf_org/g) || []).length) + ' guarded reads');

check('the estate field is passed to the engine from BOTH call sites',
  (srvCode.match(/mdrCoverage[,:)]/g) || []).length >= 3, 'route and compositeScoreFor');

check('coverageNominal is returned by the route',
  /coverageNominal,/.test(srvCode), 'returned');

check('the profile diff records the org link',
  /'awarenessProgram', 'arcticWolfOrg', 'notes'/.test(srvCode), 'in diffProfile');

check('a name supplied against an unmigrated database is refused, not dropped',
  /migrate-arctic-wolf-org\.sql/.test(serverJs), '503 names the migration');

section('the profile form and the score page');

const profileJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-client-profile.js'), 'utf8');
const scoreJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');
const reportJs  = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-arctic-wolf-org.sql'), 'utf8');

check('the form has the field', /cp-arcticWolfOrg/.test(profileJs), 'present');
check('and sends null rather than an empty string when blank',
  /body\.arcticWolfOrg = \(awOrg && awOrg\.value\.trim\(\)\) \? awOrg\.value\.trim\(\) : null/
    .test(codeOnly(profileJs)), 'null when blank');
check('and shows what the stored name resolves to',
  /arcticWolfCoverage/.test(profileJs), 'match state rendered');

/*
 * Every reason the helper can emit needs copy on the score page. Cross-checked
 * against the exported list, so adding a reason without adding a sentence fails
 * here rather than rendering a blank cell to an analyst.
 */
aw.REASON_LIST.forEach((reason) => {
  check('the Secure Score page has copy for "' + reason + '"',
    new RegExp(reason + ':').test(scoreJs), 'present');
});

check('the score page states the discount arithmetic',
  /ss-scope-discount/.test(scoreJs), 'present');
check('and says outright that the overall score is unaffected',
  /Overall Secure Score is unaffected/.test(scoreJs), 'stated');

check('the board report shows the figure only when one exists',
  /awApplied/.test(codeOnly(reportJs)), 'guarded');
check('and attributes it to Arctic Wolf with the week',
  /Arctic Wolf reports/.test(reportJs) && /week commencing/.test(reportJs), 'attributed');

check('the migration is re-runnable',
  /ADD COLUMN IF NOT EXISTS arctic_wolf_org/.test(migration), 'idempotent');
check('and rejects the empty string so "not linked" has one representation',
  /char_length\(arctic_wolf_org\) BETWEEN 1 AND 200/.test(migration), 'constrained');

done();
