'use strict';

/**
 * One cohort: the tickets RAISED in the reporting month.
 *
 * THE DEFECT THIS EXISTS FOR
 *
 * Three parts of the product measured "MDR performance this month" over three
 * different populations, and on one feed they produced 78, 62 and 95 for the
 * same August:
 *
 *   the Secure Score      read mdr_uploads.total_tickets — the WHOLE uploaded
 *                         CSV, with no period at all. A client who exported two
 *                         years of history was scored on two years of it, and a
 *                         strong recent month could not move the number.
 *   the report KPI table  counted tickets raised in the month against tickets
 *                         RESOLVED in the month — two cohorts. A June ticket
 *                         closed in August put June's duration into August's
 *                         mean, and the old "resolution rate" reached 125%
 *                         because the numerator was not a subset of the
 *                         denominator.
 *   the trend chart       counted cumulatively to each month end, so the line
 *                         flattened the longer a client stayed with us.
 *
 * The first two printed on the same slide as each other.
 *
 * The rule now lives once, in public/js/mdr-metrics.js, loaded by the browser
 * with a <script> tag and by server.js with require() — the ir-playbooks-data.js
 * pattern, for the same reason.
 *
 *   node tests/mdr-cohort.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('mdr-cohort');

const M  = require(path.join(ROOT, 'public', 'js', 'mdr-metrics'));
const SS = require(path.join(ROOT, 'lib', 'secure-score'));

const serverJs = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const srvCode = codeOnly(serverJs);

/*
 * One feed covering four months, with every boundary case in it:
 *   a) raised July, resolved August    — must NOT count for August
 *   b) raised + resolved inside August — counts
 *   c) raised + resolved inside August — counts
 *   d) raised 30 Aug, resolved 2 Sep   — counts for August, resolved
 *   e) raised 31 Aug, never resolved   — counts for August, still open
 *   f) raised + resolved in May        — history, counts for neither
 */
const FEED = [
  { createdAt: '2026-07-28T08:00:00Z', resolvedAt: '2026-08-02T08:00:00Z' },
  { createdAt: '2026-08-03T08:00:00Z', resolvedAt: '2026-08-04T08:00:00Z' },
  { createdAt: '2026-08-10T08:00:00Z', resolvedAt: '2026-08-11T08:00:00Z' },
  { createdAt: '2026-08-30T08:00:00Z', resolvedAt: '2026-09-02T08:00:00Z' },
  { createdAt: '2026-08-31T08:00:00Z', resolvedAt: null },
  { createdAt: '2026-05-01T08:00:00Z', resolvedAt: '2026-05-02T08:00:00Z' },
];

// ── The cohort ─────────────────────────────────────────────────────────────

section('a month means the tickets raised in it');

const aug = M.cohortStats(FEED, '2026-08');

check('the cohort is what was raised, not what was closed',
  aug.raised === 4, aug.raised + ' of ' + FEED.length + ' tickets in the feed');
check('a ticket raised in July and closed in August is not August\'s',
  M.raisedIn(FEED, '2026-08').every(t => t.createdAt.indexOf('2026-08') === 0),
  M.raisedIn(FEED, '2026-08').map(t => t.createdAt.slice(0, 10)).join(' '));
check('and older history is not counted at all',
  aug.raised + M.cohortStats(FEED, '2026-07').raised +
  M.cohortStats(FEED, '2026-05').raised === FEED.length,
  'every ticket lands in exactly one month');

check('a ticket raised in the month and closed after it still counts as resolved',
  aug.resolved === 3, aug.resolved + ' resolved');
check('one is still open', aug.stillOpen === 1, aug.stillOpen);
check('resolved and still-open account for the whole cohort',
  aug.resolved + aug.stillOpen === aug.raised,
  aug.resolved + ' + ' + aug.stillOpen + ' = ' + aug.raised);

// ── The rate ───────────────────────────────────────────────────────────────

section('the rate is a real fraction, because it has one denominator');

check('it is resolved over raised', aug.resolutionRate === 75, aug.resolutionRate + '%');

/*
 * THE 125% CASE. Under the old definition a month that cleared a backlog had a
 * numerator drawn from a wider population than its denominator. Here every
 * July ticket closes in August, and August's rate still cannot pass 100.
 */
const backlog = M.cohortStats([
  { createdAt: '2026-07-01T00:00:00Z', resolvedAt: '2026-08-01T00:00:00Z' },
  { createdAt: '2026-07-02T00:00:00Z', resolvedAt: '2026-08-01T00:00:00Z' },
  { createdAt: '2026-07-03T00:00:00Z', resolvedAt: '2026-08-01T00:00:00Z' },
  { createdAt: '2026-08-05T00:00:00Z', resolvedAt: '2026-08-06T00:00:00Z' },
], '2026-08');
check('clearing a backlog cannot push the rate above 100',
  backlog.resolutionRate === 100 && backlog.raised === 1,
  backlog.resolutionRate + '% of ' + backlog.raised + ' raised');

/*
 * null, not 0. A month in which nothing was raised has no rate; printing 0%
 * would read on a board pack as total failure in a month where the service had
 * nothing to do.
 */
const quiet = M.cohortStats(FEED, '2026-06');
check('a month with no tickets has no rate at all',
  quiet.resolutionRate === null && quiet.raised === 0, String(quiet.resolutionRate));

// ── The timings ────────────────────────────────────────────────────────────

section('durations are drawn from the same cohort');

/*
 * The old code timed the RESOLVED-in-month set, so a June ticket closed in
 * August contributed June's duration to August's mean. Here the July ticket
 * took 125 hours and must not appear.
 */
check('the July ticket\'s 125 hours are not in August\'s mean',
  aug.meanHours === (24 + 24 + 72) / 3, aug.meanHours + ' hrs');
check('the median is the middle of the cohort\'s durations',
  aug.medianHours === 24, aug.medianHours + ' hrs');
check('only resolutions that could be timed are counted',
  aug.measuredHours === 3, aug.measuredHours + ' of ' + aug.resolved + ' resolutions timed');

// Friday 17:05 to Monday 09:00. Three days less 8h05m = 63h55m = 63.9167 hrs.
// Under the business-hours model this repo removed, it was about one hour.
const weekend = M.elapsedHours('2026-03-06T17:05:00Z', '2026-03-09T09:00:00Z');
check('elapsed hours span nights and weekends',
  Math.abs(weekend - (72 - 8 - 5 / 60)) < 1e-9, weekend + ' hrs');
// A resolution stamped before creation is a feed error, and averaging it in
// would pull a real mean below zero.
check('a resolution before creation is unmeasurable, not negative',
  M.elapsedHours('2026-08-02T00:00:00Z', '2026-08-01T00:00:00Z') === null);
check('an unparseable stamp is unmeasurable', M.elapsedHours('not a date', '2026-08-01') === null);
check('and a missing one is too', M.elapsedHours(null, '2026-08-01') === null);

// ── The field-name trap ────────────────────────────────────────────────────

section('camelCase and snake_case are the same tickets');

/*
 * /api/mdr aliases its columns to camelCase for the browser; the server's own
 * query returns snake_case. This module is fed by both. Reading only one shape
 * would have made every server-side cohort silently EMPTY — the worst failure
 * available here, because an empty cohort scores 100 rather than erroring.
 */
const snake = FEED.map(t => ({ created_at: t.createdAt, resolved_at: t.resolvedAt }));
check('the two shapes produce identical statistics',
  JSON.stringify(M.cohortStats(snake, '2026-08')) === JSON.stringify(aug),
  JSON.stringify(M.cohortStats(snake, '2026-08')));

// pg hands back Date objects, not strings.
const dates = FEED.map(t => ({
  created_at: new Date(t.createdAt),
  resolved_at: t.resolvedAt ? new Date(t.resolvedAt) : null,
}));
check('and so do real Date objects, which is what pg returns',
  JSON.stringify(M.cohortStats(dates, '2026-08')) === JSON.stringify(aug));

check('junk in the feed is skipped rather than thrown on',
  M.cohortStats([null, 'x', 42, {}, ...FEED], '2026-08').raised === 4);

// ── Incidents only ─────────────────────────────────────────────────────────

section('only tickets typed "incident" are measured');

/*
 * The feed carries more than incidents — ticket_type is documented as
 * "incident, info, support, etc." and IRIS adds 'dfir_case'. A support request
 * answered in a week is not a slow incident response, and the 168-hour one
 * below is there to prove it cannot reach the mean.
 */
const MIXED = [
  { createdAt: '2026-08-03T08:00:00Z', resolvedAt: '2026-08-04T08:00:00Z', ticketType: 'incident' },
  { createdAt: '2026-08-10T08:00:00Z', resolvedAt: '2026-08-11T08:00:00Z', ticketType: 'Incident' },
  { createdAt: '2026-08-12T08:00:00Z', resolvedAt: '2026-08-19T08:00:00Z', ticketType: 'support' },
  { createdAt: '2026-08-14T08:00:00Z', resolvedAt: null,                   ticketType: 'info' },
  { createdAt: '2026-08-15T08:00:00Z', resolvedAt: null,                   ticketType: null },
  { createdAt: '2026-08-20T08:00:00Z', resolvedAt: '2026-08-21T08:00:00Z', ticketType: 'dfir_case' },
];
const mixed = M.cohortStats(MIXED, '2026-08');

check('only the incidents are counted', mixed.raised === 2, mixed.raised + ' of 6 tickets');
check('casing does not matter — the CSV path stores the column verbatim',
  mixed.raised === 2, "'Incident' and 'incident' both counted");
check('snake_case ticket_type works too, which is what pg returns',
  M.cohortStats(MIXED.map(t => ({
    created_at: t.createdAt, resolved_at: t.resolvedAt, ticket_type: t.ticketType,
  })), '2026-08').raised === 2);

/*
 * The point of the filter. The support ticket took 168 hours; leaving it in
 * would have put the mean at 72 and cost real points through the speed penalty.
 */
check('a week-long support ticket cannot reach the incident mean',
  mixed.meanHours === 24, mixed.meanHours + ' hrs, not 72');
check('nor can a dfir_case or an info ticket',
  mixed.resolved === 2 && mixed.stillOpen === 0,
  mixed.resolved + ' resolved, ' + mixed.stillOpen + ' open');

/*
 * WHAT WAS DROPPED IS REPORTED. If a tenant's feed labels incidents something
 * other than 'incident', every cohort empties and the score reads 100 —
 * indistinguishable from a spotless month. The counts are what make that
 * visible rather than silently wrong.
 */
check('the excluded tickets are counted', mixed.excluded === 4, mixed.excluded);
check('and named by type, so a mislabelled feed is obvious',
  JSON.stringify(mixed.excludedTypes) ===
  JSON.stringify({ support: 1, info: 1, unclassified: 1, dfir_case: 1 }),
  JSON.stringify(mixed.excludedTypes));
check('a blank type in a classifying feed is unclassified, not an incident',
  mixed.excludedTypes.unclassified === 1);

const wrongLabel = M.cohortStats(
  MIXED.map(t => Object.assign({}, t, { ticketType: 'security_incident' })), '2026-08');
check('a feed that labels incidents differently reports every ticket as excluded',
  wrongLabel.raised === 0 && wrongLabel.excluded === 6 &&
  wrongLabel.excludedTypes.security_incident === 6,
  JSON.stringify(wrongLabel.excludedTypes));

section('a feed with no ticket types at all is not silently perfect');

/*
 * THE GUARD. An empty cohort scores 100, correctly, because a month with no
 * incidents is a quiet month. But a feed carrying NO type information filters
 * to empty every time, and that would read as a flawless MDR service rather
 * than as a filter that could not be applied.
 *
 * Dormant in practice — tickets arrive through the Arctic Wolf integration,
 * which always sets a type. This is for the CSV path, where the "Ticket Type"
 * column is optional.
 */
const UNTYPED = MIXED.map(t => ({ createdAt: t.createdAt, resolvedAt: t.resolvedAt }));
const untyped = M.cohortStats(UNTYPED, '2026-08');

check('the feed is recognised as not classifying', M.feedClassifies(UNTYPED) === false);
check('and the filter is reported as not applied', untyped.typeFiltered === false);
check('so every ticket is counted rather than none',
  untyped.raised === 6, untyped.raised);
// Scored inline rather than through the scoreOf() helper further down: this
// file's own header records a `const` declared beside its section putting an
// earlier one in a temporal dead zone and crashing the suite on load.
const untypedScore = SS.calculateMdrScore({ upload: M.scoreInput(untyped) });
check('which is the difference between a real score and a silent 100',
  untypedScore !== 100, 'scores ' + untypedScore + ', not 100');
check('a classifying feed is flagged as filtered', mixed.typeFiltered === true);

// The whole feed decides, not the month: a month whose tickets happen to be
// untyped must not degrade open while the rest of the feed is filtered.
const oneBlankMonth = M.cohortStats(MIXED.concat([
  { createdAt: '2026-09-01T08:00:00Z', resolvedAt: null, ticketType: null },
]), '2026-09');
check('a month of blanks inside a classifying feed still filters',
  oneBlankMonth.typeFiltered === true && oneBlankMonth.raised === 0 &&
  oneBlankMonth.excluded === 1,
  'excluded ' + JSON.stringify(oneBlankMonth.excludedTypes));

// ── The window ─────────────────────────────────────────────────────────────

section('the score window is the last COMPLETE month');

check('mid-month, that is the month before',
  M.lastCompleteMonth('2026-09-09T10:00:00Z') === '2026-08',
  M.lastCompleteMonth('2026-09-09T10:00:00Z'));
check('on the first of a month, still the month before',
  M.lastCompleteMonth('2026-09-01T00:00:00Z') === '2026-08');
// The rollover that an off-by-one month arithmetic gets wrong.
check('January looks back into the previous year',
  M.lastCompleteMonth('2026-01-15T00:00:00Z') === '2025-12',
  M.lastCompleteMonth('2026-01-15T00:00:00Z'));

/*
 * The current month to date was rejected: on the 1st it would score a handful
 * of tickets or none, which is the volatility the weighting change removed.
 * This asserts the window never includes today's own month.
 */
const todayKey = new Date().toISOString().slice(0, 7);
check('the window never includes the month in progress',
  M.lastCompleteMonth(new Date()) < todayKey,
  M.lastCompleteMonth(new Date()) + ' < ' + todayKey);

// ── Feeding the score ──────────────────────────────────────────────────────

section('the score is computed from the cohort');

const scoreOf = (stats) => SS.calculateMdrScore({ upload: M.scoreInput(stats) });

check('the cohort scores lower than the whole feed did',
  scoreOf(aug) === 62, scoreOf(aug));
check('and the whole feed used to score higher, which is the bug',
  SS.calculateMdrScore({ upload: { total_tickets: 6, resolved_count: 5,
                                  avg_resolution_hours: 30 } }) === 78,
  'whole-upload score was 78');

/*
 * A QUIET MONTH IS A GOOD MONTH, NOT AN UNMEASURED ONE. calculateMdrScore
 * returns 100 for a period with no tickets. That is only correct because the
 * upload row is checked separately for `measured` — a client with no MDR feed
 * at all must still score 0 and be labelled unmeasured.
 */
check('a month with no tickets scores 100', scoreOf(quiet) === 100, scoreOf(quiet));
check('but a client with no feed at all is unmeasured, not perfect',
  SS.calculateMdrScore(null) === 0 && SS.isMdrMeasured(null) === false,
  'no upload -> 0 and unmeasured');
check('while an upload with a quiet month IS measured',
  SS.isMdrMeasured({ upload: M.scoreInput(quiet) }) === true);

check('scoreInput reports no timings as no penalty, not as zero hours slow',
  M.scoreInput(quiet).avg_resolution_hours === 0 &&
  M.scoreInput(aug).avg_resolution_hours === aug.meanHours,
  JSON.stringify(M.scoreInput(aug)));

// ── One implementation, both runtimes ──────────────────────────────────────

section('the server and the browser share one definition');

check('the browser loads it', /<script src="js\/mdr-metrics\.js">/.test(indexHtml));
check('and loads it before the section that uses it',
  indexHtml.indexOf('js/mdr-metrics.js') < indexHtml.indexOf('js/report-sections.js'),
  'mdr-metrics.js first');
check('the server requires the same file',
  /require\('\.\/public\/js\/mdr-metrics'\)/.test(srvCode), 'one file');

/*
 * The two places the server computes an MDR figure. Both must go through the
 * module — a second copy is how the three populations came about.
 */
check('the live score is built from a cohort',
  /mdrMetrics\.cohortStats\(/.test(srvCode) &&
  /mdrMetrics\.lastCompleteMonth\(/.test(srvCode), 'wired');
check('and so is every reconstructed month of the trend',
  (srvCode.match(/mdrMetrics\.cohortStats\(/g) || []).length >= 2,
  (srvCode.match(/mdrMetrics\.cohortStats\(/g) || []).length + ' call sites');

// The two things the old code did, gone rather than merely bypassed.
check('the score no longer reads the whole upload\'s ticket total',
  !/total_tickets:\s*raised\.length/.test(srvCode), 'removed');
check('and the trend no longer counts tickets cumulatively to a month end',
  !/created_at\)\.toISOString\(\) <= end/.test(srvCode), 'removed');

/*
 * The window has to be visible. The component used to cover however much CSV
 * somebody exported, and a figure whose period is invisible is one a client
 * cannot check.
 */
check('the API says which month the component covers',
  /period: mdrData \? mdrData\.period : null/.test(srvCode), 'exposed');

done();
