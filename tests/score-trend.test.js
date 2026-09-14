'use strict';

/**
 * What moved the Secure Score — the explanations beside the trend.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   the change is attributed      each component's move, largest first, with the
 *                                 evidence behind it in words
 *   staff reconcile, clients act  points on the composite for staff; NEVER for a
 *                                 client, even if weights are passed by mistake
 *   not recorded is not none      a component with no data is "no data", not a
 *                                 fall to zero; a quiet month is not a missing feed
 *   the figures are the score's   evidence comes from the same cohort and the
 *                                 same month-end rule the score is computed on
 *   the incident filter reaches   the score queries select ticket_type, so
 *   the score                     support tickets stop counting as incidents
 *   the dead rate is gone         loadIncidentRate and incidentRateFrom
 *
 *   node tests/score-trend.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('score-trend');

const ST = require(path.join(ROOT, 'public', 'js', 'score-trend.js'));
const EV = require(path.join(ROOT, 'lib', 'score-evidence.js'));

/** Source with comments removed, so a check cannot pass on a comment. */
function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

const WEIGHTS = { vulnerabilities: 0.40, awareness: 0.35, incidentResponse: 0.25 };

// Newest first, as /api/secure-score/history returns it.
const HISTORY = [
  {
    monthKey: '2026-08', score: 78, vulnScore: 80, awarenessScore: 81, mdrScore: 70, source: 'snapshot',
    evidence: {
      vulnerabilities: { scanMonth: '2026-08', carried: false, critical: 1, high: 4, medium: 9, low: 20 },
      awareness: { assigned: 500, completed: 405, pct: 81 },
      incidentResponse: { raised: 10, resolved: 7, stillOpen: 3, resolutionRate: 70, meanHours: 30, typeFiltered: true },
    },
  },
  {
    monthKey: '2026-07', score: 72, vulnScore: 65, awarenessScore: 80, mdrScore: 75, source: 'snapshot',
    evidence: {
      vulnerabilities: { scanMonth: '2026-07', carried: false, critical: 3, high: 9, medium: 12, low: 22 },
      awareness: { assigned: 480, completed: 384, pct: 80 },
      incidentResponse: { raised: 8, resolved: 6, stillOpen: 2, resolutionRate: 75, meanHours: 12, typeFiltered: true },
    },
  },
];

// ── Staff ──────────────────────────────────────────────────────────────────

section('a month is explained against the one before it');

const staff = ST.explainTrend(HISTORY, { audience: 'staff', weights: WEIGHTS });
const aug = staff[0];

check('one explanation per month after the first', staff.length === 1, staff.length);
check('newest first, like the history it explains', aug.monthKey === '2026-08' && aug.prevMonthKey === '2026-07');
check('the headline change is the score difference', aug.delta === 6, aug.delta);
check('the summary names the direction and the main driver',
  /^Up 6 points, driven by vulnerability management \(\+15\)/.test(aug.summary), aug.summary);
check('and what pulled the other way',
  /partly offset by managed detection and response \(−5\)/.test(aug.summary), aug.summary);

section('each component carries its evidence');

const vuln = aug.drivers.find(d => d.key === 'vulnerabilities');
const mdr = aug.drivers.find(d => d.key === 'incidentResponse');
const aw = aug.drivers.find(d => d.key === 'awareness');

check('the largest contribution leads', aug.drivers[0].key === 'vulnerabilities', aug.drivers.map(d => d.key).join(','));
// −5 × 0.25 = −1.25, which Math.round takes to −1.2 (it rounds half toward +∞).
check('staff see points on the composite: delta × weight',
  vuln.points === 6 && mdr.points === -1.2 && aw.points === 0.4,
  [vuln.points, aw.points, mdr.points].join(' / '));
check('the finding counts are named', /Critical findings 3 → 1, high 9 → 4/.test(vuln.text), vuln.text);
check('training completion is named with its denominator',
  /80% → 81% \(405 of 500 assignments\), with 20 newly assigned/.test(aw.text), aw.text);
check('incidents are named against the month before',
  /10 incidents raised, 7 resolved \(70%\), against 6 of 8 \(75%\)/.test(mdr.text), mdr.text);
check('and the speed change that explains the fall',
  /mean time to resolve 12h → 30h/.test(mdr.text), mdr.text);
check('points reconcile with the headline here, so no note', aug.note === null, aug.note);

// ── Client ─────────────────────────────────────────────────────────────────

section('a client is never shown the weighting');

const client = ST.explainTrend(HISTORY, { audience: 'client' });
const clientRaw = JSON.stringify(client);
check('the same months are explained', client.length === 1 && client[0].summary === aug.summary, client[0].summary);
check('no points on any driver', client[0].drivers.every(d => d.points === null));
check('no "pts" anywhere in the words', !/pts|point.? on the score/i.test(client[0].drivers.map(d => d.text).join(' ')));
check('and no weight', !/weight/i.test(clientRaw));
check('no reconciliation note — it is about the weighting', client[0].note === null);

/*
 * The mistake this guards against is a caller passing the staff options
 * through. The client branch must hold even then.
 */
const leaky = ST.explainTrend(HISTORY, { audience: 'client', weights: WEIGHTS });
check('weights passed with audience client are ignored',
  leaky[0].drivers.every(d => d.points === null), leaky[0].drivers.map(d => d.points).join(','));

// ── Honest gaps ────────────────────────────────────────────────────────────

section('not recorded is not none');

const gap = ST.explainTrend([
  { monthKey: '2026-08', score: 70, vulnScore: 70, awarenessScore: null, mdrScore: 70 },
  { monthKey: '2026-07', score: 60, vulnScore: 55, awarenessScore: 40, mdrScore: 70 },
], { audience: 'staff', weights: WEIGHTS })[0];
const lost = gap.drivers.find(d => d.key === 'awareness');
check('a component with no data this month is "no-data", not a delta', lost.status === 'no-data' && lost.delta === null);
check('and is described as left out, not as a fall to zero',
  /no data this month \(was 40\/100\)/.test(lost.text) && /rather than counted as zero/.test(lost.text), lost.text);
check('the unexplained part of the change is called out, with the reason',
  gap.note && /combined over different components/.test(gap.note), gap.note);

const fresh = ST.explainTrend([
  { monthKey: '2026-08', score: 70, vulnScore: 70, awarenessScore: 90, mdrScore: null },
  { monthKey: '2026-07', score: 70, vulnScore: 70, awarenessScore: null, mdrScore: null },
], { audience: 'client' })[0];
check('a component measured for the first time says so',
  fresh.drivers.some(d => d.status === 'new' && /first measured this month, at 90\/100/.test(d.text)));
check('a component with no data either month is not mentioned at all',
  !fresh.drivers.some(d => d.key === 'incidentResponse'));

const quiet = ST.explainTrend([
  { monthKey: '2026-08', score: 90, vulnScore: 90, awarenessScore: 90, mdrScore: 100,
    evidence: { incidentResponse: { raised: 0, resolved: 0, resolutionRate: null, meanHours: null, typeFiltered: true } } },
  { monthKey: '2026-07', score: 88, vulnScore: 90, awarenessScore: 90, mdrScore: 92,
    evidence: { incidentResponse: { raised: 4, resolved: 3, resolutionRate: 75, meanHours: 6, typeFiltered: true } } },
], { audience: 'client' })[0];
check('a quiet month is described as a quiet month',
  /No incidents were raised this month \(4 the month before\)/.test(quiet.drivers[0].text), quiet.drivers[0].text);

const untyped = ST.explainTrend([
  { monthKey: '2026-08', score: 80, mdrScore: 80,
    evidence: { incidentResponse: { raised: 3, resolved: 3, resolutionRate: 100, meanHours: 2, typeFiltered: false } } },
  { monthKey: '2026-07', score: 80, mdrScore: 80 },
], { audience: 'client' })[0];
check('a feed without ticket types says tickets, not incidents',
  /3 tickets raised/.test(untyped.drivers[0].text), untyped.drivers[0].text);

const carried = ST.explainTrend([
  { monthKey: '2026-08', score: 70, vulnScore: 70,
    evidence: { vulnerabilities: { scanMonth: '2026-07', carried: true, critical: 1, high: 2 } } },
  { monthKey: '2026-07', score: 70, vulnScore: 70,
    evidence: { vulnerabilities: { scanMonth: '2026-07', carried: false, critical: 1, high: 2 } } },
], { audience: 'client' })[0];
check('an unchanged vulnerability score with no new scan says nobody scanned',
  /No new scan; findings carried forward from the 2026-07 scan/.test(carried.drivers[0].text),
  carried.drivers[0].text);
check('and an unchanged month reads as unchanged', carried.summary === 'Unchanged.', carried.summary);

section('bad input degrades, never throws');

check('no history explains nothing', ST.explainTrend(null).length === 0 && ST.explainTrend([]).length === 0);
check('a single month has nothing to compare with', ST.explainTrend([HISTORY[0]]).length === 0);
check('rows with a malformed month are skipped',
  ST.explainTrend([{ monthKey: 'August', score: 1 }, HISTORY[0], HISTORY[1]]).length === 1);
check('an order other than newest-first gives the same answer',
  ST.explainTrend(HISTORY.slice().reverse(), { audience: 'client' })[0].summary === aug.summary);
check('a month with no score is "not comparable", not a change from zero',
  /Not comparable/.test(ST.explainTrend([
    { monthKey: '2026-08', score: null, vulnScore: 70 },
    { monthKey: '2026-07', score: 60, vulnScore: 60 },
  ])[0].summary));

// ── Evidence ───────────────────────────────────────────────────────────────

section('the evidence is counted the way the score is');

const scans = [
  { month_key: '2026-06', summary: { critical: 5, high: 10 } },
  { month_key: '2026-08', summary: { critical: 1, high: 2 } },
];
const julyScan = EV.vulnerabilityEvidence(scans, '2026-07');
check('a month without a scan inherits the most recent earlier one',
  julyScan.scanMonth === '2026-06' && julyScan.carried === true && julyScan.critical === 5, JSON.stringify(julyScan));
check('a month before any scan has no vulnerability evidence', EV.vulnerabilityEvidence(scans, '2026-05') === null);

const sessions = [
  { sent_date: '2026-07-10', completed_date: '2026-07-20' },
  { sent_date: '2026-07-15', completed_date: '2026-08-02' },   // completed after July
  { sent_date: '2026-08-05', completed_date: null },
];
const julyAw = EV.awarenessEvidence(sessions, '2026-07');
check('completion is counted as at the month end',
  julyAw.assigned === 2 && julyAw.completed === 1 && julyAw.pct === 50, JSON.stringify(julyAw));
check('nothing sent yet is null, not 0%', EV.awarenessEvidence(sessions, '2026-06') === null);

const tickets = [
  { created_at: '2026-08-03T10:00:00Z', resolved_at: '2026-08-03T14:00:00Z', ticket_type: 'incident' },
  { created_at: '2026-08-04T10:00:00Z', resolved_at: null,                   ticket_type: 'Incident' },
  { created_at: '2026-08-05T10:00:00Z', resolved_at: '2026-08-20T10:00:00Z', ticket_type: 'support' },
];
const augInc = EV.incidentEvidence(tickets, '2026-08');
check('only incidents are counted — the support request is not a slow incident',
  augInc.raised === 2 && augInc.resolved === 1 && augInc.meanHours === 4, JSON.stringify(augInc));
check('no MDR feed at all is null, not "no incidents"', EV.incidentEvidence([], '2026-08') === null);
check('an existing feed with a quiet month is zero raised',
  EV.incidentEvidence([], '2026-08', { feedExists: true }).raised === 0);

// ── Wiring ─────────────────────────────────────────────────────────────────

section('the server explains every point on the chart');

const server = codeOnly(read('server.js'));
check('the history route attaches evidence to reconstructed months',
  /source:\s*'reconstructed',\s*evidence:\s*evidenceOf\(monthKey\)/.test(server));
check('and to stored snapshots',
  /source:\s*'snapshot',\s*evidence:\s*evidenceOf\(s\.month_key\)/.test(server));
check('snapshot months are reconstructed too, so they have evidence',
  /\.concat\(snapshots\.map\(s => s\.month_key\)\)/.test(server));
check('reconstruction counts awareness through the shared module',
  /scoreEvidence\.awarenessEvidence\(sessions, monthKey\)/.test(server));

section('the incident filter now reaches the score');

/*
 * THE BUG. cohortStats() filters to incidents only when rows carry a type, and
 * both score queries selected created_at and resolved_at alone. The filter saw
 * a feed that never classifies and counted every support and info ticket as an
 * incident — in the live score and in every reconstructed month.
 */
const cohortSelects = server.match(/SELECT t\.created_at, t\.resolved_at[^`]*FROM mdr_tickets t/g) || [];
check('both score queries were found', cohortSelects.length === 2, cohortSelects.length);
check('and both select ticket_type', cohortSelects.every(q => /t\.ticket_type/.test(q)),
  cohortSelects.map(q => q.slice(0, 50)).join(' | '));

section('the dead incident rate is gone');

check('loadIncidentRate() no longer exists', !/loadIncidentRate/.test(server));
check('nor does anything pass incidentRate to the score', !/incidentRate/.test(server));
const ss = require(path.join(ROOT, 'lib', 'secure-score.js'));
check('incidentRateFrom is no longer exported', ss.incidentRateFrom === undefined && ss.RATE_MIN_DATED === undefined);
check('or defined', !/function incidentRateFrom/.test(codeOnly(read('lib', 'secure-score.js'))));

section('the staff tab and the portal use it');

const tab = codeOnly(read('public', 'js', 'tab-secure-score.js'));
check('the tab explains the trend as staff',
  /ScoreTrend\.explainTrend\(history,\s*\{\s*audience:\s*'staff'/.test(tab));
check('on the weights the history was computed on, not the live score\'s',
  /weights:\s*\(historyData && historyData\.weights\)/.test(tab));
check('the tooltip carries the summary', /afterBody:/.test(tab) && /why\.summary/.test(tab));
check('explanations are escaped before they reach the page',
  /esc\(e\.summary\)/.test(tab) && /esc\(d\.text\)/.test(tab));

const html = read('public', 'index.html');
// Matched on the script TAGS: an HTML comment higher up names the tab's file,
// and a bare filename search found that instead.
const trendTag = html.indexOf('<script src="js/score-trend.js"></script>');
const tabTag = html.indexOf('<script src="js/tab-secure-score.js"></script>');
check('the module loads before the tab that uses it',
  trendTag > 0 && tabTag > 0 && trendTag < tabTag, trendTag + ' < ' + tabTag);

const portalRoutes = codeOnly(read('lib', 'portal-routes.js'));
check('the portal explains as a client', /explainTrend\(history,\s*\{\s*audience:\s*'client'\s*\}\)/.test(portalRoutes));
check('and passes on an allowlist that has no points or note',
  /summary:\s*e\.summary,\s*details:\s*e\.drivers\.map\(d => d\.text\)/.test(portalRoutes) &&
  !/points|e\.note/.test((portalRoutes.match(/explainTrend\([\s\S]*?\}\)\);/) || [''])[0]));
check('portal incident counts only use tickets the client can see',
  /FROM mdr_tickets\s+WHERE tenant_id = \$1 AND portal_visible/.test(portalRoutes));
check('the portal escapes what it prints', /P\.esc\(c\.summary\)/.test(read('public', 'portal', 'js', 'portal-score.js')));

done();
