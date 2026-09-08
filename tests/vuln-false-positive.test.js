'use strict';

/**
 * False-positive vulnerability status, and the score actually moving.
 *
 * TWO DEFECTS, ONE CHANGE
 *
 * 1. A scanner finding that is not real had nowhere to go. open and
 *    in-progress claim a live risk; `fixed` claims we changed something when
 *    there was nothing to change; `accepted` is worst of all — it puts an
 *    imaginary risk on the acceptance register, so a board reviewing accepted
 *    risk reviews something that never existed. Analysts left them open, and
 *    the score carried findings that were not there.
 *
 * 2. Marking ANY finding closed did not move the Secure Score. The score reads
 *    vuln_scans.summary, which was computed once at upload and never again —
 *    computeVulnSummary() was called in exactly one place. The arithmetic was
 *    already right (fixed and accepted leave the counts); nothing re-ran it. An
 *    analyst could spend a week closing findings and watch the number sit
 *    still, which reads as the tracker being decorative.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   a false positive leaves the active counts     it was never a risk
 *   and is NOT the same as accepted               one is a correction to the
 *                                                 data, the other a live risk
 *                                                 somebody signed off
 *   the score genuinely improves                  including lifting the
 *                                                 critical cap
 *   the API and the CHECK constraint agree        one status list, both places
 *   status change and summary rebuild are atomic  they can never disagree
 *   a closed finding stops its SLA clock          and stays out of the portal
 *
 *   node tests/vuln-false-positive.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('vuln-false-positive');

const parser = require(path.join(ROOT, 'lib', 'vuln-parser'));
const SS = require(path.join(ROOT, 'lib', 'secure-score'));
const estateLib = require(path.join(ROOT, 'lib', 'estate'));

const serverJs   = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const migration  = fs.readFileSync(path.join(ROOT, 'db', 'migrate-vuln-false-positive.sql'), 'utf8');
const indexHtml  = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const vulnsJs    = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-vulns.js'), 'utf8');
const trackerJs  = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-remediation-tracker.js'), 'utf8');
const portalJs   = fs.readFileSync(path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');
const sectionsJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlOnly(sql) { return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1'); }

const f = (risk, status, i) => ({
  pluginId: 'p' + i, name: 'n' + i, risk, host: 'h' + (i % 4), port: '443', status,
});

// ── The counts ─────────────────────────────────────────────────────────────

section('a false positive leaves the active counts');

const allOpen = parser.computeVulnSummary([
  f('Critical', 'open', 1), f('High', 'open', 2), f('Medium', 'open', 3),
]);
const oneFp = parser.computeVulnSummary([
  f('Critical', 'false-positive', 1), f('High', 'open', 2), f('Medium', 'open', 3),
]);

check('the critical is counted while open',
  allOpen.critical === 1, String(allOpen.critical));
check('and is NOT counted once marked a false positive',
  oneFp.critical === 0, String(oneFp.critical));
check('the active total drops by exactly one',
  oneFp.activeTotal === allOpen.activeTotal - 1,
  allOpen.activeTotal + ' -> ' + oneFp.activeTotal);
check('the other findings are untouched',
  oneFp.high === 1 && oneFp.medium === 1, oneFp.high + '/' + oneFp.medium);

section('but it is NOT the same thing as an accepted risk');

const accepted = parser.computeVulnSummary([
  f('Critical', 'accepted', 1), f('High', 'open', 2), f('Medium', 'open', 3),
]);

check('both leave the score arithmetic alone in the same way',
  accepted.activeTotal === oneFp.activeTotal, String(accepted.activeTotal));
/*
 * ...and that is exactly why they have to be distinguishable elsewhere. An
 * acceptance is a live risk somebody signed off and belongs on the acceptance
 * register; a false positive is a correction to our data and belongs nowhere.
 * Reporting them alike would let a client accept their way to a clean score and
 * a board would not be able to tell the difference.
 */
check('but statusCounts keeps them apart',
  oneFp.statusCounts['false-positive'] === 1 && oneFp.statusCounts.accepted === 0 &&
  accepted.statusCounts.accepted === 1 && accepted.statusCounts['false-positive'] === 0,
  JSON.stringify(oneFp.statusCounts));
check('and every status has a bucket, so none can go unreported',
  ['open', 'in-progress', 'fixed', 'accepted', 'false-positive']
    .every(k => oneFp.statusCounts[k] !== undefined),
  Object.keys(oneFp.statusCounts).join(','));

// ── The score genuinely improves ───────────────────────────────────────────

section('THE POINT — the Secure Score improves');

const estate = estateLib.resolveEstate({}, { publicAssets: 4, scannedHosts: 4 });
const scoreWith = (critStatus) => {
  const findings = [
    f('Critical', critStatus, 1), f('High', 'open', 2), f('High', 'open', 3),
    f('Medium', 'open', 4), f('Medium', 'open', 5), f('Low', 'open', 6),
  ];
  const summary = parser.computeVulnSummary(findings);
  return SS.calculateSecureScore(
    { summary },
    { upload: { total_users: 100, total_incomplete: 10 } },
    { total_tickets: 40, resolved_count: 38, avg_resolution_hours: 5 },
    { estate, services: ['mdr', 'vuln', 'awareness'] });
};

const before = scoreWith('open');
const after  = scoreWith('false-positive');

check('the vulnerability component rises',
  after.vulnScore > before.vulnScore,
  before.vulnScore + ' -> ' + after.vulnScore);
check('and so does the composite',
  after.composite > before.composite,
  before.composite + ' -> ' + after.composite);

/*
 * The case that matters most. One open critical caps the vulnerability score
 * regardless of everything else, so a single false positive can hold a client
 * down by a dozen points until somebody uploads a new scan.
 */
check('classifying the only critical lifts the critical cap',
  after.vulnScore - before.vulnScore >= 10,
  'gained ' + (after.vulnScore - before.vulnScore) + ' points');

check('fixing it gives the same improvement as calling it a false positive',
  scoreWith('fixed').vulnScore === after.vulnScore,
  scoreWith('fixed').vulnScore + ' vs ' + after.vulnScore);

// ── The summary is rebuilt on a status change ──────────────────────────────

section('the summary is rebuilt when a status changes');

const srv = codeOnly(serverJs);

check('a shared resync helper exists',
  /function resyncVulnSummary\(/.test(srv), 'present');
check('it rebuilds through the SAME function the upload path uses',
  /resyncVulnSummary[\s\S]{0,1400}computeVulnSummary\(findings\)/.test(srv),
  'one implementation');
check('and writes the result back to vuln_scans.summary',
  /UPDATE vuln_scans SET summary = \$1 WHERE id = \$2/.test(srv), 'stored');

// `await` anchors this to actual CALLS — the function's own declaration
// contains the same text and was otherwise counted as a third.
check('both endpoints resync',
  (srv.match(/await resyncVulnSummary\(client, scanId\)/g) || []).length === 2,
  (srv.match(/await resyncVulnSummary\(client, scanId\)/g) || []).length + ' call sites');

/*
 * Atomic, because a crash between the two writes would leave the findings
 * saying one thing and the score reading another, with nothing to reconcile
 * them until the next upload — which is the drift this rebuild exists to end.
 */
check('both updates run inside a transaction',
  (srv.match(/BEGIN'\)[\s\S]{0,900}resyncVulnSummary[\s\S]{0,200}COMMIT/g) || []).length === 2,
  'status change and rebuild commit together');
check('and roll back together',
  (srv.match(/ROLLBACK/g) || []).length >= 2, 'guarded');

// ── One status list ────────────────────────────────────────────────────────

section('the API and the database agree on the status list');

check('the API uses one shared list',
  /const VULN_STATUSES = \[/.test(srv), 'defined once');
check('both endpoints validate against it',
  (srv.match(/VULN_STATUSES\.includes\(status\)/g) || []).length === 2,
  (srv.match(/VULN_STATUSES\.includes\(status\)/g) || []).length + ' validators');
check('no endpoint still carries a hardcoded status list',
  !/\['open', 'in-progress', 'fixed', 'accepted'\]\.includes\(status\)/.test(srv),
  'none');

const sql = sqlOnly(migration);
check('the migration widens the CHECK constraint',
  /CHECK \(status IN \('open', 'in-progress', 'fixed', 'accepted', 'false-positive'\)\)/.test(sql),
  'widened');
check('and drops the old one first, so it is re-runnable',
  /DROP CONSTRAINT IF EXISTS vuln_findings_status_chk/.test(sql), 'idempotent');

/*
 * The two lists must contain the same statuses. A status the API accepts and
 * the database rejects is a 500 on a button click; the reverse is a value that
 * can exist in the table and be rejected on the next edit.
 */
const apiList = (srv.match(/const VULN_STATUSES = \[([^\]]+)\]/) || [])[1] || '';
const apiSet = apiList.split(',').map(x => x.trim().replace(/^'|'$/g, '')).filter(Boolean).sort();
const sqlSet = ((sql.match(/CHECK \(status IN \(([^)]+)\)\)/) || [])[1] || '')
  .split(',').map(x => x.trim().replace(/^'|'$/g, '')).filter(Boolean).sort();
check('the API list and the CHECK constraint match exactly',
  apiSet.length === 5 && apiSet.join('|') === sqlSet.join('|'),
  apiSet.join(',') + '  vs  ' + sqlSet.join(','));

// ── Everything downstream treats it as closed ──────────────────────────────

section('a false positive is closed everywhere');

check('the SLA clock stops',
  /s === 'open' \|\| s === 'in-progress'/.test(codeOnly(vulnsJs)),
  'only open and in-progress are active');
check('the client portal never counts it',
  /status IN \('open', 'in-progress'\)/.test(portalJs), 'gated');
check('nor does the board report',
  /VULN_OPEN_STATUSES = \{ open: 1, 'in-progress': 1 \}/.test(codeOnly(sectionsJs)),
  'gated');

section('it is offered and labelled in the UI');

check('the finding detail dropdown offers it',
  /<option value="false-positive"/.test(indexHtml), 'present');
check('the bulk status dropdown offers it',
  (indexHtml.match(/<option value="false-positive"/g) || []).length === 2,
  (indexHtml.match(/<option value="false-positive"/g) || []).length + ' dropdowns');
check('the vulnerabilities tab labels it',
  /'false-positive': 'False Positive'/.test(vulnsJs), 'labelled');
check('and offers it as a filter',
  /key: 'false-positive'/.test(vulnsJs), 'filterable');
check('the remediation tracker offers it',
  /\['false-positive', 'False Positive'\]/.test(trackerJs), 'present');

/*
 * Neutral styling, not green. Nothing about the estate improved — the data was
 * corrected — and a green pill would read as a remediation somebody performed.
 */
check('it is styled neutrally rather than as a win',
  /\.chip-st-false-positive\b/.test(
    fs.readFileSync(path.join(ROOT, 'public', 'css', 'styles.css'), 'utf8')),
  'distinct style');

done();
