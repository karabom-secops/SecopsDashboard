'use strict';

/**
 * The Firewall Configuration Review screen.
 *
 * WHY THIS SUITE EXISTS
 *
 * The page used to print every check result — findings, not-assessable and
 * every pass — as one flat expanded column. It was complete and unreadable, so
 * the list is now filtered: one outcome at a time, narrowable by severity,
 * category and text, with each result's rationale behind a disclosure.
 *
 * Filtering an audit is where an audit screen gets dangerous. Every assertion
 * below defends one of three properties:
 *
 *   1. Nothing is hidden silently. A narrowed list says how much it is hiding
 *      and offers one click back.
 *   2. "Could not be assessed" cannot disappear. It is the boundary of what we
 *      checked, and a reader who cannot see it assumes those checks passed.
 *   3. Null is not zero, in a score and in a piece of evidence.
 *
 * The module is a browser IIFE, so it is loaded into a vm with a DOM stub and
 * exercised through the seams it exports. The string-building functions are
 * pure, which is most of what matters here.
 *
 *   node tests/firewall-ui.test.js <repoRoot>
 */

const fs = require('fs');
const vm = require('vm');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('firewall-ui');

const SRC = path.join(ROOT, 'public', 'js', 'tab-firewall.js');
const src = fs.readFileSync(SRC, 'utf8');

/** Load the module over a DOM that answers nothing, as the pure seams need. */
function load(overrides) {
  const ctx = {
    window: Object.assign({}, overrides || {}),
    document: {
      querySelector: () => null,
      getElementById: () => null,
      querySelectorAll: () => [],
    },
    fetch: () => Promise.reject(new Error('no network in this suite')),
    console,
  };
  ctx.window.document = ctx.document;
  vm.runInNewContext(src, ctx, { filename: 'tab-firewall.js' });
  return ctx.window.FirewallTab;
}

// ── Fixture ────────────────────────────────────────────────────────────────

function finding(over) {
  return Object.assign({
    checkId: 'chk-1', severity: 'medium', status: 'fail',
    category: 'administrative-access',
    title: 'A title', detail: 'Some detail', rationale: 'Because.',
    remediation: 'Do the thing.', cis: null, source: 'reflex', evidence: null,
  }, over);
}

const FINDINGS = [
  finding({ checkId: 'c1', severity: 'critical', status: 'fail',
            title: 'Admin over HTTP', category: 'administrative-access',
            remediation: 'Disable HTTP on every interface.' }),
  finding({ checkId: 'c2', severity: 'high', status: 'fail',
            title: 'Any/any outbound', category: 'risky-outbound-conditions',
            evidence: { policyIds: [7, 9], interfaces: ['port1', 'port2'] } }),
  finding({ checkId: 'c3', severity: 'low', status: 'fail',
            title: 'Policies unnamed', category: 'policy-attribute' }),
  finding({ checkId: 'c4', severity: 'high', status: 'not-assessable',
            title: 'SSL-VPN cipher suite', category: 'remote-access',
            detail: 'The SSL-VPN settings section is not present in this export.',
            evidence: { section: 'vpn.ssl.settings', section_state: 'absent' } }),
  finding({ checkId: 'c5', severity: 'medium', status: 'pass',
            title: 'Logging to disk enabled', category: 'logging-and-platform' }),
  finding({ checkId: 'c6', severity: 'critical', status: 'pass',
            title: 'No default admin password', category: 'administrative-access' }),
];

const AUDIT = {
  id: 42, score: 68, band: { key: 'fair', label: 'Fair' },
  device: { name: 'HQ-FG100F', model: 'FG100F', firmware: '7.4.3' },
  appearedMasked: true,
  totalChecks: 6, assessed: 5, passed: 2, failed: 3, notAssessable: 1,
  coverage: 83, unreadSections: [], uploadedAt: '2026-09-10T09:00:00Z',
  findings: FINDINGS,
  byCategory: [
    { key: 'administrative-access', label: 'Administrative Access', order: 6,
      score: 50, band: { key: 'fair' }, failed: 1, passed: 1, notAssessable: 0 },
    { key: 'risky-outbound-conditions', label: 'Risky Outbound Conditions', order: 5,
      score: 0, band: { key: 'poor' }, failed: 1, passed: 0, notAssessable: 0 },
    { key: 'policy-attribute', label: 'Policy Attribute', order: 2,
      score: 0, band: { key: 'poor' }, failed: 1, passed: 0, notAssessable: 0 },
    { key: 'remote-access', label: 'Remote Access', order: 8,
      score: null, band: { key: 'unknown' }, failed: 0, passed: 0, notAssessable: 1 },
    { key: 'logging-and-platform', label: 'Logging and Platform', order: 9,
      score: 100, band: { key: 'excellent' }, failed: 0, passed: 1, notAssessable: 0 },
  ],
};

const T = load();

function withFilters(f) {
  T._setAudit(AUDIT);
  T._setFilters(null);            // back to defaults first
  if (f) T._setFilters(f);
  return T._listBlock(AUDIT);
}

// ── 1. Nothing is hidden silently ──────────────────────────────────────────

section('a narrowed list says so, and offers the way back');

const filtered = withFilters({ cat: 'administrative-access' });
check('a category filter reports what it is showing',
  /Showing 1 of 3/.test(filtered), (filtered.match(/Showing \d+ of \d+/) || [])[0]);
check('it names the filter in words, not just a highlighted card',
  filtered.indexOf('Administrative Access') >= 0);
check('and it carries a clear-filters control',
  /id="fw-clear"/.test(filtered));

const sevFiltered = withFilters({ sev: ['critical'] });
check('a severity filter reports the same way',
  /Showing 1 of 3/.test(sevFiltered), (sevFiltered.match(/Showing \d+ of \d+/) || [])[0]);
check('and names the severity it kept', /critical/.test(sevFiltered));

const searched = withFilters({ q: 'unnamed' });
check('a text filter reports the same way',
  /Showing 1 of 3/.test(searched), (searched.match(/Showing \d+ of \d+/) || [])[0]);
check('and quotes the term back', searched.indexOf('unnamed') >= 0);

const unfiltered = withFilters(null);
check('an unfiltered list makes no such claim — there is nothing to disclose',
  !/Showing \d+ of \d+/.test(unfiltered) && !/id="fw-clear"/.test(unfiltered));
check('and it shows every finding of its status',
  (unfiltered.match(/<details class="fw-f/g) || []).length === 3,
  (unfiltered.match(/<details class="fw-f/g) || []).length + ' rows');

const noMatch = withFilters({ q: 'zzzz-no-such-thing' });
check('a filter that matches nothing says nothing matched',
  /Nothing here matches these filters/.test(noMatch));
check('it does NOT read as a clean firewall',
  noMatch.indexOf('Every check that could be evaluated passed') < 0);
check('and it still offers a way out', /id="fw-clear-2"/.test(noMatch));

// The empty-state wording is the one that must never be reached by filtering:
// "everything passed" and "your filter hid everything" are opposite facts.
const trulyClean = (function () {
  const clean = Object.assign({}, AUDIT, {
    findings: FINDINGS.filter(f => f.status !== 'fail'),
  });
  T._setAudit(clean);
  T._setFilters(null);
  return T._listBlock(clean);
})();
check('with no findings at all, the page says every check passed',
  /Every check that could be evaluated passed/.test(trulyClean));

// ── 2. The three outcomes keep equal billing ───────────────────────────────

section('could-not-assess cannot vanish');

T._setAudit(AUDIT);
T._setFilters(null);
const seg = T._segBlock(FINDINGS);

check('all three outcomes are offered',
  /data-status="fail"/.test(seg) && /data-status="not-assessable"/.test(seg) &&
  /data-status="pass"/.test(seg));
check('each carries its count', /Findings <span class="fw-st-n">3<\/span>/.test(seg) &&
  /Could not be assessed <span class="fw-st-n">1<\/span>/.test(seg) &&
  /Passed <span class="fw-st-n">2<\/span>/.test(seg));

// An outcome that only appears when it is non-empty is an outcome nobody can
// confirm was looked at.
const noNa = T._segBlock(FINDINGS.filter(f => f.status !== 'not-assessable'));
check('the not-assessable tab is still rendered when it is empty, at zero',
  /Could not be assessed <span class="fw-st-n">0<\/span>/.test(noNa));

const naList = withFilters({ status: 'not-assessable' });
check('the not-assessable list states it was excluded, not passed',
  /Excluded from the score/.test(naList) && /not passed/.test(naList),
  'caveat present');
check('and tells the reader to confirm on the device',
  /Confirm these on the device/.test(naList));
check('it lists the not-assessable finding',
  naList.indexOf('SSL-VPN cipher suite') >= 0);
check('and no finding of another status leaks into it',
  naList.indexOf('Admin over HTTP') < 0 && naList.indexOf('Logging to disk') < 0);

section('a blocked check explains itself without being opened');

// The symptom this fixes: a screen of "Not assessable / Telnet administration
// is disabled / CIS 1.2" rows, where the title is the least informative part
// and the reason was behind a disclosure nobody had a reason to open.
const naRow = T._findingRow(FINDINGS[3]);
check('a not-assessable row arrives open',
  / open/.test(naRow.split('>')[0]), 'the reason is the content here');
check('and the reason is in it',
  naRow.indexOf('not present in this export') >= 0);

const naFull = withFilters({ status: 'not-assessable' });
check('the tab rolls the reasons up by section',
  /<code>vpn\.ssl\.settings<\/code> was not in the uploaded file/.test(naFull),
  'named section, plain-English state');
check('the rollup counts the checks each reason blocked',
  /1 check</.test(naFull));
check('it says plainly that this describes the file, not the device',
  /describes the uploaded file, not the device/.test(naFull));
check('and it points at the likely causes',
  /single VDOM/.test(naFull) && /policy-only export/.test(naFull));

// A check blocked because one setting was absent is a different diagnosis from
// a whole section missing, and collapsing the two would send someone hunting
// for an export problem that is not there.
const naMixed = (function () {
  const mixed = Object.assign({}, AUDIT, {
    findings: [
      FINDINGS[3],
      finding({ checkId: 'x1', status: 'not-assessable', severity: 'high',
                title: 'Telnet administration is disabled',
                detail: 'admin-telnet is not present in this config.', evidence: null }),
      finding({ checkId: 'x2', status: 'not-assessable', severity: 'medium',
                title: 'Idle timeout', detail: 'admintimeout is not present.', evidence: null }),
    ],
  });
  T._setAudit(mixed);
  T._setFilters({ status: 'not-assessable' });
  return T._listBlock(mixed);
})();
check('a missing setting is reported separately from a missing section',
  /The specific setting was not present in the configuration <span class="fw-why-n">2 checks/.test(naMixed),
  'two settings, one section');
T._setAudit(AUDIT);
T._setFilters(null);

// The rollup answers "what did this file fail to answer", which is a question
// about the audit — a filtered answer to it would understate the gap.
const naNarrowed = withFilters({ status: 'not-assessable', q: 'zzz-no-match' });
check('the rollup survives a filter that empties the list',
  /<code>vpn\.ssl\.settings<\/code>/.test(naNarrowed) &&
  /Nothing here matches these filters/.test(naNarrowed));

section('tab counts');

// Counts on the tabs answer to the other filters, so a tab never promises rows
// that the active search would remove once you got there.
T._setFilters({ q: 'Admin over HTTP' });
const segNarrow = T._segBlock(FINDINGS);
check('tab counts reflect the other filters',
  /Findings <span class="fw-st-n">1<\/span>/.test(segNarrow) &&
  /Passed <span class="fw-st-n">0<\/span>/.test(segNarrow),
  'search narrows every tab count');

// ── 3. Filtering itself ────────────────────────────────────────────────────

section('applyFilters');

const A = T._applyFilters;

check('no filter state returns everything — a missing filter must not match nothing',
  A(FINDINGS, {}).length === 6, A(FINDINGS, {}).length + ' of 6');
check('an undefined state is the same', A(FINDINGS).length === 6);
check('status narrows to that outcome',
  A(FINDINGS, { status: 'pass' }).length === 2);
check('severity narrows within it',
  A(FINDINGS, { status: 'fail', sev: ['critical', 'high'] }).length === 2);
check('an empty severity list means every severity, not none',
  A(FINDINGS, { status: 'fail', sev: [] }).length === 3);
check('category narrows', A(FINDINGS, { cat: 'administrative-access' }).length === 2);

check('search reads the remediation, not only the title',
  A(FINDINGS, { q: 'Disable HTTP on every interface' }).length === 1,
  'a fix is searchable');
check('search reads the evidence values',
  A(FINDINGS, { q: 'port2' }).length === 1, 'interface names are searchable');
check('search reads the category label, not just its key',
  A(FINDINGS, { q: 'Risky Outbound' }).length === 1);
check('search is case-insensitive',
  A(FINDINGS, { q: 'ADMIN OVER HTTP' }).length === 1);
check('a blank search is not a filter',
  A(FINDINGS, { q: '   ' }).length === 6);
check('filters compose',
  A(FINDINGS, { status: 'fail', sev: ['high'], cat: 'risky-outbound-conditions' }).length === 1);
check('and compose to nothing when they disagree',
  A(FINDINGS, { status: 'pass', cat: 'risky-outbound-conditions' }).length === 0);

// ── 4. What opens by default ───────────────────────────────────────────────

section('the rows that are open on arrival');

T._setFilters(null);
const critRow = T._findingRow(FINDINGS[0]);
const lowRow  = T._findingRow(FINDINGS[2]);
const passRow = T._findingRow(FINDINGS[5]);

check('a critical finding arrives open — it is what the analyst came for',
  /<details class="fw-f fw-sev-critical" open/.test(critRow));
check('a low finding arrives closed', !/ open/.test(lowRow.split('>')[0]));
check('a pass arrives closed even at critical severity',
  !/ open/.test(passRow.split('>')[0]), 'a passed critical check is not an action');
check('the summary carries the outcome, severity and title without opening',
  /Finding/.test(critRow) && /critical/.test(critRow) && /Admin over HTTP/.test(critRow));
check('the fix is present for a finding',
  /<strong>Fix:<\/strong>/.test(critRow));
check('and absent for a pass — there is nothing to remediate',
  !/<strong>Fix:<\/strong>/.test(passRow));
check('the rationale is always present',
  /<strong>Why:<\/strong>/.test(critRow) && /<strong>Why:<\/strong>/.test(passRow));

T._setFilters({ expand: 'all' });
check('expand-all opens a row that would be closed',
  / open/.test(T._findingRow(FINDINGS[5]).split('>')[0]));
T._setFilters({ expand: 'none' });
check('collapse-all closes a row that would be open',
  !/ open/.test(T._findingRow(FINDINGS[0]).split('>')[0]));
T._setFilters({ expand: 'auto' });

// ── 5. Null is not zero ────────────────────────────────────────────────────

section('null is not zero');

check('a null evidence value is reported as not recorded, not dropped',
  T._evidenceValue(null) === 'not recorded', T._evidenceValue(null));
check('and never as 0', T._evidenceValue(null) !== 0 && T._evidenceValue(null) !== '0');
check('an array of ids reads as a list, not as JSON',
  T._evidenceValue(['port1', 'port2']) === 'port1, port2',
  T._evidenceValue(['port1', 'port2']));
check('a number stays a number', T._evidenceValue(7) === '7');
check('a camelCase key is humanised', T._evidenceLabel('policyIds') === 'Policy Ids',
  T._evidenceLabel('policyIds'));
check('and a snake_case one', T._evidenceLabel('unused_objects') === 'Unused objects',
  T._evidenceLabel('unused_objects'));

T._setAudit(AUDIT);
T._setHistory([
  { id: 3, score: null, failed: 0, coverage: 0, device: { name: 'New box' },
    uploadedAt: '2026-09-12T09:00:00Z' },
  { id: 2, score: 68, failed: 3, coverage: 83, device: { name: 'HQ-FG100F' },
    uploadedAt: '2026-09-10T09:00:00Z' },
  { id: 1, score: 51, failed: 8, coverage: 80, device: { name: 'HQ-FG100F' },
    uploadedAt: '2026-08-10T09:00:00Z' },
]);
const hist = T._historyBlock();

check('an unscored audit shows n/a, never 0',
  /fw-nd">n\/a</.test(hist) && !/fw-h-score">0/.test(hist));
// `fw-h-d ` with the trailing space: `fw-h-dev` starts with the same letters,
// and counting that instead would have passed no matter what the code did.
const deltas = (hist.match(/class="fw-h-d /g) || []).length;
check('no movement is claimed against a null score', deltas === 1,
  deltas + ' delta(s) across 3 audits — only 68-after-51 is measurable');
check('a real improvement is shown as one',
  /fw-up[^>]*>&uarr;17/.test(hist), '68 after 51');
check('the newest audit is marked', /fw-h-tag">Latest/.test(hist));

// The open audit is identified by id, so the marker lands on the row the reader
// is actually looking at rather than on the newest one.
T._setAudit(Object.assign({}, AUDIT, { id: 2 }));
const histOpen = T._historyBlock();
check('the audit on screen is marked as such',
  (histOpen.match(/fw-h-tag-on">On screen/g) || []).length === 1,
  'exactly one row');
check('and it is the row whose id matches, not the newest',
  histOpen.indexOf('data-audit="2"') < histOpen.indexOf('On screen') &&
  histOpen.indexOf('On screen') < histOpen.indexOf('data-audit="1"'));
T._setAudit(AUDIT);

// ── 6. Guards that must survive an edit ────────────────────────────────────

section('promises the page makes');

check('the no-storage promise is on the collapsed summary, not only inside',
  /fw-up-hint">The file is not stored/.test(src),
  'answerable while the card is shut');
check('and the full explanation is still in the body',
  /<strong>The file is not stored\.<\/strong>/.test(src));

check('deletion is still superadmin-only, not write-gated',
  /function canDelete\(\)\s*\{[\s\S]*?role === 'superadmin'/.test(src) &&
  !/function canDelete\(\)\s*\{[\s\S]*?canWrite/.test(src));

check('the headline score still refuses to print 0 for "not assessed"',
  /a\.score == null[\s\S]{0,80}Not assessed/.test(src));
check('a category with nothing assessable still reads n\\/a',
  /c\.score == null[\s\S]{0,60}n\/a/.test(src));

// The search box must survive its own keystrokes: re-rendering the input while
// somebody is typing in it takes the caret out, which is how the old full
// re-render made the field unusable past one character.
const refresh = (src.match(/function refreshList\(\)[\s\S]*?\n  \}/) || [])[0] || '';
check('refreshList() exists', refresh !== '');
check('it refreshes the list and the counted controls',
  /fw-list/.test(refresh) && /fw-seg/.test(refresh) && /fw-chips/.test(refresh));
check('and never rebuilds the search input', !/fw-q/.test(refresh),
  'the caret stays where the user put it');

// Switching outcome must not leave an invisible severity filter behind: the
// chips are counted per tab, so a severity present in one and absent in the
// next would hide every row with no chip left on screen to explain it.
const stHandler = (src.match(/_status = b\.dataset\.status;[\s\S]*?\}/) || [])[0] || '';
check('changing outcome clears the severity chips', /_sev = \[\]/.test(stHandler));

// Per-function, not a search of the whole file: both of these assign
// `_audit = j.audit`, so a file-wide regex passes on either one's reset and
// proves nothing about the other.
const openFn = (src.match(/async function openAudit\([\s\S]*?\n  \}\n/) || [])[0] || '';
const uploadFn = (src.match(/async function doUpload\([\s\S]*?\n  \}\n/) || [])[0] || '';
check('openAudit() is defined', openFn !== '' && openFn.indexOf('doUpload') < 0);
check('opening a different audit resets the filters',
  /resetFilters\(\)/.test(openFn), 'another audit is another set of findings');
check('and so does a fresh upload', /resetFilters\(\)/.test(uploadFn));

done();
