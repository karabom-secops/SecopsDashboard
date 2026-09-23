'use strict';

/**
 * The Managed Email Security screen.
 *
 * WHY THIS SUITE EXISTS
 *
 * The page was one long column: eight stat cards, two paragraphs of caveat, a
 * chart, five stacked breakdowns, then up to two hundred alert rows with no
 * filter, no search and no way to read a clipped subject. The question an
 * analyst opens the tab with — "did anything reach a mailbox, and whose?" — was
 * a dead number near the top, and the answer was somewhere in those rows.
 *
 * Meanwhile /api/email/alerts had taken threatClass, disposition and severity
 * parameters since it was written, and nothing had ever sent one.
 *
 * What is held here:
 *
 *   1. Nothing is truncated silently. A capped list says it is capped; a search
 *      says how much it hid; a filtered list says it is filtered.
 *   2. A client that has never been collected shows NO figures — eight zeros
 *      would be a claim about their mail that nothing was read to support.
 *   3. The filters reach the server, including the two values that are NULL in
 *      the database and would silently match nothing as equality tests.
 *   4. Attacker-authored text stays escaped in the places the redesign added:
 *      the expanded row, which now prints the full subject.
 *
 *   node tests/email-ui.test.js <repoRoot>
 */

const fs = require('fs');
const vm = require('vm');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('email-ui');

const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');
const tabJs = read('public', 'js', 'tab-email.js');

const sandbox = { console };
sandbox.window = sandbox;
sandbox.document = {
  getElementById: () => null,
  querySelectorAll: () => [],
  querySelector: (s) => (s === 'base' ? { href: 'https://secops.reflex.co.za/secops/' } : null),
};
vm.createContext(sandbox);
vm.runInContext(tabJs, sandbox);
const ET = sandbox.window.EmailTab;

const SUMMARY = {
  windowDays: 30,
  threats: { total: 431, classified: 400, unclassified: 31, targetedUsers: 22, senderDomains: 40 },
  containment: { contained: 380, delivered: 3, remediated: 5, knownDisposition: 388,
                 unknownDisposition: 43, rate: 97.9, coverage: 90 },
  byClass: [{ label: 'phishing', count: 300 }, { label: 'unclassified', count: 31 }],
  byDisposition: [{ label: 'blocked', count: 380 }, { label: 'unknown', count: 43 }],
  bySeverity: [{ label: 'high', count: 12 }],
  topSenderDomains: [{ label: 'evil.example', count: 9 }],
  topRecipients: [{ label: 'a@b.c', count: 4, delivered: 1 }],
  daily: [{ date: '2026-09-01', count: 10, contained: 7 }, { date: '2026-09-02', count: 4, contained: 4 }],
  unrecognisedTypes: [],
  sync: { last_synced_at: '2026-09-22T10:00:00Z', last_sync_status: 'ok', last_sync_message: null },
};

const alert = over => Object.assign({
  alertId: 'id-1', alertType: 'AdvancedEmailSecurity.Threat', severity: 'high',
  threatClass: 'phishing', disposition: 'delivered', status: 'open',
  recipient: 'someone@client.co.za', sender: 'attacker@evil.example',
  subject: 'Invoice overdue', createdAt: '2026-09-01T08:00:00Z',
  updatedAt: '2026-09-01T09:00:00Z', resolvedAt: null,
}, over);

function fresh(summary, alerts, filters) {
  ET._setSummary(summary || SUMMARY);
  ET._setAlerts(alerts || []);
  ET._setAvailable(true);
  ET._setFilters(filters || {});
}

// ── 1. Nothing is truncated silently ───────────────────────────────────────

section('the list says what it is not showing');

const many = [];
for (let i = 0; i < 200; i++) many.push(alert({ alertId: 'id-' + i }));
fresh(SUMMARY, many);
const capped = ET._alertsTable();
check('a capped list says it is capped', /capped at 200/.test(capped),
  (capped.match(/Showing[^<]*/) || [])[0]);
check('and states the cap against the window total',
  /Showing the most recent 200 of 431/.test(capped));

fresh(SUMMARY, [alert()]);
const few = ET._alertsTable();
check('a short list under the total still says so',
  /Showing the most recent 1 of 431/.test(few), (few.match(/Showing[^<·]*/) || [])[0]);
check('and does not claim a cap it did not reach', !/capped at/.test(few));

const complete = JSON.parse(JSON.stringify(SUMMARY));
complete.threats.total = 1;
fresh(complete, [alert()]);
check('a list holding everything makes no "of N" claim',
  /Showing 1 alert/.test(ET._alertsTable()) && !/most recent/.test(ET._alertsTable()));

section('a search says how much it hid');

fresh(SUMMARY, [alert({ alertId: 'a', subject: 'Invoice overdue' }),
                alert({ alertId: 'b', subject: 'Payroll update' })],
      { q: 'payroll' });
const searched = ET._alertsTable();
check('the search narrows the rows', (searched.match(/class="em-row/g) || []).length === 1,
  (searched.match(/class="em-row/g) || []).length + ' row(s)');
check('and says how many it hid', /the search hid 1 of the 2 loaded/.test(searched));
check('a search matching nothing says that, not "no alerts"',
  (fresh(SUMMARY, [alert()], { q: 'zzzz' }), /Nothing in the loaded alerts matches that search/.test(ET._alertsTable())));

fresh(SUMMARY, [], { disposition: 'delivered' });
check('a filter matching nothing blames the filter, not the mailbox',
  /No alert in this window matches these filters/.test(ET._alertsTable()));
fresh(SUMMARY, []);
check('and with no filter it says there were none',
  /No email alerts in this window/.test(ET._alertsTable()));

// ── 2. Never collected is not zero ─────────────────────────────────────────

section('a client never collected shows no figures at all');

check('a summary with no sync row is "never collected"',
  ET._neverCollected(Object.assign({}, SUMMARY, { sync: null })) === true);
check('so is one configured but never run',
  ET._neverCollected(Object.assign({}, SUMMARY, { sync: { last_synced_at: null } })) === true);
check('a collected client is not', ET._neverCollected(SUMMARY) === false);

const noSync = ET._syncStrip(Object.assign({}, SUMMARY, { sync: null }));
check('and the strip says which of the two it is',
  /No Acronis integration is configured/.test(noSync));
check('a configured-but-unsynced client is told to press Sync Now',
  /nothing has been collected yet/i.test(
    ET._syncStrip(Object.assign({}, SUMMARY, { sync: { last_synced_at: null } }))));
check('a failed sync shows its message, not just a cross',
  /boom/.test(ET._syncStrip(Object.assign({}, SUMMARY, {
    sync: { last_synced_at: '2026-09-22T10:00:00Z', last_sync_status: 'error', last_sync_message: 'boom' } }))));

// The render path is what must not draw the cards; assert on the source, since
// render() needs a DOM host this sandbox does not provide.
check('render() refuses the stat cards when nothing was collected',
  /neverCollected\(_summary\)\)\s*\{[\s\S]{0,400}Nothing has been collected for this client yet/.test(tabJs) &&
  !/neverCollected\(_summary\)\)\s*\{[\s\S]{0,400}statCards\(/.test(tabJs));
check('and says a quiet month would look different',
  /once a sync has run, a quiet month will show zeros/.test(tabJs));

// ── 3. The filters reach the server ────────────────────────────────────────

section('filters are asked of the server, not of the loaded page');

fresh(SUMMARY, [], { threatClass: 'phishing', disposition: 'delivered', severity: 'high' });
const q = ET._alertsQs();
check('every filter is on the query', /threatClass=phishing/.test(q) &&
  /disposition=delivered/.test(q) && /severity=high/.test(q), q);
check('with the window and an explicit limit', /days=30/.test(q) && /limit=200/.test(q));
fresh(SUMMARY, []);
check('and an unfiltered list asks for none of them',
  !/threatClass|disposition|severity/.test(ET._alertsQs()), ET._alertsQs());

const srv = read('server.js');
const route = (srv.match(/app\.get\('\/api\/email\/alerts'[\s\S]*?\n\}\);/) || [''])[0];
check('the alerts route is found', route !== '');
/*
 * threat_class and disposition are NULL for these two; the summary COALESCEs
 * them into labels. Equality against the label can never match, so the tab
 * would have offered two filters that silently returned nothing.
 */
check('"unclassified" is asked for as IS NULL', /threatClass === 'unclassified'[\s\S]{0,80}threat_class IS NULL/.test(route));
check('"unknown" likewise', /disposition === 'unknown'[\s\S]{0,80}disposition IS NULL/.test(route));
check('real values still go through a placeholder, never interpolated',
  /params\.push\(req\.query\.threatClass\);[\s\S]{0,60}threat_class = \$\$\{params\.length\}/.test(route));
check('and the NULL branches add no parameter of their own',
  !/IS NULL\$\{/.test(route));

section('a count you can act on is a control');

fresh(SUMMARY, []);
const cards = ET._statCards(SUMMARY);
check('"Reached a mailbox" is a button when it is not zero',
  /data-disposition="delivered"/.test(cards));
check('"Pulled back after delivery" too', /data-disposition="remediated"/.test(cards));
const zeroDelivered = JSON.parse(JSON.stringify(SUMMARY));
zeroDelivered.containment.delivered = 0;
zeroDelivered.containment.remediated = 0;
check('but neither is a button at zero — there is nothing to show',
  !/data-disposition/.test(ET._statCards(zeroDelivered)));
check('the containment rate carries its denominator on the card itself',
  /of 388 alert\(s\) that stated an outcome/.test(cards));
const noOutcome = JSON.parse(JSON.stringify(SUMMARY));
noOutcome.containment = { contained: 0, delivered: 0, remediated: 0, knownDisposition: 0,
                          unknownDisposition: 431, rate: null, coverage: null };
check('and says so when there is no denominator',
  /no outcome was stated/.test(ET._statCards(noOutcome)));

// ── 4. Escaping, in the places the redesign added ──────────────────────────

section('the expanded row is still escaped');

const XSS = '<script>alert(1)</script>';
fresh(SUMMARY, [alert({ alertId: 'x', subject: XSS, sender: XSS, recipient: XSS,
                        alertType: XSS, status: XSS })],
      { expanded: { x: true } });
const expanded = ET._alertsTable();
check('the row expands', /em-detail/.test(expanded));
check('the full subject is printed in it', /Subject<\/dt>/.test(expanded));
check('and every attacker-authored field is escaped',
  expanded.indexOf('<script') < 0 && (expanded.match(/&lt;script/g) || []).length >= 5,
  (expanded.match(/&lt;script/g) || []).length + ' escaped occurrences');

section('the trend colours the part that matters');

const chart = ET._trendChart([{ date: '2026-09-01', count: 10, contained: 7 }]);
check('the tooltip states what was not stopped', /3 not stopped or not stated/.test(chart));
check('the legend names the remainder rather than leaving it unlabelled',
  /Not stopped or not stated/.test(chart));
check('and dates sit outside the stretched SVG, so they are not distorted',
  /em-dates/.test(chart) && chart.indexOf('em-dates') > chart.indexOf('</svg>'));

const css = read('public', 'css', 'email.css');
check('the uncontained remainder is drawn in the alarming colour',
  /\.em-bar-total\s*\{ fill: rgba\(232, 57, 74/.test(css));
check('and the stopped part in the reassuring one',
  /\.em-bar-contained \{ fill: #22C55E; \}/.test(css));

done();
