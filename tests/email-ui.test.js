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

// Reframed onto the hero band: the stat cards it replaced are gone, and the
// same counts now live in the header the Acronis console puts them in.
fresh(SUMMARY, []);
const hero = ET._heroBand(SUMMARY);
check('"reached a mailbox" is a button when it is not zero',
  /data-disposition="delivered"/.test(hero));
check('"pulled back" too', /data-disposition="remediated"/.test(hero));
const zeroDelivered = JSON.parse(JSON.stringify(SUMMARY));
zeroDelivered.containment.delivered = 0;
zeroDelivered.containment.remediated = 0;
check('but neither is a button at zero — there is nothing to show',
  !/data-disposition/.test(ET._heroBand(zeroDelivered)));
check('the containment rate carries its denominator in the band itself',
  /over the 388 of 431 alert\(s\) that stated an outcome/.test(hero), 'denominator printed');
const noOutcome = JSON.parse(JSON.stringify(SUMMARY));
noOutcome.containment = { contained: 0, delivered: 0, remediated: 0, knownDisposition: 0,
                          unknownDisposition: 431, rate: null, coverage: null };
check('and says so when there is no denominator',
  /no outcome was stated/.test(ET._heroBand(noOutcome)));

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

/* ══ The Acronis-shaped layout ═════════════════════════════════════════════ */

section('what the Acronis console shows and this data cannot');

/*
 * The console leads with "99.95% Protection" over "2,407,983 Items Scanned",
 * and an "Attack Level 4/5" gauge derived from the share of SCANNED mail that
 * was malicious. lib/integrations/acronis.js calls one endpoint — the Alert
 * Manager — which reports what went wrong and never how much was scanned. Any
 * one of those three figures on this page would be invented.
 */
const acr = read('lib', 'integrations', 'acronis.js');
check('the adapter still reads only the alert endpoint',
  /alert_manager\/v1\/alerts/.test(acr) && !/items_scanned|scanned_count|\/statistics/.test(acr));

const tiles = ET._unavailableTiles();
check('the page says the protection rate is not available, and why',
  /Protection %/.test(tiles) && /no scanned total here to/.test(tiles));
check('and that the attack-level gauge needs the same missing denominator',
  /Attack level/.test(tiles) && /same missing denominator/.test(tiles));
check('and that impersonated brands are not on the alerts we store',
  /Top impersonated brands/.test(tiles));
// Asserted on the page, not only on the function: an explanation that is
// rendered nowhere explains nothing.
check('and the explanation is actually on the page',
  /unavailableTiles\(\);/.test(tabJs) &&
  tabJs.indexOf('unavailableTiles();') > tabJs.indexOf('alertsBlock(_summary)'));
check('no invented protection or scanned figure appears anywhere on the tab',
  !/Items Scanned|items scanned|Protection<|99\.9/.test(
    tabJs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')),
  'nothing outside the comments that explain the omission');

section('the hero band reads like the console header');

check('the badge is labelled Contained, not Protection',
  /em-badge-l">Contained</.test(hero) && !/>Protection</.test(hero));
check('the incident count leads', /em-hero-n">431 <span>incidents/.test(hero));
check('with the outcome split under it',
  /380 stopped/.test(hero) && /reached a mailbox/.test(hero) &&
  /43 with no outcome stated/.test(hero));

section('the range tabs name a real date range');

ET._setFilters({});
const tabs = ET._rangeTabs();
check('the console\'s own ranges are offered',
  /data-days="1"/.test(tabs) && /data-days="7"/.test(tabs) &&
  /data-days="30"/.test(tabs) && /data-days="90"/.test(tabs));
check('one is marked current', (tabs.match(/is-on/g) || []).length === 1);
check('and the window is spelled out as dates, not just "last quarter"',
  /em-range-dates">[^<]*\d{4}[^<]*–[^<]*\d{4}/.test(tabs),
  (tabs.match(/em-range-dates">([^<]*)/) || [])[1]);

section('the stacked chart keeps a kind the same colour throughout');

const stack = ET._stackedChart(Object.assign({}, SUMMARY, {
  dailyByClass: {
    classes: ['phishing', 'unclassified'],
    days: [
      { date: '2026-09-01', total: 10, counts: { phishing: 7, unclassified: 3 } },
      { date: '2026-09-02', total: 4,  counts: { phishing: 4 } },
    ],
  },
}));
check('each kind is drawn in its own colour', /fill="#E8394A"/.test(stack));
check('and the legend uses the same one', /background:#E8394A/.test(stack.replace(/\s/g, '')));
check('a segment names its day, kind and count', /2026-09-01 · Phishing: 7/.test(stack));
check('an all-zero window says so rather than drawing an empty frame',
  /No email threats were detected/.test(ET._stackedChart(Object.assign({}, SUMMARY, {
    dailyByClass: { classes: ['phishing'], days: [{ date: '2026-09-01', total: 0, counts: {} }] },
  }))));
check('and a summary with no stack at all renders nothing',
  ET._stackedChart(Object.assign({}, SUMMARY, { dailyByClass: null })) === '');

section('the outcome donut adds up to the alerts it describes');

const donut = ET._attackLevelBlock(SUMMARY);
check('every outcome is a labelled slice',
  /Stopped<\/i|Stopped<span|Stopped/.test(donut) && /Reached a mailbox/.test(donut) &&
  /No outcome stated/.test(donut));
check('"pulled back" is not double-counted inside "stopped"',
  /em-sl-stopped[\s\S]*?375/.test(donut), 'contained 380 less remediated 5');
check('the malicious/spam split excludes the classifier gap',
  /em-mini-n">300</.test(donut), 'phishing only; unclassified is its own tile');
check('a window with no alerts draws no ring at all',
  /em-donut-empty/.test(ET._attackLevelBlock(Object.assign({}, SUMMARY, {
    threats: { total: 0, classified: 0, unclassified: 0, targetedUsers: 0, senderDomains: 0 },
    containment: { contained: 0, delivered: 0, remediated: 0, knownDisposition: 0,
                   unknownDisposition: 0, rate: null, coverage: null },
    byClass: [],
  }))));

section('every kind is described, not just counted');

const amounts = ET._typeAmounts(SUMMARY);
check('a kind carries a plain-English description',
  /Credential theft/.test(amounts));
check('and the classifier gap is described as a gap, not a threat kind',
  /no threat kind for/.test(amounts));

/* ══ The server-side stack ═════════════════════════════════════════════════ */

section('the daily stack is a remainder, never a reclassification');

const EM = require(path.join(ROOT, 'lib', 'email-metrics.js'));
const metricsSrc = read('lib', 'email-metrics.js');

// Seven kinds over two days: five earn a band, two are summed into 'other'.
const dayRows = [
  { label: '2026-09-01', count: 28, contained: 20 },
  { label: '2026-09-02', count: 0,  contained: 0 },
];
const classRows = [
  { day: '2026-09-01', label: 'phishing',   count: 10 },
  { day: '2026-09-01', label: 'malware',    count: 6 },
  { day: '2026-09-01', label: 'spam',       count: 5 },
  { day: '2026-09-01', label: 'url',        count: 3 },
  { day: '2026-09-01', label: 'bec',        count: 2 },
  { day: '2026-09-01', label: 'dlp',        count: 1 },
  { day: '2026-09-01', label: 'attachment', count: 1 },
];
const stacked = EM.stackByClass(dayRows, classRows);

check('only the largest kinds get a band', stacked.classes.length === 6,
  stacked.classes.join(', '));
check('the five largest, in size order',
  stacked.classes.slice(0, 5).join(',') === 'phishing,malware,spam,url,bec');
check('and the rest are summed into a remainder called "other"',
  stacked.classes[5] === 'other' && stacked.days[0].counts.other === 2,
  'dlp 1 + attachment 1');
check('a day\'s bands add up to that day\'s total — nothing is dropped',
  Object.keys(stacked.days[0].counts).reduce(function (m, k) {
    return m + stacked.days[0].counts[k];
  }, 0) === stacked.days[0].total, String(stacked.days[0].total));
check('a quiet day is kept as a zero column, not a gap in the series',
  stacked.days.length === 2 && stacked.days[1].total === 0 &&
  Object.keys(stacked.days[1].counts).length === 0);
check('with five kinds or fewer there is no "other" band at all',
  EM.stackByClass(dayRows, classRows.slice(0, 4)).classes.indexOf('other') < 0);

check('byClass still reports every kind at full count',
  /byClass:\s*tallies\(byClass\.rows\)/.test(metricsSrc),
  'the per-kind record is untouched by the stack');

done();
