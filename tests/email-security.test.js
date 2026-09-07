'use strict';

/**
 * Managed Email Security (Acronis).
 *
 * THE PROPERTIES THIS SUITE EXISTS TO PROTECT
 *
 *   no invented denominator       the alert feed counts threats, not messages.
 *                                 Nothing here may present a "% of mail blocked"
 *   null is not zero              a containment rate of 0% says everything got
 *                                 through; no data says nobody recorded an
 *                                 outcome. They must never render the same
 *   unknown is not contained      an alert that did not state an outcome is
 *                                 excluded from the rate, never assumed blocked
 *   an unrecognised type is loud  a classifier gap must surface as a visible
 *                                 gap, not as a chart that quietly stops rising
 *   the secret never leaks        the client secret is encrypted like every
 *                                 other credential and never enters config_json
 *   one client's mail, one client the tenant UUID scopes every query
 *
 * The classifier and the renderers are exercised behaviourally. The routes and
 * the sync need Postgres, which is unreachable here, so their wiring is asserted
 * over the source — weaker, and said so.
 *
 *   node tests/email-security.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('email-security');

const acronis   = require(path.join(ROOT, 'lib', 'integrations', 'acronis'));
const P         = require(path.join(ROOT, 'lib', 'pages'));
const svcLib    = require(path.join(ROOT, 'lib', 'services'));

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const tabJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-email.js'), 'utf8');
const adminJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-admin.js'), 'utf8');
const metricsJs = fs.readFileSync(path.join(ROOT, 'lib', 'email-metrics.js'), 'utf8');
const adapterJs = fs.readFileSync(path.join(ROOT, 'lib', 'integrations', 'acronis.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const appJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'app.js'), 'utf8');
const sectionsJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-email-security.sql'), 'utf8');

// This repo documents its own removals, so a check that greps for a construct
// must strip comments or it passes on a comment describing what was deleted.
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlOnly(sql) { return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1'); }

const srvCode     = codeOnly(serverJs);
const tabCode     = codeOnly(tabJs);
const adapterCode = codeOnly(adapterJs);
const metricsCode = codeOnly(metricsJs);

/* ══ The classifier ═════════════════════════════════════════════════════════ */

section('what counts as an email security alert');

const emailAlert = (type, extra) => Object.assign({
  id: 'a1', type, createdAt: '2026-09-01T08:00:00Z',
}, extra || {});

check('a phishing alert is email',
  acronis.classify(emailAlert('EmailPhishingDetected')).isEmail);
check('and is classed as phishing',
  acronis.classify(emailAlert('EmailPhishingDetected')).threatClass === 'phishing',
  acronis.classify(emailAlert('EmailPhishingDetected')).threatClass);

check('a mail malware alert is classed as malware',
  acronis.classify(emailAlert('EmailMalwareBlocked')).threatClass === 'malware');
check('a BEC alert is classed as BEC',
  acronis.classify(emailAlert('EmailBECAttemptDetected')).threatClass === 'bec');
check('an impersonation alert is BEC too',
  acronis.classify(emailAlert('MailImpersonationAttempt')).threatClass === 'bec');
check('a spam alert is classed as spam',
  acronis.classify(emailAlert('EmailSpamQuarantined')).threatClass === 'spam');

/*
 * Ordering: a "phishing URL" alert is phishing, not a generic link finding.
 * The specific class has to win or every phishing alert with 'url' in its name
 * lands in the wrong bucket and the phishing count under-reports.
 */
check('a phishing URL alert is phishing, not "url"',
  acronis.classify(emailAlert('EmailPhishingUrlDetected')).threatClass === 'phishing',
  acronis.classify(emailAlert('EmailPhishingUrlDetected')).threatClass);

/*
 * REGRESSION GUARD for a real bug this suite caught.
 *
 * The classifier lower-cased the whole type name before matching, so
 * `EmailBECAttemptDetected` became `emailbecattemptdetected` — a single word in
 * which NOTHING has a boundary. Every \b pattern silently failed to match and
 * the alert fell through as unclassified. It failed open and quietly: the tab
 * would have shown zero BEC attacks with no error anywhere.
 */
section('camelCase type names are split before matching');

check('an acronym is separated from the word after it',
  acronis.words('EmailBECAttemptDetected') === 'email bec attempt detected',
  acronis.words('EmailBECAttemptDetected'));
check('and from the word before it',
  acronis.words('MailImpersonationAttempt') === 'mail impersonation attempt',
  acronis.words('MailImpersonationAttempt'));
check('punctuation and underscores become boundaries too',
  acronis.words('email_security.threat-detected') === 'email security threat detected',
  acronis.words('email_security.threat-detected'));
check('so a word-bounded pattern can actually match',
  /\bbec\b/.test(acronis.words('EmailBECAttemptDetected')));
// The failing case, stated directly: without the split this is one long word.
check('which a naive lower-case would have made impossible',
  !/\bbec\b/.test('EmailBECAttemptDetected'.toLowerCase()));

section('what is correctly NOT email security');

/*
 * Acronis raises backup, DR and patching alerts through the same endpoint.
 * Reading those as email security would inflate every count on the tab with
 * another product's telemetry.
 */
[
  'BackupFailed', 'AgentOffline', 'DisasterRecoveryServerFailed',
  'PatchManagementUpdateFailed', 'AntimalwareProtectionDisabled',
].forEach((t) => {
  check(t + ' is not email', acronis.classify(emailAlert(t)).isEmail === false);
});

/*
 * An alert we recognise as email but whose KIND we do not is a first-class
 * outcome: isEmail true, threatClass null. Folding it into a bucket would put a
 * plausible number on a chart that nobody would ever audit.
 */
const odd = acronis.classify(emailAlert('EmailSomethingBrandNew'));
check('an unrecognised email alert is still email', odd.isEmail === true);
check('but its threat class is null, not a bucket', odd.threatClass === null, odd.threatClass);

check('an alert with no type at all is not email',
  acronis.classify({ id: 'x' }).isEmail === false);

section('what happened to the message');

check('quarantined is read', acronis.readDisposition(
  emailAlert('EmailPhish', { details: { action: 'quarantined' } })) === 'quarantined');
check('blocked is read', acronis.readDisposition(
  emailAlert('EmailPhish', { details: { action: 'Blocked' } })) === 'blocked');
check('delivered is read', acronis.readDisposition(
  emailAlert('EmailPhish', { details: { verdict: 'delivered' } })) === 'delivered');
check('remediation after delivery is read', acronis.readDisposition(
  emailAlert('EmailPhish', { details: { remediationStatus: 'remediated' } })) === 'remediated');

/*
 * THE ONE THAT MATTERS. An alert that did not say what happened must return
 * null. Anything else turns a reporting gap into a reassuring number.
 */
check('an alert that did not say returns null, not "blocked"',
  acronis.readDisposition(emailAlert('EmailPhish')) === null,
  acronis.readDisposition(emailAlert('EmailPhish')));
check('and an unrecognised outcome word is null too',
  acronis.readDisposition(emailAlert('EmailPhish', { details: { action: 'flumped' } })) === null);

section('reading fields out of an alert whose shape we cannot be sure of');

const full = acronis.mapAlert({
  id: 'alert-9', type: 'EmailPhishingDetected', category: 'EmailSecurity',
  severity: 'critical', createdAt: '2026-09-01T08:00:00Z',
  updatedAt: '2026-09-01T09:00:00Z',
  details: {
    recipient: 'Karabo@Reflex.co.za', sender: 'attacker@evil.example',
    subject: 'Invoice overdue', action: 'quarantined',
  },
});
check('the id survives', full.alertId === 'alert-9');
check('the recipient survives', full.recipient === 'Karabo@Reflex.co.za');
check('the recipient domain is lowercased', full.recipientDomain === 'reflex.co.za',
  full.recipientDomain);
check('the sender domain is derived', full.senderDomain === 'evil.example');
check('timestamps normalise to ISO', full.createdAt === '2026-09-01T08:00:00.000Z',
  full.createdAt);

// pick() tries several spellings because the details shape differs by edition.
check('an alternative recipient spelling is still found',
  acronis.mapAlert({ id: 'b', type: 'EmailPhish', details: { mailbox: 'a@b.com' } })
    .recipient === 'a@b.com');
/*
 * An absent field must be null, never a placeholder that looks like data. A
 * recipient of '' or 'unknown' would be counted as a distinct targeted user.
 */
check('an absent field is null, not an empty string',
  acronis.mapAlert({ id: 'c', type: 'EmailPhish' }).recipient === null);
check('and a blank string is treated as absent',
  acronis.mapAlert({ id: 'd', type: 'EmailPhish', details: { recipient: '  ' } })
    .recipient === null);
check('an unparseable address yields no domain',
  acronis.domainOf('not-an-address') === null);
check('and a null address yields no domain', acronis.domainOf(null) === null);

// pick must not return an object stringified as "[object Object]".
check('a nested object is not stringified into a field',
  acronis.mapAlert({ id: 'e', type: 'EmailPhish', details: { recipient: { a: 1 } } })
    .recipient === null);

/* ══ The adapter's contract with the sync ═══════════════════════════════════ */

section('the tenant UUID scopes every query');

check('the alert query carries the tenant',
  /tenant=' \+ encodeURIComponent\(uuid\)/.test(adapterCode) ||
  /params\.push\('tenant='/.test(adapterCode));
check('and the admin form refuses to save without one',
  /Acronis Tenant UUID is required/.test(adminJs));
check('the client id is stored in config_json',
  /client_id: clientId/.test(adminJs));
/*
 * config_json is stored in the clear. The client SECRET must travel in api_key,
 * which the server encrypts — the same path as every other provider's
 * credential, so there is one place a secret can reach disk.
 */
check('and the SECRET is not put in config_json',
  !/client_secret/.test(codeOnly(adminJs)),
  (codeOnly(adminJs).match(/client_secret/g) || []).length + ' occurrence(s)');
check('the adapter reads the secret from api_key',
  /config\.api_key/.test(adapterCode));
check('the server passes the decrypted key to it',
  /acronisAdapter[\s\S]{0,400}decryptKey\(api_key_enc, api_key_iv\)/.test(srvCode) ||
  /runAcronisSync[\s\S]{0,900}decryptKey\(api_key_enc, api_key_iv\)/.test(srvCode));

section('the token is not the thing that leaks');

check('the token cache is not keyed by the secret',
  /String\(config\.base_url\) \+ '\|' \+ String\(config\.client_id\)/.test(adapterCode));
check('a 401 invalidates the cached token',
  /Acronis API 401[\s\S]{0,200}invalidateToken/.test(adapterCode));
/*
 * Exactly one retry. A loop would hammer the IdP with credentials that are
 * known-bad and get the API client locked out.
 */
// The trailing semicolon matters: it counts CALL sites. Without it the pattern
// also matches `function invalidateToken(config) {`, so the check would pass on
// the declaration alone even if nothing ever called it.
check('and retries exactly once, never in a loop',
  (adapterCode.match(/invalidateToken\(config\);/g) || []).length === 1,
  (adapterCode.match(/invalidateToken\(config\);/g) || []).length);
check('an error body is truncated before it becomes a message',
  /\.slice\(0, 300\)/.test(adapterCode));

section('a partial pull is reported as partial');

check('the fetch reports truncation', /truncated/.test(adapterCode));
check('and the sync says so in the status', /PAGE LIMIT REACHED/.test(serverJs));
check('marking the sync partial rather than ok',
  /truncated \? 'partial' : 'ok'/.test(srvCode));

section('every alert type seen is recorded, email or not');

check('the adapter returns a ledger of types', /typesSeen/.test(adapterCode));
check('including the ones it rejected',
  /entry\.count\+\+;[\s\S]{0,120}if \(!mapped\.isEmail\) continue;/.test(adapterCode));
check('the sync writes that ledger', /email_alert_types_seen/.test(srvCode));
check('accumulating the count across syncs',
  /seen_count   = email_alert_types_seen\.seen_count \+ EXCLUDED\.seen_count/.test(serverJs));
/*
 * is_email is OVERWRITTEN rather than accumulated, so teaching the classifier a
 * new keyword and re-syncing flips a type from unrecognised to recognised in
 * place instead of leaving a stale row that says it is still a gap.
 */
check('and overwriting is_email so a fixed classifier takes effect',
  /is_email     = EXCLUDED\.is_email/.test(serverJs));

/* ══ The metrics ════════════════════════════════════════════════════════════ */

section('no denominator is invented');

/*
 * The single most important property. The Acronis alert feed counts threats,
 * not messages scanned. Nothing may present a percentage of mail.
 */
check('the metrics never claim a share of total mail',
  !/messagesProcessed|messagesScanned|totalMessages|mailVolume/i.test(metricsCode),
  (metricsCode.match(/messagesProcessed|messagesScanned|totalMessages|mailVolume/gi) || []).join(','));
check('and the module says why in so many words',
  /does NOT report a catch rate against mail volume/.test(metricsJs));
check('the tab repeats it where the numbers are read',
  /not mail volume/i.test(tabJs));
check('and so does the board report',
  /not of mail volume/i.test(sectionsJs));

section('null is not zero');

const em = require(path.join(ROOT, 'lib', 'email-metrics'));

// pct1 is the one arithmetic rule in the module: no denominator, no rate.
check('a rate over nothing is null, not 0',
  /if \(!denominator\) return null;/.test(metricsJs));
check('containment excludes unknown outcomes from its denominator',
  /rate:     pct1\(contained, knownDisposition\)/.test(metricsJs));
/*
 * If the denominator were `total`, an alert that never said what happened would
 * count against the client as though the threat got through.
 */
check('and NOT over every alert in the window',
  !/pct1\(contained, total\)/.test(metricsCode));
check('the coverage of that rate is reported beside it',
  /coverage: pct1\(knownDisposition, total\)/.test(metricsJs));
check('unknown outcomes are counted, not dropped silently',
  /unknownDisposition: total - knownDisposition/.test(metricsJs));

check('"contained" does not include delivered',
  em.CONTAINED.indexOf('delivered') < 0, em.CONTAINED.join(','));
check('but does include a threat pulled back after delivery',
  em.CONTAINED.indexOf('remediated') >= 0);
check('blocked and quarantined both count as contained',
  em.CONTAINED.indexOf('blocked') >= 0 && em.CONTAINED.indexOf('quarantined') >= 0);

check('an unclassified email alert is counted as a gap, not a category',
  /unclassified: total - classified/.test(metricsJs));
check('and unrecognised types are surfaced un-windowed',
  /FROM email_alert_types_seen[\s\S]{0,120}is_email = FALSE/.test(metricsJs));

/* ══ Storage ════════════════════════════════════════════════════════════════ */

section('the schema');

check('alerts are unique per tenant, not globally',
  /UNIQUE \(tenant_id, alert_id\)/.test(sqlOnly(migration)));
check('and cascade when a tenant is removed',
  (sqlOnly(migration).match(/REFERENCES tenants\(id\) ON DELETE CASCADE/g) || []).length >= 2);
check('threat_class is nullable so "unrecognised" is storable',
  !/threat_class\s+VARCHAR\(30\)\s+NOT NULL/.test(sqlOnly(migration)));
check('disposition is nullable so "did not say" is storable',
  !/disposition\s+VARCHAR\(30\)\s+NOT NULL/.test(sqlOnly(migration)));
/*
 * Personal data lives in this table. The migration has to say so — this is the
 * only artefact anyone reads before running it.
 */
check('the migration flags that it holds personal data',
  /POPIA/.test(migration) && /personal data/i.test(migration));
check('and admits there is no retention sweep',
  /no retention sweep/i.test(migration));

section('the sync');

check('it resumes from updated_at, so a changed alert comes back',
  /SELECT MAX\(updated_at\) AS since FROM email_alerts/.test(serverJs));
check('and not from created_at, which would never see a change',
  !/SELECT MAX\(created_at\)[\s\S]{0,40}FROM email_alerts/.test(srvCode));
check('the upsert overwrites a changed alert rather than duplicating it',
  /ON CONFLICT \(tenant_id, alert_id\) DO UPDATE SET/.test(serverJs));
check('the whole sync is one transaction',
  /runAcronisSync[\s\S]{0,6000}BEGIN[\s\S]{0,6000}COMMIT/.test(srvCode));
check('and rolls back on a database error',
  /runAcronisSync[\s\S]{0,7000}ROLLBACK/.test(srvCode));
check('a fetch failure is recorded on the integration row',
  /runAcronisSync[\s\S]{0,3000}last_sync_status = 'error'/.test(srvCode));

/*
 * Acronis must be excluded from the generic scheduled sweep. That sweep calls
 * runTicketIntegrationSync, which calls adapter.fetchTickets — a method this
 * adapter does not have, so inclusion would be a crash every 24 hours.
 */
/*
 * Matched on the exclusion list CONTAINING EMAIL_PROVIDER rather than on the
 * exact array literal. The literal spelling broke the moment a fifth
 * non-ticket provider was added (ms_graph), which is a false failure: the
 * property being protected is that Acronis is not swept, not that exactly three
 * other providers are also not swept.
 */
check('acronis is excluded from the ticket-shaped scheduled sweep',
  /provider <> ALL\(\$1::text\[\]\)'[\s\S]{0,200}EMAIL_PROVIDER/.test(srvCode));
check('and has its own scheduler', /runEmailSyncs/.test(srvCode));
check('which does not stack overlapping runs',
  /if \(emailSyncRunning\)[\s\S]{0,200}return;/.test(srvCode));
check('and does nothing when the migration has not been run',
  /runEmailSyncs[\s\S]{0,600}if \(!await hasEmailTables\(\)\) return;/.test(srvCode));

section('the degrade-open probe');

check('the table probe caches only a positive answer',
  /_hasEmailTables = true;[\s\S]{0,120}return false;/.test(srvCode));
/*
 * Caching a false would mean running the migration needs a restart to take
 * effect — the failure mode that makes people think the migration did not work.
 */
check('so running the migration takes effect without a restart',
  !/_hasEmailTables = false;\s*\n\s*return false/.test(srvCode));

/* ══ Routes and access ══════════════════════════════════════════════════════ */

section('routes, access and wiring');

['GET /api/email/summary', 'GET /api/email/alerts', 'GET /api/email/types'].forEach((r) => {
  const [m, p] = r.split(' ');
  check(r + ' is mounted',
    new RegExp('app\\.' + m.toLowerCase() + "\\('" + p.replace(/[/:]/g, '\\$&') + "'").test(srvCode));
});

check('every email route requires auth',
  (srvCode.match(/app\.get\('\/api\/email\/[a-z]+', requireAuth/g) || []).length === 3,
  (srvCode.match(/app\.get\('\/api\/email\/[a-z]+', requireAuth/g) || []).length);
// Destructuring form only — `resolveEmailTenant(req)` alone also matches the
// function's own declaration, which would make this read 4 and pass for the
// wrong reason if a route ever dropped its call.
check('every email route is tenant-scoped',
  (srvCode.match(/const \{ tenantId \} = resolveEmailTenant\(req\);/g) || []).length === 3,
  (srvCode.match(/const \{ tenantId \} = resolveEmailTenant\(req\);/g) || []).length);
/*
 * A superadmin with no client selected is a UI state, not an error — but it must
 * not fall through to an unscoped query.
 */
check('and a superadmin with no client selected gets nothing, not everything',
  /if \(tenantId === null\) return res\.json\(/.test(srvCode) &&
  /if \(isNaN\(tid\) \|\| tid < 1\) return \{ tenantId: null \};/.test(srvCode));

// Filter VALUES are parameterised; filter COLUMNS are literals in the source.
check('alert filters are parameterised, not interpolated',
  !/where\.push\(`[^`]*\$\{req\.query/.test(serverJs));

check('"not migrated" is distinguishable from "no data"',
  /available: false/.test(srvCode) && /available: true/.test(srvCode));

check('the page is in the catalogue',
  P.PAGES.some(p => p.key === 'email' && p.type === 'tab'));
check('the API prefix maps to it', P.API_PREFIX_TO_PAGE.email === 'email');
/*
 * Client data, like Managed EDR — so read-only staff see it. Deliberately NOT in
 * NON_VIEWER_TABS: that list is for configuration surfaces and job-specific
 * tabs, and this is neither.
 */
['sales', 'readonly', 'analyst'].forEach((r) => {
  check(r + ' can read it', P.ROLE_DEFAULTS[r].email === 'read', P.ROLE_DEFAULTS[r].email);
});
check('a portal client cannot', P.ROLE_DEFAULTS.client.email === 'none');
check('and neither can a manager', P.ROLE_DEFAULTS.manager.email === 'none');

section('the service gates the report and nothing else');

check('email is in the service catalogue',
  svcLib.SERVICE_KEYS.indexOf('email') >= 0);
check('and covers no Secure Score component',
  JSON.stringify(svcLib.SERVICE_COVERS.email) === '[]');
check('so it cannot appear in a coverage gap',
  svcLib.COMPONENT_KEYS.every(k => svcLib.servicesCovering(k).indexOf('email') < 0));
/*
 * MDR includes EDR, NDR and Identity. It does not include email security, which
 * is a separately licensed Acronis product — implying it would put an empty
 * email section in every MDR client's deck.
 */
check('MDR does not imply email security',
  (svcLib.SERVICE_INCLUDES.mdr || []).indexOf('email') < 0);
check('so an MDR client is not credited with it',
  (svcLib.effectiveServices(['mdr']) || []).indexOf('email') < 0,
  (svcLib.effectiveServices(['mdr']) || []).join(','));
check('a client who bought it is', svcLib.hasService(['email'], 'email'));

section('the tab and the deck are wired');

check('the tab script is loaded', /js\/tab-email\.js/.test(indexHtml));
check('its panel exists', /id="tab-email"/.test(indexHtml));
check('its stylesheet is linked', /css\/email\.css/.test(indexHtml));
check('the panel is in the tab map',
  /email:\s*document\.getElementById\('tab-email'\)/.test(appJs));
check('and it is dispatched on open',
  /target === 'email'[\s\S]{0,140}EmailTab\.loadAndRender\(\)/.test(appJs));

/* Where the nav entry sits, not merely that one exists. */
function navGroupOf(tab) {
  const groups = [...indexHtml.matchAll(
    /data-label="([^"]+)"[\s\S]*?<div class="side-nav-group-items"[^>]*>([\s\S]*?)<\/div>/g)];
  for (const g of groups) {
    if (new RegExp('data-tab="' + tab + '"').test(g[2])) return g[1].replace('&amp;', '&');
  }
  return null;
}
check('the nav entry is under Managed Services',
  navGroupOf('email') === 'Managed Services', navGroupOf('email'));
check('beside the other managed services',
  ['edr', 'ndr', 'o365'].every(t => navGroupOf(t) === 'Managed Services'));
check('and appears exactly once',
  (indexHtml.match(/data-tab="email"/g) || []).length === 1);

check('the report section is gated on the email service',
  /id: 'emailSecurity'[\s\S]{0,120}services: \['email'\]/.test(sectionsJs));
check('and requires the email payload',
  /id: 'emailSecurity'[\s\S]{0,200}requires: \['email'\]/.test(sectionsJs));
check('the deck knows where to fetch it',
  /email:\s*function \(ctx\) \{ return 'api\/email\/summary\?days='/.test(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-reports.js'), 'utf8')));
// Display numbers are what an analyst ticks off in the Reports tab.
check('section numbers stay unique',
  (() => {
    const ns = [...sectionsJs.matchAll(/\{ n: (\d+), id: '/g)].map(m => m[1]);
    return new Set(ns).size === ns.length;
  })());

/* ══ The browser module ═════════════════════════════════════════════════════ */

section('the tab escapes what it renders');

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

check('the module loads', !!ET && typeof ET.loadAndRender === 'function');

/*
 * Every string on this tab came off the wire from an attacker-authored email.
 * Subjects and sender addresses are the most directly attacker-controlled text
 * anywhere in this application.
 */
const XSS = '<script>alert(1)</script>';
ET._setAlerts([{
  alertId: 'a', threatClass: 'phishing', disposition: 'delivered',
  recipient: XSS, sender: XSS, subject: XSS, createdAt: '2026-09-01T08:00:00Z',
}]);
const table = ET._alertsTable();
check('a subject is escaped',
  table.indexOf('<script') < 0 && table.indexOf('&lt;script') >= 0);
check('so are the sender and recipient',
  (table.match(/&lt;script/g) || []).length >= 3,
  (table.match(/&lt;script/g) || []).length + ' escaped occurrences');

ET._setSummary({
  windowDays: 30,
  threats: { total: 1, classified: 1, unclassified: 0, targetedUsers: 1, senderDomains: 1 },
  containment: { contained: 0, delivered: 1, remediated: 0, knownDisposition: 1,
                 unknownDisposition: 0, rate: 0, coverage: 100 },
  topRecipients: [{ label: XSS, count: 3, delivered: 1 }],
  unrecognisedTypes: [{ label: XSS, count: 2 }],
  byClass: [], bySeverity: [], byDisposition: [], topSenderDomains: [], daily: [],
});
check('a targeted mailbox is escaped',
  ET._targetedBlock(ET ? { topRecipients: [{ label: XSS, count: 1, delivered: 0 }] } : {})
    .indexOf('<script') < 0);
check('and an unrecognised alert type is escaped',
  ET._unrecognisedBlock({ unrecognisedTypes: [{ label: XSS, count: 1 }] })
    .indexOf('<script') < 0);

section('the tab never renders null as zero');

const noData = {
  windowDays: 30,
  threats: { total: 4, classified: 4, unclassified: 0, targetedUsers: 2, senderDomains: 2 },
  containment: { contained: 0, delivered: 0, remediated: 0, knownDisposition: 0,
                 unknownDisposition: 4, rate: null, coverage: null },
};
const cards = ET._statCards(noData);
check('a null containment rate is a dash, not 0%',
  /em-nd/.test(cards) && !/>0%</.test(cards), cards.slice(0, 200));

const zeroRate = JSON.parse(JSON.stringify(noData));
zeroRate.containment = { contained: 0, delivered: 4, remediated: 0,
  knownDisposition: 4, unknownDisposition: 0, rate: 0, coverage: 100 };
check('but a real 0% renders as 0%', /0%/.test(ET._statCards(zeroRate)));
/*
 * The two states above are the whole point: "nothing was stopped" and "nobody
 * recorded an outcome" must not look the same to a reader.
 */
check('so the two are distinguishable',
  ET._statCards(noData) !== ET._statCards(zeroRate));

section('the denominator travels with the rate');

const note = ET._denominatorNote(noData);
check('with no outcomes recorded, it refuses to show a rate',
  /No containment rate can be shown/.test(note));
check('and says that is a gap, not a clean month',
  /reporting gap, not a clean month/.test(note));

const partial = JSON.parse(JSON.stringify(noData));
partial.containment = { contained: 3, delivered: 1, remediated: 0,
  knownDisposition: 4, unknownDisposition: 6, rate: 75, coverage: 40 };
partial.threats.total = 10;
const pNote = ET._denominatorNote(partial);
check('a partial rate states what it was computed over',
  /4 of 10/.test(pNote), pNote.slice(0, 240));
check('and says the rest were excluded, not assumed blocked',
  /excluded rather than assumed blocked/.test(pNote));

section('the trend distinguishes a quiet month from no data');

check('an empty series renders nothing at all',
  ET._trendChart([]) === '');
check('an all-zero series says so rather than drawing a flat chart',
  /No email threats were detected/.test(
    ET._trendChart([{ date: '2026-09-01', count: 0, contained: 0 }])));
check('and a real series draws bars',
  /<rect/.test(ET._trendChart([{ date: '2026-09-01', count: 5, contained: 3 }])));

section('an unrecognised threat kind is labelled, not bucketed');

check('unclassified has its own label',
  ET._classLabel('unclassified') === 'Unclassified');
check('and is not silently called "other"',
  ET._classLabel('unclassified').toLowerCase().indexOf('other') < 0);

section('every request keeps the /secops/ base path');

check('the URL builder keeps the base',
  ET._apiUrl('email/summary') === 'https://secops.reflex.co.za/secops/api/email/summary',
  ET._apiUrl('email/summary'));
check('no request is hard-coded to a bare root',
  !/fetch\(['"]\/api\//.test(tabCode));
check('and the base comes from <base href> like every other module',
  /document\.querySelector\('base'\)/.test(tabCode));

done();
