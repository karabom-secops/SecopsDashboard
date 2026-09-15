'use strict';

/**
 * Microsoft Secure Score (Microsoft Graph).
 *
 * THE PROPERTIES THIS SUITE EXISTS TO PROTECT
 *
 *   Microsoft's score stays Microsoft's   it is reported alongside our
 *                                         composite and never folded into it,
 *                                         because its denominator moves and we
 *                                         cannot defend its weighting
 *   the denominator is never discarded    current AND max are stored on every
 *                                         row; a bare percentage cannot be
 *                                         trended across a maxScore change
 *   null is not zero                      a control Microsoft did not score is
 *                                         unmeasured, not worth zero points
 *   max 0 is not 0%                       an unscored tenant must not render a
 *                                         red nought
 *   the join is outer on the score side   a control whose profile is missing
 *                                         still appears; a dropped control is
 *                                         a gap nobody sees
 *   ThirdParty and Ignored are not gaps   telling a client to remediate what
 *                                         they already cover, or have formally
 *                                         accepted, costs the room
 *   the newest control state wins         controlStateUpdates is append-only
 *   the secret never leaks                it is encrypted like every other
 *                                         credential and never enters
 *                                         config_json
 *   one client, one directory             a credential answering for another
 *                                         Azure directory is caught and said
 *
 * The adapter's pure functions are exercised behaviourally. The routes and the
 * sync need Postgres and a live Graph tenant, neither reachable here, so their
 * wiring is asserted over the source — weaker, and said so.
 *
 *   node tests/ms-secure-score.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('ms-secure-score');

const g = require(path.join(ROOT, 'lib', 'integrations', 'ms-graph'));
const P = require(path.join(ROOT, 'lib', 'pages'));

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const adapterJs = fs.readFileSync(path.join(ROOT, 'lib', 'integrations', 'ms-graph.js'), 'utf8');
const adminJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-admin.js'), 'utf8');
const panelJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'ms-secure-score.js'), 'utf8');
const tabJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-ms-secure-score.sql'), 'utf8');

// This repo documents its own removals, so a check that greps for a construct
// must strip comments or it passes on a comment describing what was deleted.
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlOnly(sql) { return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1'); }

const srvCode     = codeOnly(serverJs);
const adapterCode = codeOnly(adapterJs);
const adminCode   = codeOnly(adminJs);
const panelCode   = codeOnly(panelJs);
const tabCode     = codeOnly(tabJs);
const sqlCode     = sqlOnly(migration);

// ── percentage(): the null rules ───────────────────────────────────────────

section('percentage — null is not zero, and max 0 is not 0%');

check('normal case', g.percentage(210, 400) === 52.5, g.percentage(210, 400));
check('a genuinely earned 100%', g.percentage(400, 400) === 100, g.percentage(400, 400));

check('a genuine zero survives', g.percentage(0, 400) === 0, String(g.percentage(0, 400)));

check('null current -> null, not 0',
  g.percentage(null, 400) === null, String(g.percentage(null, 400)));
check('null max -> null, not 0',
  g.percentage(210, null) === null, String(g.percentage(210, null)));
check('max 0 -> null, NOT 0% (an unscored tenant is not a failing one)',
  g.percentage(0, 0) === null, String(g.percentage(0, 0)));
check('negative max -> null',
  g.percentage(10, -5) === null, String(g.percentage(10, -5)));
check('unparseable -> null',
  g.percentage('abc', 400) === null, String(g.percentage('abc', 400)));

// ── num(): zero is data, absent is not ─────────────────────────────────────

section('num — 0 is preserved, absent is null');

check('zero is preserved as zero', g.num(0) === 0, String(g.num(0)));
check('numeric string parses', g.num('12.5') === 12.5, String(g.num('12.5')));
check('null -> null', g.num(null) === null, String(g.num(null)));
check('undefined -> null', g.num(undefined) === null, String(g.num(undefined)));
check('empty string -> null, not 0', g.num('') === null, String(g.num('')));
check('NaN -> null', g.num('nonsense') === null, String(g.num('nonsense')));

// ── graphScope: the .default footgun ───────────────────────────────────────

section('graphScope — resource root, never the versioned path');

check('commercial default',
  g.graphScope({}) === 'https://graph.microsoft.com/.default', g.graphScope({}));
check('v1.0 base does NOT leak into the scope',
  g.graphScope({ base_url: 'https://graph.microsoft.com/v1.0' }) === 'https://graph.microsoft.com/.default',
  g.graphScope({ base_url: 'https://graph.microsoft.com/v1.0' }));
check('national cloud host is respected',
  g.graphScope({ base_url: 'https://graph.microsoft.us/v1.0' }) === 'https://graph.microsoft.us/.default',
  g.graphScope({ base_url: 'https://graph.microsoft.us/v1.0' }));
check('an unparseable base falls back rather than throwing',
  g.graphScope({ base_url: 'not a url' }) === 'https://graph.microsoft.com/.default',
  g.graphScope({ base_url: 'not a url' }));

// ── readControlState: append-only means newest wins ────────────────────────

section('readControlState — the newest update wins, not the first');

check('no updates -> null (not "Default")',
  g.readControlState({ controlStateUpdates: [] }) === null,
  String(g.readControlState({ controlStateUpdates: [] })));

check('absent array -> null',
  g.readControlState({}) === null, String(g.readControlState({})));

const reversed = g.readControlState({
  controlStateUpdates: [
    { state: 'Ignored',    updatedDateTime: '2024-01-01T00:00:00Z' },
    { state: 'ThirdParty', updatedDateTime: '2025-06-01T00:00:00Z' },
  ],
});
check('newest by timestamp wins even when it is not first',
  reversed === 'ThirdParty', reversed);

const outOfOrder = g.readControlState({
  controlStateUpdates: [
    { state: 'ThirdParty', updatedDateTime: '2025-06-01T00:00:00Z' },
    { state: 'Default',    updatedDateTime: '2024-01-01T00:00:00Z' },
  ],
});
check('an older entry listed later does not win', outOfOrder === 'ThirdParty', outOfOrder);

const undated = g.readControlState({
  controlStateUpdates: [{ state: 'Default' }, { state: 'Ignored' }],
});
check('with no usable timestamps, the LAST entry wins (append-only)',
  undated === 'Ignored', undated);

// ── mergeControls: the outer join, and gap nulls ───────────────────────────

section('mergeControls — the join is outer on the score side');

const profileMap = new Map([
  ['mfaregistrationv2', {
    controlName: 'MFARegistrationV2', title: 'Require MFA for all users',
    controlCategory: 'Identity', maxScore: 30, rank: 1, tier: 'Core',
    service: 'AzureAD', actionType: 'Config', actionUrl: 'https://example.invalid',
    remediation: 'Turn on security defaults or a CA policy.',
    remediationImpact: 'Users enrol in MFA.', userImpact: 'Moderate',
    implementationCost: 'Low', threats: ['AccountBreach'],
    deprecated: false, controlState: null,
  }],
]);

const merged = g.mergeControls([
  { controlName: 'MFARegistrationV2', score: 12, controlCategory: 'Identity' },
  { controlName: 'RetiredControl',    score: 5,  controlCategory: 'Data' },
  { score: 3 }, // no name at all
], profileMap);

check('a control with no name is dropped (nothing to upsert or join on)',
  merged.length === 2, 'kept ' + merged.length);

const mfa = merged.find(c => c.controlName === 'MFARegistrationV2');
check('profile metadata joins on', mfa && mfa.title === 'Require MFA for all users', mfa && mfa.title);
check('gap = max - score', mfa && mfa.gap === 18, mfa && mfa.gap);
check('remediation text carried through', !!(mfa && mfa.remediation), mfa && mfa.remediation);

const orphan = merged.find(c => c.controlName === 'RetiredControl');
check('a control with NO profile still appears — an inner join would hide it',
  !!orphan, orphan ? 'present' : 'DROPPED');
check('its profile fields are null, not invented',
  orphan && orphan.title === null && orphan.maxScore === null,
  orphan ? String(orphan.title) + '/' + String(orphan.maxScore) : 'n/a');
check('its gap is NULL, not 0 — unknown must not sort with "no gap"',
  orphan && orphan.gap === null, orphan ? String(orphan.gap) : 'n/a');

const unscored = g.mergeControls(
  [{ controlName: 'MFARegistrationV2' }], profileMap);
check('a control Microsoft did not score has score null, not 0',
  unscored[0].score === null, String(unscored[0].score));
check('and therefore gap null, not the full max',
  unscored[0].gap === null, String(unscored[0].gap));

const overachieve = g.mergeControls(
  [{ controlName: 'MFARegistrationV2', score: 35 }], profileMap);
check('a score above max clamps the gap at 0 rather than going negative',
  overachieve[0].gap === 0, String(overachieve[0].gap));

const zeroScored = g.mergeControls(
  [{ controlName: 'MFARegistrationV2', score: 0 }], profileMap);
check('a measured zero gives the FULL gap (0 is data, not absence)',
  zeroScored[0].gap === 30, String(zeroScored[0].gap));

check('the join is case-insensitive on control name',
  g.mergeControls([{ controlName: 'mfaregistrationv2' }], profileMap)[0].title
    === 'Require MFA for all users',
  g.mergeControls([{ controlName: 'mfaregistrationv2' }], profileMap)[0].title);

check('a profile with no matching score is NOT emitted (it does not apply here)',
  g.mergeControls([], profileMap).length === 0,
  String(g.mergeControls([], profileMap).length));

// ── mapSnapshot / mapProfile ───────────────────────────────────────────────

section('mapping — honest absence');

const snap = g.mapSnapshot({
  createdDateTime: '2026-09-05T03:14:00Z',
  currentScore: 210.5, maxScore: 400,
  azureTenantId: 'aaaa-bbbb', activeUserCount: 120, licensedUserCount: 150,
  enabledServices: ['exchange'], averageComparativeScores: [{ basis: 'AllTenants', averageScore: 180 }],
  controlScores: [{ controlName: 'X', score: 1 }],
});
check('score_date is the UTC date part of createdDateTime',
  snap.scoreDate === '2026-09-05', snap.scoreDate);
check('both halves of the score survive mapping',
  snap.currentScore === 210.5 && snap.maxScore === 400,
  snap.currentScore + '/' + snap.maxScore);

const emptySnap = g.mapSnapshot({});
check('an empty snapshot maps to nulls, not zeros',
  emptySnap.currentScore === null && emptySnap.maxScore === null &&
  emptySnap.scoreDate === null,
  [emptySnap.currentScore, emptySnap.maxScore, emptySnap.scoreDate].join('/'));
check('array fields default to [] so callers need no guard',
  Array.isArray(emptySnap.controlScores) && Array.isArray(emptySnap.enabledServices),
  'ok');

const badDate = g.mapSnapshot({ createdDateTime: 'not-a-date' });
check('an unparseable date is null — never silently today',
  badDate.scoreDate === null, String(badDate.scoreDate));

check('deprecated is only ever an explicit true',
  g.mapProfile({ id: 'A' }).deprecated === false &&
  g.mapProfile({ id: 'A', deprecated: true }).deprecated === true,
  'ok');

// ── Adapter behaviour asserted over source ─────────────────────────────────

section('adapter — credential handling and honest degradation (source-level)');

check('the client secret is read from api_key, the encrypted column',
  /config\.api_key/.test(adapterCode),
  'reuses the one encrypted credential path');

check('the token cache is NOT keyed by the secret',
  /function cacheKey/.test(adapterCode) && !/cacheKey[\s\S]{0,200}api_key/.test(adapterCode),
  'keyed by authority + directory + client id');

check('a 401 retries exactly once, then surfaces',
  /retriedAuth/.test(adapterCode) && /!retriedAuth/.test(adapterCode),
  'bounded — a loop would lock the app registration');

check('429 throttling honours Retry-After',
  /retry-after/i.test(adapterCode) && /retryAfterMs/.test(adapterCode), 'present');

check('the Retry-After sleep is bounded',
  /MAX_RETRY_AFTER_MS/.test(adapterCode), 'a sync must not park indefinitely');

check('paging follows @odata.nextLink verbatim rather than rebuilding it',
  /@odata\.nextLink/.test(adapterCode), 'skiptoken is opaque');

check('paging is bounded by MAX_PAGES', /MAX_PAGES/.test(adapterCode), 'present');

check('a truncated pull is reported as truncated, not as a complete one',
  /truncated/.test(adapterCode), 'present');

check('403 is annotated with the application-vs-delegated cause',
  /statusCode === 403/.test(adapterCode) && /APPLICATION/.test(adapterJs),
  'the most common misconfiguration is named');

check('an error body is truncated before it can reach a stored sync message',
  /slice\(0, ?300\)/.test(adapterCode), 'capped');

check('a failed profile fetch does not fail the whole sync',
  /catch[\s\S]{0,200}Control profiles could not be read/.test(adapterJs),
  'the headline score still stores, with a warning');

check('testConnection reads a real record, not just a token',
  /secureScores\?\$top=1/.test(adapterCode),
  'a delegated grant authenticates and then 403s on read');

check('testConnection echoes the directory id for the operator to check',
  /azureTenantId/.test(adapterCode) && /right client/.test(adapterJs),
  'a wrong-directory credential is otherwise undetectable');

// ── Server wiring ──────────────────────────────────────────────────────────

section('server wiring (source-level — Postgres is unreachable here)');

check('ms_graph is a known provider',
  /MSGRAPH_PROVIDER = 'ms_graph'/.test(srvCode) &&
  /KNOWN_PROVIDERS[\s\S]{0,200}MSGRAPH_PROVIDER/.test(srvCode), 'registered');

check('it is EXCLUDED from the generic ticket sweep',
  /provider <> ALL\(\$1::text\[\]\)[\s\S]{0,200}MSGRAPH_PROVIDER/.test(srvCode),
  'otherwise fetchTickets would be called on an adapter without one');

check('it has its own sync branch',
  /provider === MSGRAPH_PROVIDER\) result = await runMsGraphSync/.test(srvCode), 'wired');

check('it has its own scheduler',
  /MSGRAPH_SYNC_INTERVAL_MS/.test(srvCode) && /runMsGraphSyncs/.test(srvCode), 'present');

check('overlapping scheduled runs are prevented',
  /msGraphSyncRunning/.test(srvCode), 'guarded');

check('the sync degrades open when the migration has not been run',
  /hasMsScoreTables/.test(srvCode), 'no 500, and no error every day');

check('the table probe caches only a POSITIVE answer',
  /_hasMsScoreTables = true;/.test(srvCode) &&
  !/_hasMsScoreTables = false;\s*\n\s*return true/.test(srvCode),
  'running the migration must not need a restart');

check('every snapshot is re-upserted — no watermark',
  /ON CONFLICT \(tenant_id, score_date\) DO UPDATE/.test(srvCode) &&
  !/MAX\(score_date\)[\s\S]{0,80}ms_secure_scores/.test(srvCode),
  'Microsoft restates history when maxScore moves');

check('controls are DELETEd for the day before insert, not merged',
  /DELETE FROM ms_secure_score_controls WHERE tenant_id = \$1 AND score_date = \$2/.test(srvCode),
  'a retired control must vanish, not linger at its last score');

check('a directory mismatch is detected and warned about',
  /DIRECTORY MISMATCH/.test(serverJs) && /verified_azure_tenant_id/.test(srvCode),
  'one client must never see another\'s posture');

check('a mismatch warns rather than refusing — a human adjudicates',
  /warnings\.push\('DIRECTORY MISMATCH/.test(serverJs), 'non-fatal by design');

// Either form: the Test branch now builds one config object for Secure Score
// and Managed Identity together, and assigns the field rather than spreading it.
check('the verified directory is recorded on a successful Test',
  /verified_azure_tenant_id(: |\s*=\s*)probe\.azureTenantId/.test(srvCode), 'stored');

check('a warning does not report as a clean "ok" sync',
  /warnings\.length \? 'partial' : 'ok'/.test(srvCode), 'honest status');

// ── The separation from our composite ──────────────────────────────────────

section('Microsoft\'s score is never folded into ours');

check('a dedicated read route exists',
  /app\.get\('\/api\/ms-secure-score'/.test(srvCode), 'separate endpoint');

check('lib/secure-score.js does not read the Microsoft tables',
  !/ms_secure_score/.test(fs.readFileSync(path.join(ROOT, 'lib', 'secure-score.js'), 'utf8')),
  'the composite is untouched');

check('the composite route does not query the Microsoft tables',
  !/\/api\/secure-score'[\s\S]{0,4000}ms_secure_scores/.test(srvCode),
  'reported alongside, not inside');

check('the migration explains why it is not the secure_scores table',
  /denominator|maxScore/i.test(migration), 'documented');

check('both halves are stored, never a bare percentage',
  /current_score/.test(sqlCode) && /max_score/.test(sqlCode) &&
  !/\bpercentage\s+NUMERIC/.test(sqlCode),
  'a percentage alone cannot be trended across a maxScore change');

check('control_state is stored verbatim rather than collapsed into the score',
  /control_state\s+VARCHAR/.test(sqlCode), 'ThirdParty and Ignored survive');

check('per-tenant isolation is enforced by the schema',
  (sqlCode.match(/tenant_id\s+INT\s+NOT NULL REFERENCES tenants\(id\) ON DELETE CASCADE/g) || []).length === 2,
  'both tables');

check('snapshots are unique per tenant per day',
  /UNIQUE \(tenant_id, score_date\)/.test(sqlCode), 'upsert key');

// ── The read route's exclusions ────────────────────────────────────────────

section('remediation list — what is excluded, and why');

check('ThirdParty and Ignored are excluded from the gap list',
  /c\.controlState === 'ThirdParty' \|\| c\.controlState === 'Ignored'/.test(srvCode),
  'never tell a client to buy what they already have');

check('deprecated controls are excluded',
  /c\.deprecated \|\|/.test(srvCode), 'nobody can action a retired control');

check('gap null is excluded from the list, not sorted as zero',
  /c\.gap !== null && c\.gap > 0/.test(srvCode), 'unknown is not "no gap"');

check('accepted (Ignored) controls are still RETURNED, not hidden',
  /const accepted = controls\.filter/.test(srvCode),
  'an acceptance nobody revisits is a risk nobody owns');

check('third-party controls are returned too',
  /const thirdParty = controls\.filter/.test(srvCode), 'auditable at review');

check('a category total skips controls it cannot fully measure',
  /b\.unmeasured\+\+; continue;/.test(srvCode),
  'a numerator counting what the denominator skipped is unproducible');

check('staleness is computed server-side as data, not left to the UI',
  /ageDays/.test(srvCode), 'the tab must be able to state the caveat');

check('the four empty states are distinguished',
  /not_configured/.test(srvCode) && /never_synced/.test(srvCode) &&
  /no_snapshots/.test(srvCode) && /not_migrated/.test(srvCode),
  'each needs a different action');

// ── Access control ─────────────────────────────────────────────────────────

section('access control');

check('the API prefix is mapped rather than left to pageGate\'s fail-open branch',
  P.API_PREFIX_TO_PAGE['ms-secure-score'] === 'secure-score',
  P.API_PREFIX_TO_PAGE['ms-secure-score']);

check('it grants no new page — it rides the Secure Score tab',
  P.PAGE_KEYS.indexOf('ms-secure-score') === -1, 'no new page key');

check('pageForApiPath resolves it',
  P.pageForApiPath('/ms-secure-score') === 'secure-score',
  String(P.pageForApiPath('/ms-secure-score')));

// ── Admin UI ───────────────────────────────────────────────────────────────

section('admin UI');

check('the provider is offered',
  /id:\s*'ms_graph'/.test(adminCode), 'listed');

check('the key field is relabelled as Client Secret',
  /msGraphFields[\s\S]{0,600}keyLabel: 'Client Secret'/.test(adminJs),
  'a box marked "API Key" gets the client ID pasted into it');

check('the directory ID is required',
  /Directory \(tenant\) ID is required/.test(adminJs),
  'it is a path segment of the token endpoint — nothing to default to');

check('the application ID is required',
  /Application \(client\) ID is required/.test(adminJs), 'validated');

check('the SECRET is never written into configJson',
  !/configJson[\s\S]{0,400}client_secret/.test(adminCode),
  'config_json is stored in the clear');

check('the permission requirement is stated in the form',
  /SecurityEvents\.Read\.All/.test(adminJs), 'named where it is needed');

check('the delegated-vs-application trap is called out',
  /delegated grant authenticates and then fails/.test(adminJs), 'warned');

check('verified_azure_tenant_id survives a save (it is a probe result)',
  /Object\.assign\(\{\}, existing, \{\s*azure_tenant_id/.test(adminJs),
  'dropping it would disarm the mismatch check');

check('changing the directory clears the stale verification',
  /delete body\.configJson\.verified_azure_tenant_id/.test(adminCode), 'present');

check('the Graph endpoint is prefilled rather than left to be guessed',
  /urlDefault: 'https:\/\/graph\.microsoft\.com\/v1\.0'/.test(adminCode), 'prefilled');

// ── The panel ──────────────────────────────────────────────────────────────

section('panel');

/*
 * Matched on the SCRIPT TAGS, not on the first mention of each filename.
 * A bare indexOf found a prose reference to tab-secure-score.js in an HTML
 * comment higher up the file and reported the scripts as mis-ordered — a false
 * failure, because the property is about tag order, not about where the name
 * happens to appear first.
 */
const panelTag = indexHtml.indexOf('<script src="js/ms-secure-score.js">');
const tabTag   = indexHtml.indexOf('<script src="js/tab-secure-score.js">');
check('the script is loaded before the tab that calls it',
  panelTag > -1 && tabTag > -1 && panelTag < tabTag,
  'panel@' + panelTag + ' tab@' + tabTag);

/*
 * The tab replaces #secure-score-container wholesale on every render, so any
 * markup inside it in the HTML is dead. A skeleton used to live there and had
 * already drifted out of step with the ten mounts the tab actually builds —
 * including this one. Keeping the container empty is what stops a second,
 * unrendered copy of the layout growing back.
 */
const ssContainer = indexHtml.match(
  /<div id="secure-score-container"[^>]*>([\s\S]*?)<\/div>\s*<\/section>/);
check('the secure-score container carries no dead skeleton markup',
  !!ssContainer && ssContainer[1].trim() === '',
  ssContainer ? JSON.stringify(ssContainer[1].trim().slice(0, 60)) : 'container not found');

check('the tab mounts the panel',
  /id="ms-secure-score"/.test(tabJs) && /MsSecureScorePanel\.render/.test(tabCode),
  'wired');

check('the tab guards on the module being present',
  /window\.MsSecureScorePanel\)/.test(tabCode),
  'a missing script must not take the tab down');

check('the panel never throws out to the tab',
  /try \{[\s\S]{0,120}renderPanel\(el, data\);[\s\S]{0,400}Could not be displayed/.test(panelJs),
  'a Microsoft outage must not break the client\'s own report');

check('nulls render as an em dash, not as 0',
  /return '—'/.test(panelJs), 'present');

check('points are rendered, not only a percentage',
  /ms-ss-points-val/.test(panelCode) && /points/.test(panelJs), 'both shown');

check('the panel states that it is Microsoft\'s number and not part of ours',
  /not included in, the Secure Score above/.test(panelJs), 'attributed');

check('a stale snapshot is called out rather than presented as current',
  /STALE_DAYS/.test(panelCode) && /days old/.test(panelJs), 'caveated');

check('the four empty states each get their own message',
  /not_migrated:/.test(panelCode) && /not_configured:/.test(panelCode) &&
  /never_synced:/.test(panelCode) && /no_snapshots:/.test(panelCode), 'distinguished');

check('a failing sync surfaces its message in the empty state',
  /lastSyncStatus === 'error'/.test(panelCode), 'shown');

check('exclusions are named rather than silently dropped',
  /renderExclusions/.test(panelCode) && /risk register/.test(panelJs), 'auditable');

check('every interpolated value is escaped',
  /function esc\(/.test(panelCode) && /replace\(\/&\/g, '&amp;'\)/.test(panelJs),
  'remediation text is Microsoft-supplied, not ours');

check('the wide table scrolls inside its own box',
  /ms-ss-table-wrap/.test(panelCode), 'no horizontal page scroll');

done();
