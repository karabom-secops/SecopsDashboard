'use strict';

/**
 * The client profile: estate, services, staleness, reconciliation and history.
 *
 * WHAT THIS SUITE IS PROTECTING
 *
 * The estate decides which yardstick the Secure Score uses and how it is
 * weighted — up to about forty-five points of a number printed for a client's
 * board. The invariants below are the ones that make that defensible:
 *
 *   NULL is not 0                 "not recorded" vs "declared as none"
 *   advisory stays advisory       staleness and conflicts never move a score
 *   history records events        not button presses
 *
 * lib/estate.js is exercised behaviourally. The routes need a database, which
 * is unreachable here, so their wiring is asserted over the source — weaker,
 * and honest about it: it catches deletion and rewiring, which is the failure
 * mode that matters for a permission gate.
 *
 *   node tests/client-profile.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('client-profile');

const E = require(path.join(ROOT, 'lib', 'estate'));
const P = require(path.join(ROOT, 'lib', 'pages'));
const SS = require(path.join(ROOT, 'lib', 'secure-score'));

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const estateJs  = fs.readFileSync(path.join(ROOT, 'lib', 'estate.js'), 'utf8');
const scoreJs   = fs.readFileSync(path.join(ROOT, 'lib', 'secure-score.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const adminJs   = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-admin.js'), 'utf8');
const cpJs      = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-client-profile.js'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-client-profile.sql'), 'utf8');

/**
 * Source with comments stripped.
 *
 * Every "this no longer appears" check has to run against code, not prose: the
 * comment explaining why something was removed necessarily names the thing that
 * was removed, so the naive version of the check passes on its own
 * documentation. That has bitten this repo more than once.
 */
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlCodeOnly(sql) {
  return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1');
}

/* ══ endpointsPatched is gone, everywhere ═══════════════════════════════════ */

section('the dead field is removed, not merely unused');

check('it is out of the declared fields',
  E.DECLARED_FIELDS.indexOf('endpointsPatched') < 0, E.DECLARED_FIELDS.join(','));
check('and out of the labels', !E.FIELD_LABELS.endpointsPatched);
check('and out of the patch-population map',
  Object.keys(E.PATCH_COVER).indexOf('endpointsPatched') < 0,
  Object.keys(E.PATCH_COVER).join(','));

// Grep-based on purpose: a removal like this is exactly the kind that leaves
// one live reference behind in a file nobody thought to open.
[['lib/estate.js', estateJs], ['lib/secure-score.js', scoreJs],
 ['server.js', serverJs], ['public/index.html', indexHtml],
 ['public/js/tab-admin.js', adminJs], ['public/js/tab-client-profile.js', cpJs],
].forEach(([name, js]) => {
  check('no live reference in ' + name,
    !/endpointsPatched|endpoints_patched|estateEndpointsPatched/.test(codeOnly(js)));
});

check('the migration drops the column',
  /ALTER TABLE tenant_estate\s+DROP COLUMN IF EXISTS endpoints_patched/i
    .test(sqlCodeOnly(migration)));

/*
 * Server patch coverage survives — it was never the dead one.
 *
 * It USED to be greped for in lib/secure-score.js, where resolveWeights
 * reported it to explain the exposure relief. Weights now follow the service
 * mix and the estate scores nothing, so it no longer appears there — but
 * patchCoverage() itself is still exported and still shown on the Client
 * Profile, which is the control this check exists to protect. The grep moved
 * with it; deleting the check would have let a genuinely working feature go
 * silently.
 */
check('server patch coverage survives — it was never the dead one',
  /function patchCoverage/.test(codeOnly(estateJs)));

/* ══ NULL vs 0 ══════════════════════════════════════════════════════════════ */

section('"not recorded" and "declared as none" stay different claims');

const blank = E.resolveEstate({ servers: null, publicAssets: null, cloudTenancies: null,
                                endpoints: 40 }, {});
const zeroed = E.resolveEstate({ servers: 0, publicAssets: 0, cloudTenancies: 0,
                                 endpoints: 40 }, {});

check('blank leaves the fields null', blank.servers === null && blank.publicAssets === null);
check('zero is kept as zero, not coerced to null',
  zeroed.servers === 0 && zeroed.publicAssets === 0);
check('blank is not a declaration', blank.infraDeclared === false);
check('zero IS a declaration', zeroed.infraDeclared === true);

// The consequence, which is the reason the distinction has to survive at all.
check('an unrecorded estate cannot be measured',
  E.vulnBasis(blank, { hasScan: false, hasEdr: false }) === 'unknown',
  E.vulnBasis(blank, {}));
check('a declared-none estate with endpoints moves to the endpoint yardstick',
  E.vulnBasis(zeroed, { hasScan: false, hasEdr: false }) === 'endpoint',
  E.vulnBasis(zeroed, {}));

check('an empty string is not a zero', E.count('') === null);
check('nor is null', E.count(null) === null);
check('but "0" is', E.count('0') === 0);

/* ══ The derived value survives ═════════════════════════════════════════════ */

section('the losing half of the merge is kept');

const merged = E.resolveEstate({ endpoints: 120, users: 100 },
                               { endpoints: 50, trainedUsers: 60 });

check('declared still wins the effective value', merged.endpoints === 120);
check('and is recorded as the source', merged.sources.endpoints === 'declared');
check('but what telemetry saw is still there', merged.derived.endpoints === 50);
check('alongside what was typed', merged.declared.endpoints === 120);

// Without this, reconcile() has nothing to compare and the whole panel is
// impossible — which is precisely why it went unbuilt for so long.
check('a derived-only field records no declaration',
  E.resolveEstate({}, { endpoints: 50 }).declared.endpoints === null);

/* ══ Reconciliation reports, never adjusts ══════════════════════════════════ */

section('conflicts are raised and the declared figure is left standing');

const kinds = (e) => E.reconcile(e).map(c => c.kind);

const unmanaged = E.resolveEstate({ endpoints: 120 }, { endpoints: 50 });
check('unmanaged endpoints are found',
  kinds(unmanaged).indexOf('unmanaged-endpoints') >= 0, kinds(unmanaged).join(','));
check('and counted correctly',
  E.reconcile(unmanaged)[0].delta === -70, E.reconcile(unmanaged)[0].delta);
check('and named as unmonitored machines, not a spreadsheet error',
  /no EDR agent/.test(E.reconcile(unmanaged)[0].meaning),
  E.reconcile(unmanaged)[0].meaning);
// Severity is what decides whether this reads as a finding or as a footnote,
// and it is the one thing about this conflict that must not soften.
check('and treated as serious — these machines are unmonitored',
  E.reconcile(unmanaged)[0].severity === 'high', E.reconcile(unmanaged)[0].severity);
// THE RULE. A conflict must not quietly become a correction.
check('the effective value is STILL the declared one', unmanaged.endpoints === 120);

const bigger = E.resolveEstate({ endpoints: 40 }, { endpoints: 55 });
check('an estate larger than recorded is found the other way',
  kinds(bigger).indexOf('undeclared-endpoints') >= 0, kinds(bigger).join(','));
check('and is only informational — nothing is unprotected',
  E.reconcile(bigger)[0].severity === 'info', E.reconcile(bigger)[0].severity);

const undeclared = E.resolveEstate({ publicAssets: 3 }, { publicAssets: 9 });
check('external assets outside the inventory are found',
  kinds(undeclared).indexOf('undeclared-external') >= 0, kinds(undeclared).join(','));
check('and treated as serious — they are internet-facing',
  E.reconcile(undeclared)[0].severity === 'high');

const unscanned = E.resolveEstate({ publicAssets: 10 }, { publicAssets: 6 });
check('assets the scan is not reaching are found',
  kinds(unscanned).indexOf('unscanned-external') >= 0, kinds(unscanned).join(','));

const drift = E.resolveEstate({ users: 500 }, { trainedUsers: 50 });
check('headcount drift is found', kinds(drift).indexOf('headcount-drift') >= 0,
  kinds(drift).join(','));
// Small differences are joining and leaving, not a finding. A panel that cries
// wolf on two people is a panel nobody reads.
const nudge = E.resolveEstate({ users: 100 }, { trainedUsers: 98 });
check('but a 2% difference is treated as noise', kinds(nudge).length === 0,
  kinds(nudge).join(','));
const real = E.resolveEstate({ users: 100 }, { trainedUsers: 80 });
check('and a 20% one is not', kinds(real).indexOf('headcount-drift') >= 0);

section('agreement is not a finding');

const agreed = E.resolveEstate({ endpoints: 50, publicAssets: 6, users: 100 },
                               { endpoints: 50, publicAssets: 6, trainedUsers: 100 });
check('matching figures raise nothing', E.reconcile(agreed).length === 0,
  kinds(agreed).join(','));

// Where the value CAME FROM telemetry, the two are equal by construction and
// "the scan agrees with the scan" would be a permanent, meaningless row.
const derivedOnly = E.resolveEstate({}, { endpoints: 50, publicAssets: 6 });
check('a derived-only estate raises nothing', E.reconcile(derivedOnly).length === 0,
  kinds(derivedOnly).join(','));

/* ══ Staleness flags and nothing else ═══════════════════════════════════════ */

section('staleness is advisory — this is the check that keeps it that way');

const DAY = 86400000;
const now = new Date('2026-09-01T00:00:00Z');
const fresh = E.resolveEstate(
  { servers: 4, users: 100, updatedAt: new Date(now - 10 * DAY).toISOString() }, {});
const stale = E.resolveEstate(
  { servers: 4, users: 100, updatedAt: new Date(now - 400 * DAY).toISOString() }, {});

check('a recent estate is not flagged', E.estateAge(fresh, now).stale === false,
  E.estateAge(fresh, now).days);
check('a 400-day-old one is', E.estateAge(stale, now).stale === true,
  E.estateAge(stale, now).days);
check('the threshold is six months', E.STALE_AFTER_DAYS === 180);

// A review counts, so confirming does not require faking an edit.
const reviewed = E.resolveEstate({
  servers: 4, users: 100,
  updatedAt: new Date(now - 400 * DAY).toISOString(),
  reviewedAt: new Date(now - 5 * DAY).toISOString(),
}, {});
check('a recent review clears the flag on an old edit',
  E.estateAge(reviewed, now).stale === false, E.estateAge(reviewed, now).days);

/*
 * An estate nobody ever recorded is absent, not stale. Flagging it would send
 * an analyst hunting for a number to re-confirm that was never there.
 *
 * The fixture has to be a row that EXISTS with an old timestamp and nothing
 * declared — somebody who opened the form and saved it blank. Testing this with
 * `resolveEstate(null, {})` proves nothing: that has no timestamp either, so
 * the date check alone would pass it and the guard could be deleted unnoticed.
 */
const blankButSaved = E.resolveEstate(
  { updatedAt: new Date(now - 400 * DAY).toISOString() }, {});
check('a row saved blank 400 days ago carries a timestamp',
  !!blankButSaved.updatedAt && blankButSaved.anyDeclared === false);
check('but is reported as absent, not stale',
  E.estateAge(blankButSaved, now).stale === false,
  JSON.stringify(E.estateAge(blankButSaved, now)));

/*
 * THE ONE THAT MATTERS MOST.
 *
 * If staleness ever becomes a scoring input, it will arrive as a small, sensible
 * change — discount an old declaration, weight it down a little. This is the
 * check that stops it: the score for a fresh estate and a 400-day-old identical
 * one must be indistinguishable, byte for byte.
 */
const scoreArgs = (est) => SS.calculateSecureScore(
  { summary: { critical: 1, high: 2, medium: 3, low: 4 } },
  { upload: { total_users: 100, total_incomplete: 10 } },
  { upload: { total_tickets: 10, resolved_count: 9, avg_resolution_hours: 12 } },
  { estate: est });

const freshScore = JSON.stringify(scoreArgs(fresh));
const staleScore = JSON.stringify(scoreArgs(stale));
check('a stale estate scores EXACTLY the same as a fresh one',
  freshScore === staleScore,
  'fresh=' + JSON.parse(freshScore).composite + ' stale=' + JSON.parse(staleScore).composite);

// And the same for a conflict: reconciliation must not reach the score either.
const clean    = E.resolveEstate({ servers: 4, users: 100, endpoints: 50 }, { endpoints: 50 });
const conflicted = E.resolveEstate({ servers: 4, users: 100, endpoints: 50 }, { endpoints: 5 });
check('a conflicted estate scores the same as an agreeing one',
  JSON.stringify(scoreArgs(clean)) === JSON.stringify(scoreArgs(conflicted)));
check('even though the conflict IS reported',
  E.reconcile(conflicted).length > 0, kinds(conflicted).join(','));

/* ══ Gaps name a real cost ══════════════════════════════════════════════════ */

section('gaps are read off the engine, not invented');

const gapKeys = (e, o) => E.profileGaps(e, o || {}).map(g => g.key);

const nothing = E.resolveEstate(null, {});
check('an unrecorded estate leads with the zero-score gap',
  gapKeys(nothing).indexOf('vuln-basis') >= 0, gapKeys(nothing).join(','));
check('and says the component scores zero, not "unknown"',
  /scores 0/.test(E.profileGaps(nothing, {})[0].cost),
  E.profileGaps(nothing, {})[0].cost);
check('it is the most serious one', E.profileGaps(nothing, {})[0].severity === 'high');

// The gap must track the engine's actual decision, not a hand-copied condition.
check('a scan makes the basis known, so the gap disappears',
  gapKeys(nothing, { hasScan: true }).indexOf('vuln-basis') < 0,
  gapKeys(nothing, { hasScan: true }).join(','));

check('a missing headcount is named',
  gapKeys(E.resolveEstate({ servers: 0, publicAssets: 0, cloudTenancies: 0, endpoints: 5 },
                          {}), { hasEdr: true }).indexOf('users') >= 0);
check('unrecorded managed patching is named only when there are servers',
  gapKeys(E.resolveEstate({ servers: 10 }, {}), { hasScan: true }).indexOf('serversPatched') >= 0 &&
  gapKeys(E.resolveEstate({ servers: 0 }, {}),  { hasScan: true }).indexOf('serversPatched') < 0);
check('an unrecorded awareness programme is named while nothing is measured',
  gapKeys(nothing, {}).indexOf('awarenessProgram') >= 0);
check('but not once training records exist',
  gapKeys(nothing, { awarenessMeasured: true }).indexOf('awarenessProgram') < 0);

/* ══ The gate ═══════════════════════════════════════════════════════════════ */

section('the profile is configuration, and gated as such');

check('the page exists in the catalogue',
  P.PAGES.some(p => p.key === 'client-profile' && p.type === 'tab'));
check('the API prefix maps to it',
  P.API_PREFIX_TO_PAGE['client-profile'] === 'client-profile');

check('admins may write it', P.ROLE_DEFAULTS.admin['client-profile'] === 'write');
check('superadmins may write it', P.ROLE_DEFAULTS.superadmin['client-profile'] === 'write');

// VIEWER_TABS is an allowlist by exclusion, so a new key is granted to these
// two silently unless somebody remembers. This is the check for "somebody
// remembered".
/*
 * EVERY non-admin role, derived from the catalogue rather than listed.
 *
 * These were three hand-written checks naming sales, readonly and client. When
 * the `analyst` role was added later, nothing here noticed — and a mutation
 * aimed at readonly silently landed on analyst instead and escaped, because no
 * assertion covered it. A list of roles written by hand goes stale the moment
 * somebody adds one; ROLES does not.
 */
P.ROLES.filter(r => r !== 'superadmin' && r !== 'admin').forEach((r) => {
  check(r + ' gets nothing', P.ROLE_DEFAULTS[r]['client-profile'] === 'none',
    P.ROLE_DEFAULTS[r]['client-profile']);
});

// An undefined level is not the same as 'none' — it resolves through a
// different path and is easy to leave behind when a role is added.
P.ROLES.forEach((r) => {
  const missing = P.PAGE_KEYS.filter(k => P.ROLE_DEFAULTS[r][k] === undefined);
  check(r + ' has a level for every page', missing.length === 0, missing.join(','));
});

/* ══ Route wiring ═══════════════════════════════════════════════════════════ */

section('one write path, and it is the audited one');

const srvCode = codeOnly(serverJs);

check('GET /api/client-profile is mounted',
  /app\.get\('\/api\/client-profile'/.test(srvCode));
check('PUT /api/client-profile is mounted',
  /app\.put\('\/api\/client-profile'/.test(srvCode));
check('the review endpoint is mounted',
  /app\.post\('\/api\/client-profile\/review'/.test(srvCode));
check('the history endpoint is mounted',
  /app\.get\('\/api\/client-profile\/history'/.test(srvCode));

// The retired route. Two writers to one column where only one is audited is an
// audit trail with a hole in it.
check('PUT /api/tenants/:id/services is gone',
  !/app\.put\('\/api\/tenants\/:id\/services'/.test(srvCode));
// ...but the READ stays: tab-reports.js defaults its section toggles from it.
check('GET /api/tenants/:id/services survives',
  /app\.get\('\/api\/tenants\/:id\/services'/.test(srvCode));

check('the old estate routes are gone',
  !/\/api\/secure-score\/estate/.test(srvCode));

check('estate and services are written in one transaction',
  /BEGIN'\)[\s\S]{0,1600}UPDATE tenants SET services[\s\S]{0,400}COMMIT/.test(srvCode));

// Writing on every save would make the table a log of button presses and bury
// the three edits that mattered under three hundred that did not.
check('a save that changes nothing writes nothing',
  /if \(!Object\.keys\(diff\)\.length\)[\s\S]{0,200}changed: false/.test(srvCode));

check('the score is snapshotted either side of a change',
  /const scoreBefore = await compositeScoreFor/.test(srvCode) &&
  /const scoreAfter = await compositeScoreFor/.test(srvCode));

/*
 * A missing optional column must not zero every client's vulnerability score.
 *
 * loadEstate swallows query errors and degrades to "no estate declared", which
 * is right for an un-migrated table and catastrophic as the consequence of
 * adding one column — so reviewed_at is probed, not named unconditionally.
 */
// Asserted over EVERY site, not one of them. There are two SELECTs that want
// the column — loadEstate and buildClientProfile — and an earlier version of
// this check passed while loadEstate named it unconditionally, because the
// other site still had a probe. loadEstate is the dangerous one: its catch is
// what turns a bad column name into "no estate declared" for every client.
const unguardedSelect = /updated_at,\s*reviewed_at/.test(srvCode);
const guardedCount = (srvCode.match(/NULL::timestamptz AS reviewed_at/g) || []).length;
check('no SELECT names reviewed_at unconditionally', !unguardedSelect);
check('both SELECTs go through the probe', guardedCount === 2, guardedCount);
check('the probe caches only a positive answer',
  /if \(_estateReviewedColumn\) return true;/.test(srvCode));

check('score inputs are loaded once and shared',
  /async function loadScoreInputs\(tenantId\)/.test(srvCode) &&
  /await loadScoreInputs\(tenantId\)/.test(srvCode));
check('a score that cannot be computed does not fail the save',
  /catch \(err\) \{[\s\S]{0,200}score snapshot skipped[\s\S]{0,80}return null;/.test(srvCode));

/* ══ The browser module ═════════════════════════════════════════════════════ */

section('the tab');

check('it is loaded by index.html', /js\/tab-client-profile\.js/.test(indexHtml));
check('its host element exists', /id="tab-client-profile"/.test(indexHtml));
check('its stylesheet is linked', /css\/client-profile\.css/.test(indexHtml));

/* ══ Reached through the Admin tab ══════════════════════════════════════════
 *
 * The client profile is a sub-tab of Admin rather than a top-level nav entry.
 * That is a change to WHERE THE LINK IS and nothing else: it remains its own
 * page key with its own access level, and the checks below exist because the
 * obvious way to implement this — gate the sub-tab on `admin` — would silently
 * hand every client's estate and service mix to anyone who can open that tab.
 */
section('it lives inside the Admin tab, without inheriting its access');

const appJs2 = fs.readFileSync(path.join(ROOT, 'public', 'js', 'app.js'), 'utf8');
// Comments sit between a sub-tab's key and its guard, so the spans below are
// measured over code with the comments stripped — otherwise the check is really
// asserting how long a comment is.
const adminCode = codeOnly(adminJs);

check('the standalone nav entry is gone',
  !/data-tab="client-profile"/.test(indexHtml));
check('its host sits inside the admin panel',
  (() => {
    const a = indexHtml.indexOf('<section id="tab-admin"');
    const b = indexHtml.indexOf('</section>', a);
    return indexHtml.slice(a, b).indexOf('id="tab-client-profile"') >= 0;
  })());
check('inside the client-profile pane specifically',
  /id="adminPane-client-profile"[\s\S]{0,600}id="tab-client-profile"/.test(indexHtml));

/*
 * A per-page override can grant client-profile and withhold admin. Without
 * data-tab-also that user holds a page with no route to it — access granted on
 * paper and unreachable in the product.
 */
check('the Admin nav entry stays visible for a client-profile-only user',
  /data-tab="admin" data-tab-also="client-profile"/.test(indexHtml));
check('and auth.js honours that attribute',
  /dataset\.tabAlso/.test(codeOnly(fs.readFileSync(path.join(ROOT, 'public', 'js', 'auth.js'), 'utf8'))));
check('by showing the item when ANY listed key is viewable',
  /keys\.some\(k => window\.canView\(k\)\)/.test(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'auth.js'), 'utf8')));

// THE ONE THAT MATTERS: the sub-tab is gated on its own key, not on 'admin'.
check('the sub-tab is gated on canView(\'client-profile\')',
  /key: 'client-profile'[\s\S]{0,160}window\.canView\('client-profile'\)/.test(adminCode),
  (adminCode.match(/key: 'client-profile'[\s\S]{0,160}/) || [''])[0].slice(0, 160));
check('and NOT on the admin page key',
  !/key: 'client-profile'[\s\S]{0,160}canView\('admin'\)/.test(adminCode) &&
  !/key: 'client-profile'[\s\S]{0,160}canWrite\('admin'\)/.test(adminCode));
/*
 * showSubtab re-checks allowed() rather than trusting its argument: the key can
 * arrive from a stale button or a remembered value, and a pane is only as
 * closed as the last thing that opened it.
 */
check('opening a sub-tab re-checks permission rather than trusting the caller',
  /function showSubtab[\s\S]{0,300}availableSubtabs\(\)/.test(adminJs));
check('and an unavailable key falls back to one the user has',
  /\|\| available\[0\]/.test(adminJs));

check('app.js no longer treats it as a top-level panel',
  !/'client-profile':\s*document\.getElementById/.test(codeOnly(appJs2)));
check('so renderTab cannot hide the admin panel to show a div inside it',
  !/target === 'client-profile'/.test(codeOnly(appJs2)));
/*
 * A superadmin switching organisation must re-read the profile. That path now
 * runs through renderAdmin, and this is editable data — the worst thing on this
 * dashboard to leave on screen labelled as the wrong client.
 */
check('renderAdmin re-renders the visible sub-tab',
  /window\.renderAdmin = function \(\) \{[\s\S]{0,160}showSubtab\(activeSubtab\)/.test(adminJs));
check('and opening the client-profile pane loads it',
  /key === 'client-profile'[\s\S]{0,120}ClientProfileTab\.loadAndRender\(\)/.test(adminJs));

section('the three sub-tabs the Admin tab offers');

['integrations', 'users', 'client-profile'].forEach((k) => {
  check("there is a '" + k + "' sub-tab", new RegExp("key: '" + k + "'").test(adminJs));
  check('and a pane for it', indexHtml.indexOf('id="adminPane-' + k + '"') >= 0);
});
// Every pane starts hidden, or first paint flashes sections the user may not have.
check('every pane starts hidden',
  (indexHtml.match(/id="adminPane-[a-z-]+" role="tabpanel"[\s\S]{0,120}?hidden>/g) || []).length === 3,
  (indexHtml.match(/id="adminPane-[a-z-]+" role="tabpanel"[\s\S]{0,120}?hidden>/g) || []).length);
check('integrations asks for write, not merely view',
  /key: 'integrations'[\s\S]{0,120}window\.canWrite\('admin'\)/.test(adminCode));

// Moved, not duplicated. Two editors for one value is how they drift apart.
check('the estate card is gone from the admin tab',
  !/id="estateSection"/.test(indexHtml) && !/id="estateServers"/.test(indexHtml));
check('the services card is gone from the admin tab',
  !/id="servicesSection"/.test(indexHtml));
check('and their code is gone from tab-admin.js',
  !/handleSaveEstate|loadServices|saveServices/.test(codeOnly(adminJs)));

/*
 * THE BASE PATH.
 *
 * The app is served under /secops/ and nginx strips the prefix. Every request
 * has to be built from <base href>, and this module originally read a
 * `window.apiUrl` that does not exist — each module has its own local copy —
 * so its "fallback" of '/api/' + path was the only branch that ever ran. It
 * asked nginx for /api/client-profile, got a 404, and the healthy API looked
 * broken.
 *
 * Driven for real: a stub <base> of /secops/, a stub fetch, and the URL read
 * back off the call. A grep for `document.querySelector('base')` would pass on
 * a module that then ignored the result.
 */
const sandbox = { console, window: null, document: null };
sandbox.window = sandbox;
sandbox.document = {
  getElementById: () => null,
  querySelectorAll: () => [],
  querySelector: (sel) => (sel === 'base'
    ? { href: 'https://secops.reflex.co.za/secops/' } : null),
};
let fetched = [];
sandbox.fetch = (url) => {
  fetched.push(url);
  return Promise.resolve({
    ok: true, status: 200,
    json: () => Promise.resolve({ tenantId: 2, available: {}, catalogue: [], history: [] }),
  });
};
vm.createContext(sandbox);
vm.runInContext(cpJs, sandbox);
const CP = sandbox.window.ClientProfileTab;

check('the module loads and exports a renderer',
  !!CP && typeof CP.loadAndRender === 'function');

section('every request keeps the /secops/ base path');

const BASED = 'https://secops.reflex.co.za/secops/api/';

// Synchronous, through the module's own builder. Inferring the URL from a
// stubbed fetch works but only covers the paths a test happens to drive.
check('the URL builder keeps the base path',
  CP._apiUrl('client-profile') === BASED + 'client-profile',
  CP._apiUrl('client-profile'));
// The exact shape of the bug: the prefix silently dropped.
check('and never resolves to the bare /api/ root',
  !/^\/api\//.test(CP._apiUrl('client-profile')));
// codeOnly, because the comment recording this bug necessarily names the
// thing it warns about — the check failed on its own documentation.
check('no module-local fallback invents a path',
  !/window\.apiUrl/.test(codeOnly(cpJs)));
check('the base is derived the way every other module derives it',
  /document\.querySelector\('base'\)/.test(codeOnly(cpJs)));

/*
 * And behaviourally, over EVERY request the page makes — not just the load.
 * The first version of this checked only the initial GET, so hard-coding a
 * bare '/api/...' into the save or the review went unnoticed.
 */
sandbox.document.getElementById = () => ({ innerHTML: '', hidden: false, textContent: '',
                                           value: '', disabled: false });
sandbox.document.querySelectorAll = () => [];

let asyncRan = false;
const urlChecks = (async () => {
  fetched = [];
  await CP.loadAndRender();
  check('GET goes to the based URL', fetched[0] === BASED + 'client-profile', fetched[0]);

  fetched = [];
  await CP._handleSave();
  check('PUT goes to the based URL', fetched[0] === BASED + 'client-profile', fetched[0]);

  fetched = [];
  await CP._handleReview();
  check('POST review goes to the based URL',
    fetched[0] === BASED + 'client-profile/review', fetched[0]);

  asyncRan = true;
})();

/*
 * done() calls process.exit, so a suite that reaches it before the async block
 * finishes reports green having never made those assertions. That is a
 * fabricated pass, and it is invisible: the output simply has fewer lines.
 *
 * An exit hook is the only thing that still runs at that point.
 */
process.on('exit', () => {
  if (!asyncRan) {
    console.log('FAIL  the async URL checks never ran — the suite exited early');
    process.exitCode = 1;
  }
});

section('the Secure Score tab carries the caveat, not a correction');

const ssJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');

// BOTH sites, counted. estateAge(estate) appears in buildClientProfile as well
// as in the /api/secure-score payload, and an earlier version of this check
// matched the wrong one — deleting it from the score payload left the check
// green off the profile's copy.
const ageSites = (srvCode.match(/estateLib\.estateAge\(estate\)/g) || []).length;
const conflictSites = (srvCode.match(/estateLib\.reconcile\(estate\)/g) || []).length;
check('the estate age reaches both the profile and the score payload',
  ageSites === 2, ageSites);
check('and so do the conflicts', conflictSites === 2, conflictSites);

/*
 * Rendered for real, not grepped.
 *
 * The first version of these checks searched tab-secure-score.js for the
 * caveat's wording. Deleting the condition that emits it left every string in
 * the file and every check passing, which is a test asserting that a sentence
 * exists rather than that a user sees it.
 */
const ssBox = { console };
ssBox.window = ssBox;
ssBox.document = { getElementById: () => null, querySelectorAll: () => [],
                   addEventListener: () => {} };
vm.createContext(ssBox);
vm.runInContext(ssJs, ssBox);
const SST = ssBox.window.SecureScoreTab;

function estateNoteHtml(estatePayload, weights) {
  const el = { hidden: true, className: '', innerHTML: '' };
  SST.renderEstateNote(el, {
    estate: estatePayload,
    weights: weights || {},
    components: {},
  });
  return el.hidden ? '' : el.innerHTML;
}

/*
 * The service names in the weighting sentence are escaped by the renderer, so
 * they must be authored as PLAIN TEXT. "Managed Detection &amp; Response" was
 * escaped a second time and reached the client's screen as
 * "Managed Detection &amp;amp; Response" — visible in the weighting line of
 * every MDR client's Secure Score tab.
 */
const mdrWeighting = estateNoteHtml(
  { servers: 4, users: 100, recorded: true, sources: { servers: 'declared' },
    age: { days: 3, stale: false }, conflicts: [] },
  { basis: 'services', weightedServices: ['mdr', 'vuln'],
    vulnerabilities: 0.35, awareness: 0.20, incidentResponse: 0.45 });

check('the service mix is named in the weighting sentence',
  /Managed Detection/.test(mdrWeighting), mdrWeighting.slice(-200));
check('and its ampersand is not double-escaped',
  /Managed Detection &amp; Response/.test(mdrWeighting) &&
  !/&amp;amp;/.test(mdrWeighting),
  (mdrWeighting.match(/Managed Detection[^<,.]*/) || [])[0]);

const staleNote = estateNoteHtml({
  servers: 4, users: 100, recorded: true, sources: { servers: 'declared' },
  age: { days: 400, stale: true }, conflicts: [],
});
check('a stale estate produces a visible caveat',
  /last confirmed 400 days ago/.test(staleNote), staleNote.slice(-160));
// The wording is the whole point. "Stale" beside a score invites the reader to
// assume the score was marked down for it. It was not.
check('which says the figure was used exactly as recorded',
  /used exactly as recorded/.test(staleNote) &&
  /nothing was discounted for age/.test(staleNote));

const freshNote = estateNoteHtml({
  servers: 4, users: 100, recorded: true, sources: { servers: 'declared' },
  age: { days: 3, stale: false }, conflicts: [],
});
check('a fresh estate produces no caveat at all',
  !/last confirmed/.test(freshNote), freshNote.slice(-120));

const disputedNote = estateNoteHtml({
  servers: 4, users: 100, recorded: true, sources: { servers: 'declared' },
  age: { days: 3, stale: false },
  conflicts: [{ kind: 'unmanaged-endpoints', severity: 'high' }],
});
check('a disputed figure is flagged on the score tab',
  /1 recorded figure disagrees/.test(disputedNote), disputedNote.slice(-200));
check('and it says which figure the score actually used',
  /The recorded figures were used/.test(disputedNote));

// Informational disagreements are not worth interrupting a score for.
const infoNote = estateNoteHtml({
  servers: 4, users: 100, recorded: true, sources: { servers: 'declared' },
  age: { days: 3, stale: false },
  conflicts: [{ kind: 'undeclared-endpoints', severity: 'info' }],
});
check('but an informational one is left to the profile page',
  !/disagree/.test(infoNote), infoNote.slice(-120));

// It calls window.canWrite, which auth.js defines. An invented helper name
// would silently take the always-true fallback and render an editable form for
// a user with no write access.
check('it asks the real permission helper',
  /window\.canWrite\('client-profile'\)/.test(cpJs) && !/window\.canEdit/.test(cpJs));

// Render into a stub DOM and read the markup back.
let html = '';
sandbox.document.getElementById = (id) => (id === 'tab-client-profile'
  ? { set innerHTML(v) { html = v; }, get innerHTML() { return html; } }
  : null);

const profile = {
  tenantId: 1,
  available: { estate: true, services: true, history: true },
  declared: { endpoints: 120, users: 100, servers: null, publicAssets: null,
              cloudTenancies: null, serversPatched: null, awarenessProgram: null,
              notes: '', updatedAt: '2026-08-01T00:00:00Z', reviewedAt: null },
  effective: E.resolveEstate({ endpoints: 120, users: 100 }, { endpoints: 50 }),
  summary: '120 endpoints, 100 users',
  conflicts: E.reconcile(E.resolveEstate({ endpoints: 120 }, { endpoints: 50 })),
  gaps: E.profileGaps(E.resolveEstate({ endpoints: 120 }, {}), {}),
  age: { at: '2026-08-01T00:00:00Z', days: 400, stale: true },
  services: ['mdr'],
  effectiveServices: ['mdr', 'edr', 'ndr', 'identity'],
  catalogue: [{ key: 'mdr', label: 'Managed Detection & Response', hint: '' },
              { key: 'edr', label: 'Managed EDR', hint: '' },
              { key: 'vuln', label: 'Vulnerability Management', hint: '' }],
  includes: { mdr: ['edr', 'ndr', 'identity'] },
  history: [{ id: 1, changedAt: '2026-08-01T00:00:00Z', changedBy: 'kmoloi',
              kind: 'change', diff: { endpoints: { from: null, to: 120 } },
              scoreBefore: 62, scoreAfter: 48 }],
};

CP._render(profile);

check('the declared value fills the box', /id="cp-endpoints"[^>]*value="120"/.test(html));
check('and the telemetry is shown beside it', /we can see 50/.test(html));
check('a blank field renders EMPTY, not as a zero',
  /id="cp-servers"[^>]*value=""/.test(html));
check('the conflict is on the page', /no EDR agent/.test(html));
check('the staleness banner is shown', /last confirmed 400 days ago/.test(html));
// The banner must not imply the score has been discounted, because it has not.
check('and says the figure is still being used as recorded',
  /still being used exactly as recorded/.test(html));
check('an implied service is marked included, not left unticked',
  /Managed EDR[\s\S]{0,400}included/.test(html));
check('the score movement is shown', /62 → 48/.test(html));
check('labelled as a snapshot, not a recomputed history',
  /snapshots taken when each change/.test(html));

/*
 * The base-path checks are async (they drive a real loadAndRender), so done()
 * has to wait for them. Calling done() synchronously would exit the process
 * before they ran and report a green suite that never made the assertions —
 * a fabricated pass, which is worse than a failure.
 */
urlChecks.then(done, (err) => {
  check('the base-path checks ran to completion', false, err && err.message);
  done();
});
