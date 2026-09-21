'use strict';

/**
 * Requests that used to outlive the reverse proxy.
 *
 * WHY THIS SUITE EXISTS
 *
 * FortiAnalyzer "Test Connection" on the pilot answered
 *
 *     ✗ HTTP 504 — the server, or a proxy in front of it, returned an error page.
 *
 * for a connection that had worked. The route verified the ADOM (three quick
 * RPCs) and then awaited the probe — six log searches and every FortiView view,
 * each an appliance task allowed two minutes, two at a time — before answering.
 * nginx closes a proxied request at sixty seconds by default, so the operator
 * got a 504 and a card still reading "Not verified yet", while the server went
 * on to finish the job with nobody watching.
 *
 * Sync Now on the rollup collectors had the same shape: up to four days of
 * searches behind one request.
 *
 * Held here:
 *
 *   1. settleWithin answers in time: the result if the work is quick, a
 *      pending marker if it is not, and a fast failure passed straight through.
 *   2. Late failures are caught — an unhandled rejection would kill the server.
 *   3. Test answers without awaiting the probe, and the probe's late result
 *      cannot overwrite a newer save or land on a different ADOM.
 *   4. Sync Now's window is under the common proxy limits, and the pages read a
 *      202 as "still running" rather than as success or failure.
 *
 *   node tests/long-requests.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('long-requests');

const { settleWithin } = require(path.join(ROOT, 'lib', 'settle-within.js'));
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

const delay = (ms, value, fail) => new Promise((resolve, reject) =>
  setTimeout(() => (fail ? reject(fail) : resolve(value)), ms));

(async () => {
  // ── 1. settleWithin ──────────────────────────────────────────────────────

  section('settleWithin answers in time');

  const quick = await settleWithin(delay(5, { ok: true, synced: 3 }), 200);
  check('quick work answers with its own result', quick.result && quick.result.synced === 3,
    JSON.stringify(quick));
  check('and is not reported as pending', !quick.pending);

  const t0 = Date.now();
  const slow = await settleWithin(delay(400, { ok: true }), 50);
  const waited = Date.now() - t0;
  check('slow work answers pending', slow.pending === true, JSON.stringify(slow));
  check('at the window, not when the work finishes', waited < 300, waited + 'ms for a 50ms window');

  let fastFailure = null;
  try { await settleWithin(delay(5, null, Object.assign(new Error('ADOM not verified'), { httpStatus: 409 })), 200); }
  catch (err) { fastFailure = err; }
  check('a fast failure is passed straight through', fastFailure && fastFailure.message === 'ADOM not verified',
    fastFailure && fastFailure.message);
  check('with its status intact, so the route still answers 409',
    fastFailure && fastFailure.httpStatus === 409);

  section('late failures cannot take the server down');

  let lateSeen = null;
  let unhandled = null;
  const onUnhandled = (err) => { unhandled = err; };
  process.on('unhandledRejection', onUnhandled);

  const lateOutcome = await settleWithin(delay(60, null, new Error('appliance went away')), 10,
    (err) => { lateSeen = err; });
  await delay(120);
  process.removeListener('unhandledRejection', onUnhandled);

  check('the request answered pending', lateOutcome.pending === true);
  check('the late failure reached the handler', lateSeen && lateSeen.message === 'appliance went away',
    lateSeen && lateSeen.message);
  check('and did not surface as an unhandled rejection', unhandled === null,
    unhandled ? unhandled.message : 'none');

  // No handler at all must still not leak an unhandled rejection.
  let unhandled2 = null;
  const onUnhandled2 = (err) => { unhandled2 = err; };
  process.on('unhandledRejection', onUnhandled2);
  await settleWithin(delay(30, null, new Error('no handler')), 5);
  await delay(80);
  process.removeListener('unhandledRejection', onUnhandled2);
  check('a late failure with no handler is still caught', unhandled2 === null,
    unhandled2 ? unhandled2.message : 'none');

  // ── 2. The FortiAnalyzer Test route ──────────────────────────────────────

  const srv = read('server.js');

  section('Test answers without waiting for the probe');

  const fazBranch = (srv.match(/\} else if \(provider === FAZ_PROVIDER\) \{[\s\S]*?\n    \} else \{/) || [''])[0];
  check('the FortiAnalyzer Test branch is found', fazBranch !== '');
  check('it still awaits the verification itself',
    /await fazAdapter\.testConnection\(cfg\)/.test(fazBranch));
  check('it does NOT await the probe — that is what outlived the proxy',
    !/await fazAdapter\.probe\(/.test(fazBranch) && /probeFortiAnalyzerInBackground\(/.test(fazBranch));
  check('verification is stored before the response',
    fazBranch.indexOf('verified_adom') < fazBranch.indexOf('return res.json'));
  check('a previous probe result is cleared with a new verification',
    /delete merged\.detected/.test(fazBranch));
  check('and the page is told the probe is still running',
    /probing: true/.test(fazBranch));

  section('the background probe cannot write stale results');

  const bg = (srv.match(/function probeFortiAnalyzerInBackground\([\s\S]*?\n\}/) || [''])[0];
  check('probeFortiAnalyzerInBackground() exists', bg !== '');
  check('it writes only while the probed ADOM is still the verified one',
    /AND config_json->>'verified_adom' = \$4/.test(bg),
    'a save to another ADOM in the meantime is not overwritten');
  check('it merges into the stored config instead of writing back an old copy',
    /config_json[\s\S]{0,60}\|\| \$1::jsonb/.test(bg) && !/JSON\.stringify\(merged\)/.test(bg));
  check('it clears the "probe running" marker when it lands',
    /- 'probe_started_at'/.test(bg));
  check('a failed probe is recorded, not swallowed',
    /detected: \{ probedAt: [^}]*error: err\.message \}/.test(bg));
  check('and nothing it does can reject unobserved',
    /\.catch\(e => console\.error/.test(bg));

  // ── 3. Sync Now ──────────────────────────────────────────────────────────

  section('Sync Now answers inside the proxy timeout');

  const win = Number((srv.match(/const SYNC_RESPOND_WITHIN_MS = (\d+) \* 1000;/) || [])[1]);
  check('the window is set', win > 0, win + 's');
  check('and sits under a 30-second proxy limit, let alone the default 60', win < 30, win + 's');
  check('every rollup collector goes through it',
    /BACKGROUND_SYNC_PROVIDERS = new Set\(\[FAZ_PROVIDER, DNSFILTER_PROVIDER, IDENTITY_SYNC_PROVIDER\]\)/.test(srv));
  check('a collection still running answers 202 pending',
    /res\.status\(202\)\.json\(\{\s*ok: true,\s*pending: true/.test(srv));
  check('settleWithin is the shared module, not a copy',
    /require\('\.\/lib\/settle-within'\)/.test(srv) && !/function settleWithin/.test(srv));

  // ── 4. The pages ─────────────────────────────────────────────────────────

  section('the pages read a 202 as running');

  const admin = read('public', 'js', 'tab-admin.js');
  check('the admin card shows pending as in progress, not as done',
    /data\.ok && data\.pending\)[\s\S]{0,200}⏳/.test(admin));
  check('pending is checked before the success branch that would print ✓',
    admin.indexOf('data.ok && data.pending') < admin.indexOf("data.ok && (providerId === 'fortianalyzer'"));
  check('a successful FortiAnalyzer Test redraws the card, so "Not verified yet" goes',
    /providerId === 'dnsfilter' \|\| providerId === 'fortianalyzer'\)\s*\{\s*setTimeout\(\(\) => renderIntegrations\(\)/.test(admin));
  check('the card says the probe is still running rather than showing nothing',
    /c\.probe_started_at && !c\.detected/.test(admin));
  check('and says so when the probe failed, without blocking collection',
    /d\.error[\s\S]{0,120}Collection does not depend on it/.test(admin));

  const ui = read('public', 'js', 'panel-ui.js');
  const sync = (ui.match(/async function syncNow\([\s\S]*?\n  \}/) || [''])[0];
  check('the tab Sync Now shows pending instead of reloading over it',
    /if \(data\.pending\)[\s\S]{0,200}return;/.test(sync) &&
    sync.indexOf('data.pending') < sync.indexOf('await reload()'));

  done();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
