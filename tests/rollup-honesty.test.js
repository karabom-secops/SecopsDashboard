'use strict';

/**
 * A panel that was never read is not a panel that read zero.
 *
 * WHY THIS SUITE EXISTS
 *
 * The Managed NDR screen on the pilot showed:
 *
 *     Threats Detected 0 · Blocked 0 · Allowed Through 0 · Attacking Sources 0
 *     Policy Denies 2,047 · VPN Login Failures 0 · Config Changes 0
 *
 * FortiAnalyzer had answered the traffic panel and nothing else. The rollup
 * rebuild returned every panel as `available: true` — with a `reason` nobody
 * read — so four unanswered panels were drawn as a quiet, well-defended
 * network. On a security screen that is the worst available wrong answer.
 *
 * Alongside it, three smaller lies on the same two screens:
 *
 *   - "✗ Rollups updated 15:26" for a sync that was REFUSED and stored nothing;
 *   - "✗ Sync failed: Unknown error" for a collection that was simply already
 *     running (and for one that ran with problems it had described exactly);
 *   - "✗ This ADOM has not been verified" left under "Verified 15:47".
 *
 *   node tests/rollup-honesty.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('rollup-honesty');

const DM = require(path.join(ROOT, 'lib', 'daily-metrics.js'));
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

/** A pool whose daily_metric holds exactly `rows` for every source asked. */
function poolOf(rowsBySource) {
  return {
    async query(sql, params) {
      if (!/FROM daily_metric/.test(sql)) throw new Error('unexpected SQL: ' + sql.slice(0, 60));
      const rows = (rowsBySource[params[1]] || []).map(r => Object.assign(
        { day: '2026-09-20', dim1: '', dim2: '', dim3: '', value: 0, value2: null, meta: null }, r));
      return { rows };
    },
  };
}

(async () => {
  // ── 1. The pilot's shape ─────────────────────────────────────────────────

  section('the pilot: traffic answered, nothing else did');

  const pilot = await DM.ndrFromRollups(poolOf({ fortigate: [
    { metric: 'traffic.decision', dim1: 'allowed', value: 90312 },
    { metric: 'traffic.decision', dim1: 'denied',  value: 2047 },
  ] }), 7, 30, 77);

  check('traffic is available', pilot.traffic.available === true);
  check('with the real deny count', pilot.traffic.data.denied === 2047, String(pilot.traffic.data.denied));
  check('threats is NOT available — it was never answered',
    pilot.threats.available === false, JSON.stringify(pilot.threats));
  check('and says why, in a reason the screen renders', pilot.threats.reason === 'not_collected');
  check('it carries no data a stat card could print as 0', pilot.threats.data === null);
  check('the VPN/admin panel is not available either', pilot.vpnAdmin.available === false);
  check('nor is geo', pilot.geo.available === false);

  // ── 2. Real zeros stay zeros ─────────────────────────────────────────────

  section('a panel read with nothing in it is a real zero');

  const quiet = await DM.ndrFromRollups(poolOf({ fortigate: [
    { metric: 'traffic.decision', dim1: 'allowed', value: 10 },
    { metric: 'traffic.decision', dim1: 'denied',  value: 0 },
    { metric: 'ips.total',   dim1: 'total',   value: 0, value2: 0 },
    { metric: 'ips.outcome', dim1: 'blocked', value: 0 },
    { metric: 'ips.outcome', dim1: 'allowed', value: 0 },
    { metric: 'vpn.outcome', dim1: 'success', value: 3 },
    { metric: 'vpn.outcome', dim1: 'failure', value: 0 },
    { metric: 'admin.login_total', dim1: 'total', value: 1 },
    { metric: 'geo.read', dim1: 'read', value: 1 },
  ] }), 7, 30, 77);

  check('threats read as zero is available', quiet.threats.available === true);
  check('and its zero is reported as zero', quiet.threats.data.total === 0);
  check('VPN read with no failures is available, failures 0',
    quiet.vpnAdmin.available === true && quiet.vpnAdmin.data.vpn.failed === 0);
  check('geo read with no countries is available — the marker proves the read',
    quiet.geo.available === true && quiet.geo.data.countries.length === 0);

  // Days collected before geo.read existed can only prove a read that found
  // countries; they must still count.
  const legacyGeo = await DM.ndrFromRollups(poolOf({ fortigate: [
    { metric: 'geo.src_country', dim1: 'ZA', value: 5 },
  ] }), 7, 30, 77);
  check('older days with countries still prove geo was read', legacyGeo.geo.available === true);

  // ── 3. The flattener writes the markers the rebuild relies on ────────────

  section('the flattener marks every panel it read');

  const bag = DM.flattenNdr({
    traffic:  { available: true, data: { allowed: 0, denied: 0, trend: [] } },
    threats:  { available: true, data: { blocked: 0, allowed: 0, total: 0, uniqueSources: 0 } },
    geo:      { available: true, data: { countries: [] } },
    vpnAdmin: { available: true, data: { vpn: { success: 0, failed: 0 }, admin: { logins: 0, failedLogins: 0, configChanges: 0 } } },
  });
  const has = m => bag.rows.some(r => r.metric === m);
  check('an empty traffic read still writes traffic.decision', has('traffic.decision'));
  check('an empty threats read still writes ips.total', has('ips.total'));
  check('an empty VPN read still writes vpn.outcome', has('vpn.outcome'));
  check('an empty geo read writes geo.read — the gap this fix closes', has('geo.read'));

  const failedBag = DM.flattenNdr({
    traffic: { available: true, data: { allowed: 1, denied: 1, trend: [] } },
    threats: { available: false, data: null, reason: 'query_error' },
    geo: { available: false }, vpnAdmin: { available: false },
  });
  check('a panel that failed writes no marker at all',
    !failedBag.rows.some(r => /^(ips|vpn|admin|geo)\./.test(r.metric)));

  // Round trip: what the flattener writes is what the rebuild reads.
  const round = await DM.ndrFromRollups(poolOf({ fortigate: failedBag.rows }), 7, 30, 77);
  check('round trip: the failed panel comes back unavailable, not zero',
    round.threats.available === false && round.traffic.available === true);

  // ── 4. Managed Identity has the same guarantee ───────────────────────────

  section('Managed Identity: an unread half is not an empty one');

  const idOnlyO365 = await DM.o365FromRollups(poolOf({
    office365: [{ metric: 'o365.signin', dim1: 'success', value: 40 }],
    'ms-graph': [],
  }), 7, 30, 55);
  check('the O365 half is available', idOnlyO365.o365.available === true);
  check('the Graph half, never read, is not — no zero alerts, no zero risky users',
    idOnlyO365.graph.available === false && idOnlyO365.graph.reason === 'not_collected');

  // ── 5. The screens and the pages ─────────────────────────────────────────

  section('"nothing collected yet" comes from what was stored, not when we tried');

  const srv = read('server.js');
  const faz = (srv.match(/async function fortiAnalyzerNdrScreen\([\s\S]*?\n\}/) || [''])[0];
  check('the NDR screen asks the collection record whether anything was stored',
    /hasCollected\(integration\.id, \[fazMetrics\.SOURCE\]\)/.test(faz));
  check('and no longer trusts last_synced_at, which a refusal also stamps',
    !/const collected = !!integration\.sync\.last_synced_at/.test(faz));
  const hc = (srv.match(/async function hasCollected\([\s\S]*?\n\}/) || [''])[0];
  check('a stored day is any run that did not error', /status <> 'error'/.test(hc));
  check('both screens map the rebuild\'s reason, not the retired one',
    !/p\.reason === 'no_data_in_range'\s*\n\s*\? \{ available: false, data: null, reason: 'not_synced'/.test(
      srv.slice(srv.indexOf('async function fortiAnalyzerNdrScreen'), srv.indexOf('function panelDays'))));

  section('in progress is not failure');

  ['FortiAnalyzer', 'Managed Identity', 'DNSFilter'].forEach((name) => {
    check(`an ${name} collection already running answers pending`,
      new RegExp(`return \\{ ok: true, pending: true,\\s*message: 'A ${name} collection for this client is already running`).test(srv));
  });
  check('none still answers ok:false for "already running"',
    !/ok: false, message: 'A [^']* sync for this client is already running/.test(srv));

  const admin = read('public', 'js', 'tab-admin.js');
  check('a failed sync shows the server\'s message, not "Unknown error"',
    /data\.error \|\| data\.message \|\| 'Unknown error'/.test(admin));
  check('pending is marked ⏳, not ✗', /if \(status === 'pending'\) return '⏳';/.test(admin));
  check('the last-sync message is escaped on every card — it carries upstream text',
    !/\$\{syncMsg\}/.test(admin) && /escHtmlInt\(syncMsg\)/.test(admin));

  section('a successful Test retires the refusal it resolved, and only that');

  const fazTest = (srv.match(/\} else if \(provider === FAZ_PROVIDER\) \{[\s\S]*?\n    \} else \{/) || [''])[0];
  check('the refusal is cleared after verification',
    /last_sync_message LIKE 'This ADOM has not been verified%'/.test(fazTest));
  check('only when it IS that refusal — a real collection result is left alone',
    /AND last_sync_status = 'error'\s*AND last_sync_message LIKE/.test(fazTest));

  const ui = read('public', 'js', 'panel-ui.js');
  const meta = (ui.match(/function renderSyncMeta\([\s\S]*?\n  \}/) || [''])[0];
  // Counted in rendered output only (`Rollups updated ${…}`): the comment above
  // the function quotes the phrase, and counting that passed for the wrong reason.
  check('"Rollups updated" is claimed only for a successful sync',
    /if \(status === 'ok'\)[\s\S]{0,120}Rollups updated \$\{/.test(meta) &&
    (meta.match(/Rollups updated \$\{/g) || []).length === 1);
  check('a failed sync shows its reason on the line, not only in a tooltip',
    /Last sync \$\{esc\(fmtDate\(sync\.last_synced_at\)\)\}`[\s\S]{0,60}short/.test(meta));
  check('not_collected is worded, and says it is not zero',
    /not_collected:\s*'[^']*this is not zero/.test(ui));

  done();
})().catch((err) => { console.error(err); process.exit(1); });
