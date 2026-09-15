'use strict';

/**
 * FortiAnalyzer for Managed NDR — the replacement for the Wazuh route.
 *
 * Driven against a simulated FortiAnalyzer JSON-RPC endpoint that reads each
 * request the way the appliance would: tasks are created, polled to completion,
 * paged and deleted.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   the right client's ADOM      the ADOM is validated before it reaches a URL;
 *                                a wrong ADOM is a clear error; a sync against
 *                                an ADOM sharing none of the verified FortiGates
 *                                is refused; an unverified ADOM never syncs
 *   the shared appliance         tasks are always deleted, including on timeout;
 *                                concurrent tasks per appliance are capped
 *   the certificate              a changed TLS fingerprint stops a sync; only
 *                                Test may re-pin it
 *   not recorded is not none     a panel that cannot be answered is unavailable
 *                                with a reason; a table the source cannot
 *                                produce says so; sampled counts are flagged
 *   the tab needs no rewrite     FortiAnalyzer output survives the same
 *                                flatten → store → rebuild path as Wazuh's
 *   no double counting           rollups are read per integration, so Wazuh and
 *                                FortiAnalyzer running side by side do not sum
 *
 *   node tests/fortianalyzer.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('fortianalyzer');

const FAZ = require(path.join(ROOT, 'lib', 'integrations', 'fortianalyzer.js'));
const WM  = require(path.join(ROOT, 'lib', 'wazuh-metrics.js'));
const FM  = require(path.join(ROOT, 'lib', 'fortianalyzer-metrics.js'));

function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

// ── A simulated FortiAnalyzer ──────────────────────────────────────────────

function fakeFaz(overrides) {
  const opts = Object.assign({
    adom: 'client-a',
    devices: [{ name: 'FGT-HQ', sn: 'FG100F0001', platform_str: 'FortiGate-100F', os_ver: '7.4' }],
    fingerprint: 'fp-1',
    pollsToFinish: 2,
    answer: () => ({ rows: [] }),
  }, overrides || {});

  const log = [];
  const deleted = [];
  const tasks = new Map();
  let nextTid = 1;
  let open = 0;
  let maxOpen = 0;

  async function transport(cfg, body) {
    const p = body.params[0];
    log.push({ method: body.method, url: p.url, params: p, token: cfg.api_key });
    const ok = result => ({ status: 200, json: { id: body.id, jsonrpc: '2.0', result }, fingerprint: opts.fingerprint });

    if (opts.httpStatus) return { status: opts.httpStatus, json: null, fingerprint: opts.fingerprint };

    let m = /\/(\d+)$/.exec(p.url);
    if (m && body.method === 'delete') {
      deleted.push(p.url);
      const t = tasks.get(m[1]);
      if (t && !t.deleted) { t.deleted = true; open--; }
      return ok({ status: { code: 0 } });
    }

    if (opts.delayMs) await new Promise(r => setTimeout(r, opts.delayMs));

    if (p.url === '/sys/status') {
      return ok([{ status: { code: 0, message: 'OK' }, url: p.url, data: { Version: 'v7.6.6-build3481' } }]);
    }
    const dv = /^\/dvmdb\/adom\/([^/]+)(\/device)?$/.exec(p.url);
    if (dv) {
      if (dv[1] !== opts.adom) return ok([{ status: { code: -6, message: 'Object does not exist' }, url: p.url }]);
      return ok([{ status: { code: 0 }, url: p.url, data: dv[2] ? opts.devices : { name: dv[1] } }]);
    }
    if (body.method === 'add') {
      if (opts.permissionDenied && opts.permissionDenied.test(p.url)) {
        return ok({ status: { code: -11, message: 'No permission' } });
      }
      const tid = nextTid++;
      tasks.set(String(tid), { create: p, polls: 0 });
      open++;
      maxOpen = Math.max(maxOpen, open);
      return ok({ tid });
    }
    if (m && body.method === 'get') {
      const t = tasks.get(m[1]);
      if (!t) return ok({ status: { code: -6, message: 'no such task' } });
      t.polls++;
      if (opts.neverFinish || t.polls < opts.pollsToFinish) return ok({ percentage: 40 });
      const a = opts.answer(t.create, p) || {};
      if (a.error) return ok({ status: { code: -1, message: a.error } });
      const rows = a.rows || [];
      const off = p.offset || 0;
      const lim = p.limit || 1000;
      return ok({
        percentage: 100,
        'total-count': a.total != null ? a.total : rows.length,
        data: rows.slice(off, off + lim),
        status: { code: 0, message: 'succeeded' },
      });
    }
    return ok([{ status: { code: -6, message: 'unknown ' + p.url } }]);
  }

  return { transport, log, deleted, tasks, stats: () => ({ open, maxOpen }) };
}

const noSleep = async () => {};
const cfgFor = (fake, over) => Object.assign({
  base_url: 'https://faz.example.test',
  api_key: 'tok-123',
  adom: 'client-a',
  timeZone: 'Africa/Johannesburg',
  transport: fake.transport,
  sleep: noSleep,
}, over || {});

// ── A day of telemetry ─────────────────────────────────────────────────────

const ATTACKS = [
  { attack: 'Apache.Log4j.Error.Log.Remote.Code.Execution', severity: 'critical', action: 'dropped',
    srcip: '45.1.1.1', srccountry: 'Netherlands', dstip: '10.0.1.10' },
  { attack: 'Apache.Log4j.Error.Log.Remote.Code.Execution', severity: 'critical', action: 'detected',
    srcip: '45.1.1.2', srccountry: 'Netherlands', dstip: '10.0.1.11' },
  { attack: 'Nmap.Script.Scanner', severity: 'low', action: 'reset', srcip: '45.1.1.1', dstip: '10.0.1.10' },
];
const VPN = [
  { action: 'ssl-login-fail', user: 'jdoe', remip: '41.0.0.1', reason: 'sslvpn_login_permission_denied', logdesc: 'SSL VPN login fail' },
  { action: 'ssl-login-fail', user: 'jdoe', remip: '41.0.0.2', logdesc: 'SSL VPN login fail' },
  { action: 'tunnel-up', user: 'asmith', logdesc: 'SSL VPN tunnel up' },
  { action: 'tunnel-stats', logdesc: 'SSL VPN statistics' },
];
const SYS = [
  { logid: '0100032001', user: 'admin', ui: 'https(10.0.0.2)', action: 'login', status: 'success' },
  { logid: 100032002, user: 'admin', ui: 'ssh(203.0.113.9)', action: 'login', status: 'failed' },
  { logid: '0100044547', user: 'admin', cfgpath: 'firewall.policy', action: 'Edit' },
  { logid: '0100032003', user: 'admin', action: 'logout' },
];

function dayAnswer(over) {
  const o = over || {};
  return (create) => {
    const url = create.url;
    if (/\/fortiview\//.test(url)) {
      if (/top-sources/.test(url)) return { rows: [{ srcip: '10.0.0.5', srccountry: 'South Africa', sessions: 900 }, { srcip: '10.0.0.9', sessions: 120 }] };
      if (/top-destinations/.test(url)) return { rows: [{ dstip: '8.8.8.8', sessions: 400 }] };
      if (/policy-hits/.test(url)) return { rows: [{ policyid: 12, policyname: 'LAN-to-WAN', hits: 3000 }] };
      if (/top-countries/.test(url)) return o.geo || { rows: [{ srccountry: 'Russian Federation', sessions: 50 }] };
    }
    const lt = create.logtype;
    const f = create.filter;
    if (lt === 'traffic') return { total: f === 'action==deny' ? 340 : 12000, rows: [] };
    if (lt === 'attack') return o.attack || { rows: ATTACKS };
    if (lt === 'virus') return { rows: [{ virus: 'EICAR_TEST_FILE' }] };
    if (lt === 'webfilter') return { rows: [{ catdesc: 'Malicious Websites' }, { catdesc: 'Malicious Websites' }] };
    if (lt === 'app-ctrl') return { rows: [{ app: 'BitTorrent', appcat: 'P2P' }] };
    if (lt === 'event' && f === 'subtype==vpn') return { rows: VPN };
    if (lt === 'event' && f === 'subtype==system') return { rows: SYS };
    return { rows: [] };
  };
}

(async function main() {

  // ── Connection ───────────────────────────────────────────────────────────

  section('Test connection names what it found');
  {
    const fake = fakeFaz();
    const info = await FAZ.testConnection(cfgFor(fake));
    check('it succeeds', info.ok === true);
    check('it reports the appliance version', info.version === 'v7.6.6-build3481', info.version);
    check('it lists the ADOM\'s FortiGates for the operator to check',
      info.devices.length === 1 && info.devices[0].sn === 'FG100F0001' && /FGT-HQ/.test(info.message), info.message);
    check('it pins the certificate it saw', info.tlsFingerprint === 'fp-1');
    check('every call carries the API token', fake.log.every(e => e.token === 'tok-123'));
    check('every ADOM url is this client\'s ADOM',
      fake.log.filter(e => /\/adom\//.test(e.url)).every(e => /\/adom\/client-a(\/|$)/.test(e.url)));

    const wrong = fakeFaz({ adom: 'client-b' });
    let msg = '';
    try { await FAZ.testConnection(cfgFor(wrong)); } catch (err) { msg = err.message; }
    check('a wrong or forbidden ADOM is a clear error', /ADOM "client-a" was not found, or this API user is not permitted/.test(msg), msg);

    const bad = fakeFaz();
    let badMsg = '';
    try { await FAZ.testConnection(cfgFor(bad, { adom: '../../sys/admin' })); } catch (err) { badMsg = err.message; }
    check('an ADOM that is not a plain name is refused', /invalid/.test(badMsg), badMsg);
    check('before any request is made', bad.log.length === 0, bad.log.length);
    ['root', 'client_a-01'].forEach(a => check('"' + a + '" is a valid ADOM', FAZ.ADOM_RE.test(a)));
    ['', 'a/b', 'a b', 'a%2Fb', "a'", 'x'.repeat(65)].forEach(a =>
      check('refused ADOM: ' + JSON.stringify(a.slice(0, 12)), !FAZ.ADOM_RE.test(a)));

    let noKey = '';
    try { await FAZ.testConnection(cfgFor(fakeFaz(), { api_key: '' })); } catch (err) { noKey = err.message; }
    check('a missing token is named', /token is required/.test(noKey), noKey);

    let rejected = null;
    try { await FAZ.testConnection(cfgFor(fakeFaz({ httpStatus: 401 }))); } catch (err) { rejected = err; }
    check('a rejected token says so', rejected && rejected.notPermitted && /rejected the API token/.test(rejected.message));
  }

  section('the certificate is pinned');
  {
    const fake = fakeFaz({ fingerprint: 'fp-new' });
    const cfg = cfgFor(fake, { tlsFingerprint: 'fp-old' });
    let syncErr = null;
    try { await FAZ.checkDevices(cfg, [{ sn: 'FG100F0001' }]); } catch (err) { syncErr = err; }
    check('a changed certificate stops the sync', syncErr && syncErr.certChanged === true, syncErr && syncErr.message);
    const info = await FAZ.testConnection(cfg);
    check('Test is allowed to re-pin it, and says it did',
      info.tlsFingerprint === 'fp-new' && /re-pinned/.test(info.message), info.message);
  }

  section('a sync refuses the wrong ADOM');
  {
    check('no verified list: nothing to compare', FAZ.compareDevices([], [{ sn: 'A' }]).ok === true);
    const none = FAZ.compareDevices([{ sn: 'FG999' }], [{ sn: 'FG100F0001' }]);
    check('no overlap with the verified FortiGates is refused', none.ok === false && /stopped/.test(none.error), none.error);
    const some = FAZ.compareDevices([{ sn: 'A' }, { sn: 'B' }], [{ sn: 'A' }, { sn: 'C' }]);
    check('a partial change is allowed but reported', some.ok === true && /added: C/.test(some.warning) && /removed: B/.test(some.warning), some.warning);

    let err = null;
    try { await FAZ.checkDevices(cfgFor(fakeFaz()), [{ sn: 'SOMEONE-ELSES' }]); } catch (e) { err = e; }
    check('checkDevices throws on a mismatch', err && err.deviceMismatch === true);
  }

  // ── Tasks ────────────────────────────────────────────────────────────────

  section('tasks are polled, paged and always deleted');
  {
    const rows = Array.from({ length: 2500 }, (_, i) => ({ srcip: '10.0.0.' + (i % 250) }));
    const fake = fakeFaz({ answer: () => ({ rows }) });
    const r = await FAZ.logSearch(cfgFor(fake), 'traffic', FAZ.dayRange('2026-09-14'), '');
    check('every row is read across pages', r.rows.length === 2500 && r.total === 2500 && !r.truncated, r.rows.length);
    const gets = fake.log.filter(e => e.method === 'get');
    check('the task was polled before it was read', gets.length >= 4, gets.length + ' gets');
    check('pages advance by offset', gets.map(g => g.params.offset).join(',').indexOf('1000') >= 0 &&
      gets.map(g => g.params.offset).indexOf(2000) >= 0);
    check('and the task was deleted', fake.deleted.length === 1, fake.deleted.join(','));
    check('the search asked for the whole ADOM\'s FortiGates',
      JSON.stringify(fake.log[0].params.device) === '[{"devid":"All_FortiGate"}]');
    check('for the whole appliance-local day',
      fake.log[0].params['time-range'].start === '2026-09-14 00:00:00' &&
      fake.log[0].params['time-range'].end === '2026-09-14 23:59:59');

    const capped = await FAZ.logSearch(cfgFor(fakeFaz({ answer: () => ({ rows }) }), { maxRows: 1000 }),
      'attack', FAZ.dayRange('2026-09-14'), '');
    check('a day over the row limit is marked truncated', capped.truncated === true && capped.rows.length === 1000 && capped.total === 2500);

    const counted = fakeFaz({ answer: () => ({ rows, total: 88000 }) });
    const c = await FAZ.logSearch(cfgFor(counted), 'traffic', FAZ.dayRange('2026-09-14'), 'action==deny', { countOnly: true });
    check('a count reads total-count without pulling rows', c.total === 88000 && c.rows.length === 0);
    check('asking for one row, not a page',
      counted.log.filter(e => e.method === 'get').every(g => g.params.limit === 1));
  }

  section('a task that never finishes is cancelled');
  {
    const fake = fakeFaz({ neverFinish: true });
    let err = null;
    try {
      await FAZ.logSearch(cfgFor(fake, { taskTimeoutMs: -1 }), 'traffic', FAZ.dayRange('2026-09-14'), '');
    } catch (e) { err = e; }
    check('it times out with a clear error', err && err.timedOut === true, err && err.message);
    check('and is still deleted from the appliance', fake.deleted.length === 1);
    check('no task is left open', fake.stats().open === 0, fake.stats().open);
  }

  section('the appliance is shared, so tasks are capped');
  {
    const fake = fakeFaz({ delayMs: 5 });
    const cfg = cfgFor(fake);
    await Promise.all(Array.from({ length: 8 }, () =>
      FAZ.logSearch(cfg, 'traffic', FAZ.dayRange('2026-09-14'), '', { countOnly: true })));
    check('never more than ' + FAZ.MAX_CONCURRENT_TASKS + ' tasks open at once',
      fake.stats().maxOpen <= FAZ.MAX_CONCURRENT_TASKS && fake.stats().maxOpen > 0, fake.stats().maxOpen);
    check('all eight still completed and were deleted', fake.deleted.length === 8);
    check('the slots are released afterwards', FAZ.slotStats(cfg).active === 0);
  }

  // ── Panels ───────────────────────────────────────────────────────────────

  section('one day of NDR telemetry');
  const fake = fakeFaz({ answer: dayAnswer() });
  const day = await FAZ.fetchNdrDay(cfgFor(fake), '2026-09-14');
  {
    check('every panel answered', day._partial.length === 0, day._partial.join(','));

    const t = day.traffic.data;
    check('allowed and denied are counted from the traffic log', t.allowed === 12000 && t.denied === 340);
    check('top sources come from FortiView, with country',
      t.topSources[0].label === '10.0.0.5' && t.topSources[0].count === 900 && t.topSources[0].country === 'South Africa');
    check('policies carry their names', t.topPolicies[0].label === '12' && t.topPolicies[0].name === 'LAN-to-WAN');
    check('ports and services are marked unavailable, not empty',
      t.unavailable.indexOf('topPorts') >= 0 && t.unavailable.indexOf('topServices') >= 0 &&
      t.unavailable.indexOf('topSources') < 0, t.unavailable.join(','));

    const th = day.threats.data;
    check('IPS actions are classified: dropped and reset block, detected lets through',
      th.total === 3 && th.blocked === 2 && th.allowed === 1, [th.total, th.blocked, th.allowed].join('/'));
    check('distinct attacking sources', th.uniqueSources === 2);
    const log4j = th.topAttacks[0];
    check('attacks are grouped with severity, outcome and targets',
      /Log4j/.test(log4j.label) && log4j.count === 2 && log4j.severity === 'critical' &&
      log4j.blocked === 1 && log4j.allowed === 1 && log4j.targets === 2, JSON.stringify(log4j));
    check('and not estimated', th.estimated === false);
    check('virus, web filter and app control are tallied',
      th.virus.top[0].label === 'EICAR_TEST_FILE' && th.webfilter.top[0].count === 2 &&
      th.appctrl.top[0].category === 'P2P');

    const va = day.vpnAdmin.data;
    check('VPN failures and successes, ignoring statistics events',
      va.vpn.failed === 2 && va.vpn.success === 1 && va.vpn.total === 3, JSON.stringify(va.vpn).slice(0, 80));
    check('failed users with distinct source IPs and a reason',
      va.vpn.failedUsers[0].label === 'jdoe' && va.vpn.failedUsers[0].count === 2 &&
      va.vpn.failedUsers[0].sources === 2 && /permission/.test(va.vpn.failedUsers[0].reason));
    check('admin logins by log id, including one sent without its leading zero',
      va.admin.logins === 2 && va.admin.failedLogins === 1, va.admin.logins + '/' + va.admin.failedLogins);
    check('how each admin connected', va.admin.topAdmins[0].label === 'admin' && va.admin.topAdmins[0].via === 'https');
    check('a logout is neither a login nor a change', va.admin.configChanges === 1);
    check('config changes by path', va.admin.changesByPath[0].label === 'firewall.policy');

    check('geo from FortiView', day.geo.data.countries[0].label === 'Russian Federation');
    check('every task was cleaned up', fake.stats().open === 0, fake.stats().open);
  }

  section('each panel fails on its own, with a reason');
  {
    const denied = await FAZ.fetchNdrDay(cfgFor(fakeFaz({
      answer: dayAnswer(), permissionDenied: /\/fortiview\/adom\/[^/]+\/top-countries/,
    })), '2026-09-14');
    check('a forbidden view makes its panel unavailable as not_permitted',
      denied.geo.available === false && denied.geo.reason === 'not_permitted', JSON.stringify(denied.geo));
    check('and is named in _partial', denied._partial.join(',') === 'geo', denied._partial.join(','));
    check('while the other panels still answer', denied.traffic.available && denied.threats.available && denied.vpnAdmin.available);

    const broken = await FAZ.fetchNdrDay(cfgFor(fakeFaz({ answer: dayAnswer({ attack: { error: 'search failed' } }) })), '2026-09-14');
    check('a failed search is unavailable as query_error — never zero',
      broken.threats.available === false && broken.threats.reason === 'query_error' && broken.threats.data === null);

    const viewDown = await FAZ.fetchNdrDay(cfgFor(fakeFaz({
      answer: dayAnswer(), permissionDenied: /\/fortiview\/adom\/[^/]+\/top-sources/,
    })), '2026-09-14');
    check('a failed FortiView table marks just that table unavailable',
      viewDown.traffic.available && viewDown.traffic.data.unavailable.indexOf('topSources') >= 0 &&
      viewDown.traffic.data.allowed === 12000);

    const quiet = await FAZ.fetchNdrDay(cfgFor(fakeFaz({ answer: () => ({ rows: [], total: 0 }) })), '2026-09-14');
    check('a genuinely quiet day is available with no_data_in_range',
      quiet.threats.available === true && quiet.threats.reason === 'no_data_in_range');
  }

  section('a day over the row limit is estimated, and says so');
  {
    const many = Array.from({ length: 2500 }, (_, i) => ({ attack: 'X', severity: 'high', action: i % 5 ? 'dropped' : 'detected', srcip: 's' + (i % 7), dstip: 'd' }));
    const est = await FAZ.fetchNdrDay(cfgFor(fakeFaz({ answer: dayAnswer({ attack: { rows: many } }) }), { maxRows: 1000 }), '2026-09-14');
    const th = est.threats.data;
    check('the true total comes from total-count', th.total === 2500);
    check('blocked and allowed are scaled from the sample', th.blocked === 2000 && th.allowed === 500, th.blocked + '/' + th.allowed);
    check('and flagged as estimated, with the sample size', th.estimated === true && th.sampled.rows === 1000);
  }

  section('small helpers');
  check('log ids are compared at ten digits', FAZ.normLogid(100032001) === '0100032001' && FAZ.normLogid('0100032001') === '0100032001');
  check('"ssh(203.0.113.9)" connected via ssh', FAZ.viaOf('ssh(203.0.113.9)') === 'ssh');
  check('an invalid day is refused', (() => { try { FAZ.dayRange('14/09/2026'); return false; } catch (_) { return true; } })());
  check('stored config cannot install a transport or sleep',
    !('transport' in FAZ.sanitiseStoredConfig({ transport: () => {}, sleep: () => {}, adom: 'x' })) &&
    FAZ.sanitiseStoredConfig({ transport: 1, adom: 'x' }).adom === 'x');

  // ── Rollups ──────────────────────────────────────────────────────────────

  section('FortiAnalyzer data survives the same rollup path as Wazuh');
  {
    const est = await FAZ.fetchNdrDay(cfgFor(fakeFaz({
      answer: dayAnswer({ attack: { rows: ATTACKS, total: 30 } }),
    }), { maxRows: 3 }), '2026-09-14');
    const bag = WM.flattenNdr(est);
    check('the bag carries the unavailable tables', bag.rows.some(r => r.metric === 'traffic.unavailable' && r.dim1 === 'topPorts'));
    check('and the estimate flag', bag.rows.some(r => r.metric === 'ips.estimated'));

    const q = [];
    const pool = {
      async query(sql, params) {
        q.push({ sql: String(sql).replace(/\s+/g, ' '), params });
        return { rows: bag.rows.map(r => Object.assign({ day: '2026-09-14', meta: r.meta ? JSON.parse(r.meta) : null }, r)) };
      },
    };
    const rebuilt = await WM.ndrFromRollups(pool, 7, 30, 77);
    check('the read is scoped to the integration', /\$4::int IS NULL OR integration_id = \$4/.test(q[0].sql) && q[0].params[3] === 77,
      JSON.stringify(q[0].params));
    check('traffic totals come back', rebuilt.traffic.data.allowed === 12000 && rebuilt.traffic.data.denied === 340);
    check('the unavailable tables come back', rebuilt.traffic.data.unavailable.indexOf('topPorts') >= 0);
    check('the estimate flag comes back', rebuilt.threats.data.estimated === true);
    check('admin logins come back', rebuilt.vpnAdmin.data.admin.logins === 2);
    check('the envelope keys the NDR tab reads are all present',
      ['traffic', 'threats', 'geo', 'vpnAdmin'].every(k => rebuilt[k] && 'available' in rebuilt[k]));
  }

  section('which days are collected');
  {
    const q = [];
    const pool = { async query(sql, params) {
      q.push({ sql, params });
      return { rows: [
        { day: '2026-09-13', status: 'partial_day' },
        { day: '2026-09-12', status: 'ok' },
        { day: '2026-09-11', status: 'no_data' },
      ] };
    } };
    const days = await FM.daysNeedingSnapshot(pool, 77, 'UTC', new Date('2026-09-14T10:00:00Z'));
    check('today first, then yesterday (still partial), then missing days',
      days.join(',') === '2026-09-14,2026-09-13,2026-09-10,2026-09-09', days.join(','));
    check('capped per run, so a backfill is spread out', days.length === FM.MAX_DAYS_PER_RUN);
    check('scoped to this integration and source', q[0].params[0] === 77 && q[0].params[1] === 'fortigate');
    check('looking back ' + FM.BACKFILL_DAYS + ' days', q[0].params[2] === '2026-08-15', q[0].params[2]);
  }

  section('a collected day is stored once, in a transaction');
  {
    const statements = [];
    const client = { async query(sql, params) { statements.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params }); return { rows: [] }; }, release() {} };
    const pool = { async connect() { return client; } };
    const f = fakeFaz({ answer: dayAnswer() });
    const r = await FM.snapshotDay(pool, {
      id: 77, tenant_id: 7, base_url: 'https://faz.example.test', api_key: 'tok-123',
      config: { adom: 'client-a', timeZone: 'UTC' },
    }, '2026-09-14', { isToday: true, cfg: { transport: f.transport, sleep: noSleep } });

    check('it commits', statements[0].sql === 'BEGIN' && statements[statements.length - 1].sql === 'COMMIT');
    check('rows are written for this integration and tenant',
      statements.some(s => /INSERT INTO wazuh_daily_metric/.test(s.sql) && s.params[0][0] === 7 && s.params[1][0] === 77));
    check('today is stored as partial, so it is collected again', r.status === 'partial_day' &&
      statements.some(s => /INSERT INTO wazuh_rollup_run/.test(s.sql) && s.params[3] === 'partial_day'));
    check('the replace is scoped to this integration and day',
      statements.some(s => /DELETE FROM wazuh_daily_metric/.test(s.sql) && s.params[0] === 77 && s.params[1] === '2026-09-14'));

    const failed = [];
    const failClient = { async query(sql, params) { failed.push(String(sql).replace(/\s+/g, ' ').trim()); return { rows: [] }; }, release() {} };
    const r2 = await FM.snapshotDay({ async connect() { return failClient; } }, {
      id: 77, tenant_id: 7, base_url: 'https://faz.example.test', api_key: 'tok-123', config: { adom: '../bad' },
    }, '2026-09-13', {});
    check('a day that cannot be collected is recorded as an error', r2.status === 'error' && !!r2.error, r2.error);
    check('and deletes nothing that was stored before', !failed.some(s => /DELETE FROM wazuh_daily_metric/.test(s)));
  }

  // ── Wiring ───────────────────────────────────────────────────────────────

  section('the server wiring');
  const srv = codeOnly(read('server.js'));
  check('the provider is known', /FAZ_PROVIDER = 'fortianalyzer'/.test(srv) && /KNOWN_PROVIDERS[^;]*FAZ_PROVIDER/.test(srv));
  check('stored config is sanitised on load',
    /config:\s*fazAdapter\.sanitiseStoredConfig\(r\.config_json \|\| \{\}\)/.test(srv));
  check('Test stores the verified ADOM and devices',
    /verified_adom:\s*info\.adom/.test(srv) && /verified_devices:\s*info\.devices\.map/.test(srv));

  const sync = (srv.match(/async function runFortiAnalyzerSync\(tenantId\)[\s\S]*?\n\}/) || [''])[0];
  check('an unverified or changed ADOM never syncs', /conf\.verified_adom !== conf\.adom/.test(sync));
  check('the device list is checked before any day is collected',
    sync.indexOf('fazAdapter.checkDevices(') > 0 && sync.indexOf('fazAdapter.checkDevices(') < sync.indexOf('daysNeedingSnapshot('));
  check('two syncs for one client cannot overlap', /fazSyncInProgress\.has\(tenantId\)/.test(sync));
  check('the hourly collection is scheduled', /setInterval\(\(\) => \{ runFortiAnalyzerSyncs\(\)/.test(srv));

  const screen = (srv.match(/async function wazuhScreen\([\s\S]*?\n\}/) || [''])[0];
  check('the NDR screen prefers FortiAnalyzer',
    screen.indexOf('loadFortiAnalyzerIntegration(tenantId)') > 0 &&
    screen.indexOf('loadFortiAnalyzerIntegration(tenantId)') < screen.indexOf('loadWazuhIntegration(tenantId)'));
  check('Wazuh rollups are scoped to the Wazuh integration',
    /ndrFromRollups\(pool, tenantId, days, integration\.id\)/.test(screen));
  const fazScreen = (srv.match(/async function fortiAnalyzerNdrScreen\([\s\S]*?\n\}/) || [''])[0];
  check('FortiAnalyzer rollups are scoped to the FortiAnalyzer integration',
    /ndrFromRollups\(pool, tenantId, days, integration\.id\)/.test(fazScreen));
  check('before the first collection, panels say not collected rather than quiet', /reason: 'not_synced'/.test(fazScreen));

  section('the pages');
  const ui = read('public', 'js', 'wazuh-ui.js');
  check('Sync Now reaches the provider that served the screen, and only a known one',
    /const p\s*= provider === 'fortianalyzer' \? 'fortianalyzer' : 'wazuh'/.test(ui) && /api\/integrations\/\$\{p\}\/sync/.test(ui));
  check('"not collected yet" is worded', /not_synced:\s*'Nothing has been collected yet\.'/.test(ui));
  check('an unavailable table is escaped and says so', /esc\(emptyText \|\| 'No data for this period\.'\)/.test(ui));
  const ndr = read('public', 'js', 'tab-ndr.js');
  check('the NDR tab marks unavailable tables', /notAvailable\(d, 'topPorts'\)/.test(ndr));
  check('and labels estimated IPS figures', /estimated from a sample/.test(ndr));
  const admin = read('public', 'js', 'tab-admin.js');
  check('the Admin tab has a FortiAnalyzer card', /id:\s*'fortianalyzer'/.test(admin) && /fazFields: true/.test(admin));
  check('the verified device names are escaped', /escHtmlInt\(devices\)/.test(admin));
  check('the client-side ADOM rule matches the server\'s',
    admin.indexOf('/^[A-Za-z0-9_-]{1,64}$/') >= 0 && String(FAZ.ADOM_RE) === '/^[A-Za-z0-9_-]{1,64}$/');
  check('the adapter sends the token as a bearer header',
    /'Authorization':\s*`Bearer \$\{cfg\.api_key\}`/.test(read('lib', 'integrations', 'fortianalyzer.js')));

  done();
})().catch((err) => {
  console.error('FAIL  suite crashed:', err && err.stack);
  process.exit(1);
});
