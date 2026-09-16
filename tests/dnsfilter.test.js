'use strict';

/**
 * AI Visibility — DNSFilter telemetry, the sanctioned-app register, and the
 * board section.
 *
 * Driven against a simulated DNSFilter API that answers the way the published
 * v1 description says it does, and an in-memory stand-in for the rollup tables
 * that rejects what Postgres would reject.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   one key, many clients        the organisation id is validated, sent on every
 *                                traffic report, and verified by Test; a sync
 *                                against an unverified organisation is refused;
 *                                a save cannot smuggle verification in
 *   the MSP key stays put        superadmin-only routes; never returned by GET;
 *                                the adapter only ever issues GET
 *   not recorded is not none     an unreadable report is unavailable with a
 *                                reason, never zero; an unreviewed tool is never
 *                                sanctioned; a share over part of the period is
 *                                not shown
 *   re-collection is honest      a panel read empty clears yesterday's run; a
 *                                panel that failed keeps it
 *   names stay narrow            the board section names only the top users,
 *                                by display name, never by login; the portal
 *                                has no AI Visibility route
 *
 *   node tests/dnsfilter.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('dnsfilter');

const DNS = require(path.join(ROOT, 'lib', 'integrations', 'dnsfilter.js'));
const DM  = require(path.join(ROOT, 'lib', 'dnsfilter-metrics.js'));
const AV  = require(path.join(ROOT, 'lib', 'ai-visibility.js'));
const PAGES = require(path.join(ROOT, 'lib', 'pages.js'));
const SERVICES = require(path.join(ROOT, 'lib', 'services.js'));

function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

// ── A simulated DNSFilter ───────────────────────────────────────────────────

const res = (attrs, id) => ({ id: String(id), type: 'x', attributes: attrs });

function fakeDns(over) {
  /*
   * `categoryParam` is what this DNSFilter accepts on the domain reports:
   * a parameter name, or null for "rejects every one of them". Anything else
   * gets 400 "Invalid query definition" — which is what the pilot hit.
   */
  const o = Object.assign({ bearer: false, rateLimitOnce: false, rateLimitAlways: false,
    categoryParam: 'category_ids', rowsCarryCategory: false,
    // Accepted with a 200 and silently ignored — what the first pilot's
    // DNSFilter did with the spellings after `category_ids`.
    ignoredParams: [], usersWithoutDomain: false,
    // Per-user rows are returned only for show_individual_users=true, as the
    // real API does; this forces the pilot's case where they never are.
    ignoreUserBreakdown: false,
    fail: {}, failTimes: {}, override: {} }, over || {});
  const log = [];
  const sleeps = [];
  let limited = o.rateLimitAlways ? Infinity : (o.rateLimitOnce ? 1 : 0);

  async function transport(cfg, url, headers) {
    const u = new URL(url);
    const p = u.pathname;
    const q = {};
    u.searchParams.forEach((v, k) => { q[k] = v; });
    log.push({ path: p, q, auth: headers.Authorization, url });
    const ok = json => ({ status: 200, json, headers: {} });

    if (o.bearer && !/^Bearer /.test(headers.Authorization)) return { status: 401, json: { error: 'unauthorised' }, headers: {} };
    if (limited > 0) { limited--; return { status: 429, json: null, headers: { 'retry-after': '3' } }; }
    if (o.failTimes[p] > 0) { o.failTimes[p]--; return { status: 500, json: { error: 'transient' }, headers: {} }; }
    if (o.fail[p]) return { status: o.fail[p], json: { error: 'boom' }, headers: {} };
    if (o.override[p]) return ok(o.override[p](q));

    switch (p) {
      case '/v1/organizations/all':
        return ok({ data: [res({ name: 'Client A' }, 101), res({ name: 'Client B' }, 202)], links: { next: null } });
      case '/v1/categories/all':
        return ok({ data: [res({ name: 'Adult' }, 5), res({ name: 'Generative AI' }, 77)] });
      case '/v1/application_categories':
        return ok({ data: [res({ name: 'Generative AI' }, 9), res({ name: 'Games' }, 3)] });
      case '/v1/applications/all':
        return ok({ data: [
          res({ name: 'chatgpt', display_name: 'ChatGPT', home_page_url: 'https://chat.openai.com' }, 31),
          res({ name: 'claude', display_name: 'Claude', home_page_url: 'https://claude.ai' }, 32),
        ] });
      case '/v1/traffic_reports/total_categories':
        return ok({ data: { values: [{ time: '2026-09-01T00:00:00Z', categories: [
          { category_id: 77, category_name: 'Generative AI', total: q.type === 'blocked' ? 30 : 120 },
          { category_id: 5, category_name: 'Adult', total: 40 },
        ] }] } });
      case '/v1/traffic_reports/total_requests':
        return ok({ data: { values: [{ time: '2026-09-01T00:00:00Z', total: 10000 }] } });
      case '/v1/traffic_reports/total_domains':
      case '/v1/traffic_reports/total_domains_users': {
        const catKeys = Object.keys(q).filter(k => /^categor/.test(k));
        // An ignored parameter is accepted and has no effect at all.
        const live = catKeys.filter(k => o.ignoredParams.indexOf(k) < 0);
        const accepted = live.length === 0 ||
          (o.categoryParam !== null && live.length === 1 && live[0] === o.categoryParam);
        if (!accepted) return { status: 400, json: { error: 'Invalid query definition' }, headers: {} };
        const filtered = live.length > 0;

        const withCat = r => (o.rowsCarryCategory
          ? Object.assign({}, r, { category_name: /openai|claude|unknown-ai/.test(r.domain) ? 'Generative AI' : 'News' })
          : r);
        const users = p.endsWith('_users');
        // Per-user rows ONLY when asked for — the parameter the pilot never sent.
        const perUser = users && q.show_individual_users === 'true' && !o.ignoreUserBreakdown;
        const U = (id, name, login, domain, total) => ({ user_id: id, user_name: name, user_login: login, domain, total });
        let ai;
        if (!users) {
          ai = q.type === 'blocked'
            ? [{ domain: 'claude.ai', total: 30 }]
            : [{ domain: 'chat.openai.com', total: 80 }, { domain: 'api.openai.com', total: 20 }, { domain: 'unknown-ai.io', total: 20 }];
        } else if (!perUser) {
          // Exactly the pilot's shape: per-domain totals, no user at all.
          ai = [{ bucket: '2026-09-01', domain: 'chat.openai.com', total: 90, total_agents: 0, total_networks: 90 },
                { bucket: '2026-09-01', domain: 'claude.ai', total: 10, total_agents: 0, total_networks: 10 }];
        } else {
          // Alice through the agent; 40 more from the office network, with no user.
          const allowedRows = [U(11, 'Alice Adams', 'alice@client.example', 'chat.openai.com', 50),
                               U(null, null, null, 'chat.openai.com', 40)];
          const blockedRows = [U(12, 'Bob Brown', 'bob@client.example', 'claude.ai', 10)];
          ai = q.type === 'allowed' ? allowedRows
            : q.type === 'blocked' ? blockedRows
            : allowedRows.concat(blockedRows);
        }
        // Unfiltered, the report also carries traffic that is nothing to do with AI.
        const rest = users && perUser
          ? [U(13, 'Carol Chen', 'carol@client.example', 'news.example.com', 500)]
          : [{ domain: 'news.example.com', total: 500 }];
        const strip = r => (o.usersWithoutDomain && users
          ? { user_id: r.user_id, user_name: r.user_name, user_login: r.user_login, total: r.total }
          : r);
        return ok({ data: (filtered ? ai : ai.concat(rest)).map(withCat).map(strip) });
      }
      case '/v1/policies/all':
        return ok({ data: [
          res({ name: 'Default', organization_id: 101, blacklist_categories: [77, 5], allow_list_only: false }, 1),
          res({ name: 'Someone else', organization_id: 202, blacklist_categories: [] }, 2),
        ] });
      default:
        return { status: 404, json: { error: 'nope' }, headers: {} };
    }
  }
  return { transport, log, sleeps, sleep: ms => { sleeps.push(ms); return Promise.resolve(); } };
}

function cfgFor(f, extra) {
  return Object.assign({
    api_key: 'k-msp', organization_id: '101', aiCategoryId: '77', timeZone: 'UTC',
    transport: f.transport, sleep: f.sleep,
  }, extra || {});
}

// ── An in-memory rollup store ───────────────────────────────────────────────

function fakePool() {
  let metrics = [];
  const runs = new Map();

  async function query(sql, params) {
    const s = sql.replace(/\s+/g, ' ').trim();
    if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(s)) return { rows: [] };

    if (s.startsWith('DELETE FROM wazuh_daily_metric')) {
      const [iid, day, source, ms] = params;
      metrics = metrics.filter(r => !(r.integration_id === iid && r.day === day && r.source === source && ms.indexOf(r.metric) >= 0));
      return { rows: [] };
    }
    if (s.startsWith('INSERT INTO wazuh_daily_metric')) {
      const [tids, iids, days, sources, ms, d1, d2, d3, v, v2, meta] = params;
      const seen = new Set();
      ms.forEach((metric, i) => {
        const key = [iids[i], days[i], sources[i], metric, d1[i], d2[i], d3[i]].join('|');
        // Postgres refuses to upsert the same key twice in one statement.
        if (seen.has(key)) throw new Error('ON CONFLICT DO UPDATE command cannot affect row a second time: ' + key);
        seen.add(key);
        metrics = metrics.filter(r => [r.integration_id, r.day, r.source, r.metric, r.dim1, r.dim2, r.dim3].join('|') !== key);
        metrics.push({
          tenant_id: tids[i], integration_id: iids[i], day: days[i], source: sources[i], metric,
          dim1: d1[i], dim2: d2[i], dim3: d3[i], value: v[i], value2: v2[i], meta: meta[i] ? JSON.parse(meta[i]) : null,
        });
      });
      return { rows: [] };
    }
    if (s.startsWith('INSERT INTO wazuh_rollup_run')) {
      const [iid, day, source, status, message] = params;
      runs.set(`${iid}|${day}|${source}`, { day, source, status, message });
      return { rows: [] };
    }
    if (s.includes('FROM wazuh_rollup_run')) {
      const [iid, source] = params;
      return { rows: [...runs.entries()].filter(([k]) => k.startsWith(`${iid}|`) && k.endsWith(`|${source}`)).map(([, r]) => r) };
    }
    if (s.includes('FROM wazuh_daily_metric')) {
      const [tid, source, , iid] = params;
      return { rows: metrics.filter(r => r.tenant_id === tid && r.source === source && (iid == null || r.integration_id === iid)) };
    }
    throw new Error('unexpected SQL: ' + s.slice(0, 80));
  }
  return { query, connect: async () => ({ query, release() {} }), runs, get metrics() { return metrics; } };
}

const NOW = Date.parse('2026-09-15T12:00:00Z');

(async () => {
  // ══ The adapter ═══════════════════════════════════════════════════════════

  section('the organisation id is the only thing between clients');

  const badIds = ['', '12a', '101;DROP', '1 01', null, '1234567890123'];
  check('a malformed organisation id is refused before any request',
    badIds.every((id) => { try { DNS.validOrgId(id); return false; } catch (_) { return true; } }), badIds.join(' | '));
  check('a numeric id is accepted', DNS.validOrgId(' 101 ') === '101');

  DNS._clearCatalogueCache();
  const f1 = fakeDns();
  const day1 = await DNS.fetchAiDay(cfgFor(f1), '2026-09-01', { now: NOW });
  const reports = f1.log.filter(l => l.path.indexOf('/v1/traffic_reports/') === 0);
  check('every traffic report is scoped to this organisation',
    reports.length >= 6 && reports.every(l => l.q.organization_ids === '101'),
    `${reports.length} report calls`);
  check('and the policy read is too',
    f1.log.filter(l => l.path === '/v1/policies/all').every(l => l.q.organization_id === '101'));
  check('the day window is the client-local day',
    reports[0].q.from === '2026-09-01T00:00:00.000Z' && reports[0].q.to === '2026-09-02T00:00:00.000Z',
    `${reports[0].q.from} → ${reports[0].q.to}`);

  const t1 = await DNS.testConnection(cfgFor(fakeDns()));
  check('Test names the organisation it verified', t1.orgId === '101' && t1.orgName === 'Client A', t1.message);

  let unseen = null;
  try { await DNS.testConnection(cfgFor(fakeDns(), { organization_id: '999' })); } catch (err) { unseen = err; }
  check('an organisation the key cannot see fails Test', !!(unseen && unseen.orgNotFound), unseen && unseen.message);

  const msp = await DNS.testMspConnection({ api_key: 'k-msp', transport: fakeDns().transport });
  check('the MSP Test lists organisations and finds the AI category by name',
    msp.organisations.length === 2 && msp.aiCategory && msp.aiCategory.id === '77', msp.message);

  section('the key and the transport');

  check('the key is sent as the raw Authorization value first', f1.log[0].auth === 'k-msp', f1.log[0].auth);

  const fb = fakeDns({ bearer: true });
  const bearerOrgs = await DNS.listOrganisations({ api_key: 'k-msp', transport: fb.transport });
  check('a 401 is retried once as Bearer, and Bearer is kept for the run',
    bearerOrgs.length === 2 && fb.log.length === 2 && /^Bearer k-msp$/.test(fb.log[1].auth),
    fb.log.map(l => l.auth).join(' then '));

  const fr = fakeDns({ rateLimitOnce: true });
  await DNS.listOrganisations({ api_key: 'k-msp', transport: fr.transport, sleep: fr.sleep });
  check('a 429 waits for Retry-After, then retries', fr.sleeps.length === 1 && fr.sleeps[0] === 3000, fr.sleeps.join(','));

  /*
   * THE FIRST PILOT RUN. One day's two heaviest reports came back as
   * "query_error" and nothing said why. A transient failure now gets retried,
   * and whatever it was is carried through to the operator.
   */
  DNS._clearCatalogueCache();
  const f5 = fakeDns({ failTimes: { '/v1/traffic_reports/total_domains': 1 } });
  const recovered = await DNS.fetchAiDay(cfgFor(f5), '2026-09-01', { now: NOW });
  check('a 5xx on one report is retried, and the day is collected anyway',
    recovered.apps.available && recovered.apps.data.rows.length === 3 && f5.sleeps.length === 1,
    `slept ${f5.sleeps.join(',')}ms`);

  DNS._clearCatalogueCache();
  const fLimited = fakeDns({ rateLimitAlways: true });
  const limitedDay = await DNS.fetchAiDay(cfgFor(fLimited), '2026-09-01', { now: NOW });
  check('a rate limit that will not clear is reported as one, not as a query error',
    !limitedDay.usage.available && limitedDay.usage.reason === 'rate_limited', limitedDay.usage.reason);
  check('and it says which report and how often it was retried',
    /total_categories/.test(limitedDay.usage.detail || '') && /retried 2 time/.test(limitedDay.usage.detail || ''),
    limitedDay.usage.detail);

  const paged = fakeDns({ override: { '/v1/organizations/all': q => ({
    data: Array.from({ length: q['page[number]'] === '1' ? 100 : 5 }, (_, i) => res({ name: `Org ${q['page[number]']}-${i}` }, `${q['page[number]']}${i}`)),
    links: { next: q['page[number]'] === '1' ? '/next' : null },
  }) } });
  const many = await DNS.listOrganisations({ api_key: 'k-msp', transport: paged.transport });
  check('pagination follows every page', many.length === 105, many.length);

  const srcCode = codeOnly(read('lib', 'integrations', 'dnsfilter.js'));
  check('the adapter only ever issues GET',
    /method:\s*'GET'/.test(srcCode) && !/method:\s*['"](POST|PUT|PATCH|DELETE)['"]/i.test(srcCode) &&
    !/\.(post|put|patch|delete)\s*\(/.test(srcCode));
  check('stored config cannot install a transport or an auth scheme',
    (() => { const c = DNS.sanitiseStoredConfig({ transport() {}, sleep() {}, _authScheme: 'bearer', organization_id: '1' });
      return !c.transport && !c.sleep && !c._authScheme && c.organization_id === '1'; })());

  section('usage, tools, users and policy read correctly');

  check('AI lookups allowed and blocked come from the AI category only',
    day1.usage.available && day1.usage.data.allowed === 120 && day1.usage.data.blocked === 30,
    JSON.stringify(day1.usage.data));
  check('all DNS lookups are read as the denominator', day1.usage.data.total === 10000);

  const apps = day1.apps.data.rows;
  const chatgpt = apps.find(a => a.key === 'app:31');
  check('domains map to the application they belong to',
    chatgpt && chatgpt.name === 'ChatGPT' && chatgpt.allowed === 100 && chatgpt.mapped, JSON.stringify(chatgpt));
  const claude = apps.find(a => a.key === 'app:32');
  check('blocked lookups are attributed too', claude && claude.blocked === 30 && claude.allowed === 0);
  const other = apps.find(a => a.key === 'domain:unknown-ai.io');
  check('a domain with no catalogue entry is kept under its own name, not dropped',
    other && other.allowed === 20 && other.mapped === false, JSON.stringify(other));

  /*
   * THE PILOT'S EMPTY USERS TABLE. total_domains_users names users only when
   * asked with show_individual_users=true; without it, it returns per-domain
   * totals. Every request for users must ask.
   */
  const userCalls = f1.log.filter(l => l.path === '/v1/traffic_reports/total_domains_users');
  check('the users report is asked for a per-user breakdown, every time',
    userCalls.length >= 2 && userCalls.every(l => l.q.show_individual_users === 'true'),
    `${userCalls.length} calls`);
  const alice = day1.users.data.rows.find(r => r.user === 'alice@client.example');
  check('users are read with the tool they used',
    alice && alice.allowed === 50 && alice.blocked === 0 && alice.appKey === 'app:31', JSON.stringify(alice));
  check('keyed by login, shown by name', alice && alice.name === 'Alice Adams');
  const bob = day1.users.data.rows.find(r => r.user === 'bob@client.example');
  check('blocked attempts are attributed to the user who made them',
    bob && bob.blocked === 10 && bob.allowed === 0, JSON.stringify(bob));
  check('office-network lookups with no user are counted, not dropped or invented',
    day1.users.data.unattributed === 40 && !day1.users.data.rows.some(r => /null|undefined|^User /.test(r.user)),
    day1.users.data.unattributed);

  DNS._clearCatalogueCache();
  const fNoBreakdown = fakeDns({ ignoreUserBreakdown: true });
  const noBreakdown = await DNS.fetchAiDay(cfgFor(fNoBreakdown), '2026-09-01', { now: NOW });
  check('a users report that names nobody is unreadable, not "no users"',
    !noBreakdown.users.available && noBreakdown.users.reason === 'unrecognised_response', noBreakdown.users.reason);
  check('and says what arrived instead — the pilot\'s fields',
    /bucket/.test(noBreakdown.users.detail || '') && /domain/.test(noBreakdown.users.detail || ''),
    noBreakdown.users.detail);

  check('policy status shows whether Generative AI is blocked',
    day1.policy.data.rows.length === 1 && day1.policy.data.rows[0].aiBlocked === true,
    JSON.stringify(day1.policy.data.rows));
  check('a policy belonging to another organisation is not shown',
    !day1.policy.data.rows.some(r => r.name === 'Someone else'));

  check('registered domains respect two-level suffixes',
    DNS.registeredDomain('x.example.co.za') === 'example.co.za' && DNS.registeredDomain('chat.openai.com') === 'openai.com');

  section('what cannot be read is unavailable, never zero');

  DNS._clearCatalogueCache();
  const noCat = await DNS.fetchAiDay(cfgFor(fakeDns(), { aiCategoryId: null }), '2026-09-01', { now: NOW });
  check('without the AI category, usage, tools and users are unavailable with that reason',
    ['usage', 'apps', 'users'].every(k => !noCat[k].available && noCat[k].reason === 'category_unknown'));
  check('policy is still read', noCat.policy.available);

  DNS._clearCatalogueCache();
  const weird = await DNS.fetchAiDay(cfgFor(fakeDns({ override: {
    '/v1/traffic_reports/total_categories': () => ({ data: { layout: 'unexpected' } }),
  } })), '2026-09-01', { now: NOW });
  check('an unrecognised report shape is unavailable, not zero',
    !weird.usage.available && weird.usage.reason === 'unrecognised_response', JSON.stringify(weird.usage));
  check('and the other panels still arrive', weird.apps.available && weird.users.available);

  DNS._clearCatalogueCache();
  const empty = await DNS.fetchAiDay(cfgFor(fakeDns({ override: {
    '/v1/traffic_reports/total_categories': () => ({ data: [] }),
  } })), '2026-09-01', { now: NOW });
  check('an empty report IS zero — nothing happened',
    empty.usage.available && empty.usage.data.allowed === 0 && empty.usage.data.blocked === 0);

  DNS._clearCatalogueCache();
  const fNoTotal = fakeDns({ fail: { '/v1/traffic_reports/total_requests': 500 } });
  const noTotal = await DNS.fetchAiDay(cfgFor(fNoTotal), '2026-09-01', { now: NOW });
  check('a missing denominator leaves the counts but not the total',
    noTotal.usage.available && noTotal.usage.data.total === null && noTotal.usage.data.totalReason === 'source_error',
    noTotal.usage.data.totalReason);
  check('and the failure it hit is kept, not flattened to "query error"',
    /HTTP 500/.test(noTotal.usage.data.totalDetail || ''), noTotal.usage.data.totalDetail);

  DNS._clearCatalogueCache();
  const forbidden = await DNS.fetchAiDay(cfgFor(fakeDns({ fail: { '/v1/traffic_reports/total_domains_users': 403 } })), '2026-09-01', { now: NOW });
  check('a refused report says not permitted', !forbidden.users.available && forbidden.users.reason === 'not_permitted');
  check('with the API\'s own words', /403/.test(forbidden.users.detail || ''), forbidden.users.detail);

  section('the AI category filter is asked for in whatever form DNSFilter takes');

  /*
   * THE PILOT'S SECOND FAILURE. Test probed the domain reports WITHOUT the
   * category filter and they answered; the sync added `category_ids` and every
   * day came back 400 "Invalid query definition".
   */
  const clearAll = () => { DNS._clearCatalogueCache(); DNS._clearCategoryParamCache(); };

  clearAll();
  const fAlt = fakeDns({ categoryParam: 'categories' });
  const alt = await DNS.fetchAiDay(cfgFor(fAlt), '2026-09-01', { now: NOW });
  check('a rejected filter is retried in the other spellings',
    alt.apps.available && alt.apps.data.rows.length === 3, alt.apps.reason || `${alt.apps.data.rows.length} tools`);
  check('and the one that works is the one used',
    fAlt.log.some(l => l.path === '/v1/traffic_reports/total_domains' && l.q.categories === '77') &&
    alt.apps.data.filter === null);

  clearAll();
  const fRowCat = fakeDns({ categoryParam: null, rowsCarryCategory: true });
  const rowCat = await DNS.fetchAiDay(cfgFor(fRowCat), '2026-09-01', { now: NOW });
  check('when no filter is accepted, rows are narrowed by their own category',
    rowCat.apps.available && rowCat.apps.data.filter === 'row_category' &&
    !rowCat.apps.data.rows.some(r => /news/.test(r.name)), JSON.stringify(rowCat.apps.data.rows.map(r => r.name)));

  clearAll();
  const fCatalogue = fakeDns({ categoryParam: null });
  const byCatalogue = await DNS.fetchAiDay(cfgFor(fCatalogue), '2026-09-01', { now: NOW });
  check('otherwise only domains in the AI application catalogue are kept',
    byCatalogue.apps.available && byCatalogue.apps.data.filter === 'catalogue' &&
    byCatalogue.apps.data.rows.every(r => r.mapped) &&
    !byCatalogue.apps.data.rows.some(r => /news/.test(r.name)),
    byCatalogue.apps.data.rows.map(r => r.name).join(', '));
  check('users are narrowed the same way, so a non-AI user is not listed',
    byCatalogue.users.data.filter === 'catalogue' &&
    !byCatalogue.users.data.rows.some(r => /carol/.test(r.user)),
    byCatalogue.users.data.rows.map(r => r.user).join(', '));

  clearAll();
  const fNoWay = fakeDns({ categoryParam: null, fail: {
    '/v1/application_categories': 500, '/v1/applications/all': 500,
  } });
  const noWay = await DNS.fetchAiDay(cfgFor(fNoWay), '2026-09-01', { now: NOW });
  check('with no way to tell AI traffic apart, the panel is unavailable rather than counting everything',
    !noWay.apps.available && noWay.apps.reason === 'category_filter_unsupported', noWay.apps.reason);
  check('which is the opposite of reporting a news site as an AI tool',
    noWay.apps.data === null);

  /*
   * THE PILOT, EXACTLY. `category_ids` is refused; every other spelling is
   * accepted with a 200 and ignored. Taking "accepted" for "applied" counted
   * every domain the client visited as an AI tool.
   */
  clearAll();
  const fIgnored = fakeDns({ categoryParam: 'not-a-real-param',
    ignoredParams: ['categories', 'category_ids[]', 'category_id'] });
  const ignored = await DNS.fetchAiDay(cfgFor(fIgnored), '2026-09-01', { now: NOW });
  check('a filter DNSFilter accepts but ignores is not trusted',
    ignored.apps.available && ignored.apps.data.filter === 'catalogue',
    `${ignored.apps.data && ignored.apps.data.filter}: ${(ignored.apps.data && ignored.apps.data.rows || []).map(r => r.name).join(', ')}`);
  check('so ordinary traffic is never counted as an AI tool',
    !ignored.apps.data.rows.some(r => /news/.test(r.name)));
  check('and users are narrowed the same way',
    ignored.users.available && !ignored.users.data.rows.some(r => /carol/.test(r.user)) &&
    ignored.users.data.rows.some(r => /alice/.test(r.user)),
    ignored.users.data && ignored.users.data.rows.map(r => r.user).join(', '));
  const probedIgnored = await DNS.probe(cfgFor(fakeDns({ categoryParam: 'not-a-real-param',
    ignoredParams: ['categories', 'category_ids[]', 'category_id'] })), '2026-09-01');
  check('Test records that no spelling takes effect, rather than the one that was merely accepted',
    probedIgnored.categoryFilters.total_domains === null, JSON.stringify(probedIgnored.categoryFilters));

  clearAll();
  const fNoDomain = fakeDns({ categoryParam: null, usersWithoutDomain: true });
  const noDomain = await DNS.fetchAiDay(cfgFor(fNoDomain), '2026-09-01', { now: NOW });
  check('user rows that name no domain cannot be narrowed, so users are unavailable — not zero',
    !noDomain.users.available && noDomain.users.reason === 'category_filter_unsupported', noDomain.users.reason);

  clearAll();
  const fOdd = fakeDns({ override: {
    '/v1/traffic_reports/total_domains_users': () => ({ data: [{ principal: 'alice@client.example', n: 5 }] }),
  } });
  const odd = await DNS.fetchAiDay(cfgFor(fOdd), '2026-09-01', { now: NOW });
  check('user records in a shape we do not read are unreadable, not an empty list',
    !odd.users.available && odd.users.reason === 'unrecognised_response', odd.users.reason);
  check('and the message names the fields that DID arrive',
    /principal/.test(odd.users.detail || '') && /\bn\b/.test(odd.users.detail || ''), odd.users.detail);
  check('a genuinely empty report is still zero',
    DNS.collectRows({ values: [{ time: 't', categories: [] }] }, () => false).length === 0);

  clearAll();
  const fProbe = fakeDns({ categoryParam: 'categories' });
  const probed = await DNS.probe(cfgFor(fProbe), '2026-09-01');
  check('Test probes the domain reports WITH the filter, and records the form PROVED to work',
    probed.reports.total_domains.ok && probed.categoryFilters.total_domains === 'categories',
    JSON.stringify(probed.categoryFilters));
  const srvNow = codeOnly(read('server.js'));
  check('the server stores it and the sync uses it without rediscovering it',
    /verified_category_filters: detected\.categoryFilters/.test(srvNow) &&
    /categoryFilters: conf\.verified_category_filters/.test(srvNow));
  check('and discards the unproved choice an earlier build stored',
    /delete merged\.verified_category_param/.test(srvNow));

  clearAll();

  // ══ Rollups ═══════════════════════════════════════════════════════════════

  section('flatten → store → rebuild');

  const integ = f => ({ id: 7, tenant_id: 3, base_url: DNS.DEFAULT_BASE, api_key: 'k-msp',
    config: { organization_id: '101', aiCategoryId: '77', timeZone: 'UTC', transport: 'stored-junk' },
  });

  DNS._clearCatalogueCache();
  const pool = fakePool();
  const fStore = fakeDns();
  const snap = await DM.snapshotDay(pool, integ(), '2026-09-01', { now: NOW, cfg: { transport: fStore.transport, sleep: fStore.sleep } });
  check('an older complete day is stored as ok', snap.status === 'ok', `${snap.status} (${snap.rows} rows)`);

  const back = await DM.aiFromRollups(pool, 3, 30, 7);
  check('usage rebuilds', back.usage.available && back.usage.data.allowed === 120 && back.usage.data.blocked === 30);
  check('the AI share of all DNS is computed', back.usage.data.sharePct === 1.5, back.usage.data.sharePct);
  check('tools rebuild with their names',
    back.apps.data.rows.length === 3 && back.apps.data.rows[0].name === 'ChatGPT', back.apps.data.rows.map(r => r.name).join(', '));
  const topUser = back.users.data.rows[0] || {};
  check('users rebuild with their name, login and main tools',
    topUser.user === 'Alice Adams' && topUser.login === 'alice@client.example' &&
    topUser.apps[0].name === 'ChatGPT', JSON.stringify(topUser));
  const bobBack = back.users.data.rows.find(r => r.login === 'bob@client.example') || {};
  check('allowed and blocked survive the rollup separately',
    topUser.allowed === 50 && topUser.blocked === 0 && bobBack.blocked === 10 && bobBack.allowed === 0,
    `alice ${topUser.allowed}/${topUser.blocked}, bob ${bobBack.allowed}/${bobBack.blocked}`);
  check('and so does the unattributed count', back.users.data.unattributed === 40, back.users.data.unattributed);
  check('policy rebuilds', back.policy.data.rows[0].aiBlocked === true && back.policy.data.asOf === '2026-09-01');
  check('rows are scoped to the integration they were written for',
    (await DM.aiFromRollups(pool, 3, 30, 8)).usage.reason === 'no_data_in_range');

  DNS._clearCatalogueCache();
  const todaySnap = await DM.snapshotDay(pool, integ(), '2026-09-15', { now: NOW, cfg: { transport: fakeDns().transport } });
  check('today is stored as partial_day, so it is collected again', todaySnap.status === 'partial_day', todaySnap.status);

  section('re-collecting a day is honest in both directions');

  /*
   * Its own store, holding ONE day. The first version of these checks shared
   * the store above, which also held today's snapshot — so "the figures are
   * still there" passed on today's rows whatever happened to the re-collected
   * day, and "the figures are gone" could never pass at all.
   */
  const poolR = fakePool();
  DNS._clearCatalogueCache();
  await DM.snapshotDay(poolR, integ(), '2026-09-01', { now: NOW, cfg: { transport: fakeDns().transport } });
  const seeded = await DM.aiFromRollups(poolR, 3, 30, 7);
  check('the re-collection store starts with one day of tools', seeded.apps.data.rows.length === 3);

  DNS._clearCatalogueCache();
  const fKept = fakeDns({ fail: { '/v1/traffic_reports/total_domains': 500 } });
  const failedRun = await DM.snapshotDay(poolR, integ(), '2026-09-01',
    { now: NOW, cfg: { transport: fKept.transport, sleep: fKept.sleep } });
  const kept = await DM.aiFromRollups(poolR, 3, 30, 7);
  check('a panel that failed on re-collection keeps the figures an earlier run stored',
    kept.apps.available && kept.apps.data.rows.length === 3, kept.apps.data && kept.apps.data.rows.length);
  check('and says a day could not be read', kept.apps.data.unavailableOnSomeDays === 'source_error',
    kept.apps.data.unavailableOnSomeDays);
  check('the reason reaches the screen with the failure behind it',
    /HTTP 500/.test(kept.apps.data.unavailableDetail || ''), kept.apps.data.unavailableDetail);
  check('and the sync message names it rather than saying "query_error"',
    failedRun.problems.some(p => /^apps \(source_error: .*HTTP 500/.test(p)), failedRun.problems.join('; '));

  DNS._clearCatalogueCache();
  await DM.snapshotDay(poolR, integ(), '2026-09-01', { now: NOW, cfg: { transport: fakeDns({ override: {
    '/v1/traffic_reports/total_domains': () => ({ data: [] }),
  } }).transport } });
  const cleared = await DM.aiFromRollups(poolR, 3, 30, 7);
  check('a panel READ as empty clears what the earlier run stored',
    cleared.apps.reason === 'no_data_in_range' && cleared.apps.data.rows.length === 0,
    cleared.apps.data && cleared.apps.data.rows.map(r => r.name).join(','));
  check('and the earlier "not read" note is gone with it', !cleared.apps.data.unavailableOnSomeDays);

  const pool2 = fakePool();
  DNS._clearCatalogueCache();
  await DM.snapshotDay(pool2, integ(), '2026-09-01', { now: NOW, cfg: { transport: fakeDns().transport } });
  DNS._clearCatalogueCache();
  const fShare = fakeDns({ fail: { '/v1/traffic_reports/total_requests': 500 } });
  await DM.snapshotDay(pool2, integ(), '2026-09-02', { now: NOW, cfg: { transport: fShare.transport, sleep: fShare.sleep } });
  const partialShare = await DM.aiFromRollups(pool2, 3, 30, 7);
  check('a share over only some of the days is not shown',
    partialShare.usage.data.sharePct === null && partialShare.usage.data.allowed === 240, JSON.stringify(partialShare.usage.data.totalReason));

  const pool3 = fakePool();
  DNS._clearCatalogueCache();
  const noCatInteg = integ();
  noCatInteg.config.aiCategoryId = null;
  await DM.snapshotDay(pool3, noCatInteg, '2026-09-01', { now: NOW, cfg: { transport: fakeDns().transport } });
  const noCatBack = await DM.aiFromRollups(pool3, 3, 30, 7);
  check('a reason stored for a day survives into the screen',
    !noCatBack.usage.available && noCatBack.usage.reason === 'category_unknown', JSON.stringify(noCatBack.usage));

  const dupBag = DM.flattenAi({
    usage: { available: false, reason: 'category_unknown' }, apps: { available: false, reason: 'category_unknown' },
    users: { available: false, reason: 'category_unknown' },
    policy: { available: true, data: { rows: [
      { name: 'Default', aiBlocked: false, allowListOnly: false },
      { name: 'Default', aiBlocked: true, allowListOnly: false },
    ] } },
  });
  const pol = dupBag.rows.filter(r => r.metric === 'ai.policy');
  check('two policies with one name store once, and a block is never hidden by the merge',
    pol.length === 1 && pol[0].dim2 === 'blocked', JSON.stringify(pol));

  const days = await DM.daysNeedingSnapshot(pool, 7, 'UTC', new Date(NOW));
  check('today and yesterday are always re-collected, capped per run',
    days[0] === '2026-09-15' && days[1] === '2026-09-14' && days.length === DM.MAX_DAYS_PER_RUN, days.join(', '));

  // ══ The sanctioned-app register ═══════════════════════════════════════════

  section('an unreviewed tool is not a sanctioned one');

  check('only the three statuses are accepted',
    !AV.validateDecision({ status: 'approved' }).ok && !AV.validateDecision({}).ok &&
    AV.validateDecision({ status: 'under_review' }).ok);
  check('an over-long note is refused', !AV.validateDecision({ status: 'sanctioned', note: 'x'.repeat(1001) }).ok);
  check('application keys are only the shapes the adapter produces',
    AV.validAppKey('app:31') && AV.validAppKey('domain:openai.com') &&
    !AV.validAppKey('app:../31') && !AV.validAppKey('APP:31') && !AV.validAppKey('openai.com') && !AV.validAppKey(''));

  const annotated = AV.annotateApps([
    { key: 'app:31', name: 'ChatGPT', allowed: 100, blocked: 0 },
    { key: 'app:32', name: 'Claude', allowed: 0, blocked: 30 },
    { key: 'domain:x.io', name: 'x.io', allowed: 5, blocked: 0 },
  ], new Map([['app:31', { status: 'unsanctioned' }], ['app:32', { status: 'unsanctioned' }]]));
  check('a tool with no decision is unreviewed', annotated.rows[2].status === 'unreviewed' && annotated.unreviewedCount === 1);
  check('allowed traffic to an unsanctioned tool is shadow AI', annotated.rows[0].shadow === true);
  check('blocked-only traffic to one is the policy working, not shadow AI', annotated.rows[1].shadow === false);
  check('so the shadow count is one', annotated.shadowCount === 1 && annotated.sanctionedCount === 0);

  // ══ Server wiring ═════════════════════════════════════════════════════════

  section('the server keeps clients and the MSP key apart');

  const srv = codeOnly(read('server.js'));
  check('the provider is known', /DNSFILTER_PROVIDER = 'dnsfilter'/.test(srv) && /KNOWN_PROVIDERS[^;]*DNSFILTER_PROVIDER/.test(srv));

  const syncFn = srv.slice(srv.indexOf('async function runDnsFilterSync'), srv.indexOf("app.post('/api/integrations/:provider/sync'"));
  check('sync refuses an organisation Test has not verified',
    /!conf\.verified_org_id \|\| String\(conf\.verified_org_id\) !== String\(conf\.organization_id\)/.test(syncFn) &&
    syncFn.indexOf('verified_org_id') < syncFn.indexOf('daysNeedingSnapshot'));
  check('Sync Now reaches it', /provider === DNSFILTER_PROVIDER\) result = await runDnsFilterSync/.test(srv));
  check('the hourly collection does not run under test',
    /NODE_ENV !== 'test'\) \{\s*setTimeout\(\(\) => \{ runDnsFilterSyncs/.test(srv));

  /*
   * The daily ticket sweep takes every enabled integration EXCEPT the ones
   * listed, and calls fetchTickets on it. DNSFilter has no such method, so its
   * absence from that list logged "Unknown provider: dnsfilter" once a day on
   * the pilot — and FortiAnalyzer had been missing from it in the same way.
   */
  const sweep = (srv.match(/provider <> ALL\(\$1::text\[\]\)',\s*\[\[([^\]]*)\]\]/) || [])[1] || '';
  check('the ticket sweep skips every provider that is not ticket-shaped',
    ['EDR_PROVIDER', 'WAZUH_PROVIDER', 'EMAIL_PROVIDER', 'MSGRAPH_PROVIDER', 'FAZ_PROVIDER', 'DNSFILTER_PROVIDER']
      .every(p => sweep.indexOf(p) >= 0), sweep.replace(/\s+/g, ' '));

  /*
   * Rollups from before "accepted" was checked against "applied" may count
   * ordinary traffic as AI. They are dropped once and collected again.
   */
  check('rollups older than the current version are dropped and re-collected once',
    /DNS_ROLLUP_VERSION = 2/.test(srv) &&
    /rollup_version\) \|\| 1\) < DNS_ROLLUP_VERSION/.test(syncFn) &&
    /DELETE FROM wazuh_daily_metric WHERE integration_id = \$1 AND source = \$2/.test(syncFn) &&
    /DELETE FROM wazuh_rollup_run WHERE integration_id = \$1 AND source = \$2/.test(syncFn) &&
    syncFn.indexOf('DNS_ROLLUP_VERSION') < syncFn.indexOf('daysNeedingSnapshot'));
  check('and the version is recorded, so it happens once rather than every hour',
    /rollup_version: DNS_ROLLUP_VERSION/.test(syncFn));

  const saveFn = srv.slice(srv.indexOf('async function saveDnsFilterIntegration'), srv.indexOf('async function testDnsFilterIntegration'));
  check('a save keeps the proved filters and the rollup version, so it does not trigger a re-collection',
    /'verified_category_filters', 'rollup_version'/.test(saveFn));
  check('a save builds config from an allowlist, so verification cannot be sent in',
    /const next = \{ organization_id: orgId, timeZone: tz \}/.test(saveFn) &&
    !/\.\.\.c\b|\.\.\.configJson|assign\([^)]*configJson/.test(saveFn));
  check('verification survives a save only for the same organisation',
    /prev\.verified_org_id && String\(prev\.verified_org_id\) === orgId/.test(saveFn));

  const mspRoutes = srv.match(/app\.(get|post|delete)\('\/api\/msp-integrations\/dnsfilter[^']*', [^\n]*/g) || [];
  check('every MSP key route is superadmin-only',
    mspRoutes.length === 4 && mspRoutes.every(r => /requireAuth, requireSuperAdmin/.test(r)), `${mspRoutes.length} routes`);
  const mspGet = srv.slice(srv.indexOf("app.get('/api/msp-integrations/dnsfilter'"), srv.indexOf("app.post('/api/msp-integrations/dnsfilter'"));
  check('and the key is never read back out', mspGet.length > 0 && !/api_key/.test(mspGet));
  check('the MSP key may only point at a dnsfilter.com host over https',
    /hostname\.endsWith\('\.dnsfilter\.com'\)/.test(srv) && /protocol !== 'https:'/.test(srv));

  const put = srv.slice(srv.indexOf("app.put('/api/ai-visibility/decisions/:appKey'"), srv.indexOf("app.delete('/api/ai-visibility/decisions/:appKey'"));
  check('a decision is written to the resolved tenant, validated first',
    /resolveIntegrationTenant\(req, 'body'\)/.test(put) && /validAppKey/.test(put) && /validateDecision/.test(put) &&
    /\[tenantId, appKey,/.test(put));
  check('and un-deciding is scoped the same way',
    /DELETE FROM ai_app_decisions WHERE tenant_id = \$1 AND app_key = \$2/.test(srv));

  section('staff only');

  const levels = PAGES.ROLE_DEFAULTS;
  check('the page exists and a portal client has no access to it',
    PAGES.PAGE_KEYS.indexOf('ai-visibility') >= 0 && levels.client['ai-visibility'] === 'none', levels.client['ai-visibility']);
  const pagesSrc = codeOnly(read('lib', 'pages.js'));
  check('its API is gated by its page, so a decision needs WRITE',
    /'ai-visibility':\s*'ai-visibility'/.test(pagesSrc));
  check('the MSP key API is gated by Admin as well as by role', /'msp-integrations':\s*'admin'/.test(pagesSrc));
  const portal = read('lib', 'portal-routes.js');
  check('the portal has no AI Visibility route', !/ai-visibility|dnsfilter|ai_app_decisions/i.test(portal));

  // ══ The tab, the admin cards, the report ═══════════════════════════════════

  section('the tab is wired');

  const html = read('public', 'index.html');
  const appJs = read('public', 'js', 'app.js');
  const ui = read('public', 'js', 'wazuh-ui.js');
  const tab = codeOnly(read('public', 'js', 'tab-ai-visibility.js'));
  check('nav item, panel and script are in the page',
    /data-tab="ai-visibility"/.test(html) && /id="tab-ai-visibility"/.test(html) &&
    html.indexOf('<script src="js/wazuh-ui.js">') < html.indexOf('<script src="js/tab-ai-visibility.js">'));
  check('the router renders it', /target === 'ai-visibility'[\s\S]{0,120}AiVisibilityTab\.loadAndRender\(\)/.test(appJs));
  check('Sync Now is a known target', /dnsfilter:\s*'Collecting from DNSFilter/.test(ui));
  check('the decision editor appears only for writers', /canWrite\('ai-visibility'\)/.test(tab));
  check('and an undecided tool shows as unreviewed', /STATUS\[r\.status\] \|\| STATUS\.unreviewed/.test(tab));
  check('an empty users table explains that only roaming-client traffic names a user',
    /roaming client/.test(read('public', 'js', 'tab-ai-visibility.js')) && /NO_USERS_TEXT/.test(tab));
  check('the integration card shows the fields DNSFilter returned and which filter was proved',
    /What DNSFilter returned/.test(read('public', 'js', 'tab-admin.js')) &&
    /verified_category_filters/.test(codeOnly(read('public', 'js', 'tab-admin.js'))));

  section('an HTML error page is reported as what it is');

  /*
   * The pilot saw "Unexpected token '<', "<html> <h"... is not valid JSON" on
   * the integration card. That is a proxy, a restarting server, an expired
   * session or a route missing from the running build — and res.json() turns
   * every one of them into a parser message about the wrong thing.
   */
  const uiBox = { console };
  uiBox.window = uiBox;
  vm.createContext(uiBox);
  vm.runInContext(read('public', 'js', 'wazuh-ui.js'), uiBox);
  const U = uiBox.window.WazuhUI;

  const fakeRes = (status, type, body) => ({
    ok: status >= 200 && status < 300, status,
    headers: { get: () => type },
    text: async () => body,
  });

  const htmlErr = await U.readJson(fakeRes(502, 'text/html', '<html> <head><title>502</title></head></html>'));
  check('an HTML error page names the status and a likely cause, not a parse error',
    !htmlErr.ok && /HTTP 502/.test(htmlErr.error) && /proxy/.test(htmlErr.error) && !/token/.test(htmlErr.error),
    htmlErr.error);
  const signedOut = await U.readJson(fakeRes(401, 'text/html', '<html>login</html>'));
  check('a signed-out session says so', /signed out/.test(signedOut.error), signedOut.error);
  const missing = await U.readJson(fakeRes(404, 'text/html', '<html>Cannot POST</html>'));
  check('a missing endpoint points at the deployment', /redeploying/.test(missing.error), missing.error);
  const good = await U.readJson(fakeRes(200, 'application/json', '{"ok":true,"message":"hi"}'));
  check('and real JSON still comes through', good.ok && good.data.message === 'hi');
  const jsonErr = await U.readJson(fakeRes(400, 'application/json', '{"error":"Invalid organisation id."}'));
  check('as does a JSON error body, so the server\'s own message still wins',
    !jsonErr.ok && jsonErr.data.error === 'Invalid organisation id.');

  /*
   * Scoped to the integration calls that REPORT to the operator — save, test
   * and sync — which is where the parser message appeared. The user and tenant
   * admin code reads responses its own way and is not this change's business;
   * the two integration READS left alone are guarded by `if (res.ok)` and
   * degrade to an empty card rather than throwing.
   */
  const adminSrc = codeOnly(read('public', 'js', 'tab-admin.js'));
  /*
   * From the MSP card's helper onwards: every integration call that REPORTS to
   * the operator — the MSP key card, save, test and sync — which is where the
   * parser message appeared. The user, tenant and MFA code above reads
   * responses its own way and is not this change's business; the two
   * integration READS left alone are guarded by `if (res.ok)` and degrade to an
   * empty card rather than throwing.
   */
  /*
   * Asserted per function rather than over a slice of the file. An earlier
   * version scanned a region and had to cut readIntJson's own `await
   * res.json()` fallback back out of it by regex — a test that depends on where
   * a brace sits is a test that breaks on reformatting.
   */
  const fnBody = (src, start) => {
    const from = src.indexOf(start);
    if (from < 0) return '';
    const next = src.indexOf('\n  async function ', from + start.length);
    return src.slice(from, next < 0 ? src.length : next);
  };
  const reporting = {
    'the MSP key card':  fnBody(adminSrc, 'const call = async (method, path, body)'),
    saveIntegration:     fnBody(adminSrc, 'async function saveIntegration'),
    testIntegration:     fnBody(adminSrc, 'async function testIntegration'),
    syncIntegration:     fnBody(adminSrc, 'async function syncIntegration'),
  };
  const offenders = Object.keys(reporting).filter(k => /await res\.json\(\)/.test(reporting[k]));
  const converted = Object.keys(reporting).filter(k => /await readIntJson\(res\)/.test(reporting[k]));
  check('every integration call that reports to the operator reads responses that way',
    offenders.length === 0 && converted.length === 4,
    offenders.length ? 'still bare: ' + offenders.join(', ') : converted.join(', '));
  check('and so does the AI Visibility tab',
    !/await res\.json\(\)/.test(codeOnly(read('public', 'js', 'tab-ai-visibility.js'))));

  section('the board section names the top users, and no more');

  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  for (const f of ['report-shell.js', 'report-deck.js', 'mdr-metrics.js', 'report-sections.js']) {
    vm.runInContext(read('public', 'js', f), sandbox);
  }
  const sec = sandbox.window.ReportSections.find(s => s.id === 'aiUsage');
  check('the section exists and is tied to the service',
    !!sec && sec.services.join(',') === 'ai_visibility' && sec.requires.join(',') === 'ai' &&
    SERVICES.SERVICE_KEYS.indexOf('ai_visibility') >= 0);

  const annotatedBack = Object.assign({}, back.apps, {
    data: Object.assign({}, back.apps.data, AV.annotateApps(back.apps.data.rows, new Map([['app:31', { status: 'unsanctioned' }]]))),
  });
  const deckSummary = { configured: true, windowDays: 30, usage: back.usage, apps: annotatedBack, users: back.users, policy: back.policy };
  const deck = String(sec.render({ data: { ai: deckSummary }, comments: {} }));
  check('it reports the figures', /150/.test(deck) && /ChatGPT/.test(deck) && /Blocked/.test(deck));
  /*
   * REFRAMED, NOT REMOVED. This used to assert that the deck printed no user at
   * all. Reflex asked for the top users in the report, so the property that
   * remains is narrower and still worth holding: names, few of them, never a
   * login.
   */
  check('it lists the top users by name, with allowed and blocked',
    /Top users of AI tools/.test(deck) && /Alice Adams/.test(deck) && /Bob Brown/.test(deck));
  check('but never their login — the email address stays on the staff tab',
    !/client\.example/i.test(deck), 'no login in the deck');

  const withUsers = users => String(sec.render({
    data: { ai: Object.assign({}, deckSummary, { users }) }, comments: {},
  }));
  const manyUsers = withUsers({ available: true, reason: null, data: { unattributed: 40, rows:
    Array.from({ length: 7 }, (_, i) => ({
      user: `Person ${i + 1}`, login: `p${i + 1}@client.example`, allowed: 70 - i, blocked: 0, apps: [],
    })) } });
  check('only the top five are named', /Person 5/.test(manyUsers) && !/Person 6/.test(manyUsers));
  check('office-network lookups are said, not hidden',
    /40 AI lookups came through office networks/.test(manyUsers));

  const loginOnly = withUsers({ available: true, reason: null, data: { rows: [
    { user: 'dave@client.example', login: 'dave@client.example', allowed: 3, blocked: 0, apps: [] }] } });
  check('a user with no display name is shown by the name part of their login, not the address',
    /<td>dave<\/td>/.test(loginOnly) && !/dave@/.test(loginOnly));

  const hostile = withUsers({ available: true, reason: null, data: { rows: [
    { user: '<img src=x onerror=alert(1)>', login: 'x', allowed: 1, blocked: 0, apps: [] }] } });
  check('a name from DNSFilter cannot inject markup into the deck',
    !/<img src=x/.test(hostile) && /&lt;img/.test(hostile));

  const noUsers = withUsers({ available: false, data: null, reason: 'not_permitted' });
  check('without a users panel the section still renders, just without the table',
    /ChatGPT/.test(noUsers) && !/Top users of AI tools/.test(noUsers));

  const noUsage = String(sec.render({ data: { ai: Object.assign({}, deckSummary, {
    usage: { available: false, data: null, reason: 'unrecognised_response' },
  }) }, comments: {} }));
  check('an unread usage figure says No data, not 0',
    /bi-v nd">No data<\/div><div class="bi-l">AI tool lookups/.test(noUsage));
  check('a client without DNSFilter gets no section at all',
    sec.render({ data: { ai: { configured: false } }, comments: {} }) === null);

  const rpt = codeOnly(read('public', 'js', 'tab-reports.js'));
  check('the report fetches the summary, and withholds it from clients who do not buy the service',
    /ai:\s*function \(ctx\) \{ return 'api\/ai-visibility\/summary/.test(rpt) && /ai:\s*'ai_visibility'/.test(rpt));

  const admin = codeOnly(read('public', 'js', 'tab-admin.js'));
  check('the MSP card is only fetched for a superadmin',
    /role === 'superadmin'\) \{\s*try \{\s*const r = await fetch\('api\/msp-integrations\/dnsfilter'/.test(admin));

  done();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
