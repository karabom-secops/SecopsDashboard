'use strict';

/**
 * Managed Identity from Microsoft Graph and the Office 365 Management Activity
 * API — the only source for the Managed Identity screen.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   the right directory          a sync is refused until Test has verified
 *                                Identity against the configured directory
 *   not recorded is not none     a tenant without Entra ID P2 has no risky-user
 *                                feed; one without the DLP permission no DLP.
 *                                Each part is unavailable WITH its reason, the
 *                                screen and the board report say so, and no
 *                                zero from a missing feed reaches a slide
 *   sign-ins are counted honestly MFA interruptions are not failures; spraying
 *                                is one source against many accounts; legacy
 *                                protocols and CA failures are separated
 *   the client's day              windows are local midnight to midnight, DST
 *                                included; audit events are kept by their own
 *                                time, from blobs created that day and the next;
 *                                older than 7 days is beyond retention
 *   the screen needs no rewrite  output survives flatten → store → rebuild,
 *                                scoped to its own integration
 *   Test is the only write       audit subscriptions are started on Test, never
 *                                by the hourly sync
 *
 *   node tests/ms-identity.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('ms-identity');

const IDN = require(path.join(ROOT, 'lib', 'integrations', 'ms-identity.js'));
const IM  = require(path.join(ROOT, 'lib', 'identity-metrics.js'));
const WM  = require(path.join(ROOT, 'lib', 'daily-metrics.js'));

function codeOnly(src) {
  return String(src)
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const read = (...p) => fs.readFileSync(path.join(ROOT, ...p), 'utf8');

const GRAPH = 'https://graph.microsoft.com/v1.0';
const DAY = '2026-09-14';
const TZ = 'Africa/Johannesburg';
const NOW = Date.parse('2026-09-15T08:00:00Z');
const CFG = { azure_tenant_id: 'tid-client-a', client_id: 'app', api_key: 'secret', identity_time_zone: TZ };

const err403 = msg => Object.assign(new Error('Microsoft Graph API 403: ' + msg), { statusCode: 403 });
const withHeaders = (arr, h) => Object.defineProperty(arr, '__headers', { value: h, enumerable: false });

// ── Fixtures ───────────────────────────────────────────────────────────────

const su = (upn, code, extra) => Object.assign({
  userPrincipalName: upn, status: { errorCode: code }, ipAddress: '10.0.0.1',
  clientAppUsed: 'Browser', location: { countryOrRegion: 'ZA' }, conditionalAccessStatus: 'notApplied',
}, extra || {});

const SIGNINS_P1 = [
  su('alice@a.test', 0),
  su('bob@a.test', 0, { clientAppUsed: 'Mobile Apps and Desktop clients' }),
  su('alice@a.test', 50074),
  ...['u1', 'u2', 'u3', 'u4', 'u5', 'u6'].map(u => su(u + '@a.test', 50126, {
    ipAddress: '45.9.9.9:51522', location: { countryOrRegion: 'RU' },
    status: { errorCode: 50126, failureReason: 'Invalid username or password' },
  })),
  su('alice@a.test', 50126, {
    ipAddress: '45.9.9.9', location: { countryOrRegion: 'RU' },
    status: { errorCode: 50126, failureReason: 'Invalid username or password' },
  }),
];
const SIGNINS_P2 = [
  su('carol@a.test', 0, { clientAppUsed: 'IMAP4' }),
  su('dave@a.test', 53003, {
    conditionalAccessStatus: 'failure',
    status: { errorCode: 53003, failureReason: 'Access has been blocked by Conditional Access policies.' },
  }),
];

const AUDITS = [
  { category: 'RoleManagement', activityDisplayName: 'Add member to role', activityDateTime: '2026-09-14T10:00:00Z',
    initiatedBy: { user: { userPrincipalName: 'admin@a.test', ipAddress: '10.1.1.1' } },
    targetResources: [{ userPrincipalName: 'bob@a.test' }], result: 'success' },
  { category: 'UserManagement', activityDisplayName: 'Reset user password', activityDateTime: '2026-09-14T12:00:00Z',
    initiatedBy: { app: { displayName: 'Automation' } }, result: 'failure' },
  { category: 'SelfServicePasswordManagement', activityDisplayName: 'Reset password (self-service)',
    activityDateTime: '2026-09-14T13:00:00Z', initiatedBy: { user: { userPrincipalName: 'carol@a.test' } } },
];

const ALERTS = [
  { title: 'Password spray', severity: 'high', status: 'new', serviceSource: 'microsoftDefenderForIdentity',
    mitreTechniques: ['T1110', 'T1078'], createdDateTime: '2026-09-14T09:00:00Z' },
  { title: 'Unfamiliar sign-in', severity: 'medium', status: 'resolved', serviceSource: 'azureAdIdentityProtection',
    mitreTechniques: ['T1110'], createdDateTime: '2026-09-14T11:00:00Z' },
];

const EXCHANGE_E1 = [
  { Workload: 'Exchange', Operation: 'New-InboxRule', CreationTime: '2026-09-14T09:00:00', UserId: 'mallory@a.test',
    MailboxOwnerUPN: 'bob@a.test', ClientIP: '203.0.113.7:4431' },
  { Workload: 'Exchange', Operation: 'Set-InboxRule', CreationTime: '2026-09-13T21:00:00', UserId: 'bob@a.test' },
  { Workload: 'Exchange', Operation: 'UpdateInboxRules', CreationTime: '2026-09-14T21:59:00', UserId: 'carol@a.test' },
  { Workload: 'Exchange', Operation: 'MailItemsAccessed', CreationTime: '2026-09-14T08:00:00', UserId: 'bob@a.test' },
];
const SHAREPOINT = [
  { Workload: 'SharePoint', Operation: 'AnonymousLinkCreated', CreationTime: '2026-09-14T10:00:00', UserId: 'bob@a.test', SiteUrl: 'https://a.sharepoint.com/sites/finance' },
  { Workload: 'SharePoint', Operation: 'SharingSet', TargetUserOrGroupType: 'Member', CreationTime: '2026-09-14T10:05:00', UserId: 'bob@a.test' },
  { Workload: 'OneDrive', Operation: 'SharingSet', TargetUserOrGroupType: 'Guest', CreationTime: '2026-09-14T10:10:00', UserId: 'alice@a.test', SiteUrl: 'https://a-my.sharepoint.com/personal/alice' },
];

/** A simulated Microsoft: Graph and manage.office.com, routed by URL. */
function fakeMicrosoft(over) {
  const o = over || {};
  const calls = [];
  const route = (method, url, opts) => {
    calls.push({ method, url, opts: opts || {} });
    if (url.indexOf(GRAPH + '/auditLogs/signIns') === 0) {
      if (o.signinsError) throw o.signinsError;
      return /skiptoken/.test(url)
        ? { value: SIGNINS_P2 }
        : { value: SIGNINS_P1, '@odata.nextLink': GRAPH + '/auditLogs/signIns?$skiptoken=abc' };
    }
    if (url.indexOf(GRAPH + '/auditLogs/directoryAudits') === 0) return { value: AUDITS };
    if (url.indexOf(GRAPH + '/security/alerts_v2') === 0) return { value: ALERTS };
    if (url.indexOf(GRAPH + '/identityProtection/riskyUsers') === 0) {
      if (o.riskyUsers) return { value: o.riskyUsers };
      throw err403('Tenant does not have a premium license (Entra ID P2) required for this request');
    }
    if (url.indexOf(GRAPH + '/identityProtection/riskDetections') === 0) {
      if (o.detections) return { value: o.detections };
      throw err403('Insufficient privileges to complete the operation.');
    }
    if (/\/subscriptions\/list$/.test(url)) return o.subscriptions || [{ contentType: 'Audit.Exchange', status: 'enabled' }];
    if (/\/subscriptions\/start\?contentType=DLP\.All/.test(url)) throw err403('ActivityFeed.ReadDlp not granted');
    if (/\/subscriptions\/start\?/.test(url)) return { status: 'enabled' };
    if (/\/subscriptions\/content\?contentType=Audit\.Exchange/.test(url)) {
      return /startTime=2026-09-13T22:00:00/.test(url)
        ? withHeaders([{ contentId: 'e1', contentUri: 'https://manage.office.com/blob/e1' }], { nextpageuri: 'https://manage.office.com/next-exchange' })
        : withHeaders([{ contentId: 'e1', contentUri: 'https://manage.office.com/blob/e1' }], {});
    }
    if (url === 'https://manage.office.com/next-exchange') return withHeaders([{ contentId: 'e2', contentUri: 'https://manage.office.com/blob/e2' }], {});
    if (/\/subscriptions\/content\?contentType=Audit\.SharePoint/.test(url)) {
      return withHeaders([{ contentId: 's1', contentUri: 'https://manage.office.com/blob/s1' }], {});
    }
    if (/\/subscriptions\/content\?contentType=DLP\.All/.test(url)) throw err403('ActivityFeed.ReadDlp not granted');
    if (url === 'https://manage.office.com/blob/e1') return EXCHANGE_E1;
    if (url === 'https://manage.office.com/blob/e2') return [];
    if (url === 'https://manage.office.com/blob/s1') return SHAREPOINT;
    throw new Error('unrouted ' + url);
  };
  return {
    calls,
    http: {
      get: async (url, opts) => route('GET', url, opts),
      post: async (url, opts) => route('POST', url, opts),
    },
  };
}

(async function main() {

  // ── Time ─────────────────────────────────────────────────────────────────

  section('a day is the client\'s local day');
  {
    const w = IDN.dayWindow(DAY, TZ);
    check('Johannesburg midnight is 22:00 UTC the day before',
      new Date(w.start).toISOString() === '2026-09-13T22:00:00.000Z' &&
      new Date(w.end).toISOString() === '2026-09-14T22:00:00.000Z', new Date(w.start).toISOString());
    const utc = IDN.dayWindow(DAY, 'UTC');
    check('UTC is midnight to midnight', new Date(utc.start).toISOString() === '2026-09-14T00:00:00.000Z');
    const dst = IDN.dayWindow('2026-03-29', 'Europe/London');
    check('a daylight-saving day is 23 hours, not 24',
      (dst.end - dst.start) === 23 * 3600000, (dst.end - dst.start) / 3600000 + 'h');
    let bad = '';
    try { IDN.dayWindow(DAY, 'Mars/Olympus'); } catch (e) { bad = e.message; }
    check('an invalid time zone is an error, not silently UTC', /Invalid time zone/.test(bad), bad);
  }

  // ── Aggregation ──────────────────────────────────────────────────────────

  section('sign-ins are counted honestly');
  {
    const a = IDN.aggregateSignIns(SIGNINS_P1.concat(SIGNINS_P2));
    check('successes and distinct signed-in users',
      a.signins.success === 3 && a.signins.uniqueUsers === 3, JSON.stringify(a.signins));
    check('an MFA interruption is not a failure', a.signins.interrupted === 1 && a.signins.failed === 8, a.signins.failed);
    const spray = a.failedLogins.byIp[0];
    check('the port is stripped, so one source is one row', spray.label === '45.9.9.9' && spray.count === 7, JSON.stringify(spray));
    check('one source against many accounts is flagged as spraying', spray.targetedUsers === 7 && spray.spray === true);
    check('failure reasons are named', a.failedLogins.byReason[0].label === 'Invalid username or password' && a.failedLogins.byReason[0].count === 7);
    check('failed users carry distinct IPs', a.failedLogins.byUser.find(u => u.label === 'alice@a.test').distinctIps === 1);
    check('legacy protocols are separated out', a.graphSignins.legacyAuth.total === 1 && a.graphSignins.legacyAuth.byUser[0].label === 'carol@a.test');
    check('Conditional Access failures are counted', a.graphSignins.caFailures === 1);
    const za = a.graphSignins.byCountry.find(c => c.label === 'ZA');
    const ru = a.graphSignins.byCountry.find(c => c.label === 'RU');
    check('countries with failures and users', za.count === 5 && ru.count === 7 && ru.failed === 7 && ru.users === 7,
      JSON.stringify([za, ru]));
    check('every sign-in is in the total', a.graphSignins.total === 12);
  }

  section('admin changes, alerts, risk, mailbox rules, sharing and DLP');
  {
    const ad = IDN.aggregateAdmin(AUDITS);
    check('self-service noise is not an admin change', ad.total === 2, ad.total);
    check('newest first, with an app actor when no user', ad.recent[0].operation === 'Reset user password' &&
      ad.recent[0].actor === 'Automation' && ad.recent[0].ok === false);
    check('the target and source IP are carried', ad.recent[1].target === 'bob@a.test' && ad.recent[1].clientIp === '10.1.1.1');

    const al = IDN.aggregateAlerts(ALERTS);
    check('alerts by severity, with high counted', al.total === 2 && al.high === 1);
    check('MITRE techniques across alerts', al.byTechnique[0].label === 'T1110' && al.byTechnique[0].count === 2);

    const ru = IDN.mapRiskyUsers([
      { userPrincipalName: 'x@a.test', riskLevel: 'low', riskState: 'atRisk', riskLastUpdatedDateTime: '2026-09-14T01:00:00Z' },
      { userPrincipalName: 'x@a.test', riskLevel: 'high', riskState: 'atRisk', riskLastUpdatedDateTime: '2026-09-14T09:00:00Z' },
      { userPrincipalName: 'y@a.test', riskLevel: 'medium', riskState: 'remediated', riskLastUpdatedDateTime: '2026-09-14T05:00:00Z' },
    ]);
    check('risky users are the latest state per user', ru.distinct === 2 && ru.users[0].label === 'x@a.test' && ru.users[0].level === 'high');

    const mb = IDN.aggregateMailboxRules(EXCHANGE_E1);
    check('inbox-rule operations only', mb.total === 3 && !mb.byOperation.some(r => r.label === 'MailItemsAccessed'));
    check('the mailbox owner, not the actor, is the mailbox', mb.byMailbox.some(r => r.label === 'bob@a.test'));

    const sh = IDN.aggregateSharing(SHAREPOINT);
    check('internal sharing is not external sharing', sh.total === 2, sh.total);
    check('guest sharing is', sh.byUser.some(u => u.label === 'alice@a.test'));

    const dlp = IDN.aggregateDlp([{ Operation: 'DlpRuleMatch', PolicyDetails: [{ PolicyName: 'SA ID numbers',
      Rules: [{ ConditionsMatched: { SensitiveInformation: [{ SensitiveInformationTypeName: 'South Africa Identification Number' }] } }] }] }]);
    check('DLP matches by policy and information type',
      dlp.total === 1 && dlp.byPolicy[0].label === 'SA ID numbers' && /South Africa/.test(dlp.byInfoType[0].label));
  }

  section('why a read failed');
  check('a missing premium licence is not_licensed', IDN.reasonOf(err403('Tenant does not have a premium license')) === 'not_licensed');
  check('a missing permission is not_permitted', IDN.reasonOf(err403('Insufficient privileges')) === 'not_permitted');
  check('anything else is query_error', IDN.reasonOf(new Error('socket hang up')) === 'query_error');

  // ── One day end to end ───────────────────────────────────────────────────

  section('one day, with some feeds unavailable');
  const ms = fakeMicrosoft();
  const day = await IDN.fetchIdentityDay(CFG, DAY, { timeZone: TZ, now: NOW, isToday: false, http: ms.http });
  {
    check('the Office 365 half is available', day.o365.available === true);
    const oUnavail = day.o365.data.unavailable;
    check('DLP is unavailable as not_permitted — not zero', oUnavail.some(u => u.key === 'dlp' && u.reason === 'not_permitted'),
      JSON.stringify(oUnavail));
    check('while sign-ins, admin, mailbox rules and sharing are not', !oUnavail.some(u => ['signins', 'admin', 'mailboxRules', 'sharing'].includes(u.key)));
    check('sign-ins were read across both pages', day.o365.data.signins.success === 3 && day.graph.data.signins.total === 12);

    const gUnavail = day.graph.data.unavailable;
    check('risky users are unavailable as not_licensed', gUnavail.some(u => u.key === 'riskyUsers' && u.reason === 'not_licensed'));
    check('risk detections are unavailable as not_permitted', gUnavail.some(u => u.key === 'riskDetections' && u.reason === 'not_permitted'));
    check('alerts still arrive', day.graph.data.alerts.total === 2);

    check('mailbox rules are only those whose own time falls in the day',
      day.o365.data.mailboxRules.total === 2, day.o365.data.mailboxRules.total);
    check('audit blobs are de-duplicated and paged', ms.calls.filter(c => c.url === 'https://manage.office.com/blob/e1').length === 1 &&
      ms.calls.some(c => c.url === 'https://manage.office.com/next-exchange'));
    const listCalls = ms.calls.filter(c => /content\?contentType=Audit\.Exchange/.test(c.url)).map(c => c.url);
    check('content is listed for the day and the day after, in ≤24h windows',
      listCalls.length === 2 && /startTime=2026-09-13T22:00:00&endTime=2026-09-14T22:00:00/.test(listCalls[0]) &&
      /startTime=2026-09-14T22:00:00&endTime=2026-09-15T08:00:00/.test(listCalls[1]), listCalls.join(' | '));
    check('workloads are tallied from what was read',
      day.o365.data.byWorkload.some(w => w.label === 'Exchange' && w.count === 3));

    const signinCall = ms.calls.find(c => c.url.indexOf(GRAPH + '/auditLogs/signIns') === 0);
    check('Graph is asked for the local day as a UTC window',
      decodeURIComponent(signinCall.url).indexOf('createdDateTime ge 2026-09-13T22:00:00Z and createdDateTime lt 2026-09-14T22:00:00Z') > 0,
      decodeURIComponent(signinCall.url));
    check('each Graph read names the permission it needs', signinCall.opts.permission === 'AuditLog.Read.All');
    check('audit reads use the Management API token, not Graph\'s',
      ms.calls.filter(c => /manage\.office\.com/.test(c.url)).every(c => c.opts.scope === 'https://manage.office.com/.default'));
    check('a past day does not ask for everyone currently at risk',
      !ms.calls.some(c => /riskState/.test(decodeURIComponent(c.url))));
    check('the sync never writes to the tenant', !ms.calls.some(c => c.method === 'POST'));
  }

  section('today also includes everyone still at risk');
  {
    const m2 = fakeMicrosoft({ riskyUsers: [{ userPrincipalName: 'x@a.test', riskLevel: 'high', riskState: 'atRisk' }] });
    await IDN.fetchIdentityDay(CFG, '2026-09-15', { timeZone: TZ, now: NOW, isToday: true, http: m2.http });
    check('a current at-risk query is made', m2.calls.some(c => /riskState eq 'atRisk'/.test(decodeURIComponent(c.url))));
  }

  section('beyond Office 365 retention');
  {
    const m3 = fakeMicrosoft();
    const old = await IDN.fetchIdentityDay(CFG, '2026-09-01', { timeZone: TZ, now: NOW, http: m3.http });
    check('mailbox rules, sharing and DLP are beyond_retention',
      ['mailboxRules', 'sharing', 'dlp'].every(k => old.o365.data.unavailable.some(u => u.key === k && u.reason === 'beyond_retention')),
      JSON.stringify(old.o365.data.unavailable));
    check('and no content is requested for them', !m3.calls.some(c => /subscriptions\/content/.test(c.url)));
    check('sign-ins for that day are still read', old.o365.data.signins.success === 3);
  }

  section('when nothing can be read');
  {
    const none = fakeMicrosoft({ signinsError: err403('Insufficient privileges') });
    none.http.get = async () => { throw err403('Insufficient privileges'); };
    const d = await IDN.fetchIdentityDay(CFG, DAY, { timeZone: TZ, now: NOW, http: none.http });
    check('both halves are unavailable with a reason, never available zeros',
      d.o365.available === false && d.o365.reason === 'not_permitted' && d.o365.data === null &&
      d.graph.available === false, JSON.stringify([d.o365.reason, d.graph.reason]));
  }

  // ── Test connection ──────────────────────────────────────────────────────

  section('Test checks each permission and starts the audit subscriptions');
  {
    const m = fakeMicrosoft();
    const p = await IDN.probe(CFG, { http: m.http });
    check('sign-ins, admin and alerts pass', p.graph.signins.ok && p.graph.admin.ok && p.graph.alerts.ok);
    check('risky users fail for the licence, naming the permission',
      p.graph.riskyUsers.ok === false && p.graph.riskyUsers.reason === 'not_licensed' && p.graph.riskyUsers.permission === 'IdentityRiskyUser.Read.All');
    check('a subscription already enabled is left alone', p.audit.enabled.indexOf('Audit.Exchange') >= 0 && p.audit.started.indexOf('Audit.Exchange') < 0);
    check('a missing one is started', p.audit.started.indexOf('Audit.SharePoint') >= 0 &&
      m.calls.some(c => c.method === 'POST' && /start\?contentType=Audit\.SharePoint/.test(c.url)));
    check('a refused one is reported', p.audit.failed.some(f => f.contentType === 'DLP.All' && f.reason === 'not_permitted'));
    check('something works, so Identity can be verified', p.anyOk === true);
    const words = IDN.describeProbe(p);
    check('the result reads as a sentence per resource',
      /sign-ins ✓/.test(words) && /risky users ✗ \(needs Entra ID P1\/P2\)/.test(words) &&
      /risk detections ✗ \(needs IdentityRiskEvent\.Read\.All\)/.test(words) && /started now: Audit\.SharePoint/.test(words), words);
  }

  // ── Rollups ──────────────────────────────────────────────────────────────

  section('the day survives the rollup path, reasons included');
  {
    const split = WM.flattenO365(day);
    const rows = split.office365.rows.concat(split.msgraph.rows);
    const q = [];
    const pool = {
      async query(sql, params) {
        q.push({ sql: String(sql).replace(/\s+/g, ' '), params });
        const source = params[1];
        return { rows: rows.filter(r => r.source === source).map(r => Object.assign({ day: DAY, meta: r.meta ? JSON.parse(r.meta) : null }, r)) };
      },
    };
    const rebuilt = await WM.o365FromRollups(pool, 7, 30, 55);
    check('read per integration', q.every(x => x.params[3] === 55), q.map(x => x.params[3]).join(','));
    check('sign-ins come back', rebuilt.o365.data.signins.success === 3 && rebuilt.graph.data.signins.total === 12);
    check('DLP comes back unavailable, with its reason',
      rebuilt.o365.data.unavailable.some(u => u.key === 'dlp' && u.reason === 'not_permitted'), JSON.stringify(rebuilt.o365.data.unavailable));
    check('risky users come back not_licensed',
      rebuilt.graph.data.unavailable.some(u => u.key === 'riskyUsers' && u.reason === 'not_licensed'));
    check('mailbox rules come back', rebuilt.o365.data.mailboxRules.total === 2);
  }

  section('which days are collected');
  {
    const q = [];
    const pool = { async query(sql, params) {
      q.push({ sql, params });
      return { rows: [
        { day: '2026-09-13', source: 'office365', status: 'ok' },
        { day: '2026-09-13', source: 'ms-graph', status: 'no_data' },
        { day: '2026-09-12', source: 'office365', status: 'ok' },
        { day: '2026-09-12', source: 'ms-graph', status: 'error' },
      ] };
    } };
    const days = await IM.daysNeedingSnapshot(pool, 55, TZ, new Date(NOW));
    check('today and yesterday always, then days not complete for BOTH sources',
      days.join(',') === '2026-09-15,2026-09-14,2026-09-12', days.join(','));
    check('scoped to the integration and both sources',
      q[0].params[0] === 55 && JSON.stringify(q[0].params[1]) === '["office365","ms-graph"]');
  }

  section('a collected day is stored in one transaction');
  {
    const statements = [];
    const client = { async query(sql, params) { statements.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params }); return { rows: [] }; }, release() {} };
    const pool = { async connect() { return client; } };
    const r = await IM.snapshotDay(pool, { id: 55, tenant_id: 7, base_url: GRAPH, api_key: 'secret', config: CFG },
      DAY, { timeZone: TZ, now: NOW, http: fakeMicrosoft().http });
    check('it commits', statements[0].sql === 'BEGIN' && statements[statements.length - 1].sql === 'COMMIT');
    check('both sources are written for this integration and tenant',
      statements.filter(s => /INSERT INTO daily_metric/.test(s.sql)).every(s => s.params[1][0] === 55 && s.params[0][0] === 7) &&
      ['office365', 'ms-graph'].every(src => statements.some(s => /INSERT INTO rollup_run/.test(s.sql) && s.params[2] === src)));
    check('yesterday is stored as still filling in', r.statuses.every(s => s === 'partial_day'), r.statuses.join(','));
    check('what could not be read is reported', r.problems.some(p => /riskyUsers \(not_licensed\)/.test(p)), r.problems.join('; '));

    const old = [];
    const oldClient = { async query(sql, params) { old.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params }); return { rows: [] }; }, release() {} };
    const full = fakeMicrosoft({ riskyUsers: [], detections: [] });
    const r2 = await IM.snapshotDay({ async connect() { return oldClient; } },
      { id: 55, tenant_id: 7, base_url: GRAPH, api_key: 'secret', config: CFG }, '2026-09-01', { timeZone: TZ, now: NOW, http: full.http });
    check('a day past audit retention is still complete, so it is not re-tried every hour',
      r2.statuses.join(',') === 'ok,ok', r2.statuses.join(','));
  }

  // ── Wiring ───────────────────────────────────────────────────────────────

  section('the server wiring');
  const srv = codeOnly(read('server.js'));
  check('Identity is probed on Test only when switched on',
    /if \(identityOn\) \{\s*identity = await msIdentity\.probe\(cfgAll\)/.test(srv));
  check('Test records the verified directory only when something worked',
    /if \(identity\.anyOk\) merged\.identity_verified_tenant/.test(srv));
  const sync = (srv.match(/async function runIdentitySync\(tenantId\)[\s\S]*?\n\}/) || [''])[0];
  check('a sync refuses an unverified or changed directory before collecting',
    sync.indexOf('identity_verified_tenant') > 0 && sync.indexOf('identity_verified_tenant') < sync.indexOf('daysNeedingSnapshot('));
  check('and refuses when Microsoft answered for another directory',
    /conf\.verified_azure_tenant_id && String\(conf\.verified_azure_tenant_id\)\.toLowerCase\(\) !== configured/.test(sync));
  check('two syncs for one client cannot overlap', /identitySyncInProgress\.has\(tenantId\)/.test(sync));
  check('the hourly job only takes clients with Identity switched on',
    /\(config_json->>'identity_enabled'\) = 'true'/.test(srv) && /runIdentitySyncs\(\)/.test(srv));
  check('Sync Now on the Identity tab reaches the identity sync', /provider === IDENTITY_SYNC_PROVIDER\) result = await runIdentitySync/.test(srv));
  /*
   * This asserted that the Identity screen PREFERRED the direct Microsoft APIs
   * over the Wazuh Indexer behind them. The indexer is gone, so the assertion
   * is reframed, not dropped: the direct APIs were meant to win, and now they
   * are the only source. The scoping check below stays exactly as it was — it
   * is what stops two integrations' rows being summed into one screen.
   */
  const screen = (srv.match(/async function panelScreen\([\s\S]*?\n\}/) || [''])[0];
  check('the Identity screen loads the direct-API integration',
    screen.indexOf('loadIdentityIntegration(tenantId)') > 0);
  check('and has no second source behind it', !/loadWazuhIntegration/.test(srv),
    'no fallback loader anywhere in the server');
  const idScreen = (srv.match(/async function identityScreen\([\s\S]*?\n\}/) || [''])[0];
  check('identity rollups are scoped to the Graph integration',
    /o365FromRollups\(pool, tenantId, days, integration\.id\)/.test(idScreen));
  const meta = (srv.match(/async function identitySyncMeta\([\s\S]*?\n\}/) || [''])[0];
  check('Identity sync status is kept apart from Secure Score\'s', /FROM rollup_run/.test(meta) && !/last_synced_at FROM integrations/.test(meta));
  check('before the first collection, panels say not collected', /reason: 'not_synced'/.test((srv.match(/async function identityScreen\([\s\S]*?\n\}/) || [''])[0]));

  section('the Graph connector serves both');
  const g = read('lib', 'integrations', 'ms-graph.js');
  check('tokens are cached per resource', /function cacheKey\(config, scope\)/.test(g));
  check('a 403 names the permission that call needed', /\(o\.permission \|\| 'SecurityEvents\.Read\.All'\)/.test(g));

  section('the pages and the report');
  const tab = read('public', 'js', 'tab-o365.js');
  check('each panel reads its own part, so one missing feed does not blank the rest',
    /part\(s\.graph, 'riskyUsers'\)/.test(tab) && /part\(s\.o365, 'dlp'\)/.test(tab));
  // Was a ternary choosing between the identity sync and Wazuh's. With one
  // source left there is nothing to choose: Identity's Sync Now must never
  // reach the Graph provider's own sync, which collects Secure Score instead.
  check('Sync Now on the Identity screen targets the identity sync',
    /loadAndRender,\s*\n?\s*'ms_identity'\)/.test(tab) && !/'ms_graph'\)\)/.test(tab));
  const ui = read('public', 'js', 'panel-ui.js');
  check('the identity sync is a known target', /ms_identity:\s*'Collecting from Microsoft Graph/.test(ui));
  check('not licensed and beyond retention are explained', /not_licensed:\s*'Not available/.test(ui) && /beyond_retention:\s*'Not available/.test(ui));
  const rep = read('public', 'js', 'report-sections.js');
  check('the board report does not score a feed that was not read',
    /!missing\(o\.graph, 'riskyUsers'\)/.test(rep) && /!missing\(o\.o365, 'admin'\)/.test(rep) && /var ok\s+= auditSignins/.test(rep));
  const admin = read('public', 'js', 'tab-admin.js');
  check('the Graph card switches Identity on and lists the permissions',
    /int-identity-enabled/.test(admin) && /IdentityRiskyUser\.Read\.All/.test(admin) && /ActivityFeed\.ReadDlp/.test(admin));
  check('the probe results are escaped', /escHtmlInt\(graph\)/.test(admin) && /escHtmlInt\(audit\)/.test(admin));
  check('changing the directory clears the Identity verification', /delete body\.configJson\.identity_verified_tenant/.test(admin));

  done();
})().catch((err) => {
  console.error('FAIL  suite crashed:', err && err.stack);
  process.exit(1);
});
