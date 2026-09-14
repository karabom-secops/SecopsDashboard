'use strict';

/**
 * The portal's read model, driven over real HTTP against a stubbed pool.
 *
 * WHAT THESE EXIST TO CATCH
 *
 * 1. TENANT LEAKAGE. Every query must carry the session's tenant, and no
 *    handler may honour a tenantId parameter. A regression here shows one
 *    client another client's incidents.
 *
 * 2. OVER-DISCLOSURE. The portal deliberately withholds things the internal
 *    API returns: analyst names, the vulnerability finding list, the Secure
 *    Score's weighting model. Those are decisions, and a decision nobody
 *    asserts is a decision that quietly reverses.
 *
 * 3. THE MERGE. MDR tickets and IR incidents share no key. Where an operator
 *    has linked them the pair must collapse to one row; where they have not,
 *    the duplicate is expected and must not be silently merged by guesswork.
 *
 *   node tests/portal-routes.test.js <repoRoot>
 */

const path = require('path');
const http = require('http');
const ROOT = process.argv[2] || path.join(__dirname, '..');

const express = require(path.join(ROOT, 'node_modules', 'express'));
const portalRoutes = require(path.join(ROOT, 'lib', 'portal-routes.js'));
const portalGate = require(path.join(ROOT, 'lib', 'portal-gate.js'));
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('portal-routes');

/* ── Fixtures ─────────────────────────────────────────────────────────────
   Two tenants with overlapping ids, so a handler that forgets its tenant
   filter returns the wrong client's row rather than nothing. */
const DATA = {
  tenants: { 7: 'Acme Ltd', 8: 'Globex' },
  ir: {
    7: [{ id: 1, title: 'Phishing campaign', description: 'Targeted finance.',
          severity: 'high', status: 'contained', phase: 'containment',
          incident_type: 'phishing', opened_at: '2026-08-02T08:00:00Z',
          closed_at: null, mdr_ticket_number: 'AW-100' }],
    8: [{ id: 2, title: 'GLOBEX ONLY', description: '', severity: 'critical',
          status: 'open', phase: 'identification', incident_type: 'other',
          opened_at: '2026-08-03T08:00:00Z', closed_at: null,
          mdr_ticket_number: null }],
  },
  mdr: {
    7: [
      // Linked to the IR record above: must NOT appear as its own row.
      { id: 10, ticket_number: 'AW-100', subject: 'Suspicious sign-in',
        status: 'solved', severity: 'HIGH', ticket_type: 'incident',
        created_at: '2026-08-02T07:00:00Z', resolved_at: '2026-08-02T12:00:00Z',
        status_changed_at: null, first_seen_at: null },
      { id: 11, ticket_number: 'AW-101', subject: 'Malware blocked',
        status: 'open', severity: 'medium', ticket_type: 'incident',
        created_at: '2026-08-05T07:00:00Z', resolved_at: null,
        status_changed_at: null, first_seen_at: null },
    ],
    8: [{ id: 20, ticket_number: 'GX-1', subject: 'GLOBEX TICKET',
          status: 'open', severity: 'low', ticket_type: 'incident',
          created_at: '2026-08-01T07:00:00Z', resolved_at: null,
          status_changed_at: null, first_seen_at: null }],
  },
  events: { 10: [{ event_at: '2026-08-02T07:00:00Z', event_type: 'created',
                   field: 'status', old_value: null, new_value: 'open' }] },
};

/**
 * A pool that answers from DATA by READING THE SQL, not by assuming.
 *
 * This distinction is the whole value of the stub. An earlier version filtered
 * by `DATA.x[params[0]]` unconditionally, which meant the STUB enforced tenant
 * isolation rather than the code — deleting the `tenant_id = $1` clause from a
 * real query left every isolation assertion green. A test double that is
 * stricter than the database it stands in for proves nothing.
 *
 * So: a table's rows are scoped only when the SQL actually says to scope them,
 * and the tenant used is the one bound to that placeholder.
 */
function makePool(log) {
  /**
   * Does this SQL actually filter on the tenant bound at $1?
   *
   * The dollar must be escaped: unescaped it is an end-of-string anchor, the
   * test silently never matches, and every table hands back tenant 7's rows
   * regardless of who asked — which would make every isolation check here
   * pass for the wrong reason.
   */
  const hasTenantFilter = (sql) => /tenant_id = \$1\b/.test(sql);

  /** The detail queries, distinguished from the list ones. `id = $1` alone
   *  also matches `tenant_id = $1`, so this must anchor on WHERE. */
  const isDetailQuery = (sql) => /WHERE id = \$1\b/.test(sql);

  /** All rows for a table, scoped only if the SQL asks and using the bound id. */
  function scoped(byTenant, sql, params, placeholder) {
    const re = new RegExp('tenant_id = \\$' + placeholder + '\\b');
    if (!re.test(sql)) {
      // No tenant clause: a real database returns everything.
      return Object.keys(byTenant).reduce((all, k) => all.concat(byTenant[k]), []);
    }
    const id = params[placeholder - 1];
    return byTenant[id] || [];
  }

  return {
    async query(sql, params) {
      const s = String(sql).replace(/\s+/g, ' ');
      const p = params || [];
      log.push({ sql: s, params: p });
      const t = p[0];

      if (/FROM tenants/.test(s)) {
        return { rows: DATA.tenants[t] ? [{ name: DATA.tenants[t] }] : [] };
      }
      if (/FROM ir_incidents/.test(s)) {
        // Detail: WHERE id = $1 AND tenant_id = $2. List: WHERE tenant_id = $1.
        if (isDetailQuery(s)) {
          return { rows: scoped(DATA.ir, s, p, 2).filter(r => r.id === p[0]) };
        }
        return { rows: scoped(DATA.ir, s, p, 1) };
      }
      if (/FROM ir_activities/.test(s)) return { rows: [] };
      if (/FROM ir_phase_events/.test(s)) {
        return { rows: s.indexOf(`tenant_id = $2`) >= 0 ? (DATA.phases || []) : [] };
      }
      if (/FROM risks/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7 ? (DATA.risks || []) : [] };
      }
      if (/FROM pentest_findings/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7 ? (DATA.pentest || []) : [] };
      }
      if (/FROM mdr_tickets/.test(s)) {
        let rows = scoped(DATA.mdr, s, p, 1);
        if (/ticket_number = \$2/.test(s)) {
          rows = rows.filter(r => String(r.ticket_number) === String(p[1]));
        }
        return { rows };
      }
      if (/FROM mdr_ticket_events/.test(s)) {
        const rows = DATA.events[p[0]] || [];
        return { rows: /tenant_id = \$2/.test(s) ? rows : rows };
      }
      // One row per month, for the "what changed" explanations.
      if (/FROM secure_scores/.test(s) && /DISTINCT ON/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7
          ? [{ month_key: '2026-08', composite_score: 72, vuln_score: 60, awareness_score: 88, mdr_score: 70 },
             { month_key: '2026-07', composite_score: 65, vuln_score: 50, awareness_score: 80, mdr_score: 68 }]
          : [] };
      }
      if (/FROM secure_scores/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7
          ? [{ score_date: '2026-08-01', composite_score: 72, vuln_score: 60,
               awareness_score: 88, mdr_score: 70 },
             { score_date: '2026-07-01', composite_score: 65, vuln_score: 50,
               awareness_score: 80, mdr_score: 68 }]
          : [] };
      }
      if (/FROM vuln_scans/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7
          ? [{ id: 1, month_key: '2026-08', scanned_hosts: 14,
               summary: { critical: 1, high: 3, medium: 8, low: 20 } }]
          : [] };
      }
      if (/FROM vuln_findings/.test(s)) {
        if (s.indexOf(`COUNT(*)`) >= 0) return { rows: [{ n: 2 }] };
        return { rows: DATA.findings || [] };
      }
      if (/FROM awareness_uploads/.test(s)) {
        if (hasTenantFilter(s) && t !== 7) return { rows: [] };
        const a = DATA.awareness ||
          { total_users: 100, total_incomplete: 15, upload_type: 'summary' };
        return { rows: [{ id: 5, uploaded_at: '2026-08-01',
          total_users: a.total_users, total_incomplete: a.total_incomplete,
          upload_type: a.upload_type }] };
      }
      // The aggregate over awareness_sessions: no GROUP BY, so it is the
      // totals query rather than the per-person one.
      if (/FROM awareness_sessions/.test(s) && !/GROUP BY/.test(s)) {
        const st = DATA.sessionTotals || { completed: 0, total: 0 };
        return { rows: [{ completed: st.completed, total: st.total }] };
      }
      if (/FROM awareness_sessions/.test(s)) {
        return { rows: [{ user_first_name: 'Ada', user_last_name: 'Lovelace',
                          user_email: 'ada@acme.test', completed: 2, assigned: 5 }] };
      }
      if (/FROM awareness_users/.test(s)) {
        return { rows: [{ user_first_name: 'Ada', user_last_name: 'Lovelace',
                          user_email: 'ada@acme.test', incomplete_sessions: 3 }] };
      }
      if (/FROM report_publications/.test(s)) {
        return { rows: !hasTenantFilter(s) || t === 7
          ? [{ id: 90, period: '2026-08', version: 1, title: 'August',
               client_name: 'Acme Ltd', period_label: 'August 2026',
               cover_note: 'Good month.', status: 'published',
               published_at: '2026-09-01', pptx_bytes: 1024, slide_count: 20,
               purged_at: null, has_html: true, download_count: 0,
               last_downloaded_at: null }]
          : [] };
      }
      return { rows: [] };
    },
  };
}

function buildApp(log) {
  const app = express();
  app.use(express.json());
  app.use((req, res, next) => {
    const role = req.headers['x-test-role'] || 'client';
    const tenant = req.headers['x-test-tenant'];
    req.session = { userId: 1, username: 'probe', role,
                    tenantId: tenant ? Number(tenant) : null };
    next();
  });
  portalRoutes.register(app, {
    pool: makePool(log),
    requireAuth: (req, res, next) => next(),
    portalSession: portalGate.requirePortalSession(),
    onError: (res, err) => res.status(500).json({ error: err.message }),
  });
  return app;
}

function request(server, url, tenant, role) {
  return new Promise((resolve) => {
    const headers = { 'x-test-role': role || 'client' };
    if (tenant) headers['x-test-tenant'] = String(tenant);
    http.get({ host: '127.0.0.1', port: server.address().port, path: url, headers },
      (res) => {
        let body = '';
        res.on('data', c => { body += c; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch (_) { /* not json */ }
          resolve({ status: res.statusCode, json, body });
        });
      }).on('error', () => resolve({ status: 0, json: null, body: '' }));
  });
}

(async function main() {
  const log = [];
  const server = buildApp(log).listen(0);
  const go = (u, tenant, role) => request(server, u, tenant, role);

  // ── Tenant scoping ─────────────────────────────────────────────────────
  section('every query carries the session tenant');
  {
    log.length = 0;
    const r = await go('/api/portal/incidents', 7);
    check('the request succeeds', r.status === 200, r.status);
    const scoped = log.filter(q => /FROM (ir_incidents|mdr_tickets)/.test(q.sql));
    check('both incident queries ran', scoped.length === 2, scoped.length);
    check('both filter on tenant_id',
      scoped.every(q => /WHERE tenant_id = \$1/.test(q.sql)));
    check('bound to the session tenant', scoped.every(q => q.params[0] === 7));
  }

  section('a tenantId parameter is ignored, everywhere');
  {
    // The single most important regression in this file. Every resolve*Tenant
    // helper in server.js honours this parameter for a superadmin; the portal
    // must not, for a client, ever.
    const urls = ['incidents', 'reports', 'secure-score', 'vulns', 'awareness', 'me'];
    for (const u of urls) {
      log.length = 0;
      await go('/api/portal/' + u + '?tenantId=8', 7);
      const wrong = log.filter(q => q.params.includes(8));
      check('?tenantId=8 does not reach ' + u, wrong.length === 0,
        wrong.length ? wrong[0].sql.slice(0, 60) : '');
    }
  }

  section('a client with no tenant is refused, not defaulted');
  {
    const r = await go('/api/portal/incidents', null);
    check('403 rather than tenant 1', r.status === 403, r.status);
    check('and it says why', r.json && /not linked to a client/i.test(r.json.error));
  }

  section('two tenants never see each other');
  {
    const a = await go('/api/portal/incidents', 7);
    const b = await go('/api/portal/incidents', 8);
    const titles = t => (t.json.items || []).map(i => i.title).join(' | ');
    check('tenant 7 sees only its own', !/GLOBEX/.test(titles(a)), titles(a));
    check('tenant 8 sees only its own', !/Phishing|Malware/.test(titles(b)), titles(b));
  }

  // ── The merge ──────────────────────────────────────────────────────────
  section('linked incidents collapse to one row');
  {
    const r = await go('/api/portal/incidents', 7);
    const items = r.json.items || [];
    // Tenant 7 has 1 IR incident + 2 MDR tickets, one of which is linked.
    check('three records become two rows', items.length === 2, items.length);
    check('the linked ticket does not appear separately',
      !items.some(i => i.key === 'mdr-AW-100'), items.map(i => i.key).join(','));
    const ir = items.find(i => i.source === 'incident-response');
    check('the IR record wins — it is the richer one', !!ir);
    check('and carries the original ticket reference',
      ir && ir.reference === 'AW-100', ir && ir.reference);
    check('the unlinked ticket still appears',
      items.some(i => i.key === 'mdr-AW-101'));
    check('the link count is surfaced rather than hidden',
      r.json.linkedCount === 1, r.json.linkedCount);
  }

  section('open incidents sort first, then by severity');
  {
    const r = await go('/api/portal/incidents', 7);
    const items = r.json.items;
    check('the open one leads', items[0].closed === false, items[0].key);
    // Both of tenant 7's rows are open: the IR record is 'contained', which is
    // NOT finished. Only solved/closed/resolved count as done — telling a
    // client a contained incident is closed would be a real misstatement.
    check('a contained incident still counts as open', r.json.openCount === 2, r.json.openCount);
    check('and "contained" is not in the closed set',
      portalRoutes.isClosed('contained') === false);
    check('while solved, closed and resolved all are',
      ['solved', 'closed', 'resolved'].every(portalRoutes.isClosed));
    check('severity orders the open rows',
      items[0].severity === 'high', items[0].severity);
  }

  // ── Over-disclosure ────────────────────────────────────────────────────
  section('internal detail never crosses to the client');
  {
    const r = await go('/api/portal/incidents', 7);
    const raw = JSON.stringify(r.json);
    // Analyst names are ours, not the client's business.
    check('no assigned_to anywhere', !/assigned_to|assignedTo/.test(raw));
    const q = log.filter(x => /FROM mdr_tickets/.test(x.sql)).pop();
    check('and it is not even selected', !/assigned_to/.test(q.sql), q.sql.slice(0, 90));
    check('nor are internal notes', !/notes/.test(q.sql));
    check('hidden tickets are filtered in SQL', /portal_visible/.test(q.sql));
  }

  section('the vulnerability view withholds the finding list');
  {
    const r = await go('/api/portal/vulns', 7);
    check('it responds', r.status === 200 && r.json.available === true, r.status);
    check('severity counts are present', r.json.counts.critical === 1, r.json.counts.critical);
    check('the SLA breach count is present', r.json.pastSla === 2, r.json.pastSla);
    // The deliberate omission. Host, port and CVE for open findings is a
    // working map of the client's unpatched perimeter.
    const raw = JSON.stringify(r.json);
    check('NO findings array', !r.json.findings && !/"host"|"cve"|"plugin/i.test(raw));
    const q = log.filter(x => /FROM vuln_findings/.test(x.sql)).pop();
    check('the finding query only counts, never selects detail',
      /COUNT\(\*\)/.test(q.sql) && !/host|cve|solution/.test(q.sql), q.sql.slice(0, 80));
    check('the external-only scope is stated, not left implied',
      /external-facing/i.test(r.json.note || ''), r.json.note);
  }

  section('the Secure Score arrives without its workings');
  {
    const r = await go('/api/portal/secure-score', 7);
    check('the score is there', r.json.score === 72, r.json.score);
    check('and a rating', r.json.rating === 'Good', r.json.rating);
    check('with a trend, oldest first', r.json.trend[0].score === 65, r.json.trend[0].score);
    // These explain a number to a colleague. To the customer being weighted
    // they read as an invitation to argue about arithmetic.
    const raw = JSON.stringify(r.json);
    check('no weights', !/weight/i.test(raw));
    check('no exposure points', !/exposure/i.test(raw));
    check('no estate detail', !/estate|patchCoverage|unscannable/i.test(raw));
    check('no staff recommendations', !/recommendation/i.test(raw));
    /*
     * The scoring payload now carries `scope.unpurchased` — every service the
     * client is not on — so the board report can recommend them. That is a
     * sales list. It belongs in a report an account manager walks a client
     * through, not pushed unprompted into the portal the client logs into
     * themselves.
     */
    check('and no list of services they have not bought',
      !/unpurchased/i.test(raw) && !/Penetration Testing/i.test(raw), raw.slice(0, 120));

    /*
     * What changed, month to month. Every "no weight" check above already runs
     * over this text, because it is part of the same payload; these pin that
     * the explanation is there at all and is in evidence rather than points.
     */
    const changes = r.json.changes || [];
    check('the month-to-month change is explained', changes.length === 1 && changes[0].monthKey === '2026-08',
      changes.map(c => c.monthKey).join(','));
    check('with a summary naming what drove it',
      /^Up 7 points, driven by vulnerability management \(\+10\)/.test(changes[0] && changes[0].summary),
      changes[0] && changes[0].summary);
    check('and evidence behind it', changes[0] && changes[0].details.length === 3,
      changes[0] && changes[0].details.join(' | '));
    check('never in points', !/pts|points on the score/.test(JSON.stringify(changes)));
    check('carrying only allowlisted fields',
      changes.every(c => Object.keys(c).sort().join(',') === 'delta,details,from,monthKey,summary,to'),
      changes[0] && Object.keys(changes[0]).join(','));
    const ticketQ = log.filter(x => /FROM mdr_tickets/.test(x.sql)).pop();
    check('incident counts use only tickets the client can see',
      ticketQ && /portal_visible/.test(ticketQ.sql) && ticketQ.params[0] === 7);
  }

  section('a tenant with no data gets a reason, not an empty shell');
  {
    const r = await go('/api/portal/secure-score', 8);
    check('available is false', r.json.available === false);
    check('and a reason is given', typeof r.json.reason === 'string' && r.json.reason.length > 10,
      r.json.reason);
    const v = await go('/api/portal/vulns', 8);
    check('same for vulnerabilities', v.json.available === false && !!v.json.reason);
    const a = await go('/api/portal/awareness', 8);
    check('same for awareness', a.json.available === false && !!a.json.reason);
  }

  // ── Awareness ──────────────────────────────────────────────────────────
  section('awareness returns named completion, with provenance');
  {
    const r = await go('/api/portal/awareness', 7);
    check('aggregate present', r.json.completionPct === 85, r.json.completionPct);
    check('named people present', r.json.people.length === 1 &&
      r.json.people[0].name === 'Ada Lovelace', JSON.stringify(r.json.people[0]));
    check('a platform upload is not flagged self-reported', r.json.selfReported === false);
  }

  // ── Detail views ───────────────────────────────────────────────────────
  section('incident detail is scoped by key and tenant');
  {
    const ok = await go('/api/portal/incidents/mdr-AW-101', 7);
    check('an own ticket resolves', ok.status === 200, ok.status);

    // Tenant 8 asking for tenant 7's ticket must be indistinguishable from
    // asking for one that does not exist.
    const cross = await go('/api/portal/incidents/mdr-AW-101', 8);
    check('another tenant gets 404, not 403', cross.status === 404, cross.status);
    const missing = await go('/api/portal/incidents/mdr-DOES-NOT-EXIST', 8);
    check('and a nonexistent id gives the same answer',
      missing.status === cross.status && missing.json.error === cross.json.error);

    const irCross = await go('/api/portal/incidents/ir-1', 8);
    check('the same holds for IR records', irCross.status === 404, irCross.status);

    const bad = await go('/api/portal/incidents/nonsense-key', 7);
    check('an unrecognised key shape is 404, not a crash', bad.status === 404, bad.status);
  }

  section('an MDR detail view carries the history trail');
  {
    const r = await go('/api/portal/incidents/mdr-AW-100', 7);
    check('the timeline is present', Array.isArray(r.json.timeline) && r.json.timeline.length === 1,
      r.json.timeline && r.json.timeline.length);
    check('and is tenant-scoped in SQL',
      log.filter(q => /FROM mdr_ticket_events/.test(q.sql)).pop().sql.includes('tenant_id = $2'));
    check('status values are humanised, not raw', r.json.timeline[0].to === 'Open',
      r.json.timeline[0].to);
  }

  // ── Reports ────────────────────────────────────────────────────────────
  section('the report list is published-only and scoped');
  {
    const r = await go('/api/portal/reports', 7);
    check('one report listed', r.json.reports.length === 1, r.json.reports.length);
    check('with a download flag', r.json.reports[0].canDownload === true);
    check('and a view flag from has_html', r.json.reports[0].canView === true);
    const q = log.filter(x => /FROM report_publications/.test(x.sql)).pop();
    check('withdrawn reports are excluded in SQL', /status = 'published'/.test(q.sql));
    check('and the tenant is bound', q.params[0] === 7);

    const other = await go('/api/portal/reports', 8);
    check('another tenant sees none', other.json.reports.length === 0);
  }

  // ── Staff preview ──────────────────────────────────────────────────────
  section('staff previewing see the client view, flagged');
  {
    const me = await go('/api/portal/me', 7, 'admin');
    check('preview is marked', me.json.preview === true, me.json.preview);
    const client = await go('/api/portal/me', 7, 'client');
    check('a real client is not', client.json.preview === false);
    check('the client name is returned', client.json.clientName === 'Acme Ltd',
      client.json.clientName);
  }

  // ── Units ──────────────────────────────────────────────────────────────
  section('a history upload counts sessions, not people');
  {
    /*
     * THE BUG, as a real client saw it: every member of staff reported as
     * having completed nothing, while the Awareness tab showed 78%.
     *
     * writeAwarenessHistory stores total_users = unique PEOPLE and
     * total_incomplete = not-started SESSIONS. They do not share a unit, so
     * `total_users - total_incomplete` is meaningless: 242 - 994 went negative
     * and clamped to zero. /api/secure-score already had a comment saying
     * exactly this; the portal handler did not read it.
     */
    DATA.awareness = { upload_type: 'history', total_users: 242, total_incomplete: 994 };
    DATA.sessionTotals = { completed: 3549, total: 4579 };

    const r = await go('/api/portal/awareness', 7);
    check('the response succeeds', r.status === 200, r.status);
    check('completion is NOT zero', r.json.completionPct !== 0, r.json.completionPct);
    check('it matches the dashboard figure', r.json.completionPct === 78, r.json.completionPct);
    check('completed counts sessions', r.json.completed === 3549, r.json.completed);
    check('outstanding is the remainder, not the stored column',
      r.json.outstanding === 4579 - 3549, r.json.outstanding);
    // The stored 994 must not reach the client as though it meant people.
    check('the misleading stored value is not passed through',
      r.json.outstanding !== 994, r.json.outstanding);
    check('staff are still counted as people', r.json.totalStaff === 242, r.json.totalStaff);
    // A percentage that silently changes denominator between months is a
    // number nobody can act on.
    check('the unit is declared', r.json.unit === 'sessions', r.json.unit);
    check('and the denominator is exposed', r.json.assessed === 4579, r.json.assessed);
  }

  section('a summary upload still counts people');
  {
    DATA.awareness = { upload_type: 'summary', total_users: 100, total_incomplete: 15 };
    const r = await go('/api/portal/awareness', 7);
    check('completion is user-based', r.json.completionPct === 85, r.json.completionPct);
    check('completed is people', r.json.completed === 85, r.json.completed);
    check('outstanding is the stored count', r.json.outstanding === 15, r.json.outstanding);
    check('the unit says so', r.json.unit === 'people', r.json.unit);
    DATA.awareness = null;
  }

  // ── Phase timings ──────────────────────────────────────────────────────
  section('an incident carries when it entered each phase');
  {
    /*
     * ir_incidents.phase is overwritten in place, so before ir_phase_events
     * existed the record said where an incident WAS and nothing about how it
     * got there. "Contained in four hours, eradicated the next morning" is the
     * part of an incident a client actually wants.
     */
    DATA.phases = [
      { phase: 'identification', entered_at: '2026-08-02T08:00:00Z' },
      { phase: 'containment',    entered_at: '2026-08-02T12:00:00Z' },
      { phase: 'eradication',    entered_at: '2026-08-03T09:00:00Z' },
    ];
    const r = await go('/api/portal/incidents/ir-1', 7);
    check('the phases are returned', r.json.phases.length === 3, r.json.phases.length);
    check('in the order they happened',
      r.json.phases.map(p => p.phase).join(' > ') ===
      'Identification > Containment > Eradication',
      r.json.phases.map(p => p.phase).join(' > '));
    check('each carries when it was entered', !!r.json.phases[0].enteredAt);
    // A phase is left when the NEXT one is entered; that is the only honest
    // way to date it, since nothing records an exit.
    check('a completed phase knows how long it lasted',
      r.json.phases[0].durationHours === 4, r.json.phases[0].durationHours);
    check('and the next one too', r.json.phases[1].durationHours === 21,
      r.json.phases[1].durationHours);
    check('the last phase is marked current', r.json.phases[2].current === true);
    // The incident is open, so the current phase has no end.
    check('and has no duration, because it has not ended',
      r.json.phases[2].durationHours === null, r.json.phases[2].durationHours);
    check('the query is tenant-scoped',
      log.filter(x => /FROM ir_phase_events/.test(x.sql)).pop().params[1] === 7);

    DATA.phases = [];
    const none = await go('/api/portal/incidents/ir-1', 7);
    check('an incident with no recorded phases still renders',
      none.status === 200 && Array.isArray(none.json.phases), none.status);
  }

  // ── Remediation tracker ────────────────────────────────────────────────
  section('remediation merges four sources into one shape');
  {
    DATA.findings = [
      { id: 5, name: 'Outdated OpenSSL', risk: 'High', status: 'open',
        due_date: '2020-01-01', first_seen_at: '2026-08-01',
        host: '10.0.0.5', cve: 'CVE-2024-1234', notes: 'internal only' },
    ];
    DATA.risks = [{ title: 'Single supplier', risk_score: 20, stage: 'mitigating',
                    due_date: '2027-01-01', start_date: '2026-01-01' }];
    DATA.pentest = [{ id: 3, title: 'Weak password policy', severity: 'medium',
                      status: 'open', due_date: null, created_at: '2026-06-01' }];

    const r = await go('/api/portal/remediation', 7);
    check('it responds', r.status === 200, r.status);
    const sources = r.json.items.map(i => i.source);
    check('vulnerabilities are included', sources.includes('Vulnerability'));
    check('risks too', sources.includes('Risk'));
    check('penetration test findings too', sources.includes('Penetration test'));
    check('and open incidents', sources.includes('Incident'));

    // THE constraint. /api/portal/vulns withholds the finding list because it
    // is a map of the client's unpatched perimeter; shipping the same detail
    // here would undo that decision through a different door.
    const raw = JSON.stringify(r.json);
    check('NO host is disclosed', !/10.0.0.5/.test(raw));
    check('NO CVE is disclosed', !/CVE-2024/.test(raw));
    check('NO internal notes', !/internal only/.test(raw));
    check('but the issue is named, so it is actionable',
      /Outdated OpenSSL/.test(raw));
    // The ref a client uses to request risk acceptance. A row id, not a host.
    check('a vulnerability carries an opaque ref for risk acceptance',
      r.json.items.find(i => i.source === 'Vulnerability').ref === 'vuln-5');
    check('a penetration test finding too',
      r.json.items.find(i => i.source === 'Penetration test').ref === 'pentest-3');
    check('a risk does not — it cannot be accepted through the portal',
      !r.json.items.find(i => i.source === 'Risk').ref);

    // The risk register scores 1-25; one list must not carry two scales.
    const risk = r.json.items.find(i => i.source === 'Risk');
    check('a 1-25 risk score is mapped to the shared severity words',
      risk.severity === 'critical', risk.severity + ' (score 20)');

    check('an overdue item is flagged',
      r.json.items.find(i => i.source === 'Vulnerability').overdue === true);
    check('and counted', r.json.overdue >= 1, r.json.overdue);
    check('overdue sorts first', r.json.items[0].overdue === true,
      r.json.items[0].source);
    check('severities are counted', r.json.bySeverity.high >= 1, JSON.stringify(r.json.bySeverity));
    check('the scope limit is stated', /not the affected systems/.test(r.json.note || ''),
      r.json.note);
  }

  section('remediation is tenant-scoped like everything else');
  {
    const other = await go('/api/portal/remediation', 8);
    const raw = JSON.stringify(other.json);
    check('another tenant sees none of it',
      !/Outdated OpenSSL|Single supplier|Weak password/.test(raw), raw.slice(0, 80));
    log.length = 0;
    await go('/api/portal/remediation?tenantId=7', 8);
    check('and a tenantId parameter is ignored here too',
      log.filter(x => x.params.includes(7)).length === 0);
    DATA.findings = []; DATA.risks = []; DATA.pentest = [];
  }

  // ── SQL that only a database would reject ──────────────────────────────
  section('no ORDER BY uses an output alias inside an expression');
  {
    /*
     * THE BUG THIS CATCHES, which shipped and reached a user:
     *
     *   SELECT COUNT(*) FILTER (…) AS completed, …
     *    ORDER BY completed::float / NULLIF(COUNT(*), 0)
     *
     * Postgres accepts a bare output alias in ORDER BY but NOT one inside an
     * expression — it goes looking for a real column called `completed`, finds
     * none, and raises 42703. The handler then reported "this section is not
     * available yet", which reads as a missing migration, so the actual cause
     * was invisible.
     *
     * Every other suite passed: the stubbed pool never parses SQL, so this
     * class of defect is exactly what no database costs. A static check is a
     * poor substitute for running the query and should be replaced by one.
     */
    const src = require('fs').readFileSync(
      path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');

    // Template literals holding SQL, minus comment lines.
    const queries = (src.match(/`[^`]*SELECT[\s\S]*?`/gi) || [])
      .map(q => q.split('\n').filter(l => !/^\s*--/.test(l)).join('\n'));
    check('SQL was found to inspect', queries.length >= 5, queries.length);

    const offenders = [];
    queries.forEach((q) => {
      const aliases = (q.match(/\bAS\s+"?([a-z_][a-z0-9_]*)"?/gi) || [])
        .map(a => a.replace(/\bAS\s+"?/i, '').replace(/"$/, ''));
      const order = (q.match(/ORDER BY([\s\S]*?)(?:LIMIT|$)/i) || [])[1] || '';
      aliases.forEach((a) => {
        // A bare alias is legal; an alias with anything operator-like attached
        // to it is not.
        const bad = new RegExp('\\b' + a + '\\b\\s*(::|[+\\-*/])');
        if (bad.test(order)) offenders.push(a + ' in "' + order.trim().slice(0, 60) + '"');
      });
    });
    check('none found', offenders.length === 0, offenders.join(' | '));
  }

  section('a database error says which kind it is');
  {
    const routesSrc = require('fs').readFileSync(
      path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');
    // The failure above was silent. An undefined column is almost always our
    // bug; an undefined table is almost always an un-run migration; and neither
    // should reach a log as nothing at all.
    check('the error is logged, not swallowed',
      /console\.error\('\[portal\]/.test(routesSrc));
    check('the log distinguishes a missing column from a missing table',
      /bug in this query/.test(routesSrc) && /migration has not been run/.test(routesSrc));
    check('staff previewing see the real reason',
      /req\.session\.role !== 'client'/.test(routesSrc));
    check('but a client does not', /: ''/.test(routesSrc));
  }

  server.close();
  done();
})();
