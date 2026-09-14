'use strict';

/**
 * The membrane between the staff API and the client portal.
 *
 * THE DEFECT THIS GUARDS AGAINST
 *
 * pageGate (lib/auth-middleware.js) fails OPEN: an /api path whose first
 * segment is absent from API_PREFIX_TO_PAGE reaches the route untouched, and
 * GET /api/tenants is explicitly whitelisted for every authenticated user —
 * which returns every customer the MSP has. Both are reasonable conveniences
 * for staff and cross-tenant leaks for a customer.
 *
 * So the portal is not a narrow role inside that catalog; client sessions are
 * confined to /api/portal by one rule that cannot be forgotten per route. These
 * checks drive the REAL middleware over REAL HTTP through a real Express app,
 * because what is being tested is routing ORDER, which a unit call cannot see.
 *
 * No database: requireActiveUser degrades open on a missing table, and no
 * handler here touches the pool.
 *
 *   node tests/portal-gate.test.js <repoRoot>
 */

const path = require('path');
const http = require('http');
const ROOT = process.argv[2] || path.join(__dirname, '..');

const express = require(path.join(ROOT, 'node_modules', 'express'));
const portalGate = require(path.join(ROOT, 'lib', 'portal-gate.js'));
const pages = require(path.join(ROOT, 'lib', 'pages.js'));
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('portal-gate');

/* ── A miniature of server.js's middleware stack ──────────────────────────
   Mount order is the thing under test, so it mirrors server.js exactly:
   requireAuth → requireActiveUser → requirePortalConfinement → pageGate. */
function buildApp() {
  const app = express();
  app.use(express.json());

  // Stand-in for a logged-in session; the test sets it per request.
  app.use((req, res, next) => {
    const role = req.headers['x-test-role'];
    const tenant = req.headers['x-test-tenant'];
    req.session = role
      ? { userId: 1, username: 'probe', role, tenantId: tenant ? Number(tenant) : null }
      : {};
    next();
  });

  app.use('/api', (req, res, next) =>
    req.session.userId ? next() : res.status(401).json({ error: 'Authentication required.' }));

  app.use('/api', portalGate.requirePortalConfinement);

  // Stand-in for pageGate's FAIL-OPEN behaviour on an unmapped prefix. If the
  // membrane is removed, a client reaches this and gets a 200 — which is
  // precisely the leak these checks exist to catch.
  app.use('/api', (req, res, next) => {
    const mapped = pages.pageForApiPath(req.path);
    if (!mapped) return next();                    // fail-open, as in production
    if (req.session.role === 'client') return res.status(403).json({ error: 'no page access' });
    return next();
  });

  app.use('/api/portal', portalGate.requirePortalSession());

  // Terminal handlers. Anything that answers 200 was reachable.
  app.all('/api/portal/*', (req, res) =>
    res.json({ ok: true, tenant: portalGate.resolvePortalTenant(req) }));
  app.all('/api/*', (req, res) => res.json({ ok: true, staff: true }));

  return app;
}

function request(server, method, url, role, tenant) {
  return new Promise((resolve) => {
    const headers = {};
    if (role) headers['x-test-role'] = role;
    if (tenant) headers['x-test-tenant'] = String(tenant);
    const req = http.request(
      { host: '127.0.0.1', port: server.address().port, method, path: url, headers },
      (res) => {
        let body = '';
        res.on('data', c => { body += c; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(body); } catch (_) { /* not json */ }
          resolve({ status: res.statusCode, body, json });
        });
      }
    );
    req.on('error', () => resolve({ status: 0, body: '', json: null }));
    req.end();
  });
}

(async function main() {
  const server = buildApp().listen(0);
  const go = (m, u, role, tenant) => request(server, m, u, role, tenant);

  // ── The role itself ────────────────────────────────────────────────────
  section('the client role grants nothing in the staff catalog');
  const access = pages.resolveAccess('client', []);
  check('client is a known role', pages.ROLES.includes('client'));
  check('and is marked external', pages.isExternalRole('client') === true);
  check('staff roles are not', pages.isExternalRole('readonly') === false &&
    pages.isExternalRole('admin') === false && pages.isExternalRole('superadmin') === false);
  const granted = Object.keys(access).filter(k => access[k] !== 'none');
  check('client has NO access to any staff page', granted.length === 0, granted.join(',') || 'none');
  check('every page in the catalog is covered, not just the ones we listed',
    Object.keys(access).length === pages.PAGE_KEYS.length,
    Object.keys(access).length + '/' + pages.PAGE_KEYS.length);
  // The point of starting from none rather than narrowing readonly.
  check('a NEW page would default to none for a client',
    (pages.ROLE_DEFAULTS.client['a-page-invented-tomorrow'] || 'none') === 'none');
  check('whereas readonly would have granted it read',
    pages.ROLE_DEFAULTS.readonly[pages.PAGE_KEYS.find(k => k !== 'admin' && k !== 'manager' && k !== 'upload')] === 'read');

  // ── Client confinement ─────────────────────────────────────────────────
  section('a client session cannot leave /api/portal');
  for (const url of ['/api/vulns/latest', '/api/users', '/api/redteam/projects',
                     '/api/secure-score', '/api/awareness', '/api/reports/metrics']) {
    const r = await go('GET', url, 'client');
    check('client blocked from ' + url, r.status === 404, r.status);
  }

  // THE regression that matters: an unmapped prefix. pageGate lets these
  // through for any authenticated user, so if the membrane is ever removed
  // this is the check that goes red.
  const unmapped = await go('GET', '/api/some-route-nobody-mapped', 'client');
  check('client blocked from an UNMAPPED prefix (the fail-open case)',
    unmapped.status === 404, unmapped.status);
  const staffUnmapped = await go('GET', '/api/some-route-nobody-mapped', 'readonly');
  check('while staff still reach it, so the fail-open really is live',
    staffUnmapped.status === 200, staffUnmapped.status);

  const tenants = await go('GET', '/api/tenants', 'client');
  check('client blocked from /api/tenants — the customer list',
    tenants.status === 404, tenants.status);

  check('the block is 404, not 403 — a client learns nothing about what exists',
    tenants.status === 404 && !/permission|access/i.test(tenants.body), tenants.body.slice(0, 60));

  section('but reaches the portal and the shared auth routes');
  const portal = await go('GET', '/api/portal/incidents', 'client', 7);
  check('client reaches /api/portal', portal.status === 200, portal.status);
  for (const url of ['/api/auth/me', '/api/auth/logout', '/api/auth/change-password']) {
    const r = await go('GET', url, 'client');
    check('client reaches ' + url, r.status === 200, r.status);
  }
  // A client must not be able to rotate to another tenant through the switcher.
  const switcher = await go('GET', '/api/auth/switch-tenant', 'client');
  check('client CANNOT reach /api/auth/switch-tenant', switcher.status === 404, switcher.status);

  // ── Staff on the portal surface ────────────────────────────────────────
  section('staff may preview the portal, read-only');
  const preview = await go('GET', '/api/portal/incidents', 'superadmin', 7);
  check('staff may read the portal', preview.status === 200, preview.status);
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const r = await go(method, '/api/portal/incidents', 'superadmin', 7);
    check('staff ' + method + ' on the portal is refused', r.status === 403, r.status);
  }

  /*
   * REFRAMED, not removed. The portal was entirely read-only; it now has one
   * allowlisted exception — a client REQUESTING risk acceptance, which changes
   * nothing until staff approve it (lib/risk-acceptance.js). Everything else
   * this section asserted still holds and is still asserted.
   */
  section('the portal is read-only for clients, except the risk-acceptance request');
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    const r = await go(method, '/api/portal/incidents', 'client', 7);
    check('client ' + method + ' is refused', r.status === 405, r.status);
  }
  const submit = await go('POST', '/api/portal/risk-acceptances', 'client', 7);
  check('client POST to risk-acceptances passes the gate', submit.status === 200, submit.status);
  const withdraw = await go('POST', '/api/portal/risk-acceptances/12/withdraw', 'client', 7);
  check('and so does withdrawing one', withdraw.status === 200, withdraw.status);
  for (const [method, url] of [
    ['PUT',    '/api/portal/risk-acceptances'],
    ['DELETE', '/api/portal/risk-acceptances/12'],
    ['PATCH',  '/api/portal/risk-acceptances/12/withdraw'],
    ['POST',   '/api/portal/risk-acceptances/12'],
    ['POST',   '/api/portal/risk-acceptances/abc/withdraw'],
    ['POST',   '/api/portal/risk-acceptances/12/withdraw/extra'],
    ['POST',   '/api/portal/risk-acceptances-export'],
  ]) {
    const r = await go(method, url, 'client', 7);
    check('client ' + method + ' ' + url.replace('/api/portal', '') + ' is refused', r.status === 405, r.status);
  }
  const staffSubmit = await go('POST', '/api/portal/risk-acceptances', 'superadmin', 7);
  check('staff still cannot write through the portal, even to the allowlisted route',
    staffSubmit.status === 403, staffSubmit.status);
  const clientStaffRoute = await go('POST', '/api/risk-acceptances/12/approve', 'client', 7);
  check('and a client cannot reach the staff approval route', clientStaffRoute.status === 404, clientStaffRoute.status);

  section('anonymous callers get nowhere');
  check('no session, no portal', (await go('GET', '/api/portal/incidents')).status === 401);
  check('no session, no staff API', (await go('GET', '/api/vulns/latest')).status === 401);

  // ── Tenant resolution ──────────────────────────────────────────────────
  section('resolvePortalTenant reads the session and nothing else');
  const t = (sess, query) => portalGate.resolvePortalTenant({ session: sess, query: query || {} });

  check('a client gets their session tenant', t({ role: 'client', tenantId: 42 }) === 42);
  // THE assertion. Every resolve*Tenant helper in server.js has a superadmin
  // branch that reads a tenantId param. This one must not, for a client, ever.
  check('a client tenantId QUERY PARAM IS IGNORED',
    t({ role: 'client', tenantId: 42 }, { tenantId: '99' }) === 42,
    t({ role: 'client', tenantId: 42 }, { tenantId: '99' }));
  check('a client with no tenant gets null, never a default',
    t({ role: 'client', tenantId: null }) === null);
  check('a non-numeric session tenant is null, not NaN',
    t({ role: 'client', tenantId: 'all' }) === null);
  check('a zero or negative tenant is refused',
    t({ role: 'client', tenantId: 0 }) === null && t({ role: 'client', tenantId: -1 }) === null);
  check('a missing session is safe', portalGate.resolvePortalTenant({}) === null);

  check('a previewing superadmin DOES choose via the param',
    t({ role: 'superadmin' }, { tenantId: '99' }) === 99);
  check('and gets null when they choose nothing, rather than tenant 1',
    t({ role: 'superadmin' }, {}) === null);
  check('other staff are pinned to their own tenant regardless of the param',
    t({ role: 'admin', tenantId: 3 }, { tenantId: '99' }) === 3);

  // The handler must see the same answer the middleware would.
  const asClient = await go('GET', '/api/portal/incidents', 'client', 7);
  check('the resolved tenant reaches the handler', asClient.json && asClient.json.tenant === 7,
    asClient.json && asClient.json.tenant);

  server.close();
  done();
})();
