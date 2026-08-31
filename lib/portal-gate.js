'use strict';

/**
 * lib/portal-gate.js — the membrane between the staff API and the client portal.
 *
 * WHY THIS EXISTS RATHER THAN A NEW ROLE IN lib/pages.js
 *
 * The staff access model is a page catalog with a FAIL-OPEN gate. pageGate
 * (lib/auth-middleware.js) resolves the first /api path segment to a page and,
 * when there is no mapping, calls next() — documented and deliberate, so that
 * adding a route without touching pages.js keeps the old behaviour. It also
 * explicitly whitelists GET /api/tenants for every authenticated user, which
 * returns every customer Reflex has.
 *
 * For internal staff that is a reasonable convenience. For a customer it is a
 * cross-tenant leak waiting on the next route someone forgets to map. So client
 * sessions are not gated by that catalog at all — they are confined to
 * /api/portal, which is one rule that cannot be forgotten per route.
 *
 * THE TWO DIRECTIONS
 *
 *   requirePortalConfinement  a client session may reach /api/portal and
 *                             NOTHING else. Mounted on /api BEFORE pageGate.
 *   requirePortalSession      /api/portal is for clients. Staff may reach it
 *                             only to preview, and only read-only.
 *
 * Both are deny-by-default: an unrecognised role gets nothing.
 */

const pool = require('./db');
const { isExternalRole } = require('./pages');

/** Methods that change state. Mirrors lib/auth-middleware.js. */
const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/** Paths under /api that every authenticated user needs, portal clients included. */
const SHARED_PREFIXES = [
  /^\/auth\/logout(\/|$)/,
  /^\/auth\/me(\/|$)/,
  /^\/auth\/change-password(\/|$)/,
];

/**
 * requirePortalConfinement — a client may reach /api/portal and nothing else.
 *
 * Mounted on '/api' immediately after requireAuth and BEFORE pageGate, so a
 * client request is rejected before it ever reaches the fail-open catalog.
 *
 * Note this is a DENYLIST OF ONE RULE, not an allowlist of permitted routes.
 * That is the point: a route added to server.js tomorrow is closed to clients
 * without anyone remembering to close it.
 */
function requirePortalConfinement(req, res, next) {
  const role = req.session && req.session.role;
  if (!isExternalRole(role)) return next();

  if (/^\/portal(\/|$)/.test(req.path)) return next();
  if (SHARED_PREFIXES.some(re => re.test(req.path))) return next();

  // 404 rather than 403: a client has no business knowing which staff routes
  // exist, and a 403 confirms the path is real.
  return res.status(404).json({ error: 'Not found.' });
}

/**
 * requirePortalSession — who may use /api/portal.
 *
 * Clients, always. Staff only for preview, and only for reads: a staff member
 * checking what a client sees must never be able to change something through
 * the portal's surface, because those handlers are written on the assumption
 * that the caller owns the tenant.
 *
 * `opts.allowStaffPreview` defaults true. Set false to seal the portal off
 * entirely.
 */
function requirePortalSession(opts) {
  const allowPreview = !opts || opts.allowStaffPreview !== false;

  return function (req, res, next) {
    const role = req.session && req.session.role;
    if (!role) return res.status(401).json({ error: 'Authentication required.' });

    if (isExternalRole(role)) {
      // The portal is read-only in this release. Enforced here as well as by
      // the absence of write routes, so adding one cannot silently expose it.
      if (WRITE_METHODS.includes(req.method)) {
        return res.status(405).json({ error: 'The portal is read-only.' });
      }
      return next();
    }

    if (!allowPreview) {
      return res.status(403).json({ error: 'Portal access is for client accounts.' });
    }
    if (WRITE_METHODS.includes(req.method)) {
      return res.status(403).json({ error: 'Staff may preview the portal but not act through it.' });
    }
    return next();
  };
}

/**
 * resolvePortalTenant — which tenant's data this request may see.
 *
 * THE WHOLE POINT of this function is what it does NOT do. The thirteen
 * resolve*Tenant helpers in server.js all share a superadmin branch that reads
 * a tenantId from the query string or body. That is correct for staff and is
 * exactly the escape hatch a client-facing surface must not have.
 *
 * This reads the session and nothing else. There is no parameter to trust, so
 * there is no parameter to forget to distrust.
 *
 * Staff previewing the portal DO get to choose a tenant — they legitimately
 * have cross-tenant rights — but through the same explicit branch the rest of
 * the codebase uses, never through the client path.
 *
 * @returns {number|null} tenant id, or null when there is no usable tenant
 */
function resolvePortalTenant(req) {
  const sess = req.session || {};

  if (isExternalRole(sess.role)) {
    const id = parseInt(sess.tenantId, 10);
    return Number.isInteger(id) && id > 0 ? id : null;
  }

  // Staff preview.
  if (sess.role === 'superadmin') {
    const raw = parseInt(req.query.tenantId, 10);
    if (Number.isInteger(raw) && raw > 0) return raw;
    return null;
  }
  const own = parseInt(sess.tenantId, 10);
  return Number.isInteger(own) && own > 0 ? own : null;
}

/**
 * requireActiveUser — reject a session whose account has been suspended.
 *
 * Role and tenant are snapshotted onto the session at login, so a suspended
 * user would otherwise keep working for the rest of their 8-hour session. This
 * costs one indexed lookup per request, the same trade loadPageAccess already
 * makes so that revoking page access is immediate.
 *
 * Degrades open on a missing column (42703) or missing table (42P01) so an
 * un-migrated deployment keeps working exactly as it did before.
 */
async function requireActiveUser(req, res, next) {
  try {
    if (!req.session || !req.session.userId) return next();

    const r = await pool.query(
      'SELECT is_active, must_change_password FROM users WHERE id = $1',
      [req.session.userId]
    );

    // The account was deleted mid-session.
    if (!r.rows.length) {
      return req.session.destroy(() =>
        res.status(401).json({ error: 'Your account is no longer available.' }));
    }

    const row = r.rows[0];
    if (row.is_active === false) {
      return req.session.destroy(() =>
        res.status(403).json({ error: 'This account has been suspended.' }));
    }

    // A forced password change blocks everything except the routes needed to
    // perform it, or the user would be locked into a dead end.
    if (row.must_change_password &&
        !/^\/auth\/(change-password|me|logout)(\/|$)/.test(req.path)) {
      return res.status(428).json({
        error: 'You must change your password before continuing.',
        mustChangePassword: true,
      });
    }

    return next();
  } catch (err) {
    if (err.code === '42703' || err.code === '42P01') return next();
    return next(err);
  }
}

module.exports = {
  WRITE_METHODS,
  SHARED_PREFIXES,
  requirePortalConfinement,
  requirePortalSession,
  requireActiveUser,
  resolvePortalTenant,
};
