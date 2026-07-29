'use strict';

/**
 * lib/auth-middleware.js
 * Express middleware for session-based authentication and per-page access.
 *
 * requireAuth establishes that there is a session; pageGate then decides what
 * that user may see and change, driven by the catalog in lib/pages.js.
 */

const pool = require('./db');
const { resolveAccess, hasAccess, pageForApiPath } = require('./pages');

/**
 * requireAuth — rejects requests with no active session.
 * Attach BEFORE any route that needs a logged-in user.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: 'Authentication required.' });
}

/**
 * requireSuperAdmin — allows only superadmin.
 * Must be used AFTER requireAuth.
 */
function requireSuperAdmin(req, res, next) {
  if (req.session && req.session.role === 'superadmin') {
    return next();
  }
  return res.status(403).json({ error: 'Super-admin access required.' });
}

// ── Per-page access ────────────────────────────────────────────────────────
// requireAdmin, requireManager and requireRiskWrite used to live here. They
// have been replaced by pageGate below: the role defaults in lib/pages.js
// grant exactly what those guards allowed, but an admin can now adjust it per
// user, which a hardcoded role check made impossible.

const WRITE_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * loadPageAccess — resolve the caller's { pageKey: level } map.
 *
 * Reads the user's override rows fresh on each request (one lookup on the
 * user_page_access primary key) rather than caching them on the session, so
 * that revoking someone's access takes effect immediately instead of after
 * their 8-hour session expires. Memoised per request.
 */
async function loadPageAccess(req) {
  if (req._pageAccess) return req._pageAccess;

  const role = (req.session && req.session.role) || 'readonly';
  let rows = [];
  try {
    const result = await pool.query(
      'SELECT page_key, access FROM user_page_access WHERE user_id = $1',
      [req.session.userId]
    );
    rows = result.rows;
  } catch (err) {
    // If the table is missing (migration not yet run) fall back to role
    // defaults so the app keeps working exactly as it did before.
    if (err.code !== '42P01') throw err;
  }

  req._pageAccess = resolveAccess(role, rows);
  return req._pageAccess;
}

/**
 * requirePage — guard a route on a specific page key.
 * `write` defaults to whether the request method mutates state.
 * Must be used AFTER requireAuth.
 */
function requirePage(pageKey, opts) {
  return async function (req, res, next) {
    try {
      const needWrite = opts && opts.write !== undefined
        ? opts.write
        : WRITE_METHODS.includes(req.method);
      const access = await loadPageAccess(req);
      if (hasAccess(access, pageKey, needWrite)) return next();
      return res.status(403).json({ error: 'You do not have access to this page.' });
    } catch (err) {
      return next(err);
    }
  };
}

/**
 * pageGate — blanket gate mounted on /api, just after requireAuth.
 *
 * Resolves the first path segment to a page via lib/pages.js and requires
 * write access for mutating methods, read access otherwise. Paths with no
 * mapping fall through untouched (authenticated-only, as before).
 */
async function pageGate(req, res, next) {
  try {
    // Auth and session-bootstrap routes must stay reachable, and every user
    // needs GET /tenants to populate tenant dropdowns.
    if (/^\/auth(\/|$)/.test(req.path)) return next();
    if (/^\/tenants(\/|$)/.test(req.path) && !WRITE_METHODS.includes(req.method)) return next();

    const pageKey = pageForApiPath(req.path);
    if (!pageKey) return next();

    const needWrite = WRITE_METHODS.includes(req.method);
    const access = await loadPageAccess(req);
    if (hasAccess(access, pageKey, needWrite)) return next();

    return res.status(403).json({
      error: needWrite
        ? 'You do not have permission to make changes on this page.'
        : 'You do not have access to this page.',
    });
  } catch (err) {
    return next(err);
  }
}

module.exports = {
  requireAuth,
  requireSuperAdmin,
  loadPageAccess,
  requirePage,
  pageGate,
};
