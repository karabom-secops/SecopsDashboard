'use strict';

/**
 * lib/auth-middleware.js
 * Express middleware for session-based authentication and role checks.
 */

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
 * requireAdmin — allows superadmin OR tenant admin.
 * Rejects readonly users.
 * Must be used AFTER requireAuth.
 */
function requireAdmin(req, res, next) {
  const role = req.session && req.session.role;
  if (role === 'admin' || role === 'superadmin') {
    return next();
  }
  return res.status(403).json({ error: 'Admin access required.' });
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

module.exports = { requireAuth, requireAdmin, requireSuperAdmin };
