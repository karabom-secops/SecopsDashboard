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
 * requireAdmin — rejects requests from non-admin users.
 * Must be used AFTER requireAuth (assumes session already validated).
 */
function requireAdmin(req, res, next) {
  if (req.session && req.session.role === 'admin') {
    return next();
  }
  return res.status(403).json({ error: 'Admin access required.' });
}

module.exports = { requireAuth, requireAdmin };
