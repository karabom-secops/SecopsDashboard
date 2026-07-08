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

/**
 * requireManager — allows manager, sales, admin, or superadmin.
 * Use on routes that managers need to access (e.g. awareness report data).
 * Sales is included so sales users can also reach the manager dashboard.
 * Must be used AFTER requireAuth.
 */
function requireManager(req, res, next) {
  const role = req.session && req.session.role;
  if (role === 'manager' || role === 'sales' || role === 'admin' || role === 'superadmin') {
    return next();
  }
  return res.status(403).json({ error: 'Manager access required.' });
}

/**
 * requireRiskWrite — allows sales, admin, or superadmin.
 * Use on Risk Register write routes so sales users can manage risks
 * without being granted full admin access elsewhere.
 * Must be used AFTER requireAuth.
 */
function requireRiskWrite(req, res, next) {
  const role = req.session && req.session.role;
  if (role === 'sales' || role === 'admin' || role === 'superadmin') {
    return next();
  }
  return res.status(403).json({ error: 'Sales or admin access required.' });
}

module.exports = { requireAuth, requireAdmin, requireSuperAdmin, requireManager, requireRiskWrite };
