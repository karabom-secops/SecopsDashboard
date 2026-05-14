'use strict';

require('dotenv').config();

const path    = require('path');
const fs      = require('fs');
const express = require('express');
const multer  = require('multer');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const bcrypt  = require('bcryptjs');

const { authenticator } = require('otplib');
const QRCode           = require('qrcode');

const pool = require('./lib/db');
const { requireAuth, requireAdmin, requireSuperAdmin } = require('./lib/auth-middleware');
const { parseReport } = require('./lib/parser');
const { computeAllMetrics, getSummary, getOrgHistory } = require('./lib/metrics');
const { parseNessusCSV, parseNessusXML, parseArcticWolfCSV, isArcticWolfCSV, computeVulnSummary } = require('./lib/vuln-parser');

const app  = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR     = path.join(__dirname, 'data');
const WEEKS_FILE   = path.join(DATA_DIR, 'weeks.json');
const METRICS_FILE = path.join(DATA_DIR, 'metrics.json');

// ── Data helpers (JSON — non-vuln sections) ───────────────────────────────

function readData(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return {};
  }
}

function writeData(filePath, obj) {
  fs.writeFileSync(filePath, JSON.stringify(obj, null, 2), 'utf8');
}

function recomputeMetrics() {
  const weeks   = readData(WEEKS_FILE);
  const metrics = computeAllMetrics(weeks);
  writeData(METRICS_FILE, metrics);
  return metrics;
}

// ── Middleware ────────────────────────────────────────────────────────────

const PUBLIC = path.join(__dirname, 'public');

// Serve static assets BEFORE session/auth so the login page loads without auth.
app.use('/secops', express.static(PUBLIC));
app.use(express.static(PUBLIC));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session — backed by PostgreSQL via connect-pg-simple.
app.use(session({
  store: new PgStore({
    pool,
    tableName: 'sessions',
    createTableIfMissing: true,
  }),
  secret:            process.env.SESSION_SECRET || 'change-me-in-production',
  resave:            false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure:   process.env.NODE_ENV === 'production',
    maxAge:   8 * 60 * 60 * 1000,
  },
}));

const upload     = multer({ storage: multer.memoryStorage() });
const vulnUpload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 100 * 1024 * 1024 },
});

// ── Auth routes (public — no requireAuth) ─────────────────────────────────

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = (req.body.password || '').trim();

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash, role, tenant_id,
              totp_enabled, totp_required
       FROM users WHERE username = $1`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Load all tenant IDs for this user (for multi-tenant access)
    let tenantIds = [];
    if (user.role !== 'superadmin') {
      const tRes = await pool.query(
        'SELECT tenant_id FROM user_tenants WHERE user_id = $1 ORDER BY tenant_id',
        [user.id]
      );
      tenantIds = tRes.rows.map(r => r.tenant_id);
    }

    // ── Superadmin MFA branching ─────────────────────────────────────────
    if (user.role === 'superadmin') {
      const pending = {
        userId: user.id, username: user.username, role: user.role,
        tenantId: user.tenant_id, tenantIds,
      };

      if (user.totp_enabled) {
        // Branch A: TOTP enrolled — require second factor before granting session
        req.session.mfaPending = pending;
        return res.json({ mfaRequired: true });
      }

      if (user.totp_required) {
        // Branch B: TOTP required but not yet set up — force enrollment
        req.session.enrollPending = pending;
        return res.json({ enrollRequired: true });
      }

      // Branch C: grace-period superadmin — full session, prompt banner
      req.session.userId       = user.id;
      req.session.username     = user.username;
      req.session.role         = user.role;
      req.session.tenantId     = user.tenant_id;
      req.session.tenantIds    = tenantIds;
      req.session.totpEnabled  = false;
      return res.json({
        id: user.id, username: user.username, role: user.role,
        tenantId: user.tenant_id, tenantIds, showMfaPrompt: true,
      });
    }

    // ── Non-superadmin: always full session, no MFA ───────────────────────
    req.session.userId    = user.id;
    req.session.username  = user.username;
    req.session.role      = user.role;
    req.session.tenantId  = user.tenant_id;
    req.session.tenantIds = tenantIds;
    req.session.totpEnabled = false;

    return res.json({ id: user.id, username: user.username, role: user.role, tenantId: user.tenant_id, tenantIds });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── MFA: verify TOTP code after password step ─────────────────────────────
app.post('/api/auth/mfa-verify', async (req, res) => {
  try {
    const pending = req.session.mfaPending;
    if (!pending) return res.status(401).json({ error: 'No MFA session pending.' });

    const token = String(req.body.token || '').trim();
    if (!/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'Token must be 6 digits.' });
    }

    const { rows } = await pool.query(
      'SELECT totp_secret FROM users WHERE id = $1',
      [pending.userId]
    );
    if (!rows.length || !rows[0].totp_secret) {
      return res.status(401).json({ error: 'MFA not configured.' });
    }

    const valid = authenticator.verify({ token, secret: rows[0].totp_secret });
    if (!valid) return res.status(401).json({ error: 'Invalid or expired code. Try again.' });

    // Promote to full session
    req.session.mfaPending   = undefined;
    req.session.userId       = pending.userId;
    req.session.username     = pending.username;
    req.session.role         = pending.role;
    req.session.tenantId     = pending.tenantId;
    req.session.tenantIds    = pending.tenantIds;
    req.session.totpEnabled  = true;

    return res.json({
      id: pending.userId, username: pending.username,
      role: pending.role, tenantId: pending.tenantId, tenantIds: pending.tenantIds,
    });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── MFA: forced enrollment setup (generates QR; needs enrollPending) ──────
app.get('/api/auth/enroll-totp/setup', async (req, res) => {
  try {
    const pending = req.session.enrollPending;
    if (!pending) return res.status(401).json({ error: 'No enrollment session pending.' });

    const secret  = authenticator.generateSecret();
    req.session.pendingTotpSecret = secret;

    const otpauthUri = authenticator.keyuri(pending.username, 'SecOps Dashboard', secret);
    const qrCodeUrl  = await QRCode.toDataURL(otpauthUri);

    return res.json({ qrCodeUrl, secret });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── MFA: forced enrollment confirm ────────────────────────────────────────
app.post('/api/auth/enroll-totp/confirm', async (req, res) => {
  try {
    const pending = req.session.enrollPending;
    if (!pending) return res.status(401).json({ error: 'No enrollment session pending.' });

    const secret = req.session.pendingTotpSecret;
    if (!secret) return res.status(400).json({ error: 'Setup not started. Request QR code first.' });

    const token = String(req.body.token || '').trim();
    if (!/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'Token must be 6 digits.' });
    }

    const valid = authenticator.verify({ token, secret });
    if (!valid) return res.status(401).json({ error: 'Invalid or expired code. Try again.' });

    await pool.query(
      'UPDATE users SET totp_secret=$1, totp_enabled=true WHERE id=$2',
      [secret, pending.userId]
    );

    // Promote to full session
    req.session.enrollPending    = undefined;
    req.session.pendingTotpSecret = undefined;
    req.session.userId           = pending.userId;
    req.session.username         = pending.username;
    req.session.role             = pending.role;
    req.session.tenantId         = pending.tenantId;
    req.session.tenantIds        = pending.tenantIds;
    req.session.totpEnabled      = true;

    return res.json({
      id: pending.userId, username: pending.username,
      role: pending.role, tenantId: pending.tenantId, tenantIds: pending.tenantIds,
    });
  } catch (err) {
    return serverError(res, err);
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed.' });
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  res.json({
    id:          req.session.userId,
    username:    req.session.username,
    role:        req.session.role,
    tenantId:    req.session.tenantId   || null,
    tenantIds:   req.session.tenantIds  || [],
    totpEnabled: req.session.totpEnabled || false,
  });
});

// ── All remaining /api/* routes require a valid session ───────────────────

app.use('/api', requireAuth);

// ── TOTP management routes (requireAuth + superadmin only) ───────────────

// Generate a new TOTP secret for a logged-in grace-period superadmin
app.get('/api/auth/totp-setup', async (req, res) => {
  if (req.session.role !== 'superadmin') {
    return res.status(403).json({ error: 'Superadmin only.' });
  }
  try {
    const secret     = authenticator.generateSecret();
    req.session.pendingTotpSecret = secret;

    const otpauthUri = authenticator.keyuri(req.session.username, 'SecOps Dashboard', secret);
    const qrCodeUrl  = await QRCode.toDataURL(otpauthUri);

    return res.json({ qrCodeUrl, secret });
  } catch (err) {
    return serverError(res, err);
  }
});

// Confirm a TOTP code against pendingTotpSecret and activate MFA
app.post('/api/auth/totp-confirm', async (req, res) => {
  if (req.session.role !== 'superadmin') {
    return res.status(403).json({ error: 'Superadmin only.' });
  }
  try {
    const secret = req.session.pendingTotpSecret;
    if (!secret) return res.status(400).json({ error: 'Setup not started. Request QR code first.' });

    const token = String(req.body.token || '').trim();
    if (!/^\d{6}$/.test(token)) {
      return res.status(400).json({ error: 'Token must be 6 digits.' });
    }

    const valid = authenticator.verify({ token, secret });
    if (!valid) return res.status(401).json({ error: 'Invalid or expired code. Try again.' });

    await pool.query(
      'UPDATE users SET totp_secret=$1, totp_enabled=true, totp_required=true WHERE id=$2',
      [secret, req.session.userId]
    );

    req.session.pendingTotpSecret = undefined;
    req.session.totpEnabled       = true;

    return res.json({ ok: true });
  } catch (err) {
    return serverError(res, err);
  }
});

// Disable TOTP — requires password confirmation; totp_required stays true
app.post('/api/auth/totp-disable', async (req, res) => {
  if (req.session.role !== 'superadmin') {
    return res.status(403).json({ error: 'Superadmin only.' });
  }
  try {
    const password = String(req.body.password || '');
    if (!password) return res.status(400).json({ error: 'Password is required.' });

    const { rows } = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [req.session.userId]
    );
    if (!rows.length) return res.status(404).json({ error: 'User not found.' });

    const match = await bcrypt.compare(password, rows[0].password_hash);
    if (!match) return res.status(401).json({ error: 'Incorrect password.' });

    await pool.query(
      'UPDATE users SET totp_secret=NULL, totp_enabled=false WHERE id=$1',
      [req.session.userId]
    );

    req.session.totpEnabled = false;
    return res.json({ ok: true });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── Multi-tenant helpers ──────────────────────────────────────────────────

// Returns all tenants the current user is assigned to (for tenant switcher UI)
app.get('/api/auth/my-tenants', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT t.id, t.name
       FROM user_tenants ut
       JOIN tenants t ON t.id = ut.tenant_id
       WHERE ut.user_id = $1
       ORDER BY t.name ASC`,
      [req.session.userId]
    );
    res.json(result.rows);
  } catch (err) {
    return serverError(res, err);
  }
});

// Switch the active tenant context within the current session
app.post('/api/auth/switch-tenant', (req, res) => {
  const newId   = parseInt(req.body.tenantId, 10);
  const allowed = req.session.tenantIds || [];
  if (isNaN(newId) || !allowed.includes(newId)) {
    return res.status(403).json({ error: 'Not authorised for this tenant.' });
  }
  req.session.tenantId = newId;
  res.json({ ok: true, tenantId: newId });
});

// ── Tenant routes (superadmin only) ──────────────────────────────────────

const SLUG_RE = /^[a-z0-9_-]{2,30}$/;

app.get('/api/tenants', async (req, res) => {
  // All authenticated users can list tenants (needed for dropdowns).
  try {
    const result = await pool.query(
      `SELECT t.id, t.name, t.slug, t.created_at,
              COUNT(u.id)::int AS user_count
       FROM tenants t
       LEFT JOIN users u ON u.tenant_id = t.id
       GROUP BY t.id ORDER BY t.name ASC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tenants', requireSuperAdmin, async (req, res) => {
  try {
    const name = (req.body.name || '').trim();
    const slug = (req.body.slug || '').trim().toLowerCase();

    if (!name || name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: 'Tenant name must be 2–100 characters.' });
    }
    if (!SLUG_RE.test(slug)) {
      return res.status(400).json({ error: 'Slug must be 2–30 lowercase alphanumeric characters, hyphens or underscores.' });
    }

    const result = await pool.query(
      `INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id, name, slug, created_at`,
      [name, slug]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Tenant name or slug already exists.' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tenants/:id', requireSuperAdmin, async (req, res) => {
  try {
    const tenantId = parseInt(req.params.id, 10);
    if (isNaN(tenantId)) return res.status(400).json({ error: 'Invalid tenant id.' });

    const occupied = await pool.query(
      `SELECT
         (SELECT COUNT(*) FROM users     WHERE tenant_id=$1)::int AS users,
         (SELECT COUNT(*) FROM vuln_scans WHERE tenant_id=$1)::int AS scans`,
      [tenantId]
    );
    const { users, scans } = occupied.rows[0];
    if (users > 0 || scans > 0) {
      return res.status(409).json({
        error: `Cannot delete tenant: it still has ${users} user(s) and ${scans} scan(s). Remove them first.`,
      });
    }

    const result = await pool.query('DELETE FROM tenants WHERE id=$1 RETURNING id', [tenantId]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tenant not found.' });
    res.json({ ok: true });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── User management routes ────────────────────────────────────────────────
// superadmin: full CRUD across all tenants.
// tenant admin: CRUD within their own tenant only (no superadmin role allowed).

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;

app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';
    let result;
    if (isSA) {
      result = await pool.query(
        `SELECT u.id, u.username, u.role, u.tenant_id, t.name AS tenant_name,
                u.created_at, u.last_login,
                COALESCE(
                  ARRAY_AGG(DISTINCT ut.tenant_id) FILTER (WHERE ut.tenant_id IS NOT NULL),
                  ARRAY[]::int[]
                ) AS "tenantIds"
         FROM users u
         LEFT JOIN tenants t  ON t.id  = u.tenant_id
         LEFT JOIN user_tenants ut ON ut.user_id = u.id
         GROUP BY u.id, u.username, u.role, u.tenant_id, t.name, u.created_at, u.last_login
         ORDER BY u.created_at ASC`
      );
    } else {
      result = await pool.query(
        `SELECT u.id, u.username, u.role, u.tenant_id, t.name AS tenant_name,
                u.created_at, u.last_login,
                COALESCE(
                  ARRAY_AGG(DISTINCT ut.tenant_id) FILTER (WHERE ut.tenant_id IS NOT NULL),
                  ARRAY[]::int[]
                ) AS "tenantIds"
         FROM users u
         LEFT JOIN tenants t  ON t.id  = u.tenant_id
         LEFT JOIN user_tenants ut ON ut.user_id = u.id
         WHERE u.tenant_id = $1
         GROUP BY u.id, u.username, u.role, u.tenant_id, t.name, u.created_at, u.last_login
         ORDER BY u.created_at ASC`,
        [req.session.tenantId]
      );
    }
    res.json(result.rows);
  } catch (err) {
    return serverError(res, err);
  }
});

app.post('/api/users', requireAdmin, async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = (req.body.password || '').trim();
    const isSA     = req.session.role === 'superadmin';

    let role = (req.body.role || 'readonly').trim();

    // Resolve primary tenant and full list of assigned tenant IDs
    let tenantId, tenantIds;
    if (isSA) {
      if (Array.isArray(req.body.tenantIds) && req.body.tenantIds.length > 0) {
        tenantIds = req.body.tenantIds.map(id => parseInt(id, 10)).filter(id => !isNaN(id) && id > 0);
        tenantId  = tenantIds[0];
      } else {
        tenantId  = req.body.tenantId ? parseInt(req.body.tenantId, 10) : null;
        tenantIds = tenantId ? [tenantId] : [];
      }
    } else {
      tenantId  = req.session.tenantId;
      tenantIds = tenantId ? [tenantId] : [];
    }

    if (!USERNAME_RE.test(username)) {
      return res.status(400).json({ error: 'Username must be 3–30 alphanumeric characters (underscores allowed).' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    // Superadmin can create any role; tenant admin can only create admin/readonly.
    const allowedRoles = isSA ? ['superadmin', 'admin', 'readonly'] : ['admin', 'readonly'];
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: `Role must be one of: ${allowedRoles.join(', ')}.` });
    }

    // Non-superadmin roles must belong to at least one tenant.
    if (role !== 'superadmin' && tenantIds.length === 0) {
      return res.status(400).json({ error: 'At least one tenant must be specified for non-superadmin users.' });
    }
    // Superadmin has no tenant.
    if (role === 'superadmin') { tenantId = null; tenantIds = []; }

    const hash = await bcrypt.hash(password, 12);
    // New superadmin accounts require TOTP enrollment on first login
    const requireTotp = (role === 'superadmin');
    const result = await pool.query(
      `INSERT INTO users (username, password_hash, role, tenant_id, totp_required)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, username, role, tenant_id, created_at`,
      [username, hash, role, tenantId || null, requireTotp]
    );
    const newUser = result.rows[0];

    // Assign all tenants in junction table
    for (const tid of tenantIds) {
      await pool.query(
        'INSERT INTO user_tenants (user_id, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [newUser.id, tid]
      );
    }

    res.status(201).json(newUser);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    return serverError(res, err);
  }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = parseInt(req.params.id, 10);
    if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user id.' });

    const isSA = req.session.role === 'superadmin';

    // Tenant admin can only edit users in their own tenant.
    if (!isSA) {
      const check = await pool.query('SELECT tenant_id FROM users WHERE id=$1', [targetId]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
      if (check.rows[0].tenant_id !== req.session.tenantId) {
        return res.status(403).json({ error: 'You can only edit users in your own organisation.' });
      }
    }

    const { role, password, tenantIds } = req.body;
    const updates = [];
    const values  = [];

    if (role !== undefined) {
      const allowedRoles = isSA ? ['superadmin', 'admin', 'readonly'] : ['admin', 'readonly'];
      if (!allowedRoles.includes(role)) {
        return res.status(400).json({ error: `Role must be one of: ${allowedRoles.join(', ')}.` });
      }
      if (targetId === req.session.userId) {
        return res.status(400).json({ error: 'You cannot change your own role.' });
      }
      updates.push(`role = $${values.length + 1}`);
      values.push(role);
    }

    if (password !== undefined) {
      if (String(password).length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters.' });
      }
      const hash = await bcrypt.hash(String(password), 12);
      updates.push(`password_hash = $${values.length + 1}`);
      values.push(hash);
    }

    // Superadmin can update tenant assignments
    let tenantIdsUpdate = null;
    if (isSA && tenantIds !== undefined) {
      if (!Array.isArray(tenantIds)) {
        return res.status(400).json({ error: 'tenantIds must be an array.' });
      }
      tenantIdsUpdate = tenantIds.map(id => parseInt(id, 10)).filter(id => !isNaN(id) && id > 0);
      const primary = tenantIdsUpdate[0] || null;
      updates.push(`tenant_id = $${values.length + 1}`);
      values.push(primary);
    }

    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nothing to update. Provide role, password, or tenantIds.' });
    }

    values.push(targetId);
    const result = await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length}
       RETURNING id, username, role, tenant_id, created_at, last_login`,
      values
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    // Replace junction table entries if tenantIds were supplied
    if (tenantIdsUpdate !== null) {
      await pool.query('DELETE FROM user_tenants WHERE user_id = $1', [targetId]);
      for (const tid of tenantIdsUpdate) {
        await pool.query(
          'INSERT INTO user_tenants (user_id, tenant_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [targetId, tid]
        );
      }
    }

    res.json(result.rows[0]);
  } catch (err) {
    return serverError(res, err);
  }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  try {
    const targetId = parseInt(req.params.id, 10);
    if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user id.' });

    if (targetId === req.session.userId) {
      return res.status(400).json({ error: 'You cannot delete your own account.' });
    }

    const isSA = req.session.role === 'superadmin';
    let result;
    if (isSA) {
      result = await pool.query('DELETE FROM users WHERE id=$1 RETURNING id', [targetId]);
    } else {
      // Tenant admin can only delete users in their own tenant.
      result = await pool.query(
        'DELETE FROM users WHERE id=$1 AND tenant_id=$2 RETURNING id',
        [targetId, req.session.tenantId]
      );
    }
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Existing routes: weeks / metrics ─────────────────────────────────────

app.post(
  '/api/upload',
  upload.fields([{ name: 'report', maxCount: 1 }, { name: 'csv', maxCount: 1 }]),
  (req, res) => {
    try {
      let reportText = req.body.report || '';
      if (!reportText && req.files && req.files.report) {
        reportText = req.files.report[0].buffer.toString('utf8');
      }
      if (!reportText) return res.status(400).json({ error: 'No report provided.' });

      let csvText = '';
      if (req.files && req.files.csv) {
        csvText = req.files.csv[0].buffer.toString('utf8');
      }

      const parsed = parseReport(reportText, csvText);
      if (parsed.error) return res.status(400).json({ error: parsed.error });

      const weeks = readData(WEEKS_FILE);
      weeks[parsed.weekKey] = parsed;
      writeData(WEEKS_FILE, weeks);
      recomputeMetrics();
      return res.json(parsed);
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }
);

app.get('/api/weeks', (req, res) => {
  try {
    const weeks = readData(WEEKS_FILE);
    const list = Object.keys(weeks)
      .sort((a, b) => b.localeCompare(a))
      .map(k => ({ key: k, weekCommencing: weeks[k].weekCommencing }));
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/week/:weekKey', (req, res) => {
  try {
    const weeks = readData(WEEKS_FILE);
    const week  = weeks[req.params.weekKey];
    if (!week) return res.status(404).json({ error: 'Week not found.' });
    res.json(week);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/week/:weekKey/priority/:index', (req, res) => {
  try {
    const { weekKey, index } = req.params;
    const { status } = req.body;
    if (!['open', 'wip', 'done'].includes(status)) {
      return res.status(400).json({ error: 'status must be open, wip, or done.' });
    }
    const weeks = readData(WEEKS_FILE);
    const week  = weeks[weekKey];
    if (!week) return res.status(404).json({ error: 'Week not found.' });
    const idx = parseInt(index, 10);
    if (isNaN(idx) || idx < 0 || idx >= week.priorities.length) {
      return res.status(400).json({ error: 'Invalid priority index.' });
    }
    week.priorities[idx].status = status;
    writeData(WEEKS_FILE, weeks);
    recomputeMetrics();
    res.json(week);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/metrics/summary', (req, res) => {
  try {
    const metrics = readData(METRICS_FILE);
    const summary = getSummary(metrics, 12);
    res.json(summary);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/metrics/orgs', (req, res) => {
  try {
    const weeks   = readData(WEEKS_FILE);
    const history = getOrgHistory(weeks);
    res.json(history);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Vuln helpers ──────────────────────────────────────────────────────────

/**
 * Resolve which tenant's vuln data to act on.
 * - superadmin: reads tenantId from body or query string (must be provided).
 * - admin/readonly: always their own session tenantId.
 * Returns { tenantId } or throws { status, error }.
 */
function resolveVulnTenant(req, source = 'query') {
  if (req.session.role === 'superadmin') {
    const raw = source === 'body' ? req.body.tenantId : req.query.tenantId;
    const tid = parseInt(raw, 10);
    if (isNaN(tid) || tid < 1) {
      return { error: { status: 400, message: 'superadmin must provide a valid tenantId.' } };
    }
    return { tenantId: tid };
  }
  return { tenantId: req.session.tenantId };
}

// ── Vuln routes — backed by PostgreSQL ───────────────────────────────────

app.post('/api/vulns/upload', requireAdmin, vulnUpload.single('vulnFile'), async (req, res) => {
  const client = await pool.connect();
  try {
    const monthKey = (req.body.monthKey || '').trim();
    if (!monthKey || !/^\d{4}-\d{2}$/.test(monthKey)) {
      return res.status(400).json({ error: 'Valid monthKey (YYYY-MM) is required.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No vuln file uploaded.' });
    }

    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const fileText = req.file.buffer.toString('utf8');
    const origName = (req.file.originalname || '').toLowerCase();
    const mimeType = (req.file.mimetype     || '').toLowerCase();

    let findings;
    if (origName.endsWith('.nessus') || mimeType.includes('xml')) {
      findings = parseNessusXML(fileText);
    } else if (isArcticWolfCSV(fileText)) {
      findings = parseArcticWolfCSV(fileText);
    } else {
      findings = parseNessusCSV(fileText);
    }
    if (findings.length === 0) {
      return res.status(400).json({ error: 'No findings parsed. Check it is a valid Nessus CSV, .nessus XML, or Arctic Wolf Managed Risk CSV export.' });
    }

    const summary = computeVulnSummary(findings);

    const prevScan = await client.query(
      `SELECT id FROM vuln_scans WHERE tenant_id=$1 AND month_key < $2 ORDER BY month_key DESC LIMIT 1`,
      [tenantId, monthKey]
    );

    const prevMap = new Map();
    if (prevScan.rows.length > 0) {
      const prevId = prevScan.rows[0].id;
      const prevFindings = await client.query(
        `SELECT plugin_id, host, port, status, notes, status_updated_at, first_seen_at
         FROM vuln_findings WHERE scan_id = $1`,
        [prevId]
      );
      prevFindings.rows.forEach(pf => {
        const key = `${pf.plugin_id}|${pf.host}|${pf.port}`;
        // If duplicate key, keep the one with status data or earliest first_seen_at
        if (!prevMap.has(key) || pf.status !== 'open') {
          prevMap.set(key, pf);
        }
      });
    }

    let carried = 0;
    const uploadNow = new Date();
    findings.forEach(f => {
      const match = prevMap.get(`${f.pluginId}|${f.host}|${f.port}`);
      if (match) {
        f.status          = match.status;
        f.notes           = match.notes || '';
        f.statusUpdatedAt = match.status_updated_at ? match.status_updated_at.toISOString() : null;
        f.firstSeenAt     = match.first_seen_at || uploadNow;
        carried++;
      } else {
        // Preserve firstSeenAt supplied by the parser (e.g. Arctic Wolf First Detected Time)
        f.firstSeenAt = f.firstSeenAt || uploadNow;
      }
    });

    await client.query('BEGIN');
    await client.query('DELETE FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2', [tenantId, monthKey]);

    const scanResult = await client.query(
      `INSERT INTO vuln_scans (tenant_id, month_key, summary, uploaded_by) VALUES ($1, $2, $3, $4) RETURNING id`,
      [tenantId, monthKey, JSON.stringify(summary), req.session.userId]
    );
    const scanId = scanResult.rows[0].id;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      await client.query(
        `INSERT INTO vuln_findings
           (scan_id, finding_index, plugin_id, name, risk, host, port, protocol,
            cve, cvss_v2, cvss_v3, synopsis, solution, status, notes, status_updated_at, first_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
        [
          scanId, i,
          f.pluginId   || null, f.name     || null, f.risk     || null,
          f.host       || null, f.port     || null, f.protocol || null,
          f.cve        || null, f.cvssV2   || null, f.cvssV3   || null,
          f.synopsis   || null, f.solution || null,
          f.status || 'open',
          f.notes  || '',
          f.statusUpdatedAt ? new Date(f.statusUpdatedAt) : null,
          f.firstSeenAt || null,
        ]
      );
    }

    await client.query('COMMIT');

    const carriedCounts = { fixed: 0, accepted: 0, 'in-progress': 0 };
    findings.forEach(f => {
      if (f.status && f.status !== 'open' && carriedCounts[f.status] !== undefined) {
        carriedCounts[f.status]++;
      }
    });

    console.log(`[vulns] Upload ${monthKey} (tenant ${tenantId}): ${findings.length} findings, ${carried} carried over`);
    return res.json({ monthKey, tenantId, summary, carriedCounts });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return serverError(res, err);
  } finally {
    client.release();
  }
});

app.get('/api/vulns', async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });
    const result = await pool.query(
      'SELECT month_key AS "monthKey", summary, created_at AS "uploadedAt" FROM vuln_scans WHERE tenant_id=$1 ORDER BY month_key DESC',
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/vulns/trends', async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });
    const result = await pool.query(
      `SELECT month_key AS "monthKey",
              (summary->>'critical')::int AS critical,
              (summary->>'high')::int     AS high,
              (summary->>'medium')::int   AS medium,
              (summary->>'low')::int      AS low
       FROM vuln_scans WHERE tenant_id=$1 ORDER BY month_key ASC`,
      [tenantId]
    );
    res.json(result.rows.slice(-12));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/vulns/:monthKey', async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });
    const scanResult = await pool.query(
      'SELECT id, month_key AS "monthKey", summary FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2',
      [tenantId, req.params.monthKey]
    );
    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const scan = scanResult.rows[0];

    const findingsResult = await pool.query(
      `SELECT finding_index AS idx, plugin_id AS "pluginId", name, risk, host, port,
              protocol, cve, cvss_v2 AS "cvssV2", cvss_v3 AS "cvssV3",
              synopsis, solution, status, notes,
              status_updated_at AS "statusUpdatedAt",
              first_seen_at AS "firstSeenAt"
       FROM vuln_findings WHERE scan_id = $1 ORDER BY finding_index ASC`,
      [scan.id]
    );

    const findings = findingsResult.rows.map(row => {
      const f = { ...row };
      delete f.idx;
      if (f.statusUpdatedAt) f.statusUpdatedAt = f.statusUpdatedAt.toISOString();
      if (f.firstSeenAt)     f.firstSeenAt     = f.firstSeenAt.toISOString();
      return f;
    });

    res.json({ monthKey: scan.monthKey, summary: scan.summary, findings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/vulns/:monthKey', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });
    const result = await pool.query(
      'DELETE FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2 RETURNING id',
      [tenantId, req.params.monthKey]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Bulk status update ────────────────────────────────────────────────────
app.patch('/api/vulns/:monthKey/findings/bulk-status', requireAdmin, async (req, res) => {
  try {
    const { monthKey } = req.params;
    const { status, indices } = req.body;

    if (!['open', 'in-progress', 'fixed', 'accepted'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }
    if (!Array.isArray(indices) || indices.length === 0) {
      return res.status(400).json({ error: 'indices must be a non-empty array.' });
    }
    const idxList = indices.map(i => parseInt(i, 10)).filter(i => !isNaN(i) && i >= 0);
    if (idxList.length === 0) return res.status(400).json({ error: 'No valid indices.' });

    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const scanResult = await pool.query(
      'SELECT id FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2',
      [tenantId, monthKey]
    );
    if (scanResult.rows.length === 0) return res.status(404).json({ error: 'Scan not found.' });
    const scanId = scanResult.rows[0].id;

    await pool.query(
      `UPDATE vuln_findings SET status = $1, status_updated_at = NOW()
       WHERE scan_id = $2 AND finding_index = ANY($3::int[])`,
      [status, scanId, idxList]
    );

    res.json({ ok: true, updated: idxList.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Latest vuln summary per tenant (superadmin: all, others: own) ──────────
app.get('/api/vulns/latest-summary', async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';
    let rows;
    if (isSA) {
      const result = await pool.query(
        `SELECT t.id AS "tenantId", t.name AS "tenantName",
                vs.month_key AS "monthKey", vs.summary
         FROM tenants t
         LEFT JOIN LATERAL (
           SELECT month_key, summary FROM vuln_scans
           WHERE tenant_id = t.id ORDER BY month_key DESC LIMIT 1
         ) vs ON true
         ORDER BY t.name ASC`
      );
      rows = result.rows;
    } else {
      const tenantId = req.session.tenantId;
      if (!tenantId) return res.json([]);
      const result = await pool.query(
        `SELECT $1::int AS "tenantId", '' AS "tenantName",
                month_key AS "monthKey", summary
         FROM vuln_scans WHERE tenant_id=$1 ORDER BY month_key DESC LIMIT 1`,
        [tenantId]
      );
      rows = result.rows;
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Bulk status update ──────────────────────────────────────────────────────
app.patch('/api/vulns/:monthKey/findings/bulk-status', requireAdmin, async (req, res) => {
  try {
    const { monthKey } = req.params;
    const { status, indices } = req.body;

    if (!['open', 'in-progress', 'fixed', 'accepted'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }
    if (!Array.isArray(indices) || indices.length === 0) {
      return res.status(400).json({ error: 'indices must be a non-empty array.' });
    }
    const idxList = indices.map(i => parseInt(i, 10)).filter(i => !isNaN(i) && i >= 0);
    if (idxList.length === 0) return res.status(400).json({ error: 'No valid indices.' });

    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const scanResult = await pool.query(
      'SELECT id FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2',
      [tenantId, monthKey]
    );
    if (scanResult.rows.length === 0) return res.status(404).json({ error: 'Scan not found.' });
    const scanId = scanResult.rows[0].id;

    await pool.query(
      `UPDATE vuln_findings SET status = $1, status_updated_at = NOW()
       WHERE scan_id = $2 AND finding_index = ANY($3::int[])`,
      [status, scanId, idxList]
    );

    res.json({ ok: true, updated: idxList.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Latest vuln summary per tenant (superadmin: all, others: own) ──────────
app.get('/api/vulns/latest-summary', async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';
    let rows;
    if (isSA) {
      const result = await pool.query(
        `SELECT t.id AS "tenantId", t.name AS "tenantName",
                vs.month_key AS "monthKey", vs.summary
         FROM tenants t
         LEFT JOIN LATERAL (
           SELECT month_key, summary FROM vuln_scans
           WHERE tenant_id = t.id ORDER BY month_key DESC LIMIT 1
         ) vs ON true
         ORDER BY t.name ASC`
      );
      rows = result.rows;
    } else {
      const tenantId = req.session.tenantId;
      if (!tenantId) return res.json([]);
      const result = await pool.query(
        `SELECT $1::int AS "tenantId", '' AS "tenantName",
                month_key AS "monthKey", summary
         FROM vuln_scans WHERE tenant_id=$1 ORDER BY month_key DESC LIMIT 1`,
        [tenantId]
      );
      rows = result.rows;
    }
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/vulns/:monthKey/finding/:index', requireAdmin, async (req, res) => {
  try {
    const { monthKey, index } = req.params;
    const { status, notes }   = req.body;

    if (!['open', 'in-progress', 'fixed', 'accepted'].includes(status)) {
      return res.status(400).json({ error: 'status must be open, in-progress, fixed, or accepted.' });
    }

    const idx = parseInt(index, 10);
    if (isNaN(idx) || idx < 0) return res.status(400).json({ error: 'Invalid finding index.' });

    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const scanResult = await pool.query(
      'SELECT id FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2',
      [tenantId, monthKey]
    );
    if (scanResult.rows.length === 0) {
      return res.status(404).json({ error: 'Scan not found.' });
    }
    const scanId = scanResult.rows[0].id;

    const now = new Date();
    let result;

    if (notes !== undefined) {
      result = await pool.query(
        `UPDATE vuln_findings
         SET status = $1, notes = $2, status_updated_at = $3
         WHERE scan_id = $4 AND finding_index = $5
         RETURNING status, status_updated_at AS "statusUpdatedAt"`,
        [status, String(notes).slice(0, 500), now, scanId, idx]
      );
    } else {
      result = await pool.query(
        `UPDATE vuln_findings
         SET status = $1, status_updated_at = $2
         WHERE scan_id = $3 AND finding_index = $4
         RETURNING status, status_updated_at AS "statusUpdatedAt"`,
        [status, now, scanId, idx]
      );
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Finding not found.' });
    }

    const row = result.rows[0];
    res.json({
      ok:              true,
      status:          row.status,
      statusUpdatedAt: row.statusUpdatedAt.toISOString(),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Start ─────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`SecOps Dashboard running on http://localhost:${PORT}`);
  console.log(`Access via base path:   http://localhost:${PORT}/secops/`);
}).on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${PORT} is already in use. Stop the existing process or change PORT in .env`);
  } else {
    console.error('Server error:', err.message);
  }
  process.exit(1);
});
