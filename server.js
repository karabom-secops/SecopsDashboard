'use strict';

require('dotenv').config();

const path    = require('path');
const fs      = require('fs');
const express = require('express');
const multer  = require('multer');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const bcrypt  = require('bcryptjs');

const speakeasy = require('speakeasy');
const QRCode    = require('qrcode');

const pool = require('./lib/db');
const { requireAuth, requireAdmin, requireSuperAdmin, requireManager, requireRiskWrite } = require('./lib/auth-middleware');
const { parseReport } = require('./lib/parser');
const { computeAllMetrics, getSummary, getOrgHistory } = require('./lib/metrics');
const { parseNessusCSV, parseNessusXML, parseArcticWolfCSV, isArcticWolfCSV, computeVulnSummary } = require('./lib/vuln-parser');
const { parseAwarenessCSV, detectAwarenessFormat, parseSessionHistoryCSV } = require('./lib/awareness-parser');
const XLSX = require('xlsx');
const { isSamlEnabled, getSamlLoginUrl, validateSamlResponse, getSamlMetadata } = require('./lib/saml');
const { calculateSecureScore, generateRecommendations } = require('./lib/secure-score');
const { encrypt: encryptKey, decrypt: decryptKey } = require('./lib/crypto-utils');
const arcticWolfAdapter = require('./lib/integrations/arctic-wolf');
const { PLAYBOOKS: IR_PLAYBOOKS } = require('./public/js/ir-playbooks-data');
const irisDfirAdapter   = require('./lib/integrations/iris-dfir');
const arcticWolfReportsAdapter = require('./lib/integrations/arctic-wolf-reports');

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

// Trust proxy — required when behind nginx/reverse proxy for X-Forwarded-For headers
app.set('trust proxy', 1);

// Serve static assets BEFORE session/auth so the login page loads without auth.SO is secure score stuff fine
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

const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many login attempts. Please try again later.' },
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

    if (user.role === 'manager') {
      return res.json({ id: user.id, username: user.username, role: user.role, tenantId: user.tenant_id, tenantIds, redirect: '/manager.html' });
    }
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

    const valid = speakeasy.totp.verify({ secret: rows[0].totp_secret, encoding: 'base32', token, window: 1 });
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

    const secret  = speakeasy.generateSecret({ length: 20 }).base32;
    req.session.pendingTotpSecret = secret;

    const otpauthUri = speakeasy.otpauthURL({ secret, label: pending.username, issuer: 'SecOps Dashboard', encoding: 'base32' });
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

    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
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

// ── SAML / SSO routes (public — no requireAuth) ─────────────────────────

// Reports whether SSO is configured so the login page can show the button.
app.get('/api/auth/saml/enabled', (req, res) => {
  res.json({ enabled: isSamlEnabled() });
});

// Initiates SSO: redirects browser to Azure AD login page.
app.get('/api/auth/saml/login', async (req, res) => {
  if (!isSamlEnabled()) {
    return res.status(404).json({ error: 'SSO is not enabled.' });
  }
  try {
    const url = await getSamlLoginUrl();
    res.redirect(url);
  } catch (err) {
    console.error('[saml] login redirect error:', err.message, err.stack);
    console.error('[saml] env — ENTRY_POINT set:', !!process.env.SAML_ENTRY_POINT, '| CERT set:', !!(process.env.SAML_CERT || process.env.SAML_CERT_FILE), '| CALLBACK set:', !!process.env.SAML_CALLBACK_URL);
    res.status(500).send('SSO login failed. Please try again or use your local account.');
  }
});

// ACS endpoint: Azure AD POSTs the SAML assertion here.
// External URL: https://secops.reflex.co.za/secops/api/auth/saml/callback
// Express sees: POST /api/auth/saml/callback  (nginx strips /secops/)
app.post('/api/auth/saml/callback', async (req, res) => {
  if (!isSamlEnabled()) {
    return res.status(404).json({ error: 'SSO is not enabled.' });
  }
  try {
    require("fs").writeFileSync("/tmp/saml_response.txt", req.body.SAMLResponse || "");
    const { profile } = await validateSamlResponse(req.body);
    if (!profile || !profile.nameID) {
      return res.status(401).send('SSO failed: no identity returned.');
    }

    const nameId = profile.nameID.trim();

    // Look up existing SAML account
    let userResult = await pool.query(
      'SELECT id, username, role, tenant_id, auth_type FROM users WHERE saml_nameid = $1',
      [nameId]
    );

    let user;
    if (userResult.rows.length === 0) {
      // New SSO user — provision with readonly role, no tenant
      try {
        const inserted = await pool.query(
          `INSERT INTO users (username, auth_type, saml_nameid, role, tenant_id)
           VALUES ($1, 'saml', $2, 'readonly', NULL)
           RETURNING id, username, role, tenant_id`,
          [nameId, nameId]
        );
        user = inserted.rows[0];
        console.log('[saml] provisioned new user:', nameId);
      } catch (insertErr) {
        if (insertErr.code === '23505') {
          // Username collision with an existing local account
          console.error('[saml] username collision for nameID:', nameId);
          return res.status(409).send(
            'An account with this email already exists as a local user. ' +
            'Please contact your administrator to link your SSO account.'
          );
        }
        throw insertErr;
      }
    } else {
      user = userResult.rows[0];
    }

    await pool.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Load tenant assignments
    let tenantIds = [];
    if (user.role !== 'superadmin') {
      const tRes = await pool.query(
        'SELECT tenant_id FROM user_tenants WHERE user_id = $1 ORDER BY tenant_id',
        [user.id]
      );
      tenantIds = tRes.rows.map(r => r.tenant_id);
    }

    req.session.userId     = user.id;
    req.session.username   = user.username;
    req.session.role       = user.role;
    req.session.tenantId   = user.tenant_id || (tenantIds[0] || null);
    req.session.tenantIds  = tenantIds;
    req.session.totpEnabled = false;

    // Redirect to manager page for manager role, otherwise the dashboard
    const destination = user.role === 'manager' ? '/secops/manager.html' : '/secops/';
    req.session.save(err => {
      if (err) {
        console.error('[saml] session save error:', err.message);
        return res.status(500).send('SSO session error. Please try again.');
      }
      res.redirect(destination);
    });
  } catch (err) {
    console.error('[saml] callback error:', err.message, err.stack);
    res.status(401).send('SSO authentication failed. Please try again.');
  }
});

// Returns SP metadata XML — useful for Azure AD app registration.
app.get('/api/auth/saml/metadata', (req, res) => {
  if (!isSamlEnabled()) {
    return res.status(404).json({ error: 'SSO is not enabled.' });
  }
  try {
    const xml = getSamlMetadata();
    res.set('Content-Type', 'application/xml');
    res.send(xml);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
    const secret     = speakeasy.generateSecret({ length: 20 }).base32;
    req.session.pendingTotpSecret = secret;

    const otpauthUri = speakeasy.otpauthURL({ secret, label: req.session.username, issuer: 'SecOps Dashboard', encoding: 'base32' });
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

    const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
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

const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$|^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.get('/api/users', requireAdmin, async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';
    let result;
    if (isSA) {
      result = await pool.query(
        `SELECT u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name AS tenant_name,
                u.created_at, u.last_login,
                COALESCE(
                  ARRAY_AGG(DISTINCT ut.tenant_id) FILTER (WHERE ut.tenant_id IS NOT NULL),
                  ARRAY[]::int[]
                ) AS "tenantIds"
         FROM users u
         LEFT JOIN tenants t  ON t.id  = u.tenant_id
         LEFT JOIN user_tenants ut ON ut.user_id = u.id
         GROUP BY u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name, u.created_at, u.last_login
         ORDER BY u.created_at ASC`
      );
    } else {
      result = await pool.query(
        `SELECT u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name AS tenant_name,
                u.created_at, u.last_login,
                COALESCE(
                  ARRAY_AGG(DISTINCT ut.tenant_id) FILTER (WHERE ut.tenant_id IS NOT NULL),
                  ARRAY[]::int[]
                ) AS "tenantIds"
         FROM users u
         LEFT JOIN tenants t  ON t.id  = u.tenant_id
         LEFT JOIN user_tenants ut ON ut.user_id = u.id
         WHERE u.tenant_id = $1
         GROUP BY u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name, u.created_at, u.last_login
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
      return res.status(400).json({ error: 'Username must be 3–30 alphanumeric characters (underscores allowed), or a valid email address.' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    // Superadmin can create any role; tenant admin can only create admin/readonly.
    const allowedRoles = isSA ? ['superadmin', 'admin', 'readonly', 'manager', 'sales'] : ['admin', 'readonly', 'manager', 'sales'];
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
    let targetAuthType = 'local';
    if (!isSA) {
      const check = await pool.query('SELECT tenant_id, auth_type FROM users WHERE id=$1', [targetId]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
      if (check.rows[0].tenant_id !== req.session.tenantId) {
        return res.status(403).json({ error: 'You can only edit users in your own organisation.' });
      }
      targetAuthType = check.rows[0].auth_type || 'local';
    } else {
      const check = await pool.query('SELECT auth_type FROM users WHERE id=$1', [targetId]);
      if (check.rows.length > 0) targetAuthType = check.rows[0].auth_type || 'local';
    }

    const { role, password, tenantIds } = req.body;
    const updates = [];
    const values  = [];

    if (role !== undefined) {
      const allowedRoles = isSA ? ['superadmin', 'admin', 'readonly', 'manager', 'sales'] : ['admin', 'readonly', 'manager', 'sales'];
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
      if (targetAuthType === 'saml') {
        return res.status(400).json({ error: 'Cannot set a password for SSO users.' });
      }
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

    const prevScan = await client.query(
      `SELECT id FROM vuln_scans WHERE tenant_id=$1 AND month_key < $2 ORDER BY month_key DESC LIMIT 1`,
      [tenantId, monthKey]
    );

    const prevMap = new Map();
    if (prevScan.rows.length > 0) {
      const prevId = prevScan.rows[0].id;
      const prevFindings = await client.query(
        `SELECT plugin_id, name, risk, host, port, protocol,
                cve, cvss_v2, cvss_v3, synopsis, solution,
                status, notes, status_updated_at, first_seen_at
         FROM vuln_findings WHERE scan_id = $1`,
        [prevId]
      );
      prevFindings.rows.forEach(pf => {
        const key = `${pf.plugin_id}|${pf.host}|${pf.port}`;
        if (!prevMap.has(key) || pf.status !== 'open') {
          prevMap.set(key, pf);
        }
      });
    }

    let carried = 0;
    const uploadNow = new Date();
    const newKeys = new Set();
    findings.forEach(f => {
      const key = `${f.pluginId}|${f.host}|${f.port}`;
      newKeys.add(key);

      const match = prevMap.get(key);
      if (match) {
        f.status          = match.status;
        f.notes           = match.notes || '';
        f.statusUpdatedAt = match.status_updated_at ? match.status_updated_at.toISOString() : null;
        f.firstSeenAt     = match.first_seen_at || uploadNow;
        carried++;
      } else {
        f.firstSeenAt = f.firstSeenAt || uploadNow;
      }
    });

    const autoClosedFindings = [];
    for (const [key, prev] of prevMap.entries()) {
      if (newKeys.has(key)) continue;
      const prevStatus = String(prev.status || 'open');
      if (prevStatus === 'fixed' || prevStatus === 'accepted') continue;

      autoClosedFindings.push({
        pluginId:        prev.plugin_id,
        name:            prev.name,
        risk:            prev.risk,
        host:            prev.host,
        port:            prev.port,
        protocol:        prev.protocol,
        cve:             prev.cve,
        cvssV2:          prev.cvss_v2,
        cvssV3:          prev.cvss_v3,
        synopsis:        prev.synopsis,
        solution:        prev.solution,
        status:          'fixed',
        notes:           prev.notes
                          ? `${prev.notes}\nAuto-closed because this finding no longer appears in the ${monthKey} scan.`
                          : `Auto-closed because this finding no longer appears in the ${monthKey} scan.`,
        statusUpdatedAt: uploadNow.toISOString(),
        firstSeenAt:     prev.first_seen_at || uploadNow,
      });
    }

    if (autoClosedFindings.length > 0) {
      findings = findings.concat(autoClosedFindings);
    }

    const summary = computeVulnSummary(findings);

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

    const autoClosedCount = autoClosedFindings.length;
    console.log(`[vulns] Upload ${monthKey} (tenant ${tenantId}): ${findings.length} findings, ${carried} carried over, ${autoClosedCount} auto-closed`);
    return res.json({ monthKey, tenantId, summary, carriedCounts, autoClosedCount });
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

// ── Security Awareness routes ─────────────────────────────────────────────

const awarenessUpload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 10 * 1024 * 1024 },
});

/**
 * Resolve which tenant's awareness data to act on.
 * Mirrors resolveVulnTenant.
 */
function resolveAwarenessTenant(req, source) {
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

/**
 * Replace a tenant's session-history awareness data with freshly parsed rows.
 * Shared by the manual CSV/XLSX upload route and the Arctic Wolf Reports sync route.
 */
async function writeAwarenessHistory(client, tenantId, uploadedBy, rows, stats) {
  await client.query('DELETE FROM awareness_uploads WHERE tenant_id = $1', [tenantId]);

  const notStartedCount = rows.filter(r =>
    r.status === 'Not Started' &&
    r.sessionType !== 'Phishing Simulation'
  ).length;

  const uploadRes = await client.query(
    `INSERT INTO awareness_uploads (tenant_id, uploaded_by, total_users, total_incomplete, upload_type)
     VALUES ($1, $2, $3, $4, 'history') RETURNING id, uploaded_at`,
    [tenantId, uploadedBy, stats.uniqueUsers, notStartedCount]
  );
  const uploadId   = uploadRes.rows[0].id;
  const uploadedAt = uploadRes.rows[0].uploaded_at;

  for (const row of rows) {
    await client.query(
      `INSERT INTO awareness_sessions
         (upload_id, user_first_name, user_last_name, user_email,
          manager_first_name, manager_last_name, manager_email,
          sent_date, session_type, title, status,
          completed_date, elapsed_seconds, clicked_at, quiz_score)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [
        uploadId,
        row.userFirstName, row.userLastName, row.userEmail,
        row.managerFirstName, row.managerLastName, row.managerEmail,
        row.sentDate        ? new Date(row.sentDate)        : null,
        row.sessionType,
        row.title,
        row.status,
        row.completedDate   ? new Date(row.completedDate)   : null,
        row.elapsedSeconds,
        row.clickedAt       ? new Date(row.clickedAt)       : null,
        row.quizScore,
      ]
    );
  }

  return { uploadId, uploadedAt, notStartedCount };
}

app.post('/api/awareness/upload', requireAdmin, awarenessUpload.single('awarenessFile'), async (req, res) => {
  const client = await pool.connect();
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const { tenantId, error: tenantErr } = resolveAwarenessTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const origName = (req.file.originalname || '').toLowerCase();
    let fileText;
    if (origName.endsWith('.xlsx')) {
      const wb = XLSX.read(req.file.buffer, { type: 'buffer', raw: false });
      const ws = wb.Sheets[wb.SheetNames[0]];
      fileText = XLSX.utils.sheet_to_csv(ws);
    } else {
      fileText = req.file.buffer.toString('utf8');
    }
    const formatType = detectAwarenessFormat(fileText);

    await client.query('BEGIN');
    // Delete existing upload for this tenant (cascade deletes users + sessions)
    await client.query('DELETE FROM awareness_uploads WHERE tenant_id = $1', [tenantId]);

    if (formatType === 'history') {
      // ── Session History CSV ──────────────────────────────────────────────
      let parsed;
      try {
        parsed = parseSessionHistoryCSV(fileText);
      } catch (parseErr) {
        await client.query('ROLLBACK').catch(() => {});
        return res.status(400).json({ error: parseErr.message });
      }

      const { rows, stats } = parsed;
      const { uploadedAt, notStartedCount } = await writeAwarenessHistory(client, tenantId, req.session.userId, rows, stats);

      await client.query('COMMIT');
      return res.json({
        tenantId, uploadedAt, uploadType: 'history',
        totalUsers: stats.uniqueUsers, totalRows: stats.totalRows, notStarted: notStartedCount,
      });

    } else {
      // ── Summary CSV (existing behaviour) ────────────────────────────────
      let parsed;
      try {
        parsed = parseAwarenessCSV(fileText);
      } catch (parseErr) {
        await client.query('ROLLBACK').catch(() => {});
        return res.status(400).json({ error: parseErr.message });
      }

      const { rows, totalUsers, totalIncomplete } = parsed;

      const uploadRes = await client.query(
        `INSERT INTO awareness_uploads (tenant_id, uploaded_by, total_users, total_incomplete, upload_type)
         VALUES ($1, $2, $3, $4, 'summary') RETURNING id, uploaded_at`,
        [tenantId, req.session.userId, totalUsers, totalIncomplete]
      );
      const uploadId   = uploadRes.rows[0].id;
      const uploadedAt = uploadRes.rows[0].uploaded_at;

      for (const row of rows) {
        await client.query(
          `INSERT INTO awareness_users
             (upload_id, manager_first_name, manager_last_name, manager_email,
              user_first_name, user_last_name, user_email, incomplete_sessions)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [
            uploadId,
            row.managerFirstName, row.managerLastName, row.managerEmail,
            row.userFirstName,    row.userLastName,    row.userEmail,
            row.incompleteSessions,
          ]
        );
      }

      await client.query('COMMIT');
      return res.json({ tenantId, totalUsers, totalIncomplete, uploadedAt, uploadType: 'summary' });
    }
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return serverError(res, err);
  } finally {
    client.release();
  }
});

app.get('/api/awareness', requireAuth, async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveAwarenessTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const uploadRes = await pool.query(
      'SELECT id, uploaded_at, total_users, total_incomplete, upload_type FROM awareness_uploads WHERE tenant_id = $1',
      [tenantId]
    );
    if (uploadRes.rows.length === 0) {
      return res.json({ upload: null, users: [], sessions: [] });
    }

    const upload = uploadRes.rows[0];

    if ((upload.upload_type || 'summary') === 'history') {
      const sessRes = await pool.query(
        `SELECT user_first_name, user_last_name, user_email,
                manager_first_name, manager_last_name, manager_email,
                sent_date, session_type, title, status,
                completed_date, elapsed_seconds, clicked_at, quiz_score
         FROM awareness_sessions WHERE upload_id = $1
         ORDER BY sent_date ASC, user_last_name, user_first_name`,
        [upload.id]
      );
      return res.json({ upload, sessions: sessRes.rows, users: [] });
    }

    // Summary format — existing behaviour
    const usersRes = await pool.query(
      `SELECT manager_first_name, manager_last_name, manager_email,
              user_first_name, user_last_name, user_email, incomplete_sessions
       FROM awareness_users WHERE upload_id = $1
       ORDER BY incomplete_sessions DESC, user_last_name, user_first_name`,
      [upload.id]
    );
    return res.json({ upload, users: usersRes.rows, sessions: [] });
  } catch (err) {
    return serverError(res, err);
  }
});

app.delete('/api/awareness', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveAwarenessTenant(req, 'query');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    await pool.query('DELETE FROM awareness_uploads WHERE tenant_id = $1', [tenantId]);
    return res.json({ ok: true });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── Arctic Wolf MDR Ticket routes ──────────────────────────────────────────

/**
 * Resolve which tenant's MDR data to act on.
 * Mirrors resolveVulnTenant and resolveAwarenessTenant.
 */
function resolveMdrTenant(req, source, opts = {}) {
  if (req.session.role === 'superadmin') {
    const raw = source === 'body' ? req.body.tenantId : req.query.tenantId;
    const tid = parseInt(raw, 10);
    if (isNaN(tid) || tid < 1) {
      // Operations is a global view — a superadmin who hasn't selected a tenant
      // yet should just see "no data" here rather than a hard error.
      if (opts.allowGlobal) return { tenantId: null };
      return { error: { status: 400, message: 'superadmin must provide a valid tenantId.' } };
    }
    return { tenantId: tid };
  }
  return { tenantId: req.session.tenantId };
}

app.get('/api/mdr', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveMdrTenant(req, 'query', { allowGlobal: true });
    if (error) return res.status(error.status).json({ error: error.message });
    if (tenantId === null) return res.json({ upload: null, tickets: [], stats: null });

    const uploadRes = await pool.query(
      `SELECT id, uploaded_at, total_tickets, resolved_count, pending_count, avg_resolution_hours
       FROM mdr_uploads WHERE tenant_id = $1
       ORDER BY uploaded_at DESC LIMIT 1`,
      [tenantId]
    );

    if (uploadRes.rows.length === 0) {
      return res.json({ upload: null, tickets: [], stats: null });
    }

    const upload = uploadRes.rows[0];

    const ticketsRes = await pool.query(
      `SELECT ticket_number AS "ticketNumber", subject, status, ticket_type AS "ticketType",
              severity, created_at AS "createdAt", resolved_at AS "resolvedAt",
              updated_at AS "updatedAt", assigned_to AS "assignedTo"
       FROM mdr_tickets WHERE upload_id = $1
       ORDER BY created_at DESC, ticket_number ASC`,
      [upload.id]
    );

    res.json({ upload, tickets: ticketsRes.rows });
  } catch (err) {
    return serverError(res, err);
  }
});

app.get('/api/mdr/trends', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveMdrTenant(req, 'query', { allowGlobal: true });
    if (error) return res.status(error.status).json({ error: error.message });
    if (tenantId === null) return res.json({});

    const statsRes = await pool.query(
      `SELECT
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND status = 'solved')::int AS solved,
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND status = 'closed')::int AS closed,
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND status = 'pending')::int AS pending,
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND severity = 'HIGH')::int AS high_severity,
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND severity = 'MEDIUM')::int AS medium_severity,
         (SELECT COUNT(*) FROM mdr_tickets WHERE upload_id = mu.id AND severity = 'LOW')::int AS low_severity
       FROM mdr_uploads mu
       WHERE mu.tenant_id = $1
       ORDER BY mu.uploaded_at DESC
       LIMIT 1`,
      [tenantId]
    );

    const stats = statsRes.rows.length > 0 ? statsRes.rows[0] : null;
    res.json(stats || {});
  } catch (err) {
    return serverError(res, err);
  }
});

app.delete('/api/mdr', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveMdrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });
    await pool.query('DELETE FROM mdr_uploads WHERE tenant_id = $1', [tenantId]);
    return res.json({ ok: true });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── Integrations routes ────────────────────────────────────────────────────

const INTEGRATION_ADAPTERS = {
  arctic_wolf: arcticWolfAdapter,
  iris_dfir:   irisDfirAdapter,
};

// Arctic Wolf Reports (security-awareness session history) isn't ticket-shaped,
// so it isn't in INTEGRATION_ADAPTERS — it's special-cased in the test/sync routes.
const REPORTS_PROVIDER = 'arctic_wolf_reports';
const KNOWN_PROVIDERS  = new Set([...Object.keys(INTEGRATION_ADAPTERS), REPORTS_PROVIDER]);

function resolveIntegrationTenant(req, source) {
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

// Arctic Wolf tickets come in on a single MSP-wide feed (synced under the Reflex
// tenant). Client tenants don't have their own AW org, so we route a copy of any
// matching ticket into their tenant based on a subject keyword — Reflex (the MSP)
// always keeps the full, unfiltered set.
const MDR_SUBJECT_TENANT_RULES = [
  { slug: 'ferrosa', pattern: /ferro/i },
  { slug: 'ncs',     pattern: /ncs/i },
];

async function writeMdrTickets(client, tenantId, tickets, uploadedBy) {
  const stats = calcMdrStats(tickets);
  await client.query('DELETE FROM mdr_uploads WHERE tenant_id = $1', [tenantId]);
  const uploadRes = await client.query(
    `INSERT INTO mdr_uploads (tenant_id, uploaded_at, uploaded_by, total_tickets, resolved_count, pending_count, avg_resolution_hours)
     VALUES ($1, NOW(), $2, $3, $4, $5, $6) RETURNING id`,
    [tenantId, uploadedBy, stats.total, stats.resolved_count, stats.pending_count, stats.avg_resolution_hours]
  );
  const uploadId = uploadRes.rows[0].id;

  for (const t of tickets) {
    await client.query(
      `INSERT INTO mdr_tickets (upload_id, ticket_number, subject, status, ticket_type, severity, created_at, resolved_at, updated_at, assigned_to)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [uploadId, t.ticketNumber, t.subject, t.status, t.ticketType, t.severity,
       t.createdAt || null, t.resolvedAt || null, t.updatedAt || null, t.assignedTo || null]
    );
  }

  return stats;
}

function calcMdrStats(tickets) {
  const resolved = tickets.filter(t => t.status === 'solved' || t.status === 'closed');
  const pending  = tickets.filter(t => t.status === 'pending' || t.status === 'open');
  let totalHours = 0, countedRes = 0;
  resolved.forEach(t => {
    if (t.createdAt && t.resolvedAt) {
      const hrs = (new Date(t.resolvedAt) - new Date(t.createdAt)) / 3600000;
      if (hrs >= 0) { totalHours += hrs; countedRes++; }
    }
  });
  return {
    total:               tickets.length,
    resolved_count:      resolved.length,
    pending_count:       pending.length,
    avg_resolution_hours: countedRes > 0 ? parseFloat((totalHours / countedRes).toFixed(2)) : null,
  };
}

/** GET /api/integrations — list configured integrations (no keys) */
app.get('/api/integrations', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIntegrationTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `SELECT provider, base_url, is_enabled, last_synced_at, last_sync_status, last_sync_message, config_json
       FROM integrations WHERE tenant_id = $1 ORDER BY provider`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

/** POST /api/integrations/:provider — save/update config */
app.post('/api/integrations/:provider', requireAdmin, async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!KNOWN_PROVIDERS.has(provider)) {
      return res.status(400).json({ error: `Unknown provider: ${provider}` });
    }
    const { tenantId, error } = resolveIntegrationTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { base_url, api_key, is_enabled, configJson } = req.body;
    if (!base_url) return res.status(400).json({ error: 'base_url is required.' });
    const configJsonVal = JSON.stringify(configJson || {});

    // If api_key provided, encrypt it; otherwise keep existing
    if (api_key) {
      const { enc, iv } = encryptKey(api_key);
      await pool.query(
        `INSERT INTO integrations (tenant_id, provider, base_url, api_key_enc, api_key_iv, is_enabled, config_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (tenant_id, provider) DO UPDATE
           SET base_url = $3, api_key_enc = $4, api_key_iv = $5, is_enabled = $6, config_json = $7`,
        [tenantId, provider, base_url, enc, iv, is_enabled !== false, configJsonVal]
      );
    } else {
      await pool.query(
        `UPDATE integrations SET base_url = $1, is_enabled = $2, config_json = $3
         WHERE tenant_id = $4 AND provider = $5`,
        [base_url, is_enabled !== false, configJsonVal, tenantId, provider]
      );
    }
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/integrations/:provider — remove integration */
app.delete('/api/integrations/:provider', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIntegrationTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    await pool.query(
      'DELETE FROM integrations WHERE tenant_id = $1 AND provider = $2',
      [tenantId, req.params.provider]
    );
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/integrations/:provider/test — fetch 1 record to verify credentials */
app.post('/api/integrations/:provider/test', requireAdmin, async (req, res) => {
  try {
    const provider = req.params.provider;
    const adapter  = provider === REPORTS_PROVIDER ? arcticWolfReportsAdapter : INTEGRATION_ADAPTERS[provider];
    if (!adapter) return res.status(400).json({ error: `Unknown provider: ${provider}` });

    const { tenantId, error } = resolveIntegrationTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const row = await pool.query(
      'SELECT base_url, api_key_enc, api_key_iv, config_json FROM integrations WHERE tenant_id = $1 AND provider = $2',
      [tenantId, provider]
    );
    if (!row.rows.length) return res.status(404).json({ error: 'Integration not configured.' });

    const { base_url, api_key_enc, api_key_iv, config_json } = row.rows[0];
    const api_key = decryptKey(api_key_enc, api_key_iv);

    if (provider === REPORTS_PROVIDER) {
      await arcticWolfReportsAdapter.testConnection({ base_url, api_key, ...(config_json || {}) });
    } else {
      await adapter.fetchTickets({ base_url, api_key, ...(config_json || {}) }, true);
    }
    res.json({ ok: true, message: 'Connection successful.' });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

/** Core sync logic for the Arctic Wolf Reports (session-history awareness) provider.
 *  Throws on failure; thrown errors carry `.httpStatus` (and `.stillGenerating` when
 *  applicable) so both the HTTP route and the background scheduler can react. */
async function runArcticWolfReportsSync(tenantId, userId) {
  const provider = REPORTS_PROVIDER;

  const intRow = await pool.query(
    'SELECT base_url, api_key_enc, api_key_iv, config_json FROM integrations WHERE tenant_id = $1 AND provider = $2 AND is_enabled = TRUE',
    [tenantId, provider]
  );
  if (!intRow.rows.length) {
    const err = new Error('Integration not configured or disabled.');
    err.httpStatus = 404;
    throw err;
  }

  const { base_url, api_key_enc, api_key_iv, config_json } = intRow.rows[0];
  const api_key = decryptKey(api_key_enc, api_key_iv);

  let csvText;
  try {
    csvText = await arcticWolfReportsAdapter.fetchSessionHistoryCsv({ base_url, api_key, ...(config_json || {}) });
  } catch (fetchErr) {
    if (fetchErr.stillGenerating) {
      await pool.query(
        `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'pending', last_sync_message = $1
         WHERE tenant_id = $2 AND provider = $3`,
        ['Report is still generating — click Sync Now again shortly.', tenantId, provider]
      );
      const err = new Error('Report is still generating — click Sync Now again shortly.');
      err.httpStatus = 202;
      err.stillGenerating = true;
      throw err;
    }
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [fetchErr.message, tenantId, provider]
    );
    fetchErr.httpStatus = 502;
    throw fetchErr;
  }

  let parsed;
  try {
    parsed = parseSessionHistoryCSV(csvText);
  } catch (parseErr) {
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [parseErr.message, tenantId, provider]
    );
    parseErr.httpStatus = 502;
    throw parseErr;
  }

  const { rows, stats } = parsed;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await writeAwarenessHistory(client, tenantId, userId, rows, stats);
    await client.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'ok', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [`Synced ${stats.totalRows} session row${stats.totalRows !== 1 ? 's' : ''}`, tenantId, provider]
    );
    await client.query('COMMIT');
    console.log(`[integrations] ${provider} sync: ${stats.totalRows} rows for tenant ${tenantId}`);
    return { ok: true, synced: stats.totalRows, totalUsers: stats.uniqueUsers };
  } catch (dbErr) {
    await client.query('ROLLBACK').catch(() => {});
    throw dbErr;
  } finally {
    client.release();
  }
}

/** Core sync logic for ticket-shaped providers (Arctic Wolf tickets, IrisDFIR).
 *  Throws on failure; thrown errors carry `.httpStatus` for the HTTP route. */
async function runTicketIntegrationSync(provider, tenantId, userId) {
  const adapter = INTEGRATION_ADAPTERS[provider];
  if (!adapter) {
    const err = new Error(`Unknown provider: ${provider}`);
    err.httpStatus = 400;
    throw err;
  }

  const intRow = await pool.query(
    'SELECT base_url, api_key_enc, api_key_iv, config_json FROM integrations WHERE tenant_id = $1 AND provider = $2 AND is_enabled = TRUE',
    [tenantId, provider]
  );
  if (!intRow.rows.length) {
    const err = new Error('Integration not configured or disabled.');
    err.httpStatus = 404;
    throw err;
  }

  const { base_url, api_key_enc, api_key_iv, config_json } = intRow.rows[0];
  const api_key = decryptKey(api_key_enc, api_key_iv);

  let tickets;
  try {
    tickets = await adapter.fetchTickets({ base_url, api_key, ...(config_json || {}) });
  } catch (fetchErr) {
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [fetchErr.message, tenantId, provider]
    );
    fetchErr.httpStatus = 502;
    throw fetchErr;
  }

  const stats = calcMdrStats(tickets);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // The syncing tenant always keeps the full, unfiltered ticket set.
    await writeMdrTickets(client, tenantId, tickets, userId);

    // Arctic Wolf is a single MSP-wide feed synced under Reflex — fan matching
    // tickets out to the relevant client tenant by subject keyword.
    if (provider === 'arctic_wolf') {
      const tenantRow = await client.query('SELECT slug FROM tenants WHERE id = $1', [tenantId]);
      if (tenantRow.rows[0] && tenantRow.rows[0].slug === 'reflex') {
        const slugs = MDR_SUBJECT_TENANT_RULES.map(r => r.slug);
        const subTenants = await client.query('SELECT id, slug FROM tenants WHERE slug = ANY($1)', [slugs]);
        for (const rule of MDR_SUBJECT_TENANT_RULES) {
          const subTenant = subTenants.rows.find(r => r.slug === rule.slug);
          if (!subTenant) continue;
          const matched = tickets.filter(t => rule.pattern.test(t.subject || ''));
          await writeMdrTickets(client, subTenant.id, matched, userId);
        }
      }
    }

    await client.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'ok', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [`Synced ${tickets.length} ticket${tickets.length !== 1 ? 's' : ''}`, tenantId, provider]
    );

    await client.query('COMMIT');
    console.log(`[integrations] ${provider} sync: ${tickets.length} tickets for tenant ${tenantId}`);
    return { ok: true, synced: tickets.length, stats };
  } catch (dbErr) {
    await client.query('ROLLBACK').catch(() => {});
    throw dbErr;
  } finally {
    client.release();
  }
}

/** POST /api/integrations/:provider/sync — fetch fresh data from the provider and store it */
app.post('/api/integrations/:provider/sync', requireAdmin, async (req, res) => {
  const provider = req.params.provider;
  const { tenantId, error } = resolveIntegrationTenant(req, 'body');
  if (error) return res.status(error.status).json({ error: error.message });

  try {
    const result = provider === REPORTS_PROVIDER
      ? await runArcticWolfReportsSync(tenantId, req.session.userId)
      : await runTicketIntegrationSync(provider, tenantId, req.session.userId);
    return res.json(result);
  } catch (err) {
    if (err.stillGenerating) {
      return res.status(202).json({ ok: false, stillGenerating: true, message: err.message });
    }
    if (err.httpStatus) {
      return res.status(err.httpStatus).json({ ok: false, error: err.message });
    }
    return serverError(res, err);
  }
});

// ── Scheduled integration sync (every 24h) ──────────────────────────────────

const SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000;

async function runScheduledSyncs() {
  let rows;
  try {
    rows = (await pool.query('SELECT tenant_id, provider FROM integrations WHERE is_enabled = TRUE')).rows;
  } catch (err) {
    console.error('[integrations] scheduled sync: failed to load integrations —', err.message);
    return;
  }

  for (const row of rows) {
    const tenantId = row.tenant_id;
    const provider  = row.provider;
    try {
      const result = provider === REPORTS_PROVIDER
        ? await runArcticWolfReportsSync(tenantId, null)
        : await runTicketIntegrationSync(provider, tenantId, null);
      console.log(`[integrations] scheduled sync ok: ${provider} tenant ${tenantId} (${result.synced})`);
    } catch (err) {
      if (err.stillGenerating) {
        console.log(`[integrations] scheduled sync: ${provider} tenant ${tenantId} report still generating`);
      } else {
        console.error(`[integrations] scheduled sync failed: ${provider} tenant ${tenantId} — ${err.message}`);
      }
    }
  }
}

// Run once shortly after startup (so newly-enabled integrations don't wait a full
// day for their first sync), then every 24 hours thereafter.
setTimeout(() => { runScheduledSyncs().catch(err => console.error('[integrations] scheduled sync crashed —', err.message)); }, 60 * 1000);
setInterval(() => { runScheduledSyncs().catch(err => console.error('[integrations] scheduled sync crashed —', err.message)); }, SYNC_INTERVAL_MS);

// ── GRC & Insurability routes ──────────────────────────────────────────────

function resolveGrcTenant(req, source) {
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

function calculateGrcScore(answers, questions) {
  const weightPoints = { critical: 5, high: 3, medium: 2, low: 1 };
  let totalPossible = 0, totalEarned = 0;
  const answerMap = {};
  answers.forEach(a => { answerMap[String(a.questionId)] = a.answer; });
  questions.forEach(q => {
    const pts = weightPoints[q.weight] || 2;
    const ans = answerMap[String(q.id)];
    if (!ans || ans === 'na') return;
    totalPossible += pts;
    if (ans === 'yes')     totalEarned += pts;
    if (ans === 'partial') totalEarned += pts * 0.5;
  });
  return totalPossible > 0 ? Math.round((totalEarned / totalPossible) * 100) : 0;
}

/**
 * calculateFrameworkScores — same weighted scoring as calculateGrcScore, but
 * grouped by framework (NIST_CSF, CIS_V8) via grc_question_frameworks rows
 * instead of by section. A question with no framework mapping is excluded
 * from every framework's score.
 */
function calculateFrameworkScores(answers, questions, frameworkRows) {
  const weightPoints = { critical: 5, high: 3, medium: 2, low: 1 };
  const answerMap = {};
  answers.forEach(a => { answerMap[String(a.questionId)] = a.answer; });
  const qMap = {};
  questions.forEach(q => { qMap[q.id] = q; });

  const frameworks = {};
  frameworkRows.forEach(r => {
    if (!frameworks[r.framework]) frameworks[r.framework] = { possible: 0, earned: 0, seen: new Set() };
    const bucket = frameworks[r.framework];
    if (bucket.seen.has(r.question_id)) return; // count each question once per framework
    bucket.seen.add(r.question_id);

    const q = qMap[r.question_id];
    if (!q) return;
    const ans = answerMap[String(q.id)];
    if (!ans || ans === 'na') return;
    const pts = weightPoints[q.weight] || 2;
    bucket.possible += pts;
    if (ans === 'yes')     bucket.earned += pts;
    if (ans === 'partial') bucket.earned += pts * 0.5;
  });

  const scores = {};
  Object.keys(frameworks).forEach(fw => {
    const { possible, earned } = frameworks[fw];
    scores[fw] = possible > 0 ? Math.round((earned / possible) * 100) : null;
  });
  return scores;
}

/**
 * autoPopulateRisksFromGrc — for every 'no' answer on a spreadsheet-sourced
 * question (has risk_title), auto-create a Risk Register entry if one doesn't
 * already exist for that (tenant, question) pair. Pure insert-if-missing —
 * never updates/closes/deletes a risk if the answer later changes.
 */
async function autoPopulateRisksFromGrc(tenantId, answers, questions, userId) {
  const qMap = {};
  questions.forEach(q => { qMap[q.id] = q; });

  const noAnswers = answers.filter(a => a.answer === 'no' && qMap[a.questionId]);
  for (const a of noAnswers) {
    const q = qMap[a.questionId];
    if (!q.risk_title) continue;

    const existing = await pool.query(
      'SELECT id FROM risks WHERE tenant_id = $1 AND grc_question_id = $2 LIMIT 1',
      [tenantId, q.id]
    );
    if (existing.rows.length > 0) continue;

    const likelihood = q.default_likelihood || 3;
    const impact = q.default_impact || 3;
    await pool.query(
      `INSERT INTO risks
         (tenant_id, title, description, category, likelihood, impact, risk_score,
          owner, mitigation_plan, stage, start_date, created_by, grc_question_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'identified',CURRENT_DATE,$10,$11)`,
      [
        tenantId, q.risk_title,
        `Auto-created from GRC self-assessment gap (${q.external_risk_id || 'Q' + q.id}): ${q.text}`,
        q.default_category || 'operational',
        likelihood, impact, likelihood * impact,
        q.default_owner || '', q.default_mitigation || '',
        userId, q.id
      ]
    );
  }
}

/** GET /api/grc/questions — returns all questions grouped by section */
app.get('/api/grc/questions', requireAuth, async (req, res) => {
  try {
    const [qResult, fwResult] = await Promise.all([
      pool.query('SELECT * FROM grc_questions ORDER BY section, order_num'),
      pool.query('SELECT question_id, framework, control_id, control_title FROM grc_question_frameworks'),
    ]);

    const frameworksByQuestion = {};
    fwResult.rows.forEach(r => {
      if (!frameworksByQuestion[r.question_id]) frameworksByQuestion[r.question_id] = [];
      frameworksByQuestion[r.question_id].push({
        framework: r.framework, controlId: r.control_id, controlTitle: r.control_title,
      });
    });

    const grouped = {};
    qResult.rows.forEach(q => {
      q.frameworks = frameworksByQuestion[q.id] || [];
      if (!grouped[q.section]) grouped[q.section] = [];
      grouped[q.section].push(q);
    });
    res.json({ sections: grouped });
  } catch (err) {
    return serverError(res, err);
  }
});

/** GET /api/grc/assessment — returns current tenant's assessment + answers */
app.get('/api/grc/assessment', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveGrcTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const asmtRes = await pool.query(
      'SELECT id, grc_score, assessed_at FROM grc_assessments WHERE tenant_id = $1',
      [tenantId]
    );
    if (asmtRes.rows.length === 0) return res.json({ assessment: null, answers: [] });

    const answersRes = await pool.query(
      'SELECT question_id, answer, notes FROM grc_answers WHERE assessment_id = $1',
      [asmtRes.rows[0].id]
    );

    const [qResult, fwResult] = await Promise.all([
      pool.query('SELECT id, weight FROM grc_questions'),
      pool.query('SELECT question_id, framework, control_id, control_title FROM grc_question_frameworks'),
    ]);
    const answers = answersRes.rows.map(a => ({ questionId: a.question_id, answer: a.answer }));
    const frameworkScores = calculateFrameworkScores(answers, qResult.rows, fwResult.rows);

    res.json({ assessment: asmtRes.rows[0], answers: answersRes.rows, frameworkScores });
  } catch (err) {
    return serverError(res, err);
  }
});

/** POST /api/grc/assessment — upsert assessment + all answers, recalculate score */
app.post('/api/grc/assessment', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveGrcTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { answers } = req.body;
    if (!Array.isArray(answers)) return res.status(400).json({ error: 'answers must be an array.' });

    // Fetch all questions to calculate score (full row needed for auto-population below)
    const [qResult, fwResult] = await Promise.all([
      pool.query('SELECT * FROM grc_questions'),
      pool.query('SELECT question_id, framework, control_id, control_title FROM grc_question_frameworks'),
    ]);
    const score = calculateGrcScore(answers, qResult.rows);
    const frameworkScores = calculateFrameworkScores(answers, qResult.rows, fwResult.rows);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const asmtRes = await client.query(
        `INSERT INTO grc_assessments (tenant_id, assessed_at, assessed_by, grc_score)
         VALUES ($1, NOW(), $2, $3)
         ON CONFLICT (tenant_id) DO UPDATE
           SET assessed_at = NOW(), assessed_by = $2, grc_score = $3
         RETURNING id`,
        [tenantId, req.session.userId, score]
      );
      const asmtId = asmtRes.rows[0].id;
      await client.query('DELETE FROM grc_answers WHERE assessment_id = $1', [asmtId]);
      for (const a of answers) {
        if (!a.questionId || !a.answer) continue;
        await client.query(
          'INSERT INTO grc_answers (assessment_id, question_id, answer, notes) VALUES ($1,$2,$3,$4)',
          [asmtId, a.questionId, a.answer, a.notes || null]
        );
      }
      await client.query('COMMIT');
      console.log(`[grc] Assessment saved for tenant ${tenantId}, score=${score}`);

      try {
        await autoPopulateRisksFromGrc(tenantId, answers, qResult.rows, req.session.userId);
      } catch (popErr) {
        console.error('[grc] auto-populate risks failed:', popErr);
      }

      res.json({ ok: true, score, frameworkScores, assessedAt: new Date().toISOString() });
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      return serverError(res, err);
    } finally {
      client.release();
    }
  } catch (err) {
    return serverError(res, err);
  }
});

// ── Red Team Operations routes (global — not tenant-scoped) ───────────────

/** GET /api/redteam/stats */
app.get('/api/redteam/stats', requireAuth, async (req, res) => {
  try {
    const today   = new Date().toISOString().slice(0, 10);
    const weekEnd = new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10);

    const [activeRes, upcomingRes, tasksDueRes, rateRes] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM redteam_projects WHERE status='active'`),
      pool.query(`SELECT COUNT(*) FROM redteam_projects WHERE status='planned' AND start_date>$1`, [today]),
      pool.query(`SELECT COUNT(*) FROM redteam_tasks WHERE status!='done' AND due_date BETWEEN $1 AND $2`, [today, weekEnd]),
      pool.query(`SELECT COUNT(*) FILTER (WHERE status='done') AS done, COUNT(*) AS total FROM redteam_tasks`),
    ]);

    const done  = parseInt(rateRes.rows[0].done,  10) || 0;
    const total = parseInt(rateRes.rows[0].total, 10) || 0;
    res.json({
      activeEngagements: parseInt(activeRes.rows[0].count,   10) || 0,
      upcomingPentests:  parseInt(upcomingRes.rows[0].count, 10) || 0,
      tasksDueThisWeek:  parseInt(tasksDueRes.rows[0].count, 10) || 0,
      completionRate:    total > 0 ? Math.round((done / total) * 100) : 0,
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/redteam/projects */
app.get('/api/redteam/projects', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, tn.name AS tenant_name,
              COUNT(t.id)                                 AS task_count,
              COUNT(t.id) FILTER (WHERE t.status='done') AS tasks_done
       FROM redteam_projects p
       LEFT JOIN redteam_tasks t ON t.project_id = p.id
       LEFT JOIN tenants tn ON tn.id = p.tenant_id
       GROUP BY p.id, tn.name
       ORDER BY p.start_date DESC`
    );
    res.json({ projects: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/redteam/projects */
app.post('/api/redteam/projects', requireAdmin, async (req, res) => {
  try {
    const { title, client, scope, status, start_date, end_date, tenant_id } = req.body;
    if (!title || !client || !start_date || !end_date)
      return res.status(400).json({ error: 'title, client, start_date and end_date are required.' });

    const result = await pool.query(
      `INSERT INTO redteam_projects (title, client, scope, status, start_date, end_date, tenant_id, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [title, client, scope || '', status || 'planned', start_date, end_date, tenant_id || null, req.session.userId]
    );
    res.json({ project: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/redteam/projects/:id */
app.put('/api/redteam/projects/:id', requireAdmin, async (req, res) => {
  try {
    const { title, client, scope, status, start_date, end_date, tenant_id } = req.body;
    const result = await pool.query(
      `UPDATE redteam_projects
       SET title=$1, client=$2, scope=$3, status=$4, start_date=$5, end_date=$6, tenant_id=$7, updated_at=NOW()
       WHERE id=$8 RETURNING *`,
      [title, client, scope || '', status, start_date, end_date, tenant_id || null, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    res.json({ project: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/redteam/projects/:id */
app.delete('/api/redteam/projects/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM redteam_projects WHERE id=$1 RETURNING id',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Project not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/redteam/projects/:id/tasks */
app.get('/api/redteam/projects/:id/tasks', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM redteam_tasks WHERE project_id=$1 ORDER BY due_date ASC NULLS LAST, id ASC',
      [req.params.id]
    );
    res.json({ tasks: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/redteam/tasks */
app.post('/api/redteam/tasks', requireAdmin, async (req, res) => {
  try {
    const { project_id, title, assignee, due_date, status, notes } = req.body;
    if (!project_id || !title)
      return res.status(400).json({ error: 'project_id and title are required.' });

    const result = await pool.query(
      `INSERT INTO redteam_tasks (project_id, title, assignee, due_date, status, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [project_id, title, assignee || '', due_date || null, status || 'todo', notes || '', req.session.userId]
    );
    res.json({ task: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/redteam/tasks/:id */
app.put('/api/redteam/tasks/:id', requireAdmin, async (req, res) => {
  try {
    const { title, assignee, due_date, status, notes } = req.body;
    const result = await pool.query(
      `UPDATE redteam_tasks
       SET title=$1, assignee=$2, due_date=$3, status=$4, notes=$5, updated_at=NOW()
       WHERE id=$6 RETURNING *`,
      [title, assignee || '', due_date || null, status, notes || '', req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found.' });
    res.json({ task: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/redteam/tasks/:id */
app.delete('/api/redteam/tasks/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM redteam_tasks WHERE id=$1 RETURNING id',
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Task not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/**
 * Checks the caller may act on a project's tenant-linked data: superadmin can act on
 * any project; other roles only on projects linked to their own tenant.
 * Returns { project } or { error }.
 */
async function resolveProjectForTenantAccess(req) {
  const projResult = await pool.query('SELECT * FROM redteam_projects WHERE id=$1', [req.params.id]);
  if (projResult.rows.length === 0) return { error: { status: 404, message: 'Project not found.' } };
  const project = projResult.rows[0];

  if (req.session.role !== 'superadmin' && project.tenant_id !== req.session.tenantId) {
    return { error: { status: 403, message: 'You do not have access to this engagement.' } };
  }
  return { project };
}

/** GET /api/redteam/projects/:id/findings */
app.get('/api/redteam/projects/:id/findings', requireAuth, async (req, res) => {
  try {
    const { project, error } = await resolveProjectForTenantAccess(req);
    if (error) return res.status(error.status).json({ error: error.message });
    if (!project.tenant_id) return res.json({ findings: [] });

    const result = await pool.query(
      'SELECT * FROM pentest_findings WHERE project_id=$1 ORDER BY created_at DESC',
      [req.params.id]
    );
    res.json({ findings: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/redteam/projects/:id/findings — tenant is derived from the project's linked tenant */
app.post('/api/redteam/projects/:id/findings', requireAdmin, async (req, res) => {
  try {
    const { project, error } = await resolveProjectForTenantAccess(req);
    if (error) return res.status(error.status).json({ error: error.message });
    if (!project.tenant_id) {
      return res.status(400).json({ error: 'Link this engagement to a tenant before adding findings.' });
    }

    const { title, severity, description, recommendation, owner, due_date, status, notes } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (severity !== undefined && !PENTEST_SEVERITIES.includes(severity)) return res.status(400).json({ error: 'invalid severity.' });
    if (status !== undefined && !PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const result = await pool.query(
      `INSERT INTO pentest_findings (tenant_id, project_id, title, severity, description, recommendation, owner, due_date, status, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [project.tenant_id, project.id, title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', req.session.userId]
    );
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

// ── Incident Response routes (tenant-scoped) ───────────────────────────────

function resolveIrTenant(req, source) {
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

/** GET /api/ir/stats */
app.get('/api/ir/stats', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const monthStart = new Date();
    monthStart.setDate(1);
    const monthStartStr = monthStart.toISOString().slice(0, 10);

    const [openRes, progressRes, resolvedRes, avgRes] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM ir_incidents WHERE tenant_id=$1 AND status='open'`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM ir_incidents WHERE tenant_id=$1 AND status IN ('contained','remediating')`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM ir_incidents WHERE tenant_id=$1 AND status IN ('resolved','closed') AND closed_at >= $2`, [tenantId, monthStartStr]),
      pool.query(`SELECT AVG(EXTRACT(EPOCH FROM (closed_at - opened_at)) / 3600) AS avg_hours
                  FROM ir_incidents WHERE tenant_id=$1 AND closed_at IS NOT NULL`, [tenantId]),
    ]);

    res.json({
      open:           parseInt(openRes.rows[0].count, 10) || 0,
      inProgress:     parseInt(progressRes.rows[0].count, 10) || 0,
      resolvedThisMonth: parseInt(resolvedRes.rows[0].count, 10) || 0,
      avgCloseHours:  avgRes.rows[0].avg_hours !== null ? Math.round(avgRes.rows[0].avg_hours) : null,
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/ir/incidents */
app.get('/api/ir/incidents', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `SELECT i.*, COUNT(a.id) AS activity_count
       FROM ir_incidents i
       LEFT JOIN ir_activities a ON a.incident_id = i.id
       WHERE i.tenant_id = $1
       GROUP BY i.id
       ORDER BY i.opened_at DESC`,
      [tenantId]
    );
    res.json({ incidents: result.rows });
  } catch (err) { return serverError(res, err); }
});

const IR_VALID_PHASES = ['identification', 'containment', 'eradication', 'recovery', 'post-incident-analysis'];
const IR_VALID_TYPES = ['phishing', 'malware_ransomware', 'data_breach', 'insider_threat', 'ddos', 'unauthorized_access', 'other'];
const IR_VALID_STATUSES = ['open', 'contained', 'remediating', 'resolved', 'closed'];

/** POST /api/ir/incidents */
app.post('/api/ir/incidents', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, description, severity, status, assigned_to, phase, incident_type } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    const incidentType = IR_VALID_TYPES.includes(incident_type) ? incident_type : 'other';

    const result = await pool.query(
      `INSERT INTO ir_incidents (tenant_id, title, description, severity, status, assigned_to, phase, incident_type, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [tenantId, title, description || '', severity || 'medium', status || 'open', assigned_to || '', phase || 'identification', incidentType, req.session.userId]
    );
    const incident = result.rows[0];

    // Seed the activity/task board from the incident type's playbook
    const playbook = IR_PLAYBOOKS[incidentType] || IR_PLAYBOOKS.other;
    let sortOrder = 0;
    for (const p of IR_VALID_PHASES) {
      const tasks = playbook[p] || [];
      for (const task of tasks) {
        await pool.query(
          `INSERT INTO ir_activities (incident_id, entry, status, phase, sort_order, logged_by)
           VALUES ($1,$2,'pending',$3,$4,$5)`,
          [incident.id, task, p, sortOrder++, req.session.userId]
        );
      }
    }

    res.json({ incident });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/ir/incidents/:id */
app.put('/api/ir/incidents/:id', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, description, severity, status, assigned_to, phase, incident_type } = req.body;
    const incidentType = IR_VALID_TYPES.includes(incident_type) ? incident_type : 'other';
    const result = await pool.query(
      `UPDATE ir_incidents
       SET title=$1, description=$2, severity=$3, status=$4::varchar, assigned_to=$5, phase=$6, incident_type=$7, updated_at=NOW(),
           closed_at = CASE WHEN $4::varchar IN ('resolved','closed') AND closed_at IS NULL THEN NOW()
                            WHEN $4::varchar NOT IN ('resolved','closed') THEN NULL
                            ELSE closed_at END
       WHERE id=$8 AND tenant_id=$9 RETURNING *`,
      [title, description || '', severity, status, assigned_to || '', phase || 'identification', incidentType, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });
    res.json({ incident: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/ir/incidents/:id/phase — quick-set the IR lifecycle phase */
app.patch('/api/ir/incidents/:id/phase', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { phase } = req.body;
    if (!IR_VALID_PHASES.includes(phase)) return res.status(400).json({ error: 'invalid phase.' });

    const result = await pool.query(
      `UPDATE ir_incidents SET phase=$1, updated_at=NOW() WHERE id=$2 AND tenant_id=$3 RETURNING *`,
      [phase, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });
    res.json({ incident: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/ir/incidents/:id/status — quick-set the incident status (used by the Remediation Tracker) */
app.patch('/api/ir/incidents/:id/status', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { status } = req.body;
    if (!IR_VALID_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const result = await pool.query(
      `UPDATE ir_incidents SET status=$1::varchar, updated_at=NOW(),
           closed_at = CASE WHEN $1::varchar IN ('resolved','closed') AND closed_at IS NULL THEN NOW()
                            WHEN $1::varchar NOT IN ('resolved','closed') THEN NULL
                            ELSE closed_at END
       WHERE id=$2 AND tenant_id=$3 RETURNING *`,
      [status, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });
    res.json({ incident: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/ir/incidents/:id */
app.delete('/api/ir/incidents/:id', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      'DELETE FROM ir_incidents WHERE id=$1 AND tenant_id=$2 RETURNING id',
      [req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/ir/incidents/:id/activities */
app.get('/api/ir/incidents/:id/activities', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const incRes = await pool.query('SELECT id FROM ir_incidents WHERE id=$1 AND tenant_id=$2', [req.params.id, tenantId]);
    if (incRes.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });

    const result = await pool.query(
      `SELECT * FROM ir_activities WHERE incident_id=$1
       ORDER BY phase, sort_order ASC, logged_at ASC`,
      [req.params.id]
    );
    res.json({ activities: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/ir/activities */
app.post('/api/ir/activities', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { incidentId, entry, assignee, status } = req.body;
    if (!incidentId || !entry) return res.status(400).json({ error: 'incidentId and entry are required.' });

    const incRes = await pool.query('SELECT id FROM ir_incidents WHERE id=$1 AND tenant_id=$2', [incidentId, tenantId]);
    if (incRes.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });

    const result = await pool.query(
      `INSERT INTO ir_activities (incident_id, entry, assignee, status, logged_by)
       VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [incidentId, entry, assignee || '', status || 'pending', req.session.userId]
    );
    res.json({ activity: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/ir/activities/:id */
app.put('/api/ir/activities/:id', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { entry, assignee, status } = req.body;
    const result = await pool.query(
      `UPDATE ir_activities a SET entry=$1, assignee=$2, status=$3::varchar,
           completed_at = CASE WHEN $3::varchar = 'done' AND completed_at IS NULL THEN NOW()
                                WHEN $3::varchar != 'done' THEN NULL
                                ELSE completed_at END
       FROM ir_incidents i
       WHERE a.id=$4 AND a.incident_id=i.id AND i.tenant_id=$5
       RETURNING a.*`,
      [entry, assignee || '', status, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Activity not found.' });
    res.json({ activity: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/ir/activities/:id/phase — progress a playbook task tile to a new phase */
app.patch('/api/ir/activities/:id/phase', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { phase, sort_order } = req.body;
    if (!IR_VALID_PHASES.includes(phase)) return res.status(400).json({ error: 'invalid phase.' });

    const result = await pool.query(
      `UPDATE ir_activities a SET phase=$1, sort_order=$2
       FROM ir_incidents i
       WHERE a.id=$3 AND a.incident_id=i.id AND i.tenant_id=$4
       RETURNING a.*`,
      [phase, Number.isInteger(sort_order) ? sort_order : 0, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Activity not found.' });
    res.json({ activity: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/ir/activities/:id */
app.delete('/api/ir/activities/:id', requireAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `DELETE FROM ir_activities a
       USING ir_incidents i
       WHERE a.id=$1 AND a.incident_id=i.id AND i.tenant_id=$2
       RETURNING a.id`,
      [req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Activity not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

// ── Risk Register routes (tenant-scoped) ───────────────────────────────────

function resolveRiskTenant(req, source) {
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

const RISK_CATEGORIES = ['operational', 'financial', 'compliance', 'technical', 'reputational'];
const RISK_STAGES = ['identified', 'assessing', 'mitigating', 'monitoring', 'closed'];

/** GET /api/risks/stats */
app.get('/api/risks/stats', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const monthStart = new Date();
    monthStart.setDate(1);
    const monthStartStr = monthStart.toISOString().slice(0, 10);

    const [openRes, highRiskRes, closedRes, avgRes, overdueRes] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM risks WHERE tenant_id=$1 AND stage != 'closed'`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM risks WHERE tenant_id=$1 AND stage != 'closed' AND risk_score >= 15`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM risks WHERE tenant_id=$1 AND stage = 'closed' AND closed_at >= $2`, [tenantId, monthStartStr]),
      pool.query(`SELECT AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 86400) AS avg_days
                  FROM risks WHERE tenant_id=$1 AND closed_at IS NOT NULL`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM risks WHERE tenant_id=$1 AND stage != 'closed' AND due_date IS NOT NULL AND due_date < CURRENT_DATE`, [tenantId]),
    ]);

    res.json({
      open:              parseInt(openRes.rows[0].count, 10) || 0,
      highRisk:          parseInt(highRiskRes.rows[0].count, 10) || 0,
      closedThisMonth:   parseInt(closedRes.rows[0].count, 10) || 0,
      avgResolutionDays: avgRes.rows[0].avg_days !== null ? Math.round(avgRes.rows[0].avg_days * 10) / 10 : null,
      overdue:           parseInt(overdueRes.rows[0].count, 10) || 0,
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/risks */
app.get('/api/risks', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `SELECT * FROM risks WHERE tenant_id = $1 ORDER BY created_at DESC`,
      [tenantId]
    );
    res.json({ risks: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/risks */
app.post('/api/risks', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, description, category, likelihood, impact, owner, mitigation_plan, stage, start_date, due_date } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (!start_date) return res.status(400).json({ error: 'start_date is required.' });

    const lk = parseInt(likelihood, 10);
    const im = parseInt(impact, 10);
    if (isNaN(lk) || lk < 1 || lk > 5) return res.status(400).json({ error: 'likelihood must be between 1 and 5.' });
    if (isNaN(im) || im < 1 || im > 5) return res.status(400).json({ error: 'impact must be between 1 and 5.' });
    if (category !== undefined && !RISK_CATEGORIES.includes(category)) return res.status(400).json({ error: 'invalid category.' });
    if (stage !== undefined && !RISK_STAGES.includes(stage)) return res.status(400).json({ error: 'invalid stage.' });

    const result = await pool.query(
      `INSERT INTO risks (tenant_id, title, description, category, likelihood, impact, risk_score, owner, mitigation_plan, stage, start_date, due_date, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [tenantId, title, description || '', category || 'operational', lk, im, lk * im, owner || '', mitigation_plan || '', stage || 'identified', start_date, due_date || null, req.session.userId]
    );
    res.json({ risk: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/risks/:id */
app.put('/api/risks/:id', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, description, category, likelihood, impact, owner, mitigation_plan, stage, start_date, due_date } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (!start_date) return res.status(400).json({ error: 'start_date is required.' });

    const lk = parseInt(likelihood, 10);
    const im = parseInt(impact, 10);
    if (isNaN(lk) || lk < 1 || lk > 5) return res.status(400).json({ error: 'likelihood must be between 1 and 5.' });
    if (isNaN(im) || im < 1 || im > 5) return res.status(400).json({ error: 'impact must be between 1 and 5.' });
    if (category !== undefined && !RISK_CATEGORIES.includes(category)) return res.status(400).json({ error: 'invalid category.' });
    if (stage !== undefined && !RISK_STAGES.includes(stage)) return res.status(400).json({ error: 'invalid stage.' });

    const result = await pool.query(
      `UPDATE risks
       SET title=$1, description=$2, category=$3, likelihood=$4, impact=$5, risk_score=$6, owner=$7,
           mitigation_plan=$8, stage=$9, start_date=$10, due_date=$11, updated_at=NOW(),
           closed_at = CASE WHEN $9::varchar = 'closed' AND closed_at IS NULL THEN NOW()
                            WHEN $9::varchar != 'closed' THEN NULL
                            ELSE closed_at END
       WHERE id=$12 AND tenant_id=$13 RETURNING *`,
      [title, description || '', category || 'operational', lk, im, lk * im, owner || '', mitigation_plan || '', stage || 'identified', start_date, due_date || null, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Risk not found.' });
    res.json({ risk: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/risks/:id/stage — used by kanban drag-and-drop */
app.patch('/api/risks/:id/stage', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { stage } = req.body;
    if (!RISK_STAGES.includes(stage)) return res.status(400).json({ error: 'invalid stage.' });

    const result = await pool.query(
      `UPDATE risks
       SET stage=$1, updated_at=NOW(),
           closed_at = CASE WHEN $1::varchar = 'closed' AND closed_at IS NULL THEN NOW()
                            WHEN $1::varchar != 'closed' THEN NULL
                            ELSE closed_at END
       WHERE id=$2 AND tenant_id=$3 RETURNING *`,
      [stage, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Risk not found.' });
    res.json({ risk: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/risks/:id */
app.delete('/api/risks/:id', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolveRiskTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      'DELETE FROM risks WHERE id=$1 AND tenant_id=$2 RETURNING id',
      [req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Risk not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

// ── Pentest Findings routes ───────────────────────────────────────────────

function resolvePentestTenant(req, source) {
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

const PENTEST_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const PENTEST_STATUSES = ['open', 'in-progress', 'fixed', 'accepted', 'risk-accepted'];

/** GET /api/pentest-findings */
app.get('/api/pentest-findings', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const params = [tenantId];
    let where = 'tenant_id = $1';
    if (req.query.projectId) {
      params.push(parseInt(req.query.projectId, 10));
      where += ` AND project_id = $${params.length}`;
    }

    const result = await pool.query(
      `SELECT * FROM pentest_findings WHERE ${where} ORDER BY created_at DESC`,
      params
    );
    res.json({ findings: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/pentest-findings */
app.post('/api/pentest-findings', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, severity, description, recommendation, owner, due_date, status, notes, project_id } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (severity !== undefined && !PENTEST_SEVERITIES.includes(severity)) return res.status(400).json({ error: 'invalid severity.' });
    if (status !== undefined && !PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const result = await pool.query(
      `INSERT INTO pentest_findings (tenant_id, project_id, title, severity, description, recommendation, owner, due_date, status, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [tenantId, project_id || null, title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', req.session.userId]
    );
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/pentest-findings/:id */
app.put('/api/pentest-findings/:id', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, severity, description, recommendation, owner, due_date, status, notes, project_id } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (severity !== undefined && !PENTEST_SEVERITIES.includes(severity)) return res.status(400).json({ error: 'invalid severity.' });
    if (status !== undefined && !PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const result = await pool.query(
      `UPDATE pentest_findings
       SET title=$1, severity=$2, description=$3, recommendation=$4, owner=$5, due_date=$6, status=$7, notes=$8,
           project_id=$9, updated_at=NOW(),
           status_updated_at = CASE WHEN $7::varchar IS DISTINCT FROM status THEN NOW() ELSE status_updated_at END
       WHERE id=$10 AND tenant_id=$11 RETURNING *`,
      [title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', project_id || null, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/pentest-findings/:id/status */
app.patch('/api/pentest-findings/:id/status', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { status, notes } = req.body;
    if (!PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const result = await pool.query(
      `UPDATE pentest_findings
       SET status=$1, notes=COALESCE($2, notes), status_updated_at=NOW(), updated_at=NOW()
       WHERE id=$3 AND tenant_id=$4 RETURNING *`,
      [status, notes !== undefined ? String(notes).slice(0, 500) : null, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/pentest-findings/:id */
app.delete('/api/pentest-findings/:id', requireRiskWrite, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      'DELETE FROM pentest_findings WHERE id=$1 AND tenant_id=$2 RETURNING id',
      [req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

// ── Remediation Tracker (aggregation) ─────────────────────────────────────

/** GET /api/remediation-tracker — combined vulns + risks + pentest findings for the current tenant */
app.get('/api/remediation-tracker', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const [scanRes, risksRes, pentestRes, incidentsRes] = await Promise.all([
      pool.query('SELECT id, month_key AS "monthKey" FROM vuln_scans WHERE tenant_id=$1 ORDER BY month_key DESC LIMIT 1', [tenantId]),
      pool.query('SELECT * FROM risks WHERE tenant_id=$1 ORDER BY created_at DESC', [tenantId]),
      pool.query('SELECT * FROM pentest_findings WHERE tenant_id=$1 ORDER BY created_at DESC', [tenantId]),
      pool.query('SELECT * FROM ir_incidents WHERE tenant_id=$1 ORDER BY opened_at DESC', [tenantId]),
    ]);

    let vulns = [];
    let vulnMonthKey = null;
    if (scanRes.rows.length > 0) {
      vulnMonthKey = scanRes.rows[0].monthKey;
      const findingsRes = await pool.query(
        `SELECT finding_index AS idx, name, risk, host, cve, status, notes,
                status_updated_at AS "statusUpdatedAt", first_seen_at AS "firstSeenAt"
         FROM vuln_findings WHERE scan_id=$1 ORDER BY finding_index ASC`,
        [scanRes.rows[0].id]
      );
      vulns = findingsRes.rows;
    }

    res.json({
      vulnMonthKey,
      vulns,
      risks: risksRes.rows,
      pentestFindings: pentestRes.rows,
      incidents: incidentsRes.rows,
    });
  } catch (err) { return serverError(res, err); }
});

// ── Secure Score routes ────────────────────────────────────────────────────

/**
 * GET /api/secure-score
 * Get the latest Secure Score for the current tenant.
 * Calculates on-the-fly from latest vuln/awareness/mdr data.
 */
app.get('/api/secure-score', requireAuth, async (req, res) => {
  try {
    const tenantId = req.session.tenantId;
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant context.' });
    }

    // Fetch latest vulnerability scan
    let vulnData = null;
    try {
      const vulnResult = await pool.query(
        `SELECT summary FROM vuln_scans WHERE tenant_id = $1 ORDER BY month_key DESC LIMIT 1`,
        [tenantId]
      );
      if (vulnResult.rows.length > 0) vulnData = { summary: vulnResult.rows[0].summary };
    } catch (_) { /* table may not exist yet */ }

    // Fetch latest awareness upload — normalise to session-level completion rate
    let awarenessData = null;
    try {
      const awarenessResult = await pool.query(
        `SELECT id, uploaded_at, total_users, total_incomplete, upload_type
         FROM awareness_uploads WHERE tenant_id = $1 ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      );
      if (awarenessResult.rows.length > 0) {
        const row = awarenessResult.rows[0];
        if (row.upload_type === 'history') {
          // For history uploads total_incomplete counts not-started sessions, not users.
          // Query sessions directly for an accurate completion rate.
          let totalN = 0, completedN = 0;
          try {
            const sessResult = await pool.query(
              `SELECT
                 COUNT(*) FILTER (WHERE LOWER(status) LIKE '%complet%') AS completed,
                 COUNT(*) AS total
               FROM awareness_sessions
               WHERE upload_id = $1
                 AND (session_type IS NULL OR LOWER(session_type) NOT LIKE '%phishing simulation%')`,
              [row.id]
            );
            totalN    = parseInt(sessResult.rows[0].total,     10) || 0;
            completedN = parseInt(sessResult.rows[0].completed, 10) || 0;
          } catch (_) {
            // awareness_sessions table not yet migrated — fall back to upload totals
            totalN     = parseInt(row.total_users,      10) || 0;
            completedN = Math.max(0, totalN - (parseInt(row.total_incomplete, 10) || 0));
          }
          awarenessData = {
            upload: {
              ...row,
              total_users:      totalN,
              total_incomplete: totalN - completedN,
            },
          };
        } else {
          awarenessData = { upload: row };
        }
      }
    } catch (_) { /* table may not exist yet */ }

    // Fetch latest MDR upload for this tenant
    let mdrData = null;
    try {
      const mdrResult = await pool.query(
        `SELECT total_tickets, resolved_count, avg_resolution_hours, uploaded_at
         FROM mdr_uploads
         WHERE tenant_id = $1
         ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      );
      if (mdrResult.rows.length > 0) mdrData = { upload: mdrResult.rows[0] };
    } catch (_) { /* table may not exist yet */ }

    // Calculate score
    const { composite, vulnScore, awarenessScore, mdrScore } = calculateSecureScore(vulnData, awarenessData, mdrData);
    const recommendations = generateRecommendations(vulnScore, awarenessScore, mdrScore);

    // Determine rating
    let rating = 'Critical';
    if (composite >= 80) rating = 'Excellent';
    else if (composite >= 70) rating = 'Good';
    else if (composite >= 50) rating = 'Fair';
    else rating = 'Poor';

    res.json({
      tenantId,
      score: composite,
      rating,
      components: {
        vulnerabilities: { score: vulnScore, weight: 0.40 },
        awareness: { score: awarenessScore, weight: 0.35 },
        incidentResponse: { score: mdrScore, weight: 0.25 },
      },
      dataAge: {
        vulns: vulnData ? 'current' : 'no data',
        awareness: awarenessData ? awarenessData.upload.uploaded_at : 'no data',
        mdr: mdrData ? mdrData.upload.uploaded_at : 'no data',
      },
      recommendations,
    });
  } catch (err) {
    return serverError(res, err);
  }
});

/**
 * GET /api/secure-score/history
 * Get historical Secure Score trend (last 90 days by fetching latest scan each month).
 */
app.get('/api/secure-score/history', requireAuth, async (req, res) => {
  try {
    const tenantId = req.session.tenantId;
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant context.' });
    }

    // Get monthly vuln data (last 6 months for trend)
    let vulnTrendRows = [];
    try {
      const vulnTrend = await pool.query(
        `SELECT month_key, summary FROM vuln_scans
         WHERE tenant_id = $1
         ORDER BY month_key DESC LIMIT 6`,
        [tenantId]
      );
      vulnTrendRows = vulnTrend.rows;
    } catch (_) { /* table may not exist yet */ }

    // Pre-fetch latest awareness + MDR once for all months
    let latestAwarenessData = null;
    try {
      const ar = await pool.query(
        `SELECT total_users, total_incomplete FROM awareness_uploads
         WHERE tenant_id = $1 ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      );
      if (ar.rows.length > 0) latestAwarenessData = { upload: ar.rows[0] };
    } catch (_) { /* table may not exist yet */ }

    let latestMdrData = null;
    try {
      const mr = await pool.query(
        `SELECT total_tickets, resolved_count, avg_resolution_hours FROM mdr_uploads
         WHERE tenant_id = $1
         ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      );
      if (mr.rows.length > 0) latestMdrData = { upload: mr.rows[0] };
    } catch (_) { /* table may not exist yet */ }

    const history = vulnTrendRows.map(row => {
      const { composite } = calculateSecureScore(
        { summary: row.summary },
        latestAwarenessData,
        latestMdrData
      );
      return { monthKey: row.month_key, score: composite };
    });

    res.json({ tenantId, history: history.reverse() });
  } catch (err) {
    return serverError(res, err);
  }
});

// ── Error handler helper ──────────────────────────────────────────────────

function serverError(res, err, status = 500) {
  console.error('[error]', err.message);
  res.status(status).json({ error: err.message });
}

// ── Start server ───────────────────────────────────────────────────────────

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
