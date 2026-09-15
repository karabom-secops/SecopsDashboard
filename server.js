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
const { requireAuth, requireSuperAdmin, requirePage, pageGate, loadPageAccess } = require('./lib/auth-middleware');
const portalGate = require('./lib/portal-gate');
const reportArchive = require('./lib/report-archive');
const portalRoutes = require('./lib/portal-routes');
const { ROLES, ROLE_LABELS, PAGES, PAGE_KEYS, LEVELS, LEVEL_RANK, resolveAccess } = require('./lib/pages');
const pagesLib = require('./lib/pages');
const servicesLib = require('./lib/services');
const { parseReport } = require('./lib/parser');
const { computeAllMetrics } = require('./lib/metrics');
const { parseVulnFile, computeVulnSummary, computeDueDate } = require('./lib/vuln-parser');
const vulnParserLib = require('./lib/vuln-parser');
const { parseAwarenessCSV, detectAwarenessFormat, parseSessionHistoryCSV } = require('./lib/awareness-parser');
const XLSX = require('xlsx');
const { isSamlEnabled, getSamlLoginUrl, validateSamlResponse, getSamlMetadata } = require('./lib/saml');
const {
  calculateGrcScore, calculateFrameworkScores, calculateSectionScores,
} = require('./lib/grc-score');
const { scoreVendor } = require('./lib/vendor-score');
const {
  calculateSecureScore, calculateVulnScore, calculateAwarenessScore,
  calculateMdrScore, generateRecommendations, WEIGHTS,
} = require('./lib/secure-score');
const secureScore = require('./lib/secure-score');
const { encrypt: encryptKey, decrypt: decryptKey } = require('./lib/crypto-utils');
const arcticWolfAdapter = require('./lib/integrations/arctic-wolf');
const { PLAYBOOKS: IR_PLAYBOOKS } = require('./public/js/ir-playbooks-data');
// Same file the browser loads with a <script> tag, for the same reason: the
// report's incident-resolution KPIs and the MDR score must count one cohort.
const mdrMetrics = require('./public/js/mdr-metrics');
const scoreEvidence = require('./lib/score-evidence');
const riskAcceptance = require('./lib/risk-acceptance');
const fazAdapter = require('./lib/integrations/fortianalyzer');
const fazMetrics = require('./lib/fortianalyzer-metrics');
const msIdentity = require('./lib/integrations/ms-identity');
const identityMetrics = require('./lib/identity-metrics');
const dnsAdapter = require('./lib/integrations/dnsfilter');
const dnsMetrics = require('./lib/dnsfilter-metrics');
const aiVisibility = require('./lib/ai-visibility');
const arcticWolfReportsAdapter = require('./lib/integrations/arctic-wolf-reports');
const arcticWolfMetricsAdapter = require('./lib/integrations/arctic-wolf-metrics');
const sentinelOneAdapter = require('./lib/integrations/sentinelone');
const wazuhAdapter = require('./lib/integrations/wazuh-indexer');
const acronisAdapter = require('./lib/integrations/acronis');
const msGraphAdapter = require('./lib/integrations/ms-graph');
const { computeEdrSummary } = require('./lib/edr-metrics');
const { computeEmailSummary } = require('./lib/email-metrics');
const wazuhMetrics = require('./lib/wazuh-metrics');
const { buildPentestReport, imageDimensions, DEFAULT_OWASP } = require('./lib/report-docx');
const pptxRoute = require('./lib/report-pptx-route');
const estateLib = require('./lib/estate');
const awCoverageLib = require('./lib/arctic-wolf-coverage');
const trainingLib = require('./lib/training');
const fortigateParser = require('./lib/fortigate-parser');
const fortigateChecks = require('./lib/fortigate-checks');
const fortigateScore  = require('./lib/fortigate-score');

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

/**
 * Strip the /secops base path before anything routes.
 *
 * Every HTML page carries <base href="/secops/"> and calls the API with
 * relative URLs, so the browser requests /secops/api/... In production nginx
 * strips the prefix and the app never sees it. Hitting node directly — local
 * development, a health check, a curl against the port — it was never stripped,
 * so static files worked under /secops but EVERY API CALL 404'd, including the
 * URL this server prints at startup.
 *
 * Done here, before every mount, so the existing `app.use('/api', …)` gates
 * still apply. Re-mounting the routes under a second prefix would have been the
 * obvious fix and a bad one: requireAuth, requirePortalConfinement and pageGate
 * are all bound to '/api', so a parallel '/secops/api' mount would have been
 * completely ungated.
 */
app.use((req, res, next) => {
  if (req.url === '/secops') { req.url = '/'; }
  else if (req.url.startsWith('/secops/')) { req.url = req.url.slice('/secops'.length); }
  next();
});

// Serve static assets BEFORE session/auth so the login page loads without auth.
//
// CODE ASSETS MUST REVALIDATE ON EVERY REQUEST.
//
// The script tags in index.html are unversioned (js/report-sections.js, not
// ...?v=7), so the URL of a file never changes when its contents do. Express's
// default of `public, max-age=0` requires a browser to revalidate, but
// `public` also permits a SHARED cache — the nginx in front of this app — to
// hold and serve a copy, and a fix can then sit on disk for hours while
// everyone keeps loading the old build. That has already cost two rounds of
// "it's still there" on a change that was correctly deployed.
//
// `no-cache` does not mean "do not store"; it means "store, but revalidate
// before every use". With the ETag express.static already sends, that is a
// conditional GET answered by a 304 with no body — cheap, and correct.
//
// Only for the file types that carry behaviour. Images and fonts change under
// a new name when they change at all, and pay the full round trip otherwise.
const REVALIDATE = /\.(html|js|css|map)$/i;
app.use(express.static(PUBLIC, {
  setHeaders: (res, filePath) => {
    if (REVALIDATE.test(filePath)) res.setHeader('Cache-Control', 'no-cache');
  },
}));

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
// Pentest finding evidence screenshots — images only, kept small enough to embed
// comfortably in a Word document.
const evidenceUpload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpeg)$/.test(file.mimetype)) return cb(null, true);
    cb(new Error('Only PNG and JPEG images are accepted.'));
  },
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

/**
 * The second factor needs its own limit.
 *
 * loginLimiter guards the password step only, so the TOTP routes were
 * unthrottled: having got past a password, an attacker could grind six digits
 * without limit, which makes the second factor a formality. A 30-second TOTP
 * window and 10 tries per 15 minutes leaves an honest user room for clock skew
 * and a mistyped code, and leaves an attacker nowhere.
 *
 * Keyed on IP like loginLimiter — per-account limiting would be better and is
 * noted as a gap, since neither this nor login can currently lock a single
 * account that is being attacked from many addresses.
 */
const mfaLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  validate: { xForwardedForHeader: false },
  message: { error: 'Too many verification attempts. Please try again later.' },
});

// ── Auth routes (public — no requireAuth) ─────────────────────────────────

/**
 * Start a brand-new session id, discarding the pre-authentication one.
 *
 * Without this the id issued to an anonymous visitor survives login, so anyone
 * who could plant a cookie before sign-in (shared machine, an XSS elsewhere on
 * the origin) holds a valid authenticated session afterwards. Called once,
 * immediately after the password check and before anything is written to the
 * session — including the MFA-pending payload, which is itself worth protecting.
 */
function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => (err ? reject(err) : resolve()));
  });
}

/**
 * Fetch the login row, tolerating a database that has not run
 * db/migrate-user-lifecycle.sql yet. An un-migrated deployment keeps the old
 * behaviour: every account is active and nobody is forced to rotate.
 */
async function loadLoginUser(username) {
  try {
    const r = await pool.query(
      `SELECT id, username, password_hash, role, tenant_id,
              totp_enabled, totp_required, is_active, must_change_password
       FROM users WHERE username = $1`,
      [username]
    );
    return r.rows[0] || null;
  } catch (err) {
    if (err.code !== '42703') throw err;   // undefined_column
    const r = await pool.query(
      `SELECT id, username, password_hash, role, tenant_id,
              totp_enabled, totp_required
       FROM users WHERE username = $1`,
      [username]
    );
    const row = r.rows[0];
    if (row) { row.is_active = true; row.must_change_password = false; }
    return row || null;
  }
}

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const username = (req.body.username || '').trim();
    const password = (req.body.password || '').trim();

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const user = await loadLoginUser(username);
    if (!user || !user.password_hash) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    // Told only AFTER a correct password: someone who has proved they own the
    // account is entitled to know why they cannot get in, and saying it before
    // the password check would turn login into an account-status oracle.
    if (user.is_active === false) {
      return res.status(403).json({ error: 'This account has been suspended. Contact your administrator.' });
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

    // Everything below writes to the session, so the new id is minted first.
    await regenerateSession(req);

    const pending = {
      userId: user.id, username: user.username, role: user.role,
      tenantId: user.tenant_id, tenantIds,
      mustChangePassword: !!user.must_change_password,
    };

    // ── Who must present a second factor ─────────────────────────────────
    // Superadmins, because they can reach every tenant. Portal clients,
    // because they are outside the building — an external login guarding
    // another company's security data is exactly where MFA earns its cost.
    // Both use the same enrolment and verification routes below; those are
    // already role-generic, so this is the only place that needed changing.
    const mfaRoles = user.role === 'superadmin' || pagesLib.isExternalRole(user.role);

    if (mfaRoles) {
      if (user.totp_enabled) {
        req.session.mfaPending = pending;
        return res.json({ mfaRequired: true });
      }

      // A client has no grace period: MFA is required from the first login, so
      // an unenrolled client is forced into enrolment rather than let through.
      if (user.totp_required || pagesLib.isExternalRole(user.role)) {
        req.session.enrollPending = pending;
        return res.json({ enrollRequired: true });
      }

      // Grace-period superadmin — full session, prompt banner.
      grantSession(req, pending, false);
      return res.json({
        id: user.id, username: user.username, role: user.role,
        tenantId: user.tenant_id, tenantIds, showMfaPrompt: true,
        mustChangePassword: pending.mustChangePassword,
      });
    }

    // ── Everyone else: full session, no MFA ───────────────────────────────
    grantSession(req, pending, false);

    const body = {
      id: user.id, username: user.username, role: user.role,
      tenantId: user.tenant_id, tenantIds,
      mustChangePassword: pending.mustChangePassword,
    };
    if (user.role === 'manager') body.redirect = '/manager.html';
    return res.json(body);
  } catch (err) {
    return serverError(res, err);
  }
});

/**
 * Write an authenticated identity onto the session.
 *
 * Extracted because it was previously open-coded in four places (login branch
 * C, the non-superadmin branch, mfa-verify and enroll-confirm) and they had
 * already drifted — only some of them carried every field.
 */
function grantSession(req, pending, totpEnabled) {
  req.session.mfaPending        = undefined;
  req.session.enrollPending     = undefined;
  req.session.pendingTotpSecret = undefined;
  req.session.userId       = pending.userId;
  req.session.username     = pending.username;
  req.session.role         = pending.role;
  req.session.tenantId     = pending.tenantId;
  req.session.tenantIds    = pending.tenantIds;
  req.session.totpEnabled  = !!totpEnabled;
}

/** Where a role lands after a successful sign-in. */
function landingFor(role) {
  if (pagesLib.isExternalRole(role)) return '/secops/portal.html';
  if (role === 'manager') return '/secops/manager.html';
  return '/secops/';
}

// ── MFA: verify TOTP code after password step ─────────────────────────────
app.post('/api/auth/mfa-verify', mfaLimiter, async (req, res) => {
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

    grantSession(req, pending, true);

    return res.json({
      id: pending.userId, username: pending.username,
      role: pending.role, tenantId: pending.tenantId, tenantIds: pending.tenantIds,
      mustChangePassword: !!pending.mustChangePassword,
      redirect: landingFor(pending.role),
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
app.post('/api/auth/enroll-totp/confirm', mfaLimiter, async (req, res) => {
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

    grantSession(req, pending, true);

    return res.json({
      id: pending.userId, username: pending.username,
      role: pending.role, tenantId: pending.tenantId, tenantIds: pending.tenantIds,
      mustChangePassword: !!pending.mustChangePassword,
      redirect: landingFor(pending.role),
    });
  } catch (err) {
    return serverError(res, err);
  }
});

/**
 * POST /api/auth/change-password — the user changes their own password.
 *
 * There was no such route. The only way a password could change was an admin
 * doing PUT /api/users/:id, so a credential an admin typed and read out over
 * the phone stayed that way forever, and nobody could rotate their own. For
 * internal staff that was poor; for an external client account it is
 * indefensible.
 *
 * Sits above requireAuth's mount but checks the session itself, because
 * requireActiveUser deliberately lets this path through for a user who is
 * blocked by must_change_password — otherwise they would be locked in a loop
 * where the only way out is the thing they are not allowed to do.
 */
app.post('/api/auth/change-password', mfaLimiter, async (req, res) => {
  try {
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const current = String(req.body.currentPassword || '');
    const next    = String(req.body.newPassword || '');

    if (next.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters.' });
    }
    if (next === current) {
      return res.status(400).json({ error: 'The new password must be different from the current one.' });
    }

    const r = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.session.userId]);
    if (!r.rows.length || !r.rows[0].password_hash) {
      // SAML accounts have no local password to change.
      return res.status(400).json({ error: 'This account does not use a password.' });
    }

    // Re-proving the current password matters even though the session is
    // already authenticated: it stops an unattended logged-in browser from
    // being turned into a permanent takeover.
    const ok = await bcrypt.compare(current, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect.' });

    const hash = await bcrypt.hash(next, 12);
    try {
      await pool.query(
        `UPDATE users SET password_hash = $1, must_change_password = FALSE,
                          password_changed_at = NOW()
         WHERE id = $2`,
        [hash, req.session.userId]
      );
    } catch (err) {
      if (err.code !== '42703') throw err;   // lifecycle migration not run yet
      await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2',
        [hash, req.session.userId]);
    }

    return res.json({ ok: true });
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

app.get('/api/auth/me', async (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  // pageAccess + the page catalog drive all client-side gating (nav filtering,
  // switchTab, per-tab edit controls) so the browser never hardcodes roles.
  let pageAccess;
  try {
    pageAccess = await loadPageAccess(req);
  } catch (err) {
    return serverError(res, err);
  }
  res.json({
    id:          req.session.userId,
    username:    req.session.username,
    role:        req.session.role,
    tenantId:    req.session.tenantId   || null,
    tenantIds:   req.session.tenantIds  || [],
    totpEnabled: req.session.totpEnabled || false,
    pageAccess,
    pages:       PAGES,
    roles:       ROLES.map(r => ({ value: r, label: ROLE_LABELS[r] })),
    /*
     * The remediation SLA, served rather than duplicated.
     *
     * lib/vuln-parser.js is the authority: it computes the due_date actually
     * stored on every finding. Four browser copies had drifted from it and
     * from each other — the board report used 7/30/90/180 while the
     * Vulnerabilities tab and the stored dates used 7/14/30/60, so the same
     * finding was overdue on one screen and comfortable on the other.
     * Shipping the numbers from the same module that applies them is the only
     * version of this that cannot drift again.
     */
    vulnSlaDays: vulnParserLib.SLA_DAYS,
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

// ── …and must belong to an account that is still active ──────────────────
// Role and tenant are snapshotted onto the session at login, so without this a
// suspended user keeps working until their 8-hour session expires. Costs one
// indexed lookup, the same trade loadPageAccess already makes.

app.use('/api', portalGate.requireActiveUser);

// ── The membrane: a client session may reach /api/portal and nothing else ─
//
// MOUNTED BEFORE pageGate ON PURPOSE. pageGate fails OPEN — an /api prefix
// absent from API_PREFIX_TO_PAGE falls through to authenticated-only, and it
// explicitly whitelists GET /api/tenants, which lists every customer we have.
// That is a fine convenience for staff and quite wrong for a customer, so
// external sessions never reach it. See lib/portal-gate.js.

app.use('/api', portalGate.requirePortalConfinement);

// ── The client portal's own API ───────────────────────────────────────────
// Registered BEFORE pageGate: /api/portal has no entry in the page catalog and
// must not acquire one. Its own gate decides who may read it, and every handler
// takes its tenant from the session. See lib/portal-routes.js.

portalRoutes.register(app, {
  pool,
  requireAuth,
  portalSession: portalGate.requirePortalSession(),
  onError: (res, err) => serverError(res, err),
});

// ── …and must pass the per-page access check (see lib/pages.js) ───────────
// Maps each /api prefix to a page and requires read access for GETs, write
// access for mutations. This replaces the old per-route requireAdmin /
// requireRiskWrite guards on every mapped prefix: the role defaults grant
// exactly what those guards used to allow, but an admin can now widen or
// narrow it per user. Unmapped prefixes (e.g. /api/tenants, still
// requireSuperAdmin) keep their own guard.

app.use('/api', pageGate);

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
app.post('/api/auth/totp-confirm', mfaLimiter, async (req, res) => {
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
app.post('/api/auth/totp-disable', mfaLimiter, async (req, res) => {
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

/**
 * Whether db/migrate-tenant-services.sql has been run.
 *
 * Cached only on a positive answer, so applying the migration takes effect
 * without a restart. Same idiom as hasUserLifecycleColumns.
 */
/**
 * The services a tenant consumes, or null when nobody has recorded them.
 *
 * null is load-bearing and is returned for BOTH "no row" and "column not
 * migrated yet": in neither case has anyone said this client buys nothing, and
 * the Secure Score treats unrecorded very differently from empty.
 */
async function loadTenantServices(tenantId) {
  if (!await hasTenantServicesColumn()) return null;
  try {
    const r = await pool.query('SELECT services FROM tenants WHERE id = $1', [tenantId]);
    if (!r.rows.length) return null;
    return Array.isArray(r.rows[0].services) ? r.rows[0].services : null;
  } catch (_) { return null; }
}

/*
 * Column and table probes for db/migrate-client-profile.sql.
 *
 * Cached only on a POSITIVE answer, like _tenantServicesColumn below: a "no"
 * from a database that is mid-migration must not be remembered for the life of
 * the process.
 */
let _estateReviewedColumn = null;
async function hasEstateReviewedColumn() {
  if (_estateReviewedColumn) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenant_estate' AND column_name = 'reviewed_at' LIMIT 1`);
    if (r.rows.length) _estateReviewedColumn = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

/*
 * Probe for db/migrate-arctic-wolf-org.sql.
 *
 * NOT OPTIONAL, and the reason is worth stating: loadEstate() wraps its SELECT
 * in a catch that degrades to "no estate declared", which zeroes the
 * vulnerability component for EVERY client. Naming an unmigrated column in that
 * query would therefore not fail loudly — it would quietly take a third of the
 * Secure Score off every tenant in the system until somebody noticed.
 *
 * Cached on a POSITIVE answer only, like every other probe here, so running the
 * migration takes effect without a restart.
 */
let _estateArcticWolfColumn = null;
async function hasEstateArcticWolfColumn() {
  if (_estateArcticWolfColumn) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenant_estate' AND column_name = 'arctic_wolf_org' LIMIT 1`);
    if (r.rows.length) _estateArcticWolfColumn = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

let _profileEventsTable = null;
async function hasProfileEventsTable() {
  if (_profileEventsTable) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.tables
        WHERE table_name = 'tenant_profile_events' LIMIT 1`);
    if (r.rows.length) _profileEventsTable = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

let _tenantServicesColumn = null;
async function hasTenantServicesColumn() {
  if (_tenantServicesColumn) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenants' AND column_name = 'services' LIMIT 1`);
    if (r.rows.length) _tenantServicesColumn = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

app.get('/api/tenants', async (req, res) => {
  // All authenticated users can list tenants (needed for dropdowns).
  try {
    // NULL, not '{}', when the column is missing: an un-migrated deployment has
    // not said this client buys nothing, it has said nothing at all — and the
    // report treats those two very differently.
    const servicesCol = await hasTenantServicesColumn()
      ? 't.services' : 'NULL::text[] AS services';

    const result = await pool.query(
      `SELECT t.id, t.name, t.slug, t.created_at, ${servicesCol},
              COUNT(u.id)::int AS user_count
       FROM tenants t
       LEFT JOIN users u ON u.tenant_id = t.id
       GROUP BY t.id ORDER BY t.name ASC`
    );

    // What was sold, plus what it entitles them to. The Reports tab
    // pre-selects sections from the effective set, so an MDR client is offered
    // the endpoint and identity sections MDR actually delivers — without the
    // browser needing its own copy of the implication rule.
    res.json(result.rows.map(r => Object.assign({}, r, {
      effectiveServices: servicesLib.effectiveServices(r.services),
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/** GET /api/tenants/:id/services — the catalogue plus this client's selection. */
app.get('/api/tenants/:id/services', requireAuth, async (req, res) => {
  try {
    const tenantId = parseInt(req.params.id, 10);
    if (isNaN(tenantId)) return res.status(400).json({ error: 'Invalid tenant id.' });

    // A tenant admin may only look at their own organisation.
    if (req.session.role !== 'superadmin' && req.session.tenantId !== tenantId) {
      return res.status(403).json({ error: 'You can only view your own organisation.' });
    }

    if (!await hasTenantServicesColumn()) {
      return res.json({
        tenantId, services: null, effectiveServices: null,
        catalogue: servicesLib.SERVICES, includes: servicesLib.SERVICE_INCLUDES,
        available: false,
        message: 'Service selection is not available yet. Run db/migrate-tenant-services.sql.',
      });
    }

    const r = await pool.query('SELECT services FROM tenants WHERE id = $1', [tenantId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Tenant not found.' });

    return res.json({
      tenantId, services: r.rows[0].services,
      effectiveServices: servicesLib.effectiveServices(r.rows[0].services),
      catalogue: servicesLib.SERVICES, includes: servicesLib.SERVICE_INCLUDES,
      available: true,
    });
  } catch (err) {
    return serverError(res, err);
  }
});

/*
 * PUT /api/tenants/:id/services IS GONE. Writes go through PUT /api/client-profile.
 *
 * It wrote the same column with no history, no score snapshot and a different
 * page gate (`admin`, where the profile is `client-profile`). Two write paths
 * to one piece of data where only one is audited is not a convenience — it is
 * an audit trail with a hole in it, and the hole is the path nobody remembers
 * exists. Whichever route a change came through, the history has to show it.
 *
 * GET /api/tenants/:id/services above STAYS, as does the `services` field on
 * GET /api/tenants: public/js/tab-reports.js reads the latter to default its
 * section toggles, and neither is a write.
 */

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

/** Roles the acting user is allowed to assign. */
function assignableRoles(req) {
  return req.session.role === 'superadmin'
    ? ROLES
    : ROLES.filter(r => r !== 'superadmin');
}

/**
 * validatePageAccess — check a { pageKey: level } payload from the admin UI.
 *
 * Levels must be valid and the page keys known. An admin may only grant what
 * they hold themselves, so a tenant admin cannot mint a user with more reach
 * than they have. Returns { error } or { entries } where entries is a list of
 * [pageKey, level|null] pairs — null meaning "delete the override, inherit
 * from the role".
 */
async function validatePageAccess(req, pageAccess) {
  const entries = [];
  const actorAccess = await loadPageAccess(req);

  for (const [key, rawLevel] of Object.entries(pageAccess)) {
    if (!PAGE_KEYS.includes(key)) {
      return { error: `Unknown page: ${key}.` };
    }
    // '' / null / 'inherit' all mean "no override".
    if (rawLevel === '' || rawLevel === null || rawLevel === 'inherit') {
      entries.push([key, null]);
      continue;
    }
    const level = String(rawLevel);
    if (!LEVELS.includes(level)) {
      return { error: `Access for ${key} must be one of: ${LEVELS.join(', ')}.` };
    }
    if (LEVEL_RANK[level] > LEVEL_RANK[actorAccess[key] || 'none']) {
      return { error: `You cannot grant ${level} access to ${key} because you do not have it yourself.` };
    }
    entries.push([key, level]);
  }

  return { entries };
}

/** Write validated overrides for a user. */
async function applyPageAccess(userId, entries) {
  for (const [key, level] of entries) {
    if (level === null) {
      await pool.query(
        'DELETE FROM user_page_access WHERE user_id = $1 AND page_key = $2',
        [userId, key]
      );
    } else {
      await pool.query(
        `INSERT INTO user_page_access (user_id, page_key, access)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, page_key) DO UPDATE SET access = EXCLUDED.access`,
        [userId, key, level]
      );
    }
  }
}

/**
 * Does this database have the account-lifecycle columns?
 *
 * Cached after the first successful answer: it is a deployment fact, not a
 * per-request one, and the admin tab would otherwise pay a catalog lookup on
 * every load. Deliberately NOT cached on false, so running the migration takes
 * effect without a restart.
 */
let _lifecycleColumns = null;
async function hasUserLifecycleColumns() {
  if (_lifecycleColumns) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'is_active' LIMIT 1`);
    if (r.rows.length) _lifecycleColumns = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

app.get('/api/users', async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';

    // Lifecycle columns arrive with db/migrate-user-lifecycle.sql. On a
    // deployment that has not run it the whole admin tab would 42703 and go
    // blank, so they are selected only when present and defaulted otherwise.
    const lifecycle = await hasUserLifecycleColumns();
    const lifecycleCols = lifecycle
      ? `u.is_active, u.must_change_password, u.password_changed_at, u.totp_enabled,`
      : `TRUE AS is_active, FALSE AS must_change_password,
         NULL::timestamptz AS password_changed_at, u.totp_enabled,`;
    const lifecycleGroup = lifecycle
      ? `, u.is_active, u.must_change_password, u.password_changed_at, u.totp_enabled`
      : `, u.totp_enabled`;

    const baseSelect = `
      SELECT u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name AS tenant_name,
             ${lifecycleCols}
             u.created_at, u.last_login,
             COALESCE(
               ARRAY_AGG(DISTINCT ut.tenant_id) FILTER (WHERE ut.tenant_id IS NOT NULL),
               ARRAY[]::int[]
             ) AS "tenantIds",
             COALESCE(
               JSONB_OBJECT_AGG(pa.page_key, pa.access) FILTER (WHERE pa.page_key IS NOT NULL),
               '{}'::jsonb
             ) AS "pageAccess"
      FROM users u
      LEFT JOIN tenants t          ON t.id       = u.tenant_id
      LEFT JOIN user_tenants ut    ON ut.user_id = u.id
      LEFT JOIN user_page_access pa ON pa.user_id = u.id`;
    const groupBy = `
      GROUP BY u.id, u.username, u.role, u.auth_type, u.tenant_id, t.name,
               u.created_at, u.last_login${lifecycleGroup}
      ORDER BY u.created_at ASC`;

    const result = isSA
      ? await pool.query(baseSelect + groupBy)
      : await pool.query(`${baseSelect} WHERE u.tenant_id = $1 ${groupBy}`, [req.session.tenantId]);

    res.json(result.rows);
  } catch (err) {
    return serverError(res, err);
  }
});

app.post('/api/users', async (req, res) => {
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

    // Superadmin can create any role; tenant admin cannot create superadmins.
    const allowedRoles = assignableRoles(req);
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: `Role must be one of: ${allowedRoles.join(', ')}.` });
    }

    // Optional per-page overrides on top of the new user's role defaults.
    let accessEntries = [];
    if (req.body.pageAccess && typeof req.body.pageAccess === 'object') {
      const check = await validatePageAccess(req, req.body.pageAccess);
      if (check.error) return res.status(400).json({ error: check.error });
      accessEntries = check.entries;
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

    await applyPageAccess(newUser.id, accessEntries);

    res.status(201).json(newUser);
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    return serverError(res, err);
  }
});

app.put('/api/users/:id', async (req, res) => {
  try {
    const targetId = parseInt(req.params.id, 10);
    if (isNaN(targetId)) return res.status(400).json({ error: 'Invalid user id.' });

    const isSA = req.session.role === 'superadmin';

    // Tenant admin can only edit users in their own tenant.
    let targetAuthType = 'local';
    let targetRole     = null;
    if (!isSA) {
      const check = await pool.query('SELECT tenant_id, auth_type, role FROM users WHERE id=$1', [targetId]);
      if (check.rows.length === 0) return res.status(404).json({ error: 'User not found.' });
      if (check.rows[0].tenant_id !== req.session.tenantId) {
        return res.status(403).json({ error: 'You can only edit users in your own organisation.' });
      }
      targetAuthType = check.rows[0].auth_type || 'local';
      targetRole     = check.rows[0].role || null;
    } else {
      const check = await pool.query('SELECT auth_type, role FROM users WHERE id=$1', [targetId]);
      if (check.rows.length > 0) {
        targetAuthType = check.rows[0].auth_type || 'local';
        targetRole     = check.rows[0].role || null;
      }
    }

    const { role, password, tenantIds, pageAccess,
            isActive, mustChangePassword, resetMfa } = req.body;
    const updates = [];
    const values  = [];

    /* ── Account lifecycle ──────────────────────────────────────────────
       These exist for client-portal accounts but apply to everyone. All
       three are self-inflicted-lockout risks, so each refuses to act on
       the caller's own account. */

    if (isActive !== undefined) {
      if (targetId === req.session.userId) {
        return res.status(400).json({ error: 'You cannot suspend your own account.' });
      }
      updates.push(`is_active = $${values.length + 1}`);
      values.push(!!isActive);
    }

    /*
     * Whether the target ends up as an external (client) account, taking a
     * role change in this same request into account.
     *
     * A forced password change is only meaningful for someone who has a screen
     * to satisfy it on. Staff do; clients do not — password reset for the
     * portal is admin-only by design, so a client has no way to clear the flag
     * and would be answered 428 on every portal call with nothing to click.
     * That is not a lockout worth having, so the flag is never set on them.
     */
    const targetIsExternal = pagesLib.isExternalRole(
      role !== undefined ? role : targetRole);

    if (mustChangePassword !== undefined && !targetIsExternal) {
      updates.push(`must_change_password = $${values.length + 1}`);
      values.push(!!mustChangePassword);
    }

    // Clearing the secret sends the user back through forced enrolment on
    // their next sign-in, which is what "they lost their phone" needs.
    // totp_required is left alone: for a client it is implied by the role,
    // and for a superadmin it is a separate policy decision.
    if (resetMfa) {
      if (targetId === req.session.userId) {
        return res.status(400).json({
          error: 'Reset your own MFA from the security settings, not from user administration.',
        });
      }
      updates.push('totp_secret = NULL', 'totp_enabled = FALSE');
    }

    // Per-page overrides can be updated on their own, without a role change.
    let accessEntries = null;
    if (pageAccess !== undefined) {
      if (!pageAccess || typeof pageAccess !== 'object' || Array.isArray(pageAccess)) {
        return res.status(400).json({ error: 'pageAccess must be an object.' });
      }
      const check = await validatePageAccess(req, pageAccess);
      if (check.error) return res.status(400).json({ error: check.error });
      accessEntries = check.entries;
    }

    if (role !== undefined) {
      const allowedRoles = assignableRoles(req);
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

      // An admin-set password has been typed by someone else and probably read
      // out loud, so for STAFF it is a handover credential, not the user's own:
      // force a change on next sign-in unless the caller says otherwise.
      //
      // For a client it is the opposite. An admin reset is the only reset there
      // is, so the credential the admin just issued has to work as it stands.
      // Clearing the flag rather than leaving it alone also repairs an account
      // that an earlier reset already stranded behind a 428.
      if (targetIsExternal) {
        updates.push('must_change_password = FALSE');
      } else if (mustChangePassword === undefined && targetId !== req.session.userId) {
        updates.push('must_change_password = TRUE');
      }
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

    if (updates.length === 0 && accessEntries === null) {
      return res.status(400).json({ error: 'Nothing to update. Provide role, password, tenantIds, or pageAccess.' });
    }

    let result;
    if (updates.length > 0) {
      values.push(targetId);
      result = await pool.query(
        `UPDATE users SET ${updates.join(', ')} WHERE id = $${values.length}
         RETURNING id, username, role, tenant_id, created_at, last_login`,
        values
      );
    } else {
      // pageAccess-only edit — nothing to change on the users row itself.
      result = await pool.query(
        `SELECT id, username, role, tenant_id, created_at, last_login FROM users WHERE id = $1`,
        [targetId]
      );
    }
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    if (accessEntries !== null) {
      await applyPageAccess(targetId, accessEntries);
    }

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

app.delete('/api/users/:id', async (req, res) => {
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

/* ─────────────────────────────────────────────────────────────────────────────
 * FIREWALL CONFIGURATION AUDIT
 *
 * A client takes a backup from the device (admin menu → Configuration → Backup
 * → Local PC → File format: YAML) and it is audited against the CIS FortiGate
 * Benchmark and our own checks.
 *
 * ══ THE CONFIGURATION IS NEVER STORED ══
 *
 * It arrives in memory (multer memoryStorage), is parsed, audited, and goes out
 * of scope when the request ends. It is not written to the database — see
 * db/migrate-firewall-audit.sql, which has no column it could go in — not to
 * disk, and not to a log line.
 *
 * Unmasked, a FortiGate backup carries administrator password hashes, IPsec
 * pre-shared keys, SNMP communities, LDAP and RADIUS bind credentials and
 * certificate private keys. "Password mask" on that backup screen is optional,
 * so unmasked files will arrive. Storing them would make a compromise of this
 * dashboard a compromise of every perimeter we audit.
 *
 * The response says whether the file appeared masked, so an analyst who has
 * just posted an unmasked config is told to have the client rotate what was in
 * it.
 * ───────────────────────────────────────────────────────────────────────────── */

// 25 MB: a real FortiGate backup is single-digit megabytes, and the parser
// refuses anything larger before it starts. Both limits exist because either
// one alone is a single point of failure on an endpoint that accepts uploads.
const firewallUpload = multer({
  storage: multer.memoryStorage(),
  limits:  { fileSize: fortigateParser.MAX_BYTES },
});

/** Shape an audit row plus its findings for the analyst-facing tab. */
function shapeAudit(row, findings) {
  return {
    id: row.id,
    tenantId: row.tenant_id,
    uploadedAt: row.uploaded_at,
    uploadedBy: row.uploaded_by_name || null,
    device: {
      name: row.device_name, model: row.model,
      firmware: row.firmware, configVersion: row.config_version,
    },
    appearedMasked: row.appeared_masked,
    score: row.score,
    band: fortigateScore.band(row.score),
    totalChecks: row.total_checks,
    assessed: row.assessed,
    passed: row.passed,
    failed: row.failed,
    notAssessable: row.not_assessable,
    coverage: row.coverage,
    severityCounts: row.severity_counts || {},
    unreadSections: row.unread_sections || [],
    findings: (findings || []).map(f => ({
      checkId: f.check_id, severity: f.severity, status: f.status,
      // undefined when the category column has not been added yet, NULL when
      // the finding predates categorisation. Both mean "not categorised" and
      // neither may be rendered as a category.
      category: f.category === undefined ? null : f.category,
      title: f.title, detail: f.detail, rationale: f.rationale,
      remediation: f.remediation, cis: f.cis_ref, source: f.source,
      evidence: f.evidence,
    })),
    /*
     * The per-category rollup is RECOMPUTED from the stored findings rather
     * than stored on the audit row, so a change to the category list applies to
     * historical audits on the next read instead of leaving old audits grouped
     * by a scheme that no longer exists.
     */
    byCategory: fortigateScore.scoreResults((findings || []).map(f => ({
      severity: f.severity, status: f.status, category: f.category || null,
    }))).byCategory,
  };
}

let _firewallTables = null;
async function hasFirewallTables() {
  if (_firewallTables) return true;
  try {
    const r = await pool.query(
      `SELECT COUNT(*)::int AS n FROM information_schema.tables
        WHERE table_name IN ('firewall_audits', 'firewall_findings')`);
    if (r.rows[0].n === 2) _firewallTables = true;
    return r.rows[0].n === 2;
  } catch (_) { return false; }
}

/*
 * Does firewall_findings carry the category column yet?
 *
 * db/migrate-firewall-categories.sql adds it. Naming the column unconditionally
 * on a database without it would make every INSERT fail — losing the whole
 * audit — and every SELECT throw, which the route's catch would turn into "no
 * audits", indistinguishable from a client who has never uploaded one.
 *
 * Cached ONLY on a positive answer, so running the migration takes effect
 * without a restart.
 */
let _firewallCategoryColumn = false;
async function hasFirewallCategoryColumn() {
  if (_firewallCategoryColumn) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'firewall_findings' AND column_name = 'category'`);
    if (r.rows.length) _firewallCategoryColumn = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

/**
 * POST /api/firewall/audits — upload a config, get an audit.
 *
 * The parse, the checks and the score all happen before anything touches the
 * database, so a file we cannot read is a 400 with nothing written.
 */
app.post('/api/firewall/audits', firewallUpload.single('configFile'), async (req, res) => {
  const client = await pool.connect();
  try {
    const { tenantId, error: tenantErr } = resolveVulnTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });
    if (!req.file) return res.status(400).json({ error: 'No configuration file uploaded.' });

    let model;
    try {
      model = fortigateParser.parseConfig(req.file.buffer.toString('utf8'),
        { fileName: req.file.originalname || '' });
    } catch (err) {
      // A file the client chose is a 400, never a 500. The message says what
      // was wrong with it and quotes nothing from inside it.
      if (err instanceof fortigateParser.FortigateParseError) {
        return res.status(400).json({ error: err.message });
      }
      throw err;
    }

    const results = fortigateChecks.runChecks(model);
    const scored  = fortigateScore.scoreResults(results);

    if (!await hasFirewallTables()) {
      return res.status(503).json({
        error: 'Firewall audit storage is not available yet. Run db/migrate-firewall-audit.sql.',
      });
    }

    // Probed once per upload, outside the loop — not once per finding.
    const withCategory = await hasFirewallCategoryColumn();

    await client.query('BEGIN');
    const ins = await client.query(
      `INSERT INTO firewall_audits
         (tenant_id, uploaded_by, device_name, model, firmware, config_version,
          appeared_masked, score, total_checks, assessed, passed, failed,
          not_assessable, coverage, severity_counts, unread_sections)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,$16::jsonb)
       RETURNING *`,
      [tenantId, req.session.userId || null,
       model.device.hostname, model.device.model, model.device.firmware,
       model.device.configVersion, model.masked,
       scored.score, scored.total, scored.assessed, scored.passed, scored.failed,
       scored.notAssessable, scored.coverage,
       JSON.stringify(scored.bySeverity), JSON.stringify(model.unread)]);

    const audit = ins.rows[0];

    for (const r of results) {
      await client.query(
        // The category column is named only where it exists — see
        // hasFirewallCategoryColumn. On a database without the migration the
        // audit still stores, uncategorised, rather than failing entirely.
        `INSERT INTO firewall_findings
           (audit_id, tenant_id, check_id, severity, status, title, detail,
            rationale, remediation, cis_ref, source, evidence${withCategory ? ', category' : ''})
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb${withCategory ? ',$13' : ''})`,
        [audit.id, tenantId, r.id, r.severity, r.status, r.title, r.detail,
         r.rationale, r.remediation, r.cis, r.source,
         // redact() is the net under the rule that checks put identifiers and
         // counts in evidence, never values. Nothing should need catching here;
         // "should" is not a mechanism.
         JSON.stringify(fortigateParser.redact(r.evidence))]
          .concat(withCategory ? [r.category || null] : []));
    }
    await client.query('COMMIT');

    /*
     * The config goes out of scope here and is never referenced again. The
     * response deliberately carries the FINDINGS and not the parsed model:
     * shipping the model back would put the client's ruleset through the
     * browser cache and anywhere the response is logged, for no benefit.
     */
    return res.json({
      audit: shapeAudit(audit, results.map(r => ({
        check_id: r.id, severity: r.severity, status: r.status, title: r.title,
        detail: r.detail, rationale: r.rationale, remediation: r.remediation,
        cis_ref: r.cis, source: r.source,
        evidence: fortigateParser.redact(r.evidence),
      }))),
      /*
       * FortiOS emits YAML it cannot read back — unquoted `*.bat` keys and
       * names containing " : ". Where a narrow repair pass made the file
       * readable, say so: a repaired parse is a weaker claim than a clean one,
       * and burying that would let an audit of a partially-guessed structure
       * read exactly like an audit of a config we read perfectly.
       */
      parseNote: model.repaired && model.repaired.length
        ? model.repaired.length + ' line(s) in this export are not valid YAML — ' +
          'FortiOS writes file patterns and names containing ":" unquoted. They ' +
          'were repaired to read the file. The findings are sound; if anything ' +
          'looks wrong, check those lines in the original.'
        : null,
      // Advice, never a score. See detectMasking() in lib/fortigate-parser.js.
      maskWarning: model.masked === false
        ? 'This configuration appears NOT to have been password-masked. It has not ' +
          'been stored, but it passed through a browser and this server — have the ' +
          'client rotate the credentials it contained, and tick "Password mask" next time.'
        : null,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return serverError(res, err);
  } finally {
    client.release();
  }
});

/** GET /api/firewall/audits — history for the tenant, newest first. */
app.get('/api/firewall/audits', async (req, res) => {
  try {
    const { tenantId, error } = resolveVulnTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });
    if (!await hasFirewallTables()) return res.json({ audits: [], available: false });

    const r = await pool.query(
      `SELECT a.*, u.username AS uploaded_by_name
         FROM firewall_audits a
         LEFT JOIN users u ON u.id = a.uploaded_by
        WHERE a.tenant_id = $1
        ORDER BY a.uploaded_at DESC
        LIMIT 50`, [tenantId]);
    return res.json({
      available: true,
      audits: r.rows.map(row => shapeAudit(row, [])),
    });
  } catch (err) { return serverError(res, err); }
});

/**
 * GET /api/firewall/audits/latest — the current posture.
 *
 * Registered BEFORE /:id, or Express would match 'latest' as an id.
 */
app.get('/api/firewall/audits/latest', async (req, res) => {
  try {
    const { tenantId, error } = resolveVulnTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });
    if (!await hasFirewallTables()) return res.json({ audit: null, available: false });

    const r = await pool.query(
      `SELECT a.*, u.username AS uploaded_by_name
         FROM firewall_audits a
         LEFT JOIN users u ON u.id = a.uploaded_by
        WHERE a.tenant_id = $1
        ORDER BY a.uploaded_at DESC LIMIT 1`, [tenantId]);
    if (!r.rows.length) return res.json({ audit: null, available: true });

    const f = await pool.query(
      `SELECT * FROM firewall_findings WHERE audit_id = $1 AND tenant_id = $2
        ORDER BY id`, [r.rows[0].id, tenantId]);
    return res.json({ available: true, audit: shapeAudit(r.rows[0], f.rows) });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/firewall/audits/:id — one audit with its findings. */
app.get('/api/firewall/audits/:id', async (req, res) => {
  try {
    const { tenantId, error } = resolveVulnTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid audit id.' });
    if (!await hasFirewallTables()) return res.status(404).json({ error: 'Audit not found.' });

    // Ownership in the WHERE clause, not as a check after the fetch: a wrong id
    // and another tenant's id both 404, and neither can be told apart.
    const r = await pool.query(
      `SELECT a.*, u.username AS uploaded_by_name
         FROM firewall_audits a
         LEFT JOIN users u ON u.id = a.uploaded_by
        WHERE a.id = $1 AND a.tenant_id = $2`, [id, tenantId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Audit not found.' });

    const f = await pool.query(
      `SELECT * FROM firewall_findings WHERE audit_id = $1 AND tenant_id = $2
        ORDER BY id`, [id, tenantId]);
    return res.json({ audit: shapeAudit(r.rows[0], f.rows) });
  } catch (err) { return serverError(res, err); }
});

/**
 * DELETE /api/firewall/audits/:id — superadmin only.
 *
 * Tenant is in the WHERE clause, exactly as it is on the GETs. Being a
 * superadmin means you may delete any tenant's audit; it does not mean you
 * should be able to delete a tenant you are not looking at by mistyping an id.
 * The scoping makes the id you pass mean something in the context you are in.
 *
 * The findings go with it by ON DELETE CASCADE (db/migrate-firewall-audit.sql),
 * so there is no orphan row and no second statement that could half-succeed.
 * Nothing else references an audit — the config was never stored, so there is
 * no file to clean up.
 */
app.delete('/api/firewall/audits/:id', requireSuperAdmin, async (req, res) => {
  try {
    const { tenantId, error } = resolveVulnTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });
    const id = parseInt(req.params.id, 10);
    if (isNaN(id)) return res.status(400).json({ error: 'Invalid audit id.' });
    if (!await hasFirewallTables()) return res.status(404).json({ error: 'Audit not found.' });

    // RETURNING the identity so the caller can say WHAT it deleted rather than
    // "deleted." A destructive confirmation that cannot name its subject is not
    // a confirmation.
    const r = await pool.query(
      `DELETE FROM firewall_audits
        WHERE id = $1 AND tenant_id = $2
        RETURNING id, device_name, uploaded_at`, [id, tenantId]);
    if (!r.rows.length) return res.status(404).json({ error: 'Audit not found.' });

    return res.json({
      ok: true,
      deleted: {
        id: r.rows[0].id,
        device: r.rows[0].device_name || null,
        uploadedAt: r.rows[0].uploaded_at,
      },
    });
  } catch (err) { return serverError(res, err); }
});

// ── Vuln routes — backed by PostgreSQL ───────────────────────────────────

app.post('/api/vulns/upload', vulnUpload.single('vulnFile'), async (req, res) => {
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

    let { findings, format: usedFormat, mergedCount, scannedHosts } = parseVulnFile(fileText, {
      format:   (req.body.fileFormat || 'auto').trim(),
      fileName: req.file.originalname || '',
      mimeType: req.file.mimetype     || '',
    });

    if (findings.length === 0) {
      return res.status(400).json({
        error: `No findings parsed (read as ${usedFormat}). Check it is a valid Nessus CSV, .nessus XML, or Arctic Wolf Managed Risk CSV export — or pick the matching format explicitly.`,
      });
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
      // SLA clock runs from first exposure, so carried-over findings keep their
      // original deadline rather than resetting each month.
      f.dueDate = computeDueDate(f.risk, f.firstSeenAt);
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
        dueDate:         computeDueDate(prev.risk, prev.first_seen_at || uploadNow),
      });
    }

    if (autoClosedFindings.length > 0) {
      findings = findings.concat(autoClosedFindings);
    }

    const summary = computeVulnSummary(findings);

    await client.query('BEGIN');
    await client.query('DELETE FROM vuln_scans WHERE tenant_id=$1 AND month_key=$2', [tenantId, monthKey]);

    // scanned_hosts is the scan's real SCOPE — every host it touched, including
    // the clean ones that leave no finding behind. Null for a format that
    // cannot report scope (Arctic Wolf), which the score treats as unknown.
    const scanResult = await client.query(
      `INSERT INTO vuln_scans (tenant_id, month_key, summary, uploaded_by, scanned_hosts)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [tenantId, monthKey, JSON.stringify(summary), req.session.userId, scannedHosts || null]
    );
    const scanId = scanResult.rows[0].id;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      await client.query(
        `INSERT INTO vuln_findings
           (scan_id, finding_index, plugin_id, name, risk, host, port, protocol,
            cve, cvss_v2, cvss_v3, synopsis, solution, status, notes, status_updated_at,
            first_seen_at, due_date)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
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
          f.dueDate     || null,
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
    console.log(`[vulns] Upload ${monthKey} (tenant ${tenantId}, ${usedFormat}): ${findings.length} findings, ${mergedCount} duplicate rows merged, ${carried} carried over, ${autoClosedCount} auto-closed`);
    return res.json({ monthKey, tenantId, summary, carriedCounts, autoClosedCount, format: usedFormat, mergedCount });
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

/**
 * GET /api/vulns/latest-summary
 *
 * Two callers, with genuinely different needs:
 *   - tab-orgs.js asks with NO tenantId and wants one row per tenant for the
 *     Org Health table.
 *   - tab-reports.js asks WITH ?tenantId= for one client's deck.
 *
 * This used to ignore ?tenantId= entirely — the only vuln route that did — and
 * left the report to filter the all-tenants array on the client. That worked
 * by accident and made any scoping problem invisible in the response, so the
 * parameter is honoured when present, matching every sibling vuln route.
 *
 * The LEFT JOIN LATERAL is deliberate: a tenant with no scans still comes back
 * as a row with a NULL summary, so a caller can tell "no scan uploaded" apart
 * from "tenant does not exist".
 */
app.get('/api/vulns/latest-summary', async (req, res) => {
  try {
    const isSA = req.session.role === 'superadmin';
    const requested = parseInt(req.query.tenantId, 10);
    const scopeTo = isSA
      ? (isNaN(requested) || requested < 1 ? null : requested)
      : req.session.tenantId;

    if (!isSA && !scopeTo) return res.json([]);

    const result = await pool.query(
      `SELECT t.id AS "tenantId", t.name AS "tenantName",
              vs.month_key AS "monthKey", vs.summary
       FROM tenants t
       LEFT JOIN LATERAL (
         SELECT month_key, summary FROM vuln_scans
         WHERE tenant_id = t.id ORDER BY month_key DESC LIMIT 1
       ) vs ON true
       ${scopeTo ? 'WHERE t.id = $1' : ''}
       ORDER BY t.name ASC`,
      scopeTo ? [scopeTo] : []
    );
    res.json(result.rows);
  } catch (err) {
    return serverError(res, err);
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
              first_seen_at AS "firstSeenAt",
              due_date AS "dueDate"
       FROM vuln_findings WHERE scan_id = $1 ORDER BY finding_index ASC`,
      [scan.id]
    );

    const findings = findingsResult.rows.map(row => {
      const f = { ...row };
      delete f.idx;
      if (f.statusUpdatedAt) f.statusUpdatedAt = f.statusUpdatedAt.toISOString();
      if (f.firstSeenAt)     f.firstSeenAt     = f.firstSeenAt.toISOString();
      if (f.dueDate)         f.dueDate         = f.dueDate.toISOString();
      return f;
    });

    res.json({ monthKey: scan.monthKey, summary: scan.summary, findings });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/vulns/:monthKey', async (req, res) => {
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

/**
 * Every status a vulnerability finding can hold. One list, used by both update
 * endpoints and asserted against the CHECK constraint in the test suite, so a
 * status can never be accepted by the API and rejected by the database.
 */
const VULN_STATUSES = ['open', 'in-progress', 'fixed', 'accepted', 'false-positive'];

/**
 * Recompute and store a scan's summary from the CURRENT status of its findings.
 *
 * ══ WHY THIS EXISTS ══
 *
 * `vuln_scans.summary` is what the Secure Score reads — loadScoreInputs selects
 * it and hands it straight to calculateVulnScore. It was written ONCE, at
 * upload, and never again.
 *
 * So marking a finding fixed, accepted or false-positive updated
 * `vuln_findings.status`, moved the item in the remediation tracker, stopped
 * its SLA clock — and left the score exactly where it was. An analyst could
 * spend a week closing findings and watch the number not move, which reads as
 * the tracker being decorative. The correct arithmetic was already in
 * computeVulnSummary(); nothing ever re-ran it.
 *
 * That mattered most for the caps. One open critical holds the vulnerability
 * score at 65 (CRITICAL_CAPS in lib/secure-score.js). Classify that single
 * finding as a false positive and the cap should lift immediately — under the
 * old behaviour it held until somebody uploaded a new scan, possibly a month
 * away.
 *
 * ══ WHAT IT DOES NOT DO ══
 *
 * It does not re-parse or re-classify anything. The findings are read back
 * exactly as stored and passed through the same computeVulnSummary() the upload
 * path uses, so a summary written here and a summary written at upload are
 * produced by one function and cannot drift.
 *
 * @param {Object} client   a pg client or pool — the caller decides whether
 *                          this shares their transaction
 * @param {number} scanId
 * @returns {Object|null}   the stored summary, or null if the scan vanished
 */
async function resyncVulnSummary(client, scanId) {
  const rows = await client.query(
    `SELECT plugin_id, name, risk, host, port, protocol, cve, cvss_v2, cvss_v3,
            synopsis, solution, status
       FROM vuln_findings WHERE scan_id = $1 ORDER BY finding_index`,
    [scanId]
  );
  if (!rows.rows.length) return null;

  // Mapped back to the shape the parser produces, because computeVulnSummary is
  // the upload path's function and must stay the only implementation.
  const findings = rows.rows.map(r => ({
    pluginId: r.plugin_id,
    name:     r.name,
    risk:     r.risk,
    host:     r.host,
    port:     r.port,
    protocol: r.protocol,
    cve:      r.cve,
    cvssV2:   r.cvss_v2,
    cvssV3:   r.cvss_v3,
    synopsis: r.synopsis,
    solution: r.solution,
    status:   r.status,
  }));

  const summary = computeVulnSummary(findings);
  await client.query('UPDATE vuln_scans SET summary = $1 WHERE id = $2',
    [JSON.stringify(summary), scanId]);
  return summary;
}

// ── Bulk status update ────────────────────────────────────────────────────
app.patch('/api/vulns/:monthKey/findings/bulk-status', async (req, res) => {
  try {
    const { monthKey } = req.params;
    const { status, indices } = req.body;

    if (!VULN_STATUSES.includes(status)) {
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

    /*
      * The status change and the summary rebuild are ONE transaction.
      *
      * Split, a crash between them leaves the findings saying one thing and the
      * score reading another, with nothing to reconcile them until the next
      * upload — which is precisely the drift this rebuild exists to end.
      */
    const client = await pool.connect();
    let summary = null;
    try {
      await client.query('BEGIN');
      await client.query(
        `UPDATE vuln_findings SET status = $1, status_updated_at = NOW()
         WHERE scan_id = $2 AND finding_index = ANY($3::int[])`,
        [status, scanId, idxList]
      );
      summary = await resyncVulnSummary(client, scanId);
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally {
      client.release();
    }

    // Returned so the page can refresh the counts without a second round trip,
    // and so a caller can see the score inputs actually moved.
    res.json({ ok: true, updated: idxList.length, summary });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/vulns/:monthKey/finding/:index', async (req, res) => {
  try {
    const { monthKey, index } = req.params;
    const { status, notes }   = req.body;

    if (!VULN_STATUSES.includes(status)) {
      return res.status(400).json({ error: 'status must be one of: ' + VULN_STATUSES.join(', ') + '.' });
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
    let summary = null;

    // One transaction, for the same reason as the bulk endpoint above: the
    // finding statuses and the summary the Secure Score reads must never be
    // able to disagree.
    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      if (notes !== undefined) {
        result = await client.query(
          `UPDATE vuln_findings
           SET status = $1, notes = $2, status_updated_at = $3
           WHERE scan_id = $4 AND finding_index = $5
           RETURNING status, status_updated_at AS "statusUpdatedAt"`,
          [status, String(notes).slice(0, 500), now, scanId, idx]
        );
      } else {
        result = await client.query(
          `UPDATE vuln_findings
           SET status = $1, status_updated_at = $2
           WHERE scan_id = $3 AND finding_index = $4
           RETURNING status, status_updated_at AS "statusUpdatedAt"`,
          [status, now, scanId, idx]
        );
      }

      if (result.rows.length) summary = await resyncVulnSummary(client, scanId);
      await client.query('COMMIT');
    } catch (txErr) {
      await client.query('ROLLBACK').catch(() => {});
      throw txErr;
    } finally {
      client.release();
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Finding not found.' });
    }

    const row = result.rows[0];
    res.json({
      ok:              true,
      status:          row.status,
      statusUpdatedAt: row.statusUpdatedAt.toISOString(),
      // The rebuilt counts, so the page can show the score inputs moving in the
      // same response that recorded the change.
      summary,
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

  /*
   * `clicked` is separate from `clicked_at` because an export may report the
   * fact without the time. Probed once rather than per row, and the whole
   * import falls back to the old column set if migrate-awareness-clicked.sql
   * has not been run — the same degrade-open idiom the user list uses.
   */
  const hasClicked = await hasAwarenessClickedColumn();

  const cols = `(upload_id, user_first_name, user_last_name, user_email,
          manager_first_name, manager_last_name, manager_email,
          sent_date, session_type, title, status,
          completed_date, elapsed_seconds, clicked_at, quiz_score` +
        (hasClicked ? ', clicked)' : ')');
  const placeholders = hasClicked
    ? '($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)'
    : '($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)';

  for (const row of rows) {
    const values = [
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
    ];
    // Tri-state: true, false, or null for "the export did not say".
    if (hasClicked) values.push(row.clicked === undefined ? null : row.clicked);

    await client.query(
      `INSERT INTO awareness_sessions ${cols} VALUES ${placeholders}`,
      values
    );
  }

  return { uploadId, uploadedAt, notStartedCount };
}

/**
 * Whether db/migrate-awareness-clicked.sql has been run.
 *
 * Same shape as hasUserLifecycleColumns: cached only on a positive answer, so
 * running the migration takes effect without a restart.
 */
let _awarenessClickedColumn = null;
async function hasAwarenessClickedColumn() {
  if (_awarenessClickedColumn) return true;
  try {
    const r = await pool.query(
      `SELECT 1 FROM information_schema.columns
        WHERE table_name = 'awareness_sessions' AND column_name = 'clicked' LIMIT 1`);
    if (r.rows.length) _awarenessClickedColumn = true;
    return r.rows.length > 0;
  } catch (_) { return false; }
}

app.post('/api/awareness/upload', awarenessUpload.single('awarenessFile'), async (req, res) => {
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
      // NULL, not FALSE, when the column is missing: on an un-migrated
      // database we genuinely do not know, and saying FALSE would report a
      // perfect zero click rate off the back of a missing migration.
      const clickedCol = await hasAwarenessClickedColumn()
        ? 'clicked' : 'NULL::boolean AS clicked';

      const sessRes = await pool.query(
        `SELECT user_first_name, user_last_name, user_email,
                manager_first_name, manager_last_name, manager_email,
                sent_date, session_type, title, status,
                completed_date, elapsed_seconds, clicked_at, ${clickedCol}, quiz_score
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

/**
 * POST /api/awareness/manual — record completion figures by hand.
 *
 * For a client who runs their own awareness programme. Their HR system or LMS
 * produces "X of Y staff completed" perfectly well; it just does not produce an
 * Arctic Wolf export, and until now that meant they scored zero on a control
 * they actually operate.
 *
 * Stored as a normal awareness_uploads row with upload_type 'manual', so the
 * scorer, the Secure Score history and the board report all read it through the
 * existing path with no special cases. The provenance stays on the row: these
 * are numbers a client gave us, not numbers we verified, and every surface that
 * shows them says so.
 */
app.post('/api/awareness/manual', requireAuth, async (req, res) => {
  try {
    const { tenantId, error: tenantErr } = resolveAwarenessTenant(req, 'body');
    if (tenantErr) return res.status(tenantErr.status).json({ error: tenantErr.message });

    const body = req.body || {};
    const total     = estateLib.count(body.totalUsers);
    const completed = estateLib.count(body.completedUsers);

    if (total === null || total < 1) {
      return res.status(400).json({ error: 'Staff covered must be a whole number of one or more.' });
    }
    if (completed === null) {
      return res.status(400).json({ error: 'Staff completed must be a whole number of zero or more.' });
    }
    // Silently clamping would manufacture a 100% completion rate out of a typo.
    if (completed > total) {
      return res.status(400).json({
        error: 'Staff completed (' + completed + ') cannot exceed staff covered (' + total + ').',
      });
    }

    // Replaces rather than appends, matching every other awareness write path —
    // the tenant holds one current set of figures, not a pile of them.
    await pool.query('DELETE FROM awareness_uploads WHERE tenant_id = $1', [tenantId]);
    const r = await pool.query(
      `INSERT INTO awareness_uploads (tenant_id, uploaded_by, total_users, total_incomplete, upload_type)
       VALUES ($1, $2, $3, $4, 'manual') RETURNING id, uploaded_at`,
      [tenantId, req.session.userId || null, total, total - completed]
    );

    return res.json({
      tenantId, uploadType: 'manual',
      uploadedAt: r.rows[0].uploaded_at,
      totalUsers: total, completedUsers: completed,
      completionPct: Math.round((completed / total) * 100),
    });
  } catch (err) { return serverError(res, err); }
});

app.delete('/api/awareness', async (req, res) => {
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

/**
 * DELETE /api/mdr — remove a tenant's MDR data.
 *
 * Two things changed here.
 *
 * 1. It used to delete mdr_uploads alone and let ON DELETE CASCADE take the
 *    tickets with it. That cascade is now SET NULL (see
 *    db/migrate-mdr-history.sql), so the same statement would ORPHAN every
 *    ticket instead of removing it — "delete my MDR data" would quietly stop
 *    meaning what it says. The deletion is explicit and ordered now, inside a
 *    transaction so a failure halfway cannot leave events without tickets.
 *
 * 2. It was missing requireAuth, unlike GET /api/mdr and /api/mdr/trends
 *    beside it. It was reachable by anyone with a session because pageGate maps
 *    the `mdr` prefix to the mdr-pricing page — the wrong page entirely for a
 *    destructive route on somebody's incident record.
 */
app.delete('/api/mdr', requireAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const { tenantId, error } = resolveMdrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    await client.query('BEGIN');
    // Children first: mdr_ticket_events cascades from mdr_tickets, but naming
    // it explicitly means this route does not depend on that staying true.
    await client.query(
      'DELETE FROM mdr_ticket_events WHERE tenant_id = $1', [tenantId]);
    await client.query('DELETE FROM mdr_tickets WHERE tenant_id = $1', [tenantId]);
    await client.query('DELETE FROM mdr_uploads WHERE tenant_id = $1', [tenantId]);
    await client.query('COMMIT');

    return res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    return serverError(res, err);
  } finally {
    client.release();
  }
});

// ── Integrations routes ────────────────────────────────────────────────────

const INTEGRATION_ADAPTERS = {
  arctic_wolf: arcticWolfAdapter,
};

// Arctic Wolf Reports (security-awareness session history) isn't ticket-shaped,
// so it isn't in INTEGRATION_ADAPTERS — it's special-cased in the test/sync routes.
const REPORTS_PROVIDER = 'arctic_wolf_reports';

// SentinelOne isn't ticket-shaped either — it syncs threats, activities and the
// agent fleet into their own tables for the Managed EDR tab.
const EDR_PROVIDER = 'sentinelone';

// Wazuh is a log SOURCE rather than a ticket feed: the Managed NDR and Managed
// Office 365 tabs live-query its indexer for short ranges, and its "sync" writes
// daily rollups for the long ones. Not in INTEGRATION_ADAPTERS for that reason.
const WAZUH_PROVIDER = 'wazuh';

/*
 * Acronis backs Managed Email Security. Not ticket-shaped either: it syncs
 * email-security alerts into their own table.
 *
 * It is also the only provider here that does NOT authenticate with an API key.
 * Acronis uses OAuth client credentials, so the integrations row holds the
 * client id in config_json and the client SECRET in the existing encrypted
 * api_key column — reusing the encrypted column rather than adding a second
 * secret store, so there is exactly one path a credential can take to disk.
 */
const EMAIL_PROVIDER = 'acronis';

/*
 * Microsoft Graph backs Microsoft Secure Score.
 *
 * Distinct from WAZUH_PROVIDER even though both surface Microsoft data. Wazuh
 * forwards Graph EVENTS (alerts, risky users, sign-ins) into its index; Secure
 * Score is a daily posture snapshot that the Wazuh ms-graph wodle does not
 * carry and cannot, so it is pulled from Graph directly. A tenant will commonly
 * have both configured, and they are not redundant.
 *
 * Like Acronis, it authenticates with OAuth client credentials rather than an
 * API key: config_json holds the application (client) ID and the Azure
 * directory (tenant) ID, and the client SECRET goes in the encrypted api_key
 * column with every other credential.
 */
const MSGRAPH_PROVIDER = 'ms_graph';

/*
 * FortiAnalyzer backs Managed NDR, replacing the Wazuh route for firewall
 * telemetry. The REST API token goes in the encrypted api_key column; the ADOM
 * and time zone in config_json, alongside the device list verified at Test.
 * While a client is being migrated both may be configured — the NDR screen
 * prefers FortiAnalyzer when it is enabled. See lib/integrations/fortianalyzer.js.
 */
const FAZ_PROVIDER = 'fortianalyzer';

/*
 * Managed Identity is NOT a separate integration row: it reuses the Microsoft
 * Graph registration (config_json.identity_enabled switches it on), because
 * it is the same app, directory and secret with extra permissions. It has its
 * own sync target so "Sync Now" on the Identity tab collects identity rather
 * than re-reading Secure Score. See lib/integrations/ms-identity.js.
 */
const IDENTITY_SYNC_PROVIDER = 'ms_identity';

/*
 * DNSFilter backs AI Visibility. Unlike every provider above, the credential is
 * NOT on the client's row: one MSP key sees every client organisation, so it is
 * held once in msp_integrations (superadmin-only). The client's row carries only
 * its DNSFilter organisation id and time zone — see saveDnsFilterIntegration.
 */
const DNSFILTER_PROVIDER = 'dnsfilter';

const KNOWN_PROVIDERS  = new Set([...Object.keys(INTEGRATION_ADAPTERS), REPORTS_PROVIDER, EDR_PROVIDER, WAZUH_PROVIDER, EMAIL_PROVIDER, MSGRAPH_PROVIDER, FAZ_PROVIDER, DNSFILTER_PROVIDER]);

/*
 * Degrade-open probe for the email-security tables, matching hasFirewallTables.
 * The migration is unrun on any database that has not had it applied, and a tab
 * that 500s is worse than one that says "not set up yet".
 *
 * Cached ONLY on a positive answer: a false result must stay re-checkable, or
 * running the migration would require a restart to take effect.
 */
let _hasEmailTables = false;
async function hasEmailTables() {
  if (_hasEmailTables) return true;
  try {
    await pool.query('SELECT 1 FROM email_alerts LIMIT 1');
    _hasEmailTables = true;
    return true;
  } catch (_) {
    return false;
  }
}

// Same degrade-open probe for the Microsoft Secure Score tables, and cached on
// a positive answer only for the same reason: a false must stay re-checkable,
// or running the migration would need a restart to take effect.
let _hasMsScoreTables = false;
async function hasMsScoreTables() {
  if (_hasMsScoreTables) return true;
  try {
    await pool.query('SELECT 1 FROM ms_secure_scores LIMIT 1');
    _hasMsScoreTables = true;
    return true;
  } catch (_) {
    return false;
  }
}

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

/*
 * MDR ingest lives in lib/mdr-ingest.js.
 *
 * It was moved out because it is the riskiest code in this file — a live
 * ingest path that runs several times a day and that every tenant Secure
 * Score depends on — and inside server.js it could not be tested without a
 * database. The extracted version takes an explicit client, so a test can
 * pass a recorder and assert the exact statement sequence.
 */
const mdrIngest = require('./lib/mdr-ingest');
const { calcMdrStats, writeMdrTickets } = mdrIngest;

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
app.post('/api/integrations/:provider', async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!KNOWN_PROVIDERS.has(provider)) {
      return res.status(400).json({ error: `Unknown provider: ${provider}` });
    }
    const { tenantId, error } = resolveIntegrationTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    if (provider === DNSFILTER_PROVIDER) return await saveDnsFilterIntegration(req, res, tenantId);

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
app.delete('/api/integrations/:provider', async (req, res) => {
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

// ── DNSFilter (AI Visibility): the MSP key and the per-client organisation ──

/** The MSP DNSFilter credential, decrypted, or null when none is stored. */
async function loadMspDnsFilter() {
  let r;
  try {
    r = await pool.query(
      'SELECT base_url, api_key_enc, api_key_iv, config_json, updated_at FROM msp_integrations WHERE provider = $1',
      [DNSFILTER_PROVIDER]
    );
  } catch (err) {
    if (err.code === '42P01') return null;   // migration not run yet
    throw err;
  }
  if (!r.rows.length) return null;
  const row = r.rows[0];
  return {
    base_url: row.base_url,
    api_key:  decryptKey(row.api_key_enc, row.api_key_iv),
    config:   row.config_json || {},
    updated_at: row.updated_at,
  };
}

/** Only DNSFilter's own API host: the key is an MSP-wide credential. */
function validDnsFilterBase(value) {
  let u;
  try { u = new URL(String(value || dnsAdapter.DEFAULT_BASE)); } catch (_) { return null; }
  if (u.protocol !== 'https:') return null;
  if (u.hostname !== 'dnsfilter.com' && !u.hostname.endsWith('.dnsfilter.com')) return null;
  return `${u.protocol}//${u.host}`;
}

/*
 * The client's DNSFilter row: organisation id and time zone, nothing else.
 *
 * Built from an allowlist rather than merged over the request body, so the
 * verification fields (verified_org_id, …) can only ever be written by Test —
 * a crafted save cannot mark an organisation verified. Verification survives a
 * save only while the organisation id is unchanged.
 *
 * integrations.api_key_enc is NOT NULL, and this provider has no per-client
 * secret, so the row stores an encrypted empty string. Nothing reads it: the
 * loader always takes the MSP key.
 */
async function saveDnsFilterIntegration(req, res, tenantId) {
  const { is_enabled, configJson } = req.body;
  const c = configJson || {};
  let orgId;
  try { orgId = dnsAdapter.validOrgId(c.organization_id); } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  const tz = String(c.timeZone || 'Africa/Johannesburg');
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); } catch (_) {
    return res.status(400).json({ error: `Unknown time zone: ${tz}` });
  }

  const prevRow = await pool.query(
    'SELECT config_json FROM integrations WHERE tenant_id = $1 AND provider = $2',
    [tenantId, DNSFILTER_PROVIDER]
  );
  const prev = (prevRow.rows[0] && prevRow.rows[0].config_json) || {};
  const next = { organization_id: orgId, timeZone: tz };
  if (prev.verified_org_id && String(prev.verified_org_id) === orgId) {
    ['verified_org_id', 'verified_org_name', 'verified_at', 'verified_ai_category_id', 'detected']
      .forEach((k) => { if (prev[k] !== undefined) next[k] = prev[k]; });
  }

  const { enc, iv } = encryptKey('');
  await pool.query(
    `INSERT INTO integrations (tenant_id, provider, base_url, api_key_enc, api_key_iv, is_enabled, config_json)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (tenant_id, provider) DO UPDATE
       SET base_url = $3, is_enabled = $6, config_json = $7`,
    [tenantId, DNSFILTER_PROVIDER, dnsAdapter.DEFAULT_BASE, enc, iv, is_enabled !== false, JSON.stringify(next)]
  );
  return res.json({ ok: true });
}

/*
 * Test for one client: the MSP key can see THIS organisation. That is the check
 * that matters — a mistyped id that happens to be another real client would
 * otherwise fill this tab with someone else's AI use, and nothing downstream
 * could tell. The organisation's name is echoed for the operator to confirm.
 */
async function testDnsFilterIntegration(res, tenantId) {
  const row = await pool.query(
    'SELECT config_json, is_enabled FROM integrations WHERE tenant_id = $1 AND provider = $2',
    [tenantId, DNSFILTER_PROVIDER]
  );
  if (!row.rows.length) return res.status(404).json({ error: 'Integration not configured.' });
  const { config_json, is_enabled } = row.rows[0];

  const msp = await loadMspDnsFilter();
  if (!msp) {
    return res.status(409).json({
      error: 'The DNSFilter MSP key is not configured. A superadmin sets it under Admin → Integrations → DNSFilter (MSP).',
    });
  }

  const conf = dnsAdapter.sanitiseStoredConfig(config_json || {});
  const cfg = {
    base_url: msp.base_url,
    api_key: msp.api_key,
    organization_id: conf.organization_id,
    timeZone: conf.timeZone,
    aiCategoryId: msp.config.ai_category_id || null,
  };

  let info;
  try {
    info = await dnsAdapter.testConnection(cfg);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }

  let detected = null;
  try {
    detected = await dnsAdapter.probe(Object.assign({}, cfg, { aiCategoryId: info.aiCategory ? info.aiCategory.id : null }));
  } catch (probeErr) {
    console.warn('[dnsfilter] probe failed after a successful connection —', probeErr.message);
  }

  const merged = Object.assign({}, config_json || {}, {
    verified_org_id:         info.orgId,
    verified_org_name:       info.orgName,
    verified_at:             new Date().toISOString(),
    verified_ai_category_id: info.aiCategory ? info.aiCategory.id : null,
  }, detected ? { detected } : {});
  await pool.query(
    'UPDATE integrations SET config_json = $1 WHERE tenant_id = $2 AND provider = $3',
    [JSON.stringify(merged), tenantId, DNSFILTER_PROVIDER]
  );

  const disabledNote = is_enabled ? '' :
    ' This integration is currently disabled — enable it to start syncing and to show data on its screens.';
  return res.json({
    ok: true,
    message: info.message + disabledNote,
    organisation: { id: info.orgId, name: info.orgName },
    aiCategory: info.aiCategory,
    detected,
    isEnabled: is_enabled,
  });
}

/*
 * The MSP key. Superadmin only, on every verb — it reads every client's DNS
 * traffic. The key itself never leaves the server: GET reports only whether one
 * is stored, and what the last Test found.
 */
app.get('/api/msp-integrations/dnsfilter', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    let r;
    try {
      r = await pool.query(
        'SELECT base_url, config_json, updated_at FROM msp_integrations WHERE provider = $1',
        [DNSFILTER_PROVIDER]
      );
    } catch (err) {
      if (err.code === '42P01') return res.json({ configured: false, migrationNeeded: true });
      throw err;
    }
    if (!r.rows.length) return res.json({ configured: false });
    const row = r.rows[0];
    res.json({ configured: true, base_url: row.base_url, config_json: row.config_json || {}, updated_at: row.updated_at });
  } catch (err) { return serverError(res, err); }
});

app.post('/api/msp-integrations/dnsfilter', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const base = validDnsFilterBase(req.body.base_url);
    if (!base) return res.status(400).json({ error: 'The DNSFilter API URL must be https on a dnsfilter.com host.' });
    const apiKey = typeof req.body.api_key === 'string' ? req.body.api_key.trim() : '';

    if (apiKey) {
      const { enc, iv } = encryptKey(apiKey);
      // A new key may see a different set of organisations: its verification
      // starts again from nothing.
      await pool.query(
        `INSERT INTO msp_integrations (provider, base_url, api_key_enc, api_key_iv, config_json, updated_by, updated_at)
         VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, NOW())
         ON CONFLICT (provider) DO UPDATE
           SET base_url = $2, api_key_enc = $3, api_key_iv = $4, config_json = '{}'::jsonb,
               updated_by = $5, updated_at = NOW()`,
        [DNSFILTER_PROVIDER, base, enc, iv, req.session.userId]
      );
    } else {
      const upd = await pool.query(
        'UPDATE msp_integrations SET base_url = $1, updated_by = $2, updated_at = NOW() WHERE provider = $3',
        [base, req.session.userId, DNSFILTER_PROVIDER]
      );
      if (!upd.rowCount) return res.status(400).json({ error: 'An API key is required.' });
    }
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '42P01') return res.status(503).json({ error: 'Run db/migrate-ai-visibility.sql first.' });
    return serverError(res, err);
  }
});

app.post('/api/msp-integrations/dnsfilter/test', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const msp = await loadMspDnsFilter();
    if (!msp) return res.status(404).json({ error: 'No DNSFilter MSP key is stored.' });
    let info;
    try {
      info = await dnsAdapter.testMspConnection({ base_url: msp.base_url, api_key: msp.api_key });
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }
    const config = {
      verified_at: new Date().toISOString(),
      organisations: info.organisations,
      ai_category_id: info.aiCategory ? info.aiCategory.id : null,
      ai_category_name: info.aiCategory ? info.aiCategory.name : null,
    };
    await pool.query(
      'UPDATE msp_integrations SET config_json = $1 WHERE provider = $2',
      [JSON.stringify(config), DNSFILTER_PROVIDER]
    );
    res.json({ ok: true, message: info.message, organisations: info.organisations, aiCategory: info.aiCategory });
  } catch (err) { return serverError(res, err); }
});

app.delete('/api/msp-integrations/dnsfilter', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM msp_integrations WHERE provider = $1', [DNSFILTER_PROVIDER]);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '42P01') return res.json({ ok: true });
    return serverError(res, err);
  }
});

/** POST /api/integrations/:provider/test — fetch 1 record to verify credentials */
app.post('/api/integrations/:provider/test', async (req, res) => {
  try {
    const provider = req.params.provider;
    if (!KNOWN_PROVIDERS.has(provider)) return res.status(400).json({ error: `Unknown provider: ${provider}` });
    const adapter = INTEGRATION_ADAPTERS[provider];

    const { tenantId, error } = resolveIntegrationTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    // Before the key is decrypted: this row holds no key of its own.
    if (provider === DNSFILTER_PROVIDER) return await testDnsFilterIntegration(res, tenantId);

    const row = await pool.query(
      'SELECT base_url, api_key_enc, api_key_iv, config_json, is_enabled FROM integrations WHERE tenant_id = $1 AND provider = $2',
      [tenantId, provider]
    );
    if (!row.rows.length) return res.status(404).json({ error: 'Integration not configured.' });

    const { base_url, api_key_enc, api_key_iv, config_json, is_enabled } = row.rows[0];
    const api_key = decryptKey(api_key_enc, api_key_iv);

    // Testing deliberately ignores is_enabled — you should be able to verify
    // credentials before switching an integration on. But a working connection
    // on a disabled integration is invisible to every screen and every sync, so
    // say so rather than returning a bare tick.
    const disabledNote = is_enabled ? '' :
      ' This integration is currently disabled — enable it to start syncing and to show data on its screens.';

    if (provider === REPORTS_PROVIDER) {
      await arcticWolfReportsAdapter.testConnection({ base_url, api_key, ...(config_json || {}) });
    } else if (provider === EDR_PROVIDER) {
      await sentinelOneAdapter.testConnection({ base_url, api_key, ...(config_json || {}) });
    } else if (provider === EMAIL_PROVIDER) {
      /*
       * A tick here is not enough. Acronis serves backup, DR and patching alerts
       * through the same endpoint, so credentials can be perfect while the
       * classifier reads none of what comes back as email security — which on
       * the tab looks identical to a quiet month.
       *
       * So the test reports what it actually saw: how many alert types came
       * back and how many were read as email. An operator who connects a tenant
       * and is told "0 of 7 types look like email security" knows to check the
       * Advanced Email Security licence, rather than waiting a week for a chart
       * that will never fill.
       */
      const probe = await acronisAdapter.testConnection({
        base_url, api_key, ...(config_json || {}),
      });
      const types = probe.typesSeen || [];
      const emailTypes = types.filter(t => t.isEmail);
      const note = types.length === 0
        ? ' No alerts were returned for this tenant, so nothing could be classified yet.'
        : ` ${emailTypes.length} of ${types.length} alert type(s) on the first page were read as email security.`;
      return res.json({
        ok: true,
        message: 'Connection successful.' + note + disabledNote,
        typesSeen: types,
        isEnabled: is_enabled,
      });
    } else if (provider === MSGRAPH_PROVIDER) {
      /*
       * As with Acronis, a bare tick is not enough — but the failure being
       * guarded against here is different and worse. Graph credentials that
       * authenticate perfectly can still be pointed at the WRONG DIRECTORY
       * (a partner app registration, a test tenant), in which case the
       * dashboard fills with a real, plausible, entirely unrelated client's
       * posture. Nothing downstream can detect that.
       *
       * So the directory id Microsoft answered with is echoed back for the
       * operator to check by eye, along with the score actually read.
       */
      const cfgAll = { base_url, api_key, ...(config_json || {}) };
      const identityOn = !!(config_json && config_json.identity_enabled);

      /*
       * Secure Score and Managed Identity share this registration but need
       * different permissions. With Identity switched on, a Secure Score
       * failure must not hide whether the Identity permissions work, so both
       * are tried and both reported.
       */
      let probe = null;
      let scoreError = null;
      try {
        probe = await msGraphAdapter.testConnection(cfgAll);
      } catch (err) {
        if (!identityOn) throw err;
        scoreError = err.message;
      }

      // Record the directory we saw. It is not a secret, and having it stored
      // lets the sync notice later if the credential starts answering for a
      // different tenant than the one that was verified here.
      const merged = Object.assign({}, config_json || {});
      if (probe && probe.azureTenantId) merged.verified_azure_tenant_id = probe.azureTenantId;

      /*
       * The Identity probe records which resources this tenant allows, and
       * starts the Office 365 audit subscriptions — the one write this
       * integration makes to a client tenant, so it happens here, on an
       * explicit operator action. identity_verified_tenant is what the sync
       * checks before collecting anything.
       */
      let identity = null;
      if (identityOn) {
        identity = await msIdentity.probe(cfgAll);
        merged.identity_probe = identity;
        if (identity.anyOk) merged.identity_verified_tenant = String(config_json.azure_tenant_id || '');
        else delete merged.identity_verified_tenant;
      }

      await pool.query(
        'UPDATE integrations SET config_json = $1 WHERE tenant_id = $2 AND provider = $3',
        [JSON.stringify(merged), tenantId, provider]
      );

      if (!probe && !(identity && identity.anyOk)) {
        return res.status(400).json({ ok: false, error: scoreError || 'Connection failed.' });
      }

      return res.json({
        ok: true,
        message: (probe ? probe.message : `Secure Score could not be read (${scoreError}).`) +
          (identity ? ' ' + msIdentity.describeProbe(identity) : '') + disabledNote,
        latest: probe ? probe.latest : null,
        azureTenantId: probe ? (probe.azureTenantId || null) : null,
        identity,
        isEnabled: is_enabled,
      });
    } else if (provider === FAZ_PROVIDER) {
      /*
       * The device list is the check that matters. A token that works against
       * the wrong ADOM fills the NDR screen with another client's real traffic,
       * and nothing downstream can tell. So the FortiGates found are echoed back
       * for the operator to confirm, and stored: every sync compares against
       * them and refuses an ADOM that shares none (fazAdapter.checkDevices).
       *
       * Test also re-pins the TLS certificate — the one explicit operator
       * action allowed to accept a changed one.
       */
      const cfg  = { ...fazAdapter.sanitiseStoredConfig(config_json || {}), base_url, api_key };
      const info = await fazAdapter.testConnection(cfg);

      let detected = null;
      try {
        detected = await fazAdapter.probe({ ...cfg, tlsFingerprint: info.tlsFingerprint || cfg.tlsFingerprint });
      } catch (probeErr) {
        console.warn('[fortianalyzer] probe failed after a successful connection —', probeErr.message);
      }

      const merged = Object.assign({}, config_json || {}, {
        verified_adom:    info.adom,
        verified_devices: info.devices.map(d => ({ name: d.name, sn: d.sn })),
        verified_at:      new Date().toISOString(),
        faz_version:      info.version,
      },
      info.tlsFingerprint ? { tlsFingerprint: info.tlsFingerprint } : {},
      detected ? { detected } : {});
      await pool.query(
        'UPDATE integrations SET config_json = $1 WHERE tenant_id = $2 AND provider = $3',
        [JSON.stringify(merged), tenantId, provider]
      );
      return res.json({
        ok: true,
        message: info.message + disabledNote,
        version: info.version,
        devices: info.devices,
        detected,
        isEnabled: is_enabled,
      });
    } else if (provider === WAZUH_PROVIDER) {
      const cfg  = { base_url, api_key, ...(config_json || {}) };
      const info = await wazuhAdapter.testConnection(cfg);

      // A successful test is the natural moment to work out which modules are
      // actually ingesting. The screens read this to decide whether a panel
      // draws a chart or explains why it can't — see detectModules().
      let detected = null;
      try {
        detected = await wazuhAdapter.detectModules({ ...cfg, tsField: info.tsField });
      } catch (probeErr) {
        console.warn('[wazuh] module probe failed after a successful connection —', probeErr.message);
      }

      const merged = {
        ...(config_json || {}),
        tsField: info.tsField,
        ...(info.tlsFingerprint ? { tlsFingerprint: info.tlsFingerprint } : {}),
        ...(detected ? { detected } : {}),
      };
      await pool.query(
        'UPDATE integrations SET config_json = $1 WHERE tenant_id = $2 AND provider = $3',
        [JSON.stringify(merged), tenantId, provider]
      );
      return res.json({ ok: true, message: info.message + disabledNote, detected, isEnabled: is_enabled });
    } else {
      await adapter.fetchTickets({ base_url, api_key, ...(config_json || {}) }, true);
    }
    res.json({ ok: true, message: 'Connection successful.' + disabledNote, isEnabled: is_enabled });
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
      /*
       * The click signal is called out explicitly.
       *
       * This feed is the only source of the phishing click rate, and when its
       * Clicked column changed shape the dashboard reported 99% without a word
       * of complaint. A sync that lands no click data now says so here, where
       * an admin looking at the integrations panel will see it, rather than
       * leaving the number on the Awareness tab to be believed.
       */
      [`Synced ${stats.totalRows} session row${stats.totalRows !== 1 ? 's' : ''}` +
       (stats.clickSource === 'absent'
         ? ' — no phishing click column in this export'
         : stats.clickUnknown
           ? ` — ${stats.clickUnknown} row${stats.clickUnknown !== 1 ? 's' : ''} with an unreadable click value`
           : ''),
       tenantId, provider]
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

/** Core sync logic for ticket-shaped providers (Arctic Wolf tickets).
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

    await writeMdrTickets(client, tenantId, tickets, userId);

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

/** Core sync logic for SentinelOne (Managed EDR).
 *  Pulls threats + activities incrementally (by the newest row already stored)
 *  and refreshes the agent fleet snapshot in full.
 *  Throws on failure; thrown errors carry `.httpStatus` for the HTTP route. */
async function runSentinelOneSync(tenantId) {
  const provider = EDR_PROVIDER;

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
  const config = { base_url, api_key: decryptKey(api_key_enc, api_key_iv), ...(config_json || {}) };

  // Resume from the newest row we already hold. A threat that changed verdict or
  // mitigation state comes back on updatedAt and overwrites its stored row.
  const watermarks = await pool.query(
    `SELECT (SELECT MAX(updated_at) FROM edr_threats    WHERE tenant_id = $1) AS threat_since,
            (SELECT MAX(created_at) FROM edr_activities WHERE tenant_id = $1) AS activity_since`,
    [tenantId]
  );
  const threatSince   = watermarks.rows[0].threat_since   ? new Date(watermarks.rows[0].threat_since).toISOString()   : null;
  const activitySince = watermarks.rows[0].activity_since ? new Date(watermarks.rows[0].activity_since).toISOString() : null;

  let threats, activities, agents;
  try {
    [threats, activities, agents] = await Promise.all([
      sentinelOneAdapter.fetchThreats(config,    { since: threatSince }),
      sentinelOneAdapter.fetchActivities(config, { since: activitySince }),
      sentinelOneAdapter.fetchAgents(config),
    ]);
  } catch (fetchErr) {
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [fetchErr.message, tenantId, provider]
    );
    fetchErr.httpStatus = 502;
    throw fetchErr;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const t of threats) {
      await client.query(
        `INSERT INTO edr_threats (
           tenant_id, threat_id, threat_name, classification, classification_source,
           confidence_level, analyst_verdict, incident_status, mitigation_status,
           detection_type, detection_engines, endpoint_name, endpoint_id, os_name,
           agent_version, site_name, group_name, file_path, file_hash, initiated_by,
           detected_at, mitigated_at, resolved_at, updated_at, raw_json, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,NOW())
         ON CONFLICT (tenant_id, threat_id) DO UPDATE SET
           threat_name = EXCLUDED.threat_name,
           classification = EXCLUDED.classification,
           classification_source = EXCLUDED.classification_source,
           confidence_level = EXCLUDED.confidence_level,
           analyst_verdict = EXCLUDED.analyst_verdict,
           incident_status = EXCLUDED.incident_status,
           mitigation_status = EXCLUDED.mitigation_status,
           detection_type = EXCLUDED.detection_type,
           detection_engines = EXCLUDED.detection_engines,
           endpoint_name = EXCLUDED.endpoint_name,
           endpoint_id = EXCLUDED.endpoint_id,
           os_name = EXCLUDED.os_name,
           agent_version = EXCLUDED.agent_version,
           site_name = EXCLUDED.site_name,
           group_name = EXCLUDED.group_name,
           file_path = EXCLUDED.file_path,
           file_hash = EXCLUDED.file_hash,
           initiated_by = EXCLUDED.initiated_by,
           detected_at = EXCLUDED.detected_at,
           mitigated_at = EXCLUDED.mitigated_at,
           resolved_at = EXCLUDED.resolved_at,
           updated_at = EXCLUDED.updated_at,
           raw_json = EXCLUDED.raw_json,
           synced_at = NOW()`,
        [tenantId, t.threatId, t.threatName, t.classification, t.classificationSource,
         t.confidenceLevel, t.analystVerdict, t.incidentStatus, t.mitigationStatus,
         t.detectionType, t.detectionEngines, t.endpointName, t.endpointId, t.osName,
         t.agentVersion, t.siteName, t.groupName, t.filePath, t.fileHash, t.initiatedBy,
         t.detectedAt, t.mitigatedAt, t.resolvedAt, t.updatedAt, JSON.stringify(t.raw)]
      );
    }

    for (const a of activities) {
      await client.query(
        `INSERT INTO edr_activities (
           tenant_id, activity_id, activity_type, activity_type_name, primary_description,
           secondary_description, endpoint_name, endpoint_id, site_name, group_name,
           user_name, threat_id, created_at, raw_json, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW())
         ON CONFLICT (tenant_id, activity_id) DO NOTHING`,
        [tenantId, a.activityId, a.activityType, a.activityTypeName, a.primaryDescription,
         a.secondaryDescription, a.endpointName, a.endpointId, a.siteName, a.groupName,
         a.userName, a.threatId, a.createdAt, JSON.stringify(a.raw)]
      );
    }

    for (const g of agents) {
      await client.query(
        `INSERT INTO edr_agents (
           tenant_id, agent_id, computer_name, os_name, os_type, agent_version,
           machine_type, domain, site_name, group_name, is_active, is_infected,
           is_up_to_date, network_status, scan_status, active_threats,
           last_active_at, registered_at, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
         ON CONFLICT (tenant_id, agent_id) DO UPDATE SET
           computer_name = EXCLUDED.computer_name,
           os_name = EXCLUDED.os_name,
           os_type = EXCLUDED.os_type,
           agent_version = EXCLUDED.agent_version,
           machine_type = EXCLUDED.machine_type,
           domain = EXCLUDED.domain,
           site_name = EXCLUDED.site_name,
           group_name = EXCLUDED.group_name,
           is_active = EXCLUDED.is_active,
           is_infected = EXCLUDED.is_infected,
           is_up_to_date = EXCLUDED.is_up_to_date,
           network_status = EXCLUDED.network_status,
           scan_status = EXCLUDED.scan_status,
           active_threats = EXCLUDED.active_threats,
           last_active_at = EXCLUDED.last_active_at,
           registered_at = EXCLUDED.registered_at,
           synced_at = NOW()`,
        [tenantId, g.agentId, g.computerName, g.osName, g.osType, g.agentVersion,
         g.machineType, g.domain, g.siteName, g.groupName, g.isActive, g.isInfected,
         g.isUpToDate, g.networkStatus, g.scanStatus, g.activeThreats,
         g.lastActiveAt, g.registeredAt]
      );
    }

    // Agents is always a full pull, so anything not touched by this run has been
    // decommissioned in the console and should drop out of the fleet metrics.
    if (agents.length > 0) {
      await client.query(
        `DELETE FROM edr_agents WHERE tenant_id = $1 AND synced_at < NOW() - INTERVAL '1 minute'`,
        [tenantId]
      );
    }

    const message = `Synced ${threats.length} threat${threats.length !== 1 ? 's' : ''}, `
      + `${activities.length} activit${activities.length !== 1 ? 'ies' : 'y'}, ${agents.length} agent${agents.length !== 1 ? 's' : ''}`;

    await client.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'ok', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [message, tenantId, provider]
    );

    await client.query('COMMIT');
    console.log(`[integrations] ${provider} sync: ${message} for tenant ${tenantId}`);
    return { ok: true, synced: threats.length, threats: threats.length, activities: activities.length, agents: agents.length };
  } catch (dbErr) {
    await client.query('ROLLBACK').catch(() => {});
    throw dbErr;
  } finally {
    client.release();
  }
}

/**
 * Core sync logic for Acronis (Managed Email Security).
 *
 * Pulls alerts incrementally from the newest updated_at already stored, keeps
 * the ones the classifier reads as email security, and records EVERY alert type
 * it saw — including the ones it rejected — so a classifier gap is visible in
 * the tab instead of showing up as a chart that quietly stops rising.
 *
 * Throws on failure; thrown errors carry `.httpStatus` for the HTTP route.
 */
async function runAcronisSync(tenantId) {
  const provider = EMAIL_PROVIDER;

  if (!await hasEmailTables()) {
    const err = new Error('Email security tables are not present — run db/migrate-email-security.sql.');
    err.httpStatus = 503;
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
  const config = { base_url, api_key: decryptKey(api_key_enc, api_key_iv), ...(config_json || {}) };

  /*
   * Resume from the newest alert we already hold, on updated_at rather than
   * created_at: an alert that was later dismissed or reclassified comes back
   * and overwrites its stored row. Watermarking on created_at would pull it
   * once and never see the change.
   */
  const watermark = await pool.query(
    'SELECT MAX(updated_at) AS since FROM email_alerts WHERE tenant_id = $1',
    [tenantId]
  );
  const since = watermark.rows[0].since ? new Date(watermark.rows[0].since).toISOString() : null;

  let result;
  try {
    result = await acronisAdapter.fetchAlerts(config, { since });
  } catch (fetchErr) {
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [fetchErr.message, tenantId, provider]
    );
    fetchErr.httpStatus = 502;
    throw fetchErr;
  }

  const { alerts, typesSeen, truncated } = result;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const a of alerts) {
      await client.query(
        `INSERT INTO email_alerts (
           tenant_id, alert_id, alert_type, category, severity, threat_class,
           disposition, recipient, recipient_domain, sender, sender_domain,
           subject, created_at, updated_at, received_at, resolved_at,
           alert_status, raw_json, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,NOW())
         ON CONFLICT (tenant_id, alert_id) DO UPDATE SET
           alert_type       = EXCLUDED.alert_type,
           category         = EXCLUDED.category,
           severity         = EXCLUDED.severity,
           threat_class     = EXCLUDED.threat_class,
           disposition      = EXCLUDED.disposition,
           recipient        = EXCLUDED.recipient,
           recipient_domain = EXCLUDED.recipient_domain,
           sender           = EXCLUDED.sender,
           sender_domain    = EXCLUDED.sender_domain,
           subject          = EXCLUDED.subject,
           updated_at       = EXCLUDED.updated_at,
           received_at      = EXCLUDED.received_at,
           resolved_at      = EXCLUDED.resolved_at,
           alert_status     = EXCLUDED.alert_status,
           raw_json         = EXCLUDED.raw_json,
           synced_at        = NOW()`,
        [tenantId, a.alertId, a.alertType, a.category, a.severity, a.threatClass,
         a.disposition, a.recipient, a.recipientDomain, a.sender, a.senderDomain,
         a.subject, a.createdAt, a.updatedAt, a.receivedAt, a.resolvedAt,
         a.status, JSON.stringify(a.raw)]);
    }

    // The ledger of what was seen, email or not. seen_count accumulates across
    // syncs; is_email is overwritten, so teaching the classifier a new keyword
    // and re-syncing flips the type from unrecognised to recognised in place.
    for (const t of typesSeen) {
      await client.query(
        `INSERT INTO email_alert_types_seen
           (tenant_id, alert_type, category, is_email, seen_count, first_seen_at, last_seen_at)
         VALUES ($1,$2,$3,$4,$5,NOW(),NOW())
         ON CONFLICT (tenant_id, alert_type) DO UPDATE SET
           category     = EXCLUDED.category,
           is_email     = EXCLUDED.is_email,
           seen_count   = email_alert_types_seen.seen_count + EXCLUDED.seen_count,
           last_seen_at = NOW()`,
        [tenantId, t.alertType, t.category, t.isEmail, t.count]);
    }

    const unrecognised = typesSeen.filter(t => !t.isEmail).length;
    let message = `Synced ${alerts.length} email alert${alerts.length !== 1 ? 's' : ''}`
      + ` from ${typesSeen.length} alert type(s); ${unrecognised} type(s) were not read as email security`;
    // A capped pull is reported as capped. Silently returning the first N pages
    // would look like a quiet period rather than a partial sync.
    if (truncated) message += '. PAGE LIMIT REACHED — this sync is partial; run it again to continue';

    await client.query(
      `UPDATE integrations SET last_synced_at = NOW(),
              last_sync_status = $1, last_sync_message = $2
       WHERE tenant_id = $3 AND provider = $4`,
      [truncated ? 'partial' : 'ok', message, tenantId, provider]
    );

    await client.query('COMMIT');
    console.log(`[integrations] ${provider} sync: ${message} for tenant ${tenantId}`);
    return {
      ok: true, synced: alerts.length, alerts: alerts.length,
      typesSeen: typesSeen.length, unrecognisedTypes: unrecognised,
      truncated, message,
    };
  } catch (dbErr) {
    await client.query('ROLLBACK').catch(() => {});
    throw dbErr;
  } finally {
    client.release();
  }
}

/**
 * Microsoft Secure Score sync.
 *
 * Writes up to ~90 daily snapshots (Graph's own retention) plus the per-control
 * detail for the NEWEST snapshot only — see db/migrate-ms-secure-score.sql for
 * why per-control history is not kept.
 *
 * There is no watermark here, unlike the Acronis sync. Microsoft RESTATES
 * history: maxScore changes when controls are published, and an already-stored
 * day's snapshot legitimately comes back different. Resuming from the newest
 * date we hold would pin every earlier day to whatever it was on first sync,
 * so every returned snapshot is upserted every time. Ninety small rows a day is
 * a price worth paying for a trend that stays true.
 */
async function runMsGraphSync(tenantId) {
  const provider = MSGRAPH_PROVIDER;

  if (!await hasMsScoreTables()) {
    const err = new Error('Microsoft Secure Score tables are not present — run db/migrate-ms-secure-score.sql.');
    err.httpStatus = 503;
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
  const cfg = config_json || {};
  const config = { base_url, api_key: decryptKey(api_key_enc, api_key_iv), ...cfg };

  let result;
  try {
    result = await msGraphAdapter.fetchAll(config, {});
  } catch (fetchErr) {
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'error', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [fetchErr.message, tenantId, provider]
    );
    fetchErr.httpStatus = 502;
    throw fetchErr;
  }

  const { snapshots, latest, controls, truncated } = result;
  const warnings = [...(result.warnings || [])];

  if (!snapshots.length) {
    const message = 'Connected, but Microsoft has published no Secure Score snapshots for this tenant.';
    await pool.query(
      `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = 'no_data', last_sync_message = $1
       WHERE tenant_id = $2 AND provider = $3`,
      [message, tenantId, provider]
    );
    return { ok: true, synced: 0, snapshots: 0, controls: 0, message, warnings };
  }

  /*
   * The directory check promised by the Test button.
   *
   * A credential that starts answering for a different Azure directory than the
   * one an operator verified is either a rotated app registration or a
   * misconfiguration, and the data it returns is some other organisation's
   * posture. Warn loudly and keep going — refusing to sync would strand a
   * client whose directory id legitimately changed (a tenant migration), and
   * this is a claim for a human to adjudicate, not for the sync to enforce.
   */
  const seenDirectory = latest && latest.azureTenantId;
  if (cfg.verified_azure_tenant_id && seenDirectory &&
      String(cfg.verified_azure_tenant_id).toLowerCase() !== String(seenDirectory).toLowerCase()) {
    warnings.push('DIRECTORY MISMATCH — this credential now answers for Azure directory ' +
      seenDirectory + ', not the ' + cfg.verified_azure_tenant_id +
      ' that was verified. Confirm the app registration before trusting these figures.');
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    for (const s of snapshots) {
      await client.query(
        `INSERT INTO ms_secure_scores (
           tenant_id, score_date, current_score, max_score, azure_tenant_id,
           active_user_count, licensed_user_count, enabled_services,
           comparative_json, raw_json, synced_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
         ON CONFLICT (tenant_id, score_date) DO UPDATE SET
           current_score       = EXCLUDED.current_score,
           max_score           = EXCLUDED.max_score,
           azure_tenant_id     = EXCLUDED.azure_tenant_id,
           active_user_count   = EXCLUDED.active_user_count,
           licensed_user_count = EXCLUDED.licensed_user_count,
           enabled_services    = EXCLUDED.enabled_services,
           comparative_json    = EXCLUDED.comparative_json,
           raw_json            = EXCLUDED.raw_json,
           synced_at           = NOW()`,
        [tenantId, s.scoreDate, s.currentScore, s.maxScore, s.azureTenantId,
         s.activeUserCount, s.licensedUserCount,
         JSON.stringify(s.enabledServices || []),
         JSON.stringify(s.comparative || []),
         JSON.stringify(s.raw)]);
    }

    /*
     * Controls are REPLACED for the day being written, not merged.
     *
     * A control that disappears from Microsoft's snapshot — retired, or no
     * longer applicable after a licence change — must disappear from the
     * remediation list too. An upsert-only pass would leave it sitting there
     * forever at its last known score, and a stale control is worse than a
     * missing one: somebody works the item and nothing moves.
     */
    if (latest && controls.length) {
      await client.query(
        'DELETE FROM ms_secure_score_controls WHERE tenant_id = $1 AND score_date = $2',
        [tenantId, latest.scoreDate]);

      for (const c of controls) {
        await client.query(
          `INSERT INTO ms_secure_score_controls (
             tenant_id, score_date, control_name, control_category, score,
             score_in_percentage, implementation_status, description,
             title, max_score, rank, tier, service, action_type, action_url,
             remediation, remediation_impact, user_impact, implementation_cost,
             threats, deprecated, control_state, raw_json, synced_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,NOW())
           ON CONFLICT (tenant_id, score_date, control_name) DO UPDATE SET
             control_category      = EXCLUDED.control_category,
             score                 = EXCLUDED.score,
             score_in_percentage   = EXCLUDED.score_in_percentage,
             implementation_status = EXCLUDED.implementation_status,
             description           = EXCLUDED.description,
             title                 = EXCLUDED.title,
             max_score             = EXCLUDED.max_score,
             rank                  = EXCLUDED.rank,
             tier                  = EXCLUDED.tier,
             service               = EXCLUDED.service,
             action_type           = EXCLUDED.action_type,
             action_url            = EXCLUDED.action_url,
             remediation           = EXCLUDED.remediation,
             remediation_impact    = EXCLUDED.remediation_impact,
             user_impact           = EXCLUDED.user_impact,
             implementation_cost   = EXCLUDED.implementation_cost,
             threats               = EXCLUDED.threats,
             deprecated            = EXCLUDED.deprecated,
             control_state         = EXCLUDED.control_state,
             raw_json              = EXCLUDED.raw_json,
             synced_at             = NOW()`,
          [tenantId, latest.scoreDate, c.controlName, c.controlCategory, c.score,
           c.scoreInPercentage, c.implementationStatus, c.description,
           c.title, c.maxScore, c.rank, c.tier, c.service, c.actionType, c.actionUrl,
           c.remediation, c.remediationImpact, c.userImpact, c.implementationCost,
           JSON.stringify(c.threats || []), c.deprecated, c.controlState,
           JSON.stringify(c.raw)]);
      }
    }

    const pct = msGraphAdapter.percentage(latest.currentScore, latest.maxScore);
    let message = `Synced ${snapshots.length} snapshot(s) and ${controls.length} control(s);`
      + ` latest ${latest.scoreDate} = ${latest.currentScore ?? '?'}/${latest.maxScore ?? '?'}`
      + (pct === null ? '' : ` (${pct}%)`);
    if (warnings.length) message += '. ' + warnings.join(' ');

    // A partial pull is reported as partial, and a warning is not an "ok".
    const status = truncated ? 'partial' : (warnings.length ? 'partial' : 'ok');

    await client.query(
      `UPDATE integrations SET last_synced_at = NOW(),
              last_sync_status = $1, last_sync_message = $2
       WHERE tenant_id = $3 AND provider = $4`,
      [status, message, tenantId, provider]
    );

    await client.query('COMMIT');
    console.log(`[integrations] ${provider} sync: ${message} for tenant ${tenantId}`);
    return {
      ok: true,
      synced: snapshots.length,
      snapshots: snapshots.length,
      controls: controls.length,
      latest: {
        scoreDate: latest.scoreDate,
        currentScore: latest.currentScore,
        maxScore: latest.maxScore,
        percentage: pct,
      },
      truncated, warnings, message,
    };
  } catch (dbErr) {
    await client.query('ROLLBACK').catch(() => {});
    throw dbErr;
  } finally {
    client.release();
  }
}

/** Load an enabled Wazuh integration row with its key decrypted, or throw.
 *  The thrown error carries `.reason` so callers can tell a missing integration
 *  apart from one that exists but is switched off — those need completely
 *  different things from the operator, and collapsing them into "no data yet"
 *  sends people hunting for a connection problem they do not have. */
async function loadWazuhIntegration(tenantId) {
  const row = await pool.query(
    `SELECT id, tenant_id, base_url, api_key_enc, api_key_iv, config_json, is_enabled
       FROM integrations WHERE tenant_id = $1 AND provider = $2`,
    [tenantId, WAZUH_PROVIDER]
  );
  if (!row.rows.length) {
    const err = new Error('Wazuh integration not configured.');
    err.httpStatus = 404;
    err.reason = 'not_configured';
    throw err;
  }
  if (!row.rows[0].is_enabled) {
    const err = new Error('Wazuh integration is disabled.');
    err.httpStatus = 409;
    err.reason = 'disabled';
    throw err;
  }
  const r = row.rows[0];
  return {
    id:        r.id,
    tenant_id: r.tenant_id,
    base_url:  r.base_url,
    api_key:   decryptKey(r.api_key_enc, r.api_key_iv),
    config:    r.config_json || {},
  };
}

/** Config object the adapter expects, assembled from the integration row. */
function wazuhConfig(integration) {
  return Object.assign({}, integration.config, {
    base_url: integration.base_url,
    api_key:  integration.api_key,
    // Stable shard routing per tenant, so cardinality/terms approximations do
    // not jitter between refreshes. Users notice numbers moving on a reload.
    preference: `secops-${integration.tenant_id}`,
  });
}

/** Core sync for Wazuh: snapshot yesterday plus any day the backfill window
 *  says is missing, errored or partial. Idempotent by construction — see
 *  lib/wazuh-metrics.js writeBag(). */
async function runWazuhRollupSync(tenantId) {
  const integration = await loadWazuhIntegration(tenantId);
  const tz   = integration.config.timeZone || 'UTC';
  const days = await wazuhMetrics.daysNeedingSnapshot(pool, integration.id, tz);

  let rows = 0;
  const failures = [];
  for (const day of days) {
    try {
      const r = await wazuhMetrics.snapshotDay(pool, integration, day);
      rows += r.rows;
    } catch (err) {
      failures.push(`${day}: ${err.message}`);
    }
  }

  const ok = failures.length === 0;
  const message = ok
    ? `Snapshotted ${days.length} day${days.length !== 1 ? 's' : ''} (${rows} metric rows)`
    : `Snapshotted ${days.length - failures.length}/${days.length} days — ${failures[0]}`;

  await pool.query(
    `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = $1, last_sync_message = $2
      WHERE tenant_id = $3 AND provider = $4`,
    [ok ? 'ok' : 'error', message, tenantId, WAZUH_PROVIDER]
  );

  console.log(`[integrations] wazuh rollup: ${message} for tenant ${tenantId}`);
  return { ok, synced: rows, days: days.length, message };
}

/** Load an enabled FortiAnalyzer integration, or throw with `.reason` — the
 *  same contract as loadWazuhIntegration(). Stored config is sanitised so
 *  nothing in the database can install an adapter test seam. */
async function loadFortiAnalyzerIntegration(tenantId) {
  const row = await pool.query(
    `SELECT id, tenant_id, base_url, api_key_enc, api_key_iv, config_json, is_enabled,
            last_synced_at, last_sync_status, last_sync_message
       FROM integrations WHERE tenant_id = $1 AND provider = $2`,
    [tenantId, FAZ_PROVIDER]
  );
  if (!row.rows.length) {
    throw Object.assign(new Error('FortiAnalyzer integration not configured.'),
      { httpStatus: 404, reason: 'not_configured' });
  }
  const r = row.rows[0];
  if (!r.is_enabled) {
    throw Object.assign(new Error('FortiAnalyzer integration is disabled.'),
      { httpStatus: 409, reason: 'disabled' });
  }
  return {
    id:        r.id,
    tenant_id: r.tenant_id,
    base_url:  r.base_url,
    api_key:   decryptKey(r.api_key_enc, r.api_key_iv),
    config:    fazAdapter.sanitiseStoredConfig(r.config_json || {}),
    sync: {
      last_synced_at:    r.last_synced_at,
      last_sync_status:  r.last_sync_status,
      last_sync_message: r.last_sync_message,
    },
  };
}

async function recordFortiAnalyzerSync(tenantId, status, message) {
  await pool.query(
    `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = $1, last_sync_message = $2
      WHERE tenant_id = $3 AND provider = $4`,
    [status, message, tenantId, FAZ_PROVIDER]
  );
}

/** The Graph integration row with Managed Identity switched on, or throw with `.reason`. */
async function loadIdentityIntegration(tenantId) {
  const row = await pool.query(
    `SELECT id, tenant_id, base_url, api_key_enc, api_key_iv, config_json, is_enabled
       FROM integrations WHERE tenant_id = $1 AND provider = $2`,
    [tenantId, MSGRAPH_PROVIDER]
  );
  const r = row.rows[0];
  // Graph configured for Secure Score only is "not configured" for Identity,
  // so the screen falls back to Wazuh rather than claiming to be switched off.
  if (!r || !(r.config_json && r.config_json.identity_enabled)) {
    throw Object.assign(new Error('Managed Identity collection is not switched on.'),
      { httpStatus: 404, reason: 'not_configured' });
  }
  if (!r.is_enabled) {
    throw Object.assign(new Error('The Microsoft Graph integration is disabled.'),
      { httpStatus: 409, reason: 'disabled' });
  }
  return {
    id:        r.id,
    tenant_id: r.tenant_id,
    base_url:  r.base_url,
    api_key:   decryptKey(r.api_key_enc, r.api_key_iv),
    config:    r.config_json || {},
  };
}

/**
 * The last Identity collection, from its rollup bookkeeping. The integration
 * row's last_sync_* columns belong to the Secure Score sync on the same row,
 * and sharing them would let one overwrite the other's status.
 */
async function identitySyncMeta(integrationId) {
  try {
    const r = await pool.query(
      `SELECT ran_at, status, message FROM wazuh_rollup_run
        WHERE integration_id = $1 AND source = ANY($2::text[])
        ORDER BY ran_at DESC LIMIT 1`,
      [integrationId, identityMetrics.SOURCES]
    );
    if (!r.rows.length) return null;
    const row = r.rows[0];
    return {
      last_synced_at: row.ran_at,
      last_sync_status: ['ok', 'no_data', 'partial_day'].includes(row.status) ? 'ok' : 'error',
      last_sync_message: row.message,
    };
  } catch (err) {
    if (err.code === '42P01') return null;
    throw err;
  }
}

const identitySyncInProgress = new Set();

/**
 * Collect Managed Identity telemetry for one tenant.
 *
 * Refused unless Test has verified Identity against THIS directory: a mistyped
 * directory id that happens to be another real tenant where the app has
 * consent would otherwise fill the screen with someone else's sign-ins.
 */
async function runIdentitySync(tenantId) {
  if (identitySyncInProgress.has(tenantId)) {
    return { ok: false, message: 'A Managed Identity sync for this client is already running.' };
  }
  identitySyncInProgress.add(tenantId);
  try {
    const integration = await loadIdentityIntegration(tenantId);
    const conf = integration.config;
    const configured = String(conf.azure_tenant_id || '').toLowerCase();

    if (!conf.identity_verified_tenant || String(conf.identity_verified_tenant).toLowerCase() !== configured) {
      throw Object.assign(new Error(
        'Managed Identity has not been verified for this directory. Run Test Connection on the ' +
        'Microsoft Graph integration under Admin → Integrations before syncing.'), { httpStatus: 409 });
    }
    if (conf.verified_azure_tenant_id && String(conf.verified_azure_tenant_id).toLowerCase() !== configured) {
      throw Object.assign(new Error(
        'Microsoft answered for a different directory than the one configured. Sync stopped — ' +
        'check the Directory (tenant) ID and re-test.'), { httpStatus: 409 });
    }

    const tz = conf.identity_time_zone || 'UTC';
    const days = await identityMetrics.daysNeedingSnapshot(pool, integration.id, tz);

    let rows = 0;
    const problems = [];
    for (const day of days) {
      try {
        const r = await identityMetrics.snapshotDay(pool, integration, day, { timeZone: tz });
        rows += r.rows;
        if (r.problems.length) problems.push(`${day}: ${r.problems.join(', ')}`);
      } catch (err) {
        problems.push(`${day}: ${err.message}`);
      }
    }

    for (const key of [...wazuhCache.keys()]) {
      if (key.indexOf(`idn:${integration.id}:`) === 0) wazuhCache.delete(key);
    }

    const ok = problems.length === 0;
    const message = `Collected ${days.length} day${days.length !== 1 ? 's' : ''} (${rows} metric rows)` +
      (ok ? '' : ` — not everything could be read: ${problems[0]}`);
    console.log(`[integrations] managed identity: ${message} for tenant ${tenantId}`);
    return { ok, synced: rows, days: days.length, message };
  } finally {
    identitySyncInProgress.delete(tenantId);
  }
}

const fazSyncInProgress = new Set();

/**
 * Collect FortiAnalyzer telemetry for one tenant into the daily rollups.
 *
 * Two refusals come BEFORE any day is collected, because both mean the data
 * could belong to someone else:
 *   - the ADOM has not been verified by Test (or changed since it was);
 *   - the ADOM's FortiGates share none of the verified devices.
 */
async function runFortiAnalyzerSync(tenantId) {
  if (fazSyncInProgress.has(tenantId)) {
    return { ok: false, message: 'A FortiAnalyzer sync for this client is already running.' };
  }
  fazSyncInProgress.add(tenantId);
  try {
    const integration = await loadFortiAnalyzerIntegration(tenantId);
    const conf = integration.config;

    if (!conf.verified_adom || conf.verified_adom !== conf.adom) {
      const msg = 'This ADOM has not been verified. Run Test connection under Admin → Integrations before syncing.';
      await recordFortiAnalyzerSync(tenantId, 'error', msg);
      throw Object.assign(new Error(msg), { httpStatus: 409 });
    }

    const cfg = Object.assign({}, conf, { base_url: integration.base_url, api_key: integration.api_key });

    let warning = null;
    try {
      warning = (await fazAdapter.checkDevices(cfg, conf.verified_devices)).warning;
    } catch (err) {
      await recordFortiAnalyzerSync(tenantId, 'error', err.message);
      throw err;
    }

    const tz    = conf.timeZone || 'UTC';
    const today = wazuhMetrics.localDay(new Date(), tz);
    const days  = await fazMetrics.daysNeedingSnapshot(pool, integration.id, tz);

    let rows = 0;
    const failures = [];
    for (const day of days) {
      try {
        const r = await fazMetrics.snapshotDay(pool, integration, day, { isToday: day === today });
        rows += r.rows;
        if (r.error) failures.push(`${day}: ${r.error}`);
        else if (r.partialPanels.length) failures.push(`${day}: panels unavailable (${r.partialPanels.join(', ')})`);
      } catch (err) {
        failures.push(`${day}: ${err.message}`);
      }
    }

    const ok = failures.length === 0;
    const message = (ok
      ? `Collected ${days.length} day${days.length !== 1 ? 's' : ''} (${rows} metric rows)`
      : `Collected ${days.length} day${days.length !== 1 ? 's' : ''} with problems — ${failures[0]}`) +
      (warning ? ' ' + warning : '');

    await recordFortiAnalyzerSync(tenantId, ok ? 'ok' : 'error', message);

    // The screen caches for 45 seconds; a fresh collection should show at once.
    for (const key of [...wazuhCache.keys()]) {
      if (key.indexOf(`faz:${integration.id}:`) === 0) wazuhCache.delete(key);
    }

    console.log(`[integrations] fortianalyzer: ${message} for tenant ${tenantId}`);
    return { ok, synced: rows, days: days.length, message };
  } finally {
    fazSyncInProgress.delete(tenantId);
  }
}

/**
 * The client's DNSFilter row with the MSP key attached, or throw with `.reason`.
 * The AI category comes from the client's own Test when it ran, else from the
 * MSP Test — both resolved by name, never hard-coded.
 */
async function loadDnsFilterIntegration(tenantId) {
  const row = await pool.query(
    `SELECT id, tenant_id, config_json, is_enabled, last_synced_at, last_sync_status, last_sync_message
       FROM integrations WHERE tenant_id = $1 AND provider = $2`,
    [tenantId, DNSFILTER_PROVIDER]
  );
  if (!row.rows.length) {
    throw Object.assign(new Error('DNSFilter is not configured for this client.'),
      { httpStatus: 404, reason: 'not_configured' });
  }
  const r = row.rows[0];
  if (!r.is_enabled) {
    throw Object.assign(new Error('The DNSFilter integration is disabled.'),
      { httpStatus: 409, reason: 'disabled' });
  }
  const msp = await loadMspDnsFilter();
  if (!msp) {
    throw Object.assign(new Error('The DNSFilter MSP key is not configured.'),
      { httpStatus: 409, reason: 'msp_not_configured' });
  }
  const conf = dnsAdapter.sanitiseStoredConfig(r.config_json || {});
  return {
    id:        r.id,
    tenant_id: r.tenant_id,
    base_url:  msp.base_url,
    api_key:   msp.api_key,
    config:    Object.assign({}, conf, {
      aiCategoryId: conf.verified_ai_category_id || msp.config.ai_category_id || null,
    }),
    sync: {
      last_synced_at:    r.last_synced_at,
      last_sync_status:  r.last_sync_status,
      last_sync_message: r.last_sync_message,
    },
  };
}

async function recordDnsFilterSync(tenantId, status, message) {
  await pool.query(
    `UPDATE integrations SET last_synced_at = NOW(), last_sync_status = $1, last_sync_message = $2
      WHERE tenant_id = $3 AND provider = $4`,
    [status, message, tenantId, DNSFILTER_PROVIDER]
  );
}

/** Drop this client's cached AI Visibility screens (after a sync or a decision). */
function clearAiCache(tenantId) {
  for (const key of [...wazuhCache.keys()]) {
    if (key.indexOf(`ai:${tenantId}:`) === 0) wazuhCache.delete(key);
  }
}

const dnsSyncInProgress = new Set();

/**
 * Collect AI Visibility telemetry for one tenant.
 *
 * Refused unless Test has verified THIS organisation id: every client shares
 * the MSP key, so the organisation id is the only thing between one client's
 * tab and another's traffic.
 */
async function runDnsFilterSync(tenantId) {
  if (dnsSyncInProgress.has(tenantId)) {
    return { ok: false, message: 'A DNSFilter sync for this client is already running.' };
  }
  dnsSyncInProgress.add(tenantId);
  try {
    const integration = await loadDnsFilterIntegration(tenantId);
    const conf = integration.config;

    if (!conf.verified_org_id || String(conf.verified_org_id) !== String(conf.organization_id)) {
      const msg = 'This DNSFilter organisation has not been verified. Run Test Connection under Admin → Integrations before syncing.';
      await recordDnsFilterSync(tenantId, 'error', msg);
      throw Object.assign(new Error(msg), { httpStatus: 409 });
    }

    const tz = conf.timeZone || 'UTC';
    const days = await dnsMetrics.daysNeedingSnapshot(pool, integration.id, tz);

    let rows = 0;
    const problems = [];
    for (const day of days) {
      try {
        const r = await dnsMetrics.snapshotDay(pool, integration, day);
        rows += r.rows;
        if (r.problems.length) problems.push(`${day}: ${r.problems.join(', ')}`);
      } catch (err) {
        problems.push(`${day}: ${err.message}`);
      }
    }

    const ok = problems.length === 0;
    const message = `Collected ${days.length} day${days.length !== 1 ? 's' : ''} (${rows} metric rows)` +
      (ok ? '' : ` — not everything could be read: ${problems[0]}`);
    await recordDnsFilterSync(tenantId, ok ? 'ok' : 'error', message);
    clearAiCache(tenantId);

    console.log(`[integrations] dnsfilter: ${message} for tenant ${tenantId}`);
    return { ok, synced: rows, days: days.length, message };
  } finally {
    dnsSyncInProgress.delete(tenantId);
  }
}

/** POST /api/integrations/:provider/sync — fetch fresh data from the provider and store it */
app.post('/api/integrations/:provider/sync', async (req, res) => {
  const provider = req.params.provider;
  const { tenantId, error } = resolveIntegrationTenant(req, 'body');
  if (error) return res.status(error.status).json({ error: error.message });

  try {
    let result;
    if (provider === REPORTS_PROVIDER)     result = await runArcticWolfReportsSync(tenantId, req.session.userId);
    else if (provider === EDR_PROVIDER)    result = await runSentinelOneSync(tenantId);
    else if (provider === WAZUH_PROVIDER)  result = await runWazuhRollupSync(tenantId);
    else if (provider === FAZ_PROVIDER)    result = await runFortiAnalyzerSync(tenantId);
    else if (provider === DNSFILTER_PROVIDER) result = await runDnsFilterSync(tenantId);
    else if (provider === IDENTITY_SYNC_PROVIDER) result = await runIdentitySync(tenantId);
    else if (provider === EMAIL_PROVIDER)  result = await runAcronisSync(tenantId);
    else if (provider === MSGRAPH_PROVIDER) result = await runMsGraphSync(tenantId);
    else                                   result = await runTicketIntegrationSync(provider, tenantId, req.session.userId);
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
    // SentinelOne, Wazuh, Acronis and Microsoft Graph are excluded — each runs
    // on its own cadence below. A provider missing from this list would be
    // swept into runTicketIntegrationSync, which would call fetchTickets on an
    // adapter that has no such method.
    rows = (await pool.query(
      'SELECT tenant_id, provider FROM integrations WHERE is_enabled = TRUE AND provider <> ALL($1::text[])',
      [[EDR_PROVIDER, WAZUH_PROVIDER, EMAIL_PROVIDER, MSGRAPH_PROVIDER]]
    )).rows;
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

      // Same credentials, different reports: warm the client-deck Overview tiles
      // that only Arctic Wolf can supply. Never allowed to fail the main sync.
      if (provider === REPORTS_PROVIDER) {
        try {
          const period = new Date().toISOString().slice(0, 7);
          const m = await arcticWolfMetricsAdapter.syncDeckMetrics({
            pool, tenantId, period, decrypt: decryptKey,
          });
          console.log(`[integrations] deck metrics: wrote ${m.written} for tenant ${tenantId} (${period})`);
          (m.warnings || []).forEach(w => console.log(`[integrations] deck metrics: ${w}`));
        } catch (metricsErr) {
          console.error(`[integrations] deck metrics failed for tenant ${tenantId} — ${metricsErr.message}`);
        }
      }
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

// ── Report archive housekeeping ────────────────────────────────────────────
// The sweep runs once at boot: a publish that crashed between writing the file
// and committing the row leaves an orphan, and only the database can tell an
// orphan from a live artefact. The prune unlinks superseded and withdrawn
// versions past the retention window, keeping the row so the record of what
// was sent to whom outlives the bytes.
const ARCHIVE_PRUNE_INTERVAL_MS = 24 * 60 * 60 * 1000;
setTimeout(() => {
  reportArchive.sweepOrphanReportFiles(pool)
    .then(n => { if (n) console.log('[archive] swept ' + n + ' orphaned report file(s)'); })
    .catch(err => console.error('[archive] sweep failed —', err.message));
}, 90 * 1000);
setInterval(() => {
  reportArchive.pruneReportArchive(pool)
    .then(n => { if (n) console.log('[archive] pruned ' + n + ' expired report file(s)'); })
    .catch(err => console.error('[archive] prune failed —', err.message));
}, ARCHIVE_PRUNE_INTERVAL_MS);

// ── Managed EDR sync (every 6 hours) ───────────────────────────────────────
// SentinelOne threat/activity data is operational rather than reporting-cadence,
// so it polls more often than the other integrations — but four times a day is
// enough to keep the tab current without hammering the console API.

const EDR_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
let edrSyncRunning = false;

async function runEdrSyncs() {
  // A slow console (large fleets, first full backfill) must not stack up runs.
  if (edrSyncRunning) {
    console.log('[integrations] sentinelone sync still running — skipping this tick');
    return;
  }
  edrSyncRunning = true;

  try {
    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [EDR_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] sentinelone sync: failed to load integrations —', err.message);
      return;
    }

    for (const row of rows) {
      try {
        const result = await runSentinelOneSync(row.tenant_id);
        console.log(`[integrations] sentinelone sync ok: tenant ${row.tenant_id} (${result.threats} threats, ${result.activities} activities, ${result.agents} agents)`);
      } catch (err) {
        console.error(`[integrations] sentinelone sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    edrSyncRunning = false;
  }
}

setTimeout(() => { runEdrSyncs().catch(err => console.error('[integrations] sentinelone sync crashed —', err.message)); }, 45 * 1000);
setInterval(() => { runEdrSyncs().catch(err => console.error('[integrations] sentinelone sync crashed —', err.message)); }, EDR_SYNC_INTERVAL_MS);

// ── Managed Email Security sync (every 6 hours) ────────────────────────────
// Same reasoning as EDR: email threat data is operational, and a client asking
// "did we get hit by that campaign this morning" is not well served by a feed
// that refreshes once a day. Four times a day keeps the tab current without
// pulling a partner's alert history around the clock.

const EMAIL_SYNC_INTERVAL_MS = 6 * 60 * 60 * 1000;
let emailSyncRunning = false;

async function runEmailSyncs() {
  // A first backfill over a busy tenant can run long; overlapping runs would
  // fight over the same upsert keys and double the API load for nothing.
  if (emailSyncRunning) {
    console.log('[integrations] acronis sync still running — skipping this tick');
    return;
  }
  emailSyncRunning = true;

  try {
    // No tables, no sync — and no error every six hours on a database where the
    // migration has not been run.
    if (!await hasEmailTables()) return;

    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [EMAIL_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] acronis sync: failed to load integrations —', err.message);
      return;
    }

    for (const row of rows) {
      try {
        const result = await runAcronisSync(row.tenant_id);
        console.log(`[integrations] acronis sync ok: tenant ${row.tenant_id} (${result.alerts} email alerts, ${result.unrecognisedTypes} unrecognised type(s))`);
      } catch (err) {
        console.error(`[integrations] acronis sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    emailSyncRunning = false;
  }
}

setTimeout(() => { runEmailSyncs().catch(err => console.error('[integrations] acronis sync crashed —', err.message)); }, 75 * 1000);
setInterval(() => { runEmailSyncs().catch(err => console.error('[integrations] acronis sync crashed —', err.message)); }, EMAIL_SYNC_INTERVAL_MS);

// ── Microsoft Secure Score sync (daily) ────────────────────────────────────
//
// Daily, not six-hourly like the operational feeds: Microsoft recomputes Secure
// Score roughly once every 24 hours, so a shorter interval spends Graph request
// quota re-reading a number that has not moved. Quota matters here because this
// app registration is usually shared with whatever else the client has
// integrated against their directory.

const MSGRAPH_SYNC_INTERVAL_MS = 24 * 60 * 60 * 1000;
let msGraphSyncRunning = false;

async function runMsGraphSyncs() {
  // A first pull is ~90 snapshots plus the full control catalogue across
  // several pages; overlapping runs would fight over the same upsert keys and
  // double the API load for nothing.
  if (msGraphSyncRunning) {
    console.log('[integrations] ms_graph sync still running — skipping this tick');
    return;
  }
  msGraphSyncRunning = true;

  try {
    // No tables, no sync — and no error every day on a database where the
    // migration has not been run.
    if (!await hasMsScoreTables()) return;

    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [MSGRAPH_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] ms_graph sync: failed to load integrations —', err.message);
      return;
    }

    for (const row of rows) {
      try {
        const result = await runMsGraphSync(row.tenant_id);
        console.log(`[integrations] ms_graph sync ok: tenant ${row.tenant_id} (${result.snapshots} snapshot(s), ${result.controls} control(s))`);
        // Warnings are the point of this integration degrading honestly — a
        // directory mismatch or a missing control catalogue must not be
        // visible only in a database column nobody tails.
        (result.warnings || []).forEach(w => console.warn(`[integrations] ms_graph tenant ${row.tenant_id}: ${w}`));
      } catch (err) {
        console.error(`[integrations] ms_graph sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    msGraphSyncRunning = false;
  }
}

setTimeout(() => { runMsGraphSyncs().catch(err => console.error('[integrations] ms_graph sync crashed —', err.message)); }, 105 * 1000);
setInterval(() => { runMsGraphSyncs().catch(err => console.error('[integrations] ms_graph sync crashed —', err.message)); }, MSGRAPH_SYNC_INTERVAL_MS);

// ── Wazuh daily rollups (hourly tick, snapshots complete days) ──────────────
// The Managed NDR and Managed Identity tabs read the indexer live for short ranges,
// so this job exists only to keep long-range trends alive past the indexer's
// retention. It ticks hourly rather than daily because daysNeedingSnapshot()
// always re-runs yesterday: the Office 365 Management Activity API delivers
// events up to 24h late, so a day that looked complete last night usually is
// not. Re-snapshotting is safe — writeBag() is idempotent.

const WAZUH_ROLLUP_INTERVAL_MS = 60 * 60 * 1000;
let wazuhRollupRunning = false;

async function runWazuhRollups() {
  if (wazuhRollupRunning) {
    console.log('[integrations] wazuh rollup still running — skipping this tick');
    return;
  }
  wazuhRollupRunning = true;

  try {
    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [WAZUH_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] wazuh rollup: failed to load integrations —', err.message);
      return;
    }

    for (const row of rows) {
      try {
        await runWazuhRollupSync(row.tenant_id);
      } catch (err) {
        console.error(`[integrations] wazuh rollup failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    wazuhRollupRunning = false;
  }
}

setTimeout(() => { runWazuhRollups().catch(err => console.error('[integrations] wazuh rollup crashed —', err.message)); }, 90 * 1000);
setInterval(() => { runWazuhRollups().catch(err => console.error('[integrations] wazuh rollup crashed —', err.message)); }, WAZUH_ROLLUP_INTERVAL_MS);

// ── FortiAnalyzer collection (hourly) ────────────────────────────────────────
// Tenants run one after another; the adapter additionally caps concurrent
// tasks per appliance, because every client shares the same FortiAnalyzer.

const FAZ_SYNC_INTERVAL_MS = 60 * 60 * 1000;
let fazSchedulerRunning = false;

async function runFortiAnalyzerSyncs() {
  if (fazSchedulerRunning) {
    console.log('[integrations] fortianalyzer collection still running — skipping this tick');
    return;
  }
  fazSchedulerRunning = true;
  try {
    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [FAZ_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] fortianalyzer: failed to load integrations —', err.message);
      return;
    }
    for (const row of rows) {
      try {
        await runFortiAnalyzerSync(row.tenant_id);
      } catch (err) {
        console.error(`[integrations] fortianalyzer sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    fazSchedulerRunning = false;
  }
}

if (process.env.NODE_ENV !== 'test') {
  setTimeout(() => { runFortiAnalyzerSyncs().catch(err => console.error('[integrations] fortianalyzer crashed —', err.message)); }, 120 * 1000);
  setInterval(() => { runFortiAnalyzerSyncs().catch(err => console.error('[integrations] fortianalyzer crashed —', err.message)); }, FAZ_SYNC_INTERVAL_MS);
}

// ── Managed Identity collection (hourly) ─────────────────────────────────────

const IDENTITY_SYNC_INTERVAL_MS = 60 * 60 * 1000;
let identitySchedulerRunning = false;

async function runIdentitySyncs() {
  if (identitySchedulerRunning) {
    console.log('[integrations] managed identity collection still running — skipping this tick');
    return;
  }
  identitySchedulerRunning = true;
  try {
    let rows;
    try {
      rows = (await pool.query(
        `SELECT tenant_id FROM integrations
          WHERE is_enabled = TRUE AND provider = $1 AND (config_json->>'identity_enabled') = 'true'`,
        [MSGRAPH_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] managed identity: failed to load integrations —', err.message);
      return;
    }
    for (const row of rows) {
      try {
        await runIdentitySync(row.tenant_id);
      } catch (err) {
        console.error(`[integrations] managed identity sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    identitySchedulerRunning = false;
  }
}

if (process.env.NODE_ENV !== 'test') {
  setTimeout(() => { runIdentitySyncs().catch(err => console.error('[integrations] managed identity crashed —', err.message)); }, 150 * 1000);
  setInterval(() => { runIdentitySyncs().catch(err => console.error('[integrations] managed identity crashed —', err.message)); }, IDENTITY_SYNC_INTERVAL_MS);
}

// ── AI Visibility collection (hourly) ────────────────────────────────────────
// Tenants run one after another, and each client's calls are serial inside the
// adapter: every client shares one DNSFilter MSP key and its rate limit.

const DNS_SYNC_INTERVAL_MS = 60 * 60 * 1000;
let dnsSchedulerRunning = false;

async function runDnsFilterSyncs() {
  if (dnsSchedulerRunning) {
    console.log('[integrations] dnsfilter collection still running — skipping this tick');
    return;
  }
  dnsSchedulerRunning = true;
  try {
    let rows;
    try {
      rows = (await pool.query(
        'SELECT tenant_id FROM integrations WHERE is_enabled = TRUE AND provider = $1',
        [DNSFILTER_PROVIDER]
      )).rows;
    } catch (err) {
      console.error('[integrations] dnsfilter: failed to load integrations —', err.message);
      return;
    }
    for (const row of rows) {
      try {
        await runDnsFilterSync(row.tenant_id);
      } catch (err) {
        console.error(`[integrations] dnsfilter sync failed: tenant ${row.tenant_id} — ${err.message}`);
      }
    }
  } finally {
    dnsSchedulerRunning = false;
  }
}

if (process.env.NODE_ENV !== 'test') {
  setTimeout(() => { runDnsFilterSyncs().catch(err => console.error('[integrations] dnsfilter crashed —', err.message)); }, 180 * 1000);
  setInterval(() => { runDnsFilterSyncs().catch(err => console.error('[integrations] dnsfilter crashed —', err.message)); }, DNS_SYNC_INTERVAL_MS);
}

// ── Managed NDR & Managed Identity (Wazuh) data routes ───────────────────

function resolveWazuhTenant(req) {
  if (req.session.role === 'superadmin') {
    const tid = parseInt(req.query.tenantId, 10);
    if (isNaN(tid) || tid < 1) return { tenantId: null };
    return { tenantId: tid };
  }
  return { tenantId: req.session.tenantId };
}

/**
 * Short-lived response cache. Dashboards get tab-switched and refreshed
 * constantly, and Wazuh Indexer nodes are usually undersized — without this one
 * impatient user can fan a single screen out into dozens of searches.
 */
const WAZUH_CACHE_TTL_MS = 45 * 1000;
const wazuhCache   = new Map();  // key → { at, value }
const wazuhInFlight = new Map(); // key → Promise (collapses concurrent misses)

async function wazuhCached(key, produce) {
  const hit = wazuhCache.get(key);
  if (hit && Date.now() - hit.at < WAZUH_CACHE_TTL_MS) return hit.value;

  const pending = wazuhInFlight.get(key);
  if (pending) return pending;

  const p = (async () => {
    try {
      const value = await produce();
      wazuhCache.set(key, { at: Date.now(), value });
      return value;
    } finally {
      wazuhInFlight.delete(key);
    }
  })();

  wazuhInFlight.set(key, p);
  return p;
}

/** Envelope returned when the Wazuh integration is missing or switched off.
 *  `reason` is 'not_configured' | 'disabled' — the screens word their empty
 *  state from it, because "you have not set this up" and "you set this up and
 *  then disabled it" call for completely different next steps. */
function wazuhUnavailable(days, keys, reason, provider) {
  const out = {
    windowDays: days,
    source: null,
    provider: provider || null,
    configured: false,
    reason: reason || 'not_configured',
    detected: null,
    sync: null,
    partial: [],
  };
  keys.forEach(k => { out[k] = { available: false, data: null, reason: 'not_ingesting', lastEventAt: null }; });
  return out;
}

/**
 * Fetch a screen's panels, choosing the data source by range.
 *
 * ≤ 30 days comes from the indexer live; longer ranges come from the Postgres
 * rollups, which is the only place data older than the indexer's retention
 * still exists. The two are never blended inside one chart — the response says
 * which was used so the UI can label it.
 */
async function wazuhScreen(tenantId, screen, days) {
  const keys = screen === 'ndr' ? ['traffic', 'threats', 'geo', 'vpnAdmin'] : ['o365', 'graph'];

  /*
   * NDR prefers FortiAnalyzer when it is configured and enabled; Wazuh remains
   * the fallback while clients are migrated. A disabled FortiAnalyzer with no
   * Wazuh behind it reports 'disabled', so the screen says "switched off"
   * rather than "never set up".
   */
  let fazReason = null;
  const directProvider = screen === 'ndr' ? FAZ_PROVIDER : MSGRAPH_PROVIDER;
  if (screen === 'ndr') {
    try {
      const faz = await loadFortiAnalyzerIntegration(tenantId);
      return fortiAnalyzerNdrScreen(tenantId, faz, days);
    } catch (err) {
      if (!err.reason) throw err;
      fazReason = err.reason;
    }
  }
  // Managed Identity likewise prefers the direct Microsoft APIs.
  if (screen === 'o365') {
    try {
      const idn = await loadIdentityIntegration(tenantId);
      return identityScreen(tenantId, idn, days);
    } catch (err) {
      if (!err.reason) throw err;
      fazReason = err.reason;
    }
  }

  let integration;
  try {
    integration = await loadWazuhIntegration(tenantId);
  } catch (err) {
    if (fazReason === 'disabled' && err.reason === 'not_configured') {
      return wazuhUnavailable(days, keys, 'disabled', directProvider);
    }
    return wazuhUnavailable(days, keys, err.reason, WAZUH_PROVIDER);
  }

  const tz  = integration.config.timeZone || 'UTC';
  const key = `${integration.id}:${screen}:${days}:${tz}`;

  return wazuhCached(key, async () => {
    const live = days <= wazuhMetrics.LIVE_MAX_DAYS;
    let panels;

    if (live) {
      const cfg   = wazuhConfig(integration);
      const range = { from: `now-${days}d/d`, to: 'now', tz };
      panels = screen === 'ndr'
        ? await wazuhAdapter.fetchNdr(cfg, range)
        : await wazuhAdapter.fetchO365(cfg, range);
    } else {
      // Scoped to THIS integration: a FortiAnalyzer running alongside writes
      // the same 'fortigate' rows, and must not be summed in.
      panels = screen === 'ndr'
        ? await wazuhMetrics.ndrFromRollups(pool, tenantId, days, integration.id)
        : await wazuhMetrics.o365FromRollups(pool, tenantId, days, integration.id);
    }

    const meta = await pool.query(
      `SELECT last_synced_at, last_sync_status, last_sync_message
         FROM integrations WHERE tenant_id = $1 AND provider = $2`,
      [tenantId, WAZUH_PROVIDER]
    );

    const out = {
      windowDays: days,
      source: live ? 'live' : 'rollup',
      provider: WAZUH_PROVIDER,
      configured: true,
      timeZone: tz,
      detected: integration.config.detected || null,
      sync: meta.rows[0] || null,
      partial: panels._partial || [],
    };
    keys.forEach(k => { out[k] = panels[k]; });
    return out;
  });
}

/**
 * The NDR screen from FortiAnalyzer's rollups — always rollups, never live
 * (see lib/fortianalyzer-metrics.js for why). Before the first collection has
 * run, empty panels say "not collected yet" rather than "no events", which
 * would read as a quiet network.
 */
async function fortiAnalyzerNdrScreen(tenantId, integration, days) {
  return wazuhCached(`faz:${integration.id}:${days}`, async () => {
    const panels = await wazuhMetrics.ndrFromRollups(pool, tenantId, days, integration.id);
    const collected = !!integration.sync.last_synced_at;
    const out = {
      windowDays: days,
      source: 'rollup',
      provider: FAZ_PROVIDER,
      configured: true,
      timeZone: integration.config.timeZone || 'UTC',
      adom: integration.config.adom || null,
      detected: null,
      sync: integration.sync,
      partial: [],
    };
    ['traffic', 'threats', 'geo', 'vpnAdmin'].forEach((k) => {
      const p = panels[k];
      out[k] = !collected && p && p.reason === 'no_data_in_range'
        ? { available: false, data: null, reason: 'not_synced', lastEventAt: null }
        : p;
    });
    return out;
  });
}

/**
 * The Managed Identity screen from the direct Microsoft APIs' rollups, scoped
 * to the Graph integration. Before the first collection, empty panels say
 * "not collected yet" rather than "no sign-ins".
 */
async function identityScreen(tenantId, integration, days) {
  return wazuhCached(`idn:${integration.id}:${days}`, async () => {
    const [panels, sync] = await Promise.all([
      wazuhMetrics.o365FromRollups(pool, tenantId, days, integration.id),
      identitySyncMeta(integration.id),
    ]);
    const out = {
      windowDays: days,
      source: 'rollup',
      provider: MSGRAPH_PROVIDER,
      configured: true,
      timeZone: integration.config.identity_time_zone || 'UTC',
      detected: null,
      sync,
      partial: [],
    };
    ['o365', 'graph'].forEach((k) => {
      const p = panels[k];
      out[k] = !sync && p && p.reason === 'no_data_in_range'
        ? { available: false, data: null, reason: 'not_synced', lastEventAt: null }
        : p;
    });
    return out;
  });
}

function wazuhDays(req) {
  return Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 30));
}

/* Keys the two screens expect back, so an unavailable response is still shaped
   the way the client renders. */
const WAZUH_SCREEN_KEYS = {
  ndr:  ['traffic', 'threats', 'geo', 'vpnAdmin'],
  o365: ['o365', 'graph'],
};

/** Resolve the tenant, or answer with a *reasoned* envelope rather than `null`.
 *  A bare null forced the client to guess why it got nothing, and it guessed
 *  wrong — an admin whose account has no active organisation was told to pick
 *  one from a dropdown only superadmins can see. */
function wazuhScreenFor(req, screen) {
  const days = wazuhDays(req);
  const { tenantId } = resolveWazuhTenant(req);
  if (tenantId === null || tenantId === undefined) {
    return wazuhUnavailable(days, WAZUH_SCREEN_KEYS[screen], 'no_tenant');
  }
  return wazuhScreen(tenantId, screen, days);
}

/** GET /api/ndr/summary?days=30 — Managed NDR panels (firewall) */
app.get('/api/ndr/summary', requireAuth, async (req, res) => {
  try {
    res.json(await wazuhScreenFor(req, 'ndr'));
  } catch (err) { return serverError(res, err); }
});

/** GET /api/o365/summary?days=30 — Managed Identity panels */
app.get('/api/o365/summary', requireAuth, async (req, res) => {
  try {
    res.json(await wazuhScreenFor(req, 'o365'));
  } catch (err) { return serverError(res, err); }
});

// ── AI Visibility (DNSFilter) data routes ──────────────────────────────────

const AI_SCREEN_KEYS = ['usage', 'apps', 'users', 'policy'];

/** This client's sanctioned-app register as a Map, or null before the migration. */
async function loadAiDecisions(tenantId) {
  try {
    const r = await pool.query(
      'SELECT app_key, app_name, status, note, decided_at FROM ai_app_decisions WHERE tenant_id = $1',
      [tenantId]
    );
    return new Map(r.rows.map(d => [d.app_key, d]));
  } catch (err) {
    if (err.code === '42P01') return null;
    throw err;
  }
}

/**
 * The AI Visibility screen, from rollups only. Before the first collection,
 * empty panels say "not collected yet" rather than "no AI use", which would
 * read as a client with none.
 */
async function aiVisibilityScreen(tenantId, days) {
  let integration;
  try {
    integration = await loadDnsFilterIntegration(tenantId);
  } catch (err) {
    if (!err.reason) throw err;
    return wazuhUnavailable(days, AI_SCREEN_KEYS, err.reason, DNSFILTER_PROVIDER);
  }

  return wazuhCached(`ai:${tenantId}:${integration.id}:${days}`, async () => {
    const [panels, decisions] = await Promise.all([
      dnsMetrics.aiFromRollups(pool, tenantId, days, integration.id),
      loadAiDecisions(tenantId),
    ]);
    const conf = integration.config;
    const collected = !!integration.sync.last_synced_at;
    const out = {
      windowDays: days,
      source: 'rollup',
      provider: DNSFILTER_PROVIDER,
      configured: true,
      timeZone: conf.timeZone || 'UTC',
      organisation: { id: conf.organization_id || null, name: conf.verified_org_name || null },
      verified: !!conf.verified_org_id && String(conf.verified_org_id) === String(conf.organization_id),
      decisionsAvailable: decisions !== null,
      detected: null,
      sync: integration.sync,
      partial: [],
    };
    AI_SCREEN_KEYS.forEach((k) => {
      const p = panels[k];
      out[k] = !collected && p && p.reason === 'no_data_in_range'
        ? { available: false, data: null, reason: 'not_synced', lastEventAt: null }
        : p;
    });
    if (out.apps && out.apps.available && out.apps.data) {
      const annotated = aiVisibility.annotateApps(out.apps.data.rows, decisions || new Map());
      out.apps = Object.assign({}, out.apps, { data: Object.assign({}, out.apps.data, annotated) });
    }
    return out;
  });
}

/** GET /api/ai-visibility/summary?days=30 — AI Visibility panels (staff only) */
app.get('/api/ai-visibility/summary', requireAuth, async (req, res) => {
  try {
    const days = wazuhDays(req);
    const { tenantId } = resolveWazuhTenant(req);
    if (tenantId === null || tenantId === undefined) {
      return res.json(wazuhUnavailable(days, AI_SCREEN_KEYS, 'no_tenant'));
    }
    res.json(await aiVisibilityScreen(tenantId, days));
  } catch (err) { return serverError(res, err); }
});

/*
 * The sanctioned-app register. WRITE on the AI Visibility page is required for
 * PUT and DELETE — pageGate enforces it from API_PREFIX_TO_PAGE. The tenant
 * comes from the session (or a superadmin's explicit tenantId) and is part of
 * every WHERE clause, so a decision can only ever land on the caller's client.
 */
app.put('/api/ai-visibility/decisions/:appKey', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIntegrationTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });
    const appKey = req.params.appKey;
    if (!aiVisibility.validAppKey(appKey)) return res.status(400).json({ error: 'Invalid application key.' });
    const v = aiVisibility.validateDecision(req.body);
    if (!v.ok) return res.status(400).json({ error: v.error });

    const r = await pool.query(
      `INSERT INTO ai_app_decisions (tenant_id, app_key, app_name, status, note, decided_by, decided_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
       ON CONFLICT ON CONSTRAINT ai_app_decisions_uniq DO UPDATE
         SET status = EXCLUDED.status,
             note = EXCLUDED.note,
             app_name = COALESCE(EXCLUDED.app_name, ai_app_decisions.app_name),
             decided_by = EXCLUDED.decided_by,
             decided_at = CASE WHEN ai_app_decisions.status = EXCLUDED.status
                               THEN ai_app_decisions.decided_at ELSE NOW() END,
             updated_at = NOW()
       RETURNING app_key, app_name, status, note, decided_at`,
      [tenantId, appKey, v.value.appName, v.value.status, v.value.note, req.session.userId]
    );
    clearAiCache(tenantId);
    res.json({ ok: true, decision: r.rows[0] });
  } catch (err) {
    if (err.code === '42P01') return res.status(503).json({ error: 'Run db/migrate-ai-visibility.sql first.' });
    return serverError(res, err);
  }
});

/** DELETE — the tool goes back to unreviewed. */
app.delete('/api/ai-visibility/decisions/:appKey', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIntegrationTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });
    const appKey = req.params.appKey;
    if (!aiVisibility.validAppKey(appKey)) return res.status(400).json({ error: 'Invalid application key.' });
    await pool.query('DELETE FROM ai_app_decisions WHERE tenant_id = $1 AND app_key = $2', [tenantId, appKey]);
    clearAiCache(tenantId);
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '42P01') return res.json({ ok: true });
    return serverError(res, err);
  }
});

// ── Managed EDR (SentinelOne) data routes ──────────────────────────────────

function resolveEdrTenant(req) {
  if (req.session.role === 'superadmin') {
    const tid = parseInt(req.query.tenantId, 10);
    if (isNaN(tid) || tid < 1) return { tenantId: null };
    return { tenantId: tid };
  }
  return { tenantId: req.session.tenantId };
}

/** GET /api/edr/summary?days=30 — headline metrics, breakdowns and trends */
app.get('/api/edr/summary', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEdrTenant(req);
    if (tenantId === null) return res.json(null);
    res.json(await computeEdrSummary(pool, tenantId, req.query.days));
  } catch (err) { return serverError(res, err); }
});

/** GET /api/edr/threats — filterable threat list backing the tab's table */
app.get('/api/edr/threats', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEdrTenant(req);
    if (tenantId === null) return res.json([]);

    const days   = Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 30));
    const limit  = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 200));
    const params = [tenantId, days];
    const where  = [`tenant_id = $1`, `detected_at >= NOW() - ($2::int * INTERVAL '1 day')`];

    if (req.query.status) {
      params.push(req.query.status);
      where.push(`incident_status = $${params.length}`);
    }
    if (req.query.confidence) {
      params.push(req.query.confidence);
      where.push(`confidence_level = $${params.length}`);
    }
    if (req.query.mitigation) {
      params.push(req.query.mitigation);
      where.push(`mitigation_status = $${params.length}`);
    }
    params.push(limit);

    const result = await pool.query(
      `SELECT threat_id AS "threatId", threat_name AS "threatName", classification,
              confidence_level AS "confidenceLevel", analyst_verdict AS "analystVerdict",
              incident_status AS "incidentStatus", mitigation_status AS "mitigationStatus",
              detection_type AS "detectionType", detection_engines AS "detectionEngines",
              endpoint_name AS "endpointName", os_name AS "osName", site_name AS "siteName",
              group_name AS "groupName", file_path AS "filePath", file_hash AS "fileHash",
              initiated_by AS "initiatedBy", detected_at AS "detectedAt",
              mitigated_at AS "mitigatedAt", resolved_at AS "resolvedAt"
       FROM edr_threats
       WHERE ${where.join(' AND ')}
       ORDER BY detected_at DESC NULLS LAST
       LIMIT $${params.length}`,
      params
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

/** GET /api/edr/activities — most recent console activity */
app.get('/api/edr/activities', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEdrTenant(req);
    if (tenantId === null) return res.json([]);

    const days  = Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 30));
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 100));

    const result = await pool.query(
      `SELECT activity_id AS "activityId", activity_type AS "activityType",
              activity_type_name AS "activityTypeName", primary_description AS "primaryDescription",
              secondary_description AS "secondaryDescription", endpoint_name AS "endpointName",
              site_name AS "siteName", group_name AS "groupName", user_name AS "userName",
              threat_id AS "threatId", created_at AS "createdAt"
       FROM edr_activities
       WHERE tenant_id = $1 AND created_at >= NOW() - ($2::int * INTERVAL '1 day')
       ORDER BY created_at DESC NULLS LAST
       LIMIT $3`,
      [tenantId, days, limit]
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

/** GET /api/edr/agents — endpoint fleet snapshot */
app.get('/api/edr/agents', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEdrTenant(req);
    if (tenantId === null) return res.json([]);

    const result = await pool.query(
      `SELECT agent_id AS "agentId", computer_name AS "computerName", os_name AS "osName",
              os_type AS "osType", agent_version AS "agentVersion", machine_type AS "machineType",
              domain, site_name AS "siteName", group_name AS "groupName",
              is_active AS "isActive", is_infected AS "isInfected", is_up_to_date AS "isUpToDate",
              network_status AS "networkStatus", scan_status AS "scanStatus",
              active_threats AS "activeThreats", last_active_at AS "lastActiveAt"
       FROM edr_agents WHERE tenant_id = $1
       ORDER BY is_infected DESC, active_threats DESC, computer_name ASC`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

// ── Managed Email Security (Acronis) data routes ───────────────────────────

/*
 * Tenant resolution mirrors resolveEdrTenant: a superadmin with no client
 * selected resolves to null and the routes answer with an empty shape rather
 * than an error, because "pick a client" is a UI state and not a failure.
 */
function resolveEmailTenant(req) {
  if (req.session.role === 'superadmin') {
    const tid = parseInt(req.query.tenantId, 10);
    if (isNaN(tid) || tid < 1) return { tenantId: null };
    return { tenantId: tid };
  }
  return { tenantId: req.session.tenantId };
}

/** GET /api/email/summary?days=30 — headline metrics, breakdowns and trends */
app.get('/api/email/summary', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEmailTenant(req);
    if (tenantId === null) return res.json(null);
    // `available: false` is NOT the same as an empty summary, and the tab says
    // so: one means the migration has not been run, the other means a quiet
    // month. Returning zeros for the first would be a lie about the data.
    if (!await hasEmailTables()) return res.json({ available: false, summary: null });
    res.json({
      available: true,
      summary: await computeEmailSummary(pool, tenantId, req.query.days),
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/email/alerts — the alert list backing the tab's table */
app.get('/api/email/alerts', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEmailTenant(req);
    if (tenantId === null) return res.json([]);
    if (!await hasEmailTables()) return res.json([]);

    const days  = Math.max(1, Math.min(365, parseInt(req.query.days, 10) || 30));
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 200));
    const params = [tenantId, days];
    const where  = ['tenant_id = $1', `created_at >= NOW() - ($2::int * INTERVAL '1 day')`];

    /*
     * Filters are parameterised and the COLUMN names are fixed literals here —
     * never interpolated from req.query. The value goes in a placeholder; the
     * column is chosen by this code and nothing else.
     */
    if (req.query.threatClass) {
      params.push(req.query.threatClass);
      where.push(`threat_class = $${params.length}`);
    }
    if (req.query.disposition) {
      params.push(req.query.disposition);
      where.push(`disposition = $${params.length}`);
    }
    if (req.query.severity) {
      params.push(req.query.severity);
      where.push(`severity = $${params.length}`);
    }
    params.push(limit);

    const result = await pool.query(
      `SELECT alert_id AS "alertId", alert_type AS "alertType", category, severity,
              threat_class AS "threatClass", disposition,
              recipient, recipient_domain AS "recipientDomain",
              sender, sender_domain AS "senderDomain", subject,
              created_at AS "createdAt", updated_at AS "updatedAt",
              resolved_at AS "resolvedAt", alert_status AS "status"
         FROM email_alerts
        WHERE ${where.join(' AND ')}
        ORDER BY created_at DESC NULLS LAST
        LIMIT $${params.length}`,
      params
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

/**
 * GET /api/email/types — every Acronis alert type seen, and how it was read.
 *
 * The classifier's own report card. Exists so that "the chart is flat" can be
 * told apart from "the classifier does not recognise this tenant's alert types"
 * without anyone reading server logs.
 */
app.get('/api/email/types', requireAuth, async (req, res) => {
  try {
    const { tenantId } = resolveEmailTenant(req);
    if (tenantId === null) return res.json([]);
    if (!await hasEmailTables()) return res.json([]);

    const result = await pool.query(
      `SELECT alert_type AS "alertType", category, is_email AS "isEmail",
              seen_count AS "seenCount", first_seen_at AS "firstSeenAt",
              last_seen_at AS "lastSeenAt"
         FROM email_alert_types_seen
        WHERE tenant_id = $1
        ORDER BY is_email DESC, seen_count DESC, alert_type`,
      [tenantId]
    );
    res.json(result.rows);
  } catch (err) { return serverError(res, err); }
});

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

// GRC scoring lives in lib/grc-score.js — calculateGrcScore,
// calculateFrameworkScores and calculateSectionScores are imported at the top of
// this file. Keeping one implementation is what stops a domain score in the
// board report disagreeing with the same domain on the GRC tab.

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
    // Same keys in both branches — a consumer should not have to null-check the
    // envelope as well as the assessment inside it.
    if (asmtRes.rows.length === 0) {
      return res.json({ assessment: null, answers: [], frameworkScores: {}, sectionScores: {} });
    }

    const answersRes = await pool.query(
      'SELECT question_id, answer, notes FROM grc_answers WHERE assessment_id = $1',
      [asmtRes.rows[0].id]
    );

    const [qResult, fwResult] = await Promise.all([
      pool.query('SELECT id, weight, section FROM grc_questions'),
      pool.query('SELECT question_id, framework, control_id, control_title FROM grc_question_frameworks'),
    ]);
    const answers = answersRes.rows.map(a => ({ questionId: a.question_id, answer: a.answer }));
    const frameworkScores = calculateFrameworkScores(answers, qResult.rows, fwResult.rows);
    const sectionScores   = calculateSectionScores(answers, qResult.rows);

    res.json({
      assessment: asmtRes.rows[0], answers: answersRes.rows, frameworkScores, sectionScores,
    });
  } catch (err) {
    return serverError(res, err);
  }
});

/** POST /api/grc/assessment — upsert assessment + all answers, recalculate score */
app.post('/api/grc/assessment', async (req, res) => {
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
app.post('/api/redteam/projects', async (req, res) => {
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
app.put('/api/redteam/projects/:id', async (req, res) => {
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
app.delete('/api/redteam/projects/:id', async (req, res) => {
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
app.post('/api/redteam/tasks', async (req, res) => {
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
app.put('/api/redteam/tasks/:id', async (req, res) => {
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
app.delete('/api/redteam/tasks/:id', async (req, res) => {
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
app.post('/api/redteam/projects/:id/findings', async (req, res) => {
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

    const rep = parseReportFields(req.body);
    if (rep.error) return res.status(400).json({ error: rep.error });

    const result = await pool.query(
      `INSERT INTO pentest_findings (tenant_id, project_id, title, severity, description, recommendation, owner, due_date, status, notes, created_by,
                                     cvss_vector, cvss_score, classification, affected_endpoints, business_impact, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
      [project.tenant_id, project.id, title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', req.session.userId,
       rep.cvss_vector, rep.cvss_score, rep.classification, rep.affected_endpoints, rep.business_impact, rep.sort_order]
    );
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

// ── Red Team report generation ─────────────────────────────────────────────

const CVSS_VECTOR_RE = /^CVSS:[234]\.\d\/[A-Z]{1,3}:[A-Z](\/[A-Z]{1,3}:[A-Z])*$/i;

/**
 * Validates and normalises the report-only fields shared by every pentest
 * finding write path. Returns { error } or the coerced column values.
 */
function parseReportFields(b) {
  const vector = String(b.cvss_vector || '').trim();
  if (vector && !CVSS_VECTOR_RE.test(vector)) {
    return { error: 'invalid CVSS vector — expected e.g. CVSS:4.0/AV:N/AC:L/...' };
  }

  let score = null;
  if (b.cvss_score !== undefined && b.cvss_score !== null && String(b.cvss_score).trim() !== '') {
    score = Number(b.cvss_score);
    if (isNaN(score) || score < 0 || score > 10) {
      return { error: 'cvss_score must be a number between 0 and 10.' };
    }
    score = Math.round(score * 10) / 10;
  }

  const order = parseInt(b.sort_order, 10);

  return {
    cvss_vector:        vector.slice(0, 160),
    cvss_score:         score,
    classification:     String(b.classification || '').trim().slice(0, 200),
    affected_endpoints: String(b.affected_endpoints || ''),
    business_impact:    String(b.business_impact || ''),
    sort_order:         isNaN(order) ? 0 : order,
  };
}

/** Default narrative, used when an engagement has no saved report meta yet. */
function defaultReportMeta(project) {
  const name = project.title || 'the application';
  return {
    project_id:       project.id,
    report_title:     project.title || '',
    report_subtitle:  'Web Application Penetration Test Report',
    report_version:   'v1.0',
    report_date:      null,
    exec_summary:
      `Reflex conducted a black-box, unauthenticated web application penetration test of ${name} to `
      + 'assess its externally observable security posture and identify exploitable vulnerabilities from '
      + 'the perspective of an unauthenticated attacker.\n\n'
      + 'The assessment focused on vulnerabilities that could be identified and exploited without valid '
      + 'user credentials, including weaknesses in exposed functionality, access controls, input handling, '
      + 'and application security configuration.\n\n'
      + 'Exploitation could result in sensitive data exposure, disruption to critical systems, regulatory '
      + 'non-compliance, and reputational harm.',
    key_risk_themes: '',
    approach:
      `Reflex performed a black-box web application penetration test of ${name}. The assessment focused on `
      + 'identifying critical, high, and medium-risk vulnerabilities that could be discovered from an '
      + 'external, unauthenticated perspective within the agreed timeframe.\n\n'
      + 'This report summarises the scope, key findings, business risks, and recommended remediation actions.',
    scope_objectives:
      `The assessment simulated an external black-box web application penetration test of ${name} to identify `
      + "weaknesses that could be discovered and exploited without prior knowledge of the application's "
      + 'internal design or architecture. The objective was to identify exploitable vulnerabilities and '
      + 'misconfigurations that could lead to unauthorised access, data exposure, or disruption.\n\n'
      + 'Testing prioritised commonly exploited web application vulnerabilities and attack techniques '
      + 'relevant to unauthenticated external users. The detailed scope of the assessment is contained '
      + 'within Appendix A.',
    findings_summary:
      "Overall, the external-facing infrastructure and application security posture were assessed as "
      + 'adequate, with several opportunities for improvement to better align with leading cybersecurity '
      + 'practices. Remediation of the high and medium-risk findings should be prioritised.',
    mitigating_factors: '',
    attack_paths_intro:
      'The diagrams below present hypothetical scenarios. The leftmost node represents the target asset or '
      + 'objective, with nodes to the right representing identified or theoretical weaknesses.',
    attack_paths_narrative: '',
    next_steps:
      'Regular assessments help validate hardening standards, detect control drift over time, and identify '
      + 'new vulnerabilities. Reflex recommends conducting penetration testing at least bi-annually.\n\n'
      + 'Additional testing should be performed following deployment of new software or major feature '
      + 'updates to ensure the security posture is maintained.',
    scope_endpoints: project.scope || '',
    methodology:     'The assessment was conducted using a black-box methodology.',
    timeline_note:   '',
    delivery_team:   [],
    owasp_results:   DEFAULT_OWASP,
    updated_at:      null,
  };
}

const REPORT_META_TEXT_FIELDS = [
  'report_title', 'report_subtitle', 'report_version', 'exec_summary', 'key_risk_themes',
  'approach', 'scope_objectives', 'findings_summary', 'mitigating_factors',
  'attack_paths_intro', 'attack_paths_narrative', 'next_steps', 'scope_endpoints',
  'methodology', 'timeline_note',
];

/** GET /api/redteam/projects/:id/report-meta — saved narrative, or pre-filled defaults */
app.get('/api/redteam/projects/:id/report-meta', requireAuth, async (req, res) => {
  try {
    const { project, error } = await resolveProjectForTenantAccess(req);
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query('SELECT * FROM redteam_report_meta WHERE project_id=$1', [project.id]);
    if (result.rows.length === 0) {
      return res.json({ meta: defaultReportMeta(project), isDefault: true });
    }
    res.json({ meta: result.rows[0], isDefault: false });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/redteam/projects/:id/report-meta — upsert the narrative */
app.put('/api/redteam/projects/:id/report-meta', async (req, res) => {
  try {
    const { project, error } = await resolveProjectForTenantAccess(req);
    if (error) return res.status(error.status).json({ error: error.message });

    const b = req.body || {};
    const text = REPORT_META_TEXT_FIELDS.map((f) => String(b[f] == null ? '' : b[f]));
    const team = Array.isArray(b.delivery_team)
      ? b.delivery_team
          .filter((t) => t && (t.name || t.role))
          .map((t) => ({ name: String(t.name || '').slice(0, 200), role: String(t.role || '').slice(0, 200) }))
      : [];
    const owasp = Array.isArray(b.owasp_results) && b.owasp_results.length
      ? b.owasp_results.map((o) => ({
          id:     String(o.id || ''),
          title:  String(o.title || ''),
          result: String(o.result || 'Pass') === 'Pass' ? 'Pass' : 'Issues Identified',
        }))
      : DEFAULT_OWASP;

    const result = await pool.query(
      `INSERT INTO redteam_report_meta
         (project_id, tenant_id, report_title, report_subtitle, report_version, exec_summary,
          key_risk_themes, approach, scope_objectives, findings_summary, mitigating_factors,
          attack_paths_intro, attack_paths_narrative, next_steps, scope_endpoints, methodology,
          timeline_note, report_date, delivery_team, owasp_results, updated_by, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20::jsonb,$21,NOW())
       ON CONFLICT (project_id) DO UPDATE SET
         tenant_id=EXCLUDED.tenant_id, report_title=EXCLUDED.report_title,
         report_subtitle=EXCLUDED.report_subtitle, report_version=EXCLUDED.report_version,
         exec_summary=EXCLUDED.exec_summary, key_risk_themes=EXCLUDED.key_risk_themes,
         approach=EXCLUDED.approach, scope_objectives=EXCLUDED.scope_objectives,
         findings_summary=EXCLUDED.findings_summary, mitigating_factors=EXCLUDED.mitigating_factors,
         attack_paths_intro=EXCLUDED.attack_paths_intro,
         attack_paths_narrative=EXCLUDED.attack_paths_narrative, next_steps=EXCLUDED.next_steps,
         scope_endpoints=EXCLUDED.scope_endpoints, methodology=EXCLUDED.methodology,
         timeline_note=EXCLUDED.timeline_note, report_date=EXCLUDED.report_date,
         delivery_team=EXCLUDED.delivery_team, owasp_results=EXCLUDED.owasp_results,
         updated_by=EXCLUDED.updated_by, updated_at=NOW()
       RETURNING *`,
      [project.id, project.tenant_id, ...text, b.report_date || null,
       JSON.stringify(team), JSON.stringify(owasp), req.session.userId]
    );
    res.json({ meta: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/**
 * Resolves a finding via its parent engagement so evidence inherits the same
 * tenant check as everything else hanging off a project.
 */
async function resolveFindingForTenantAccess(req, findingId) {
  const found = await pool.query('SELECT * FROM pentest_findings WHERE id=$1', [findingId]);
  if (found.rows.length === 0) return { error: { status: 404, message: 'Finding not found.' } };
  const finding = found.rows[0];

  if (req.session.role !== 'superadmin' && finding.tenant_id !== req.session.tenantId) {
    return { error: { status: 403, message: 'You do not have access to this finding.' } };
  }
  return { finding };
}

/** GET /api/redteam/findings/:id/evidence — metadata only, never the bytes */
app.get('/api/redteam/findings/:id/evidence', requireAuth, async (req, res) => {
  try {
    const { error } = await resolveFindingForTenantAccess(req, req.params.id);
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `SELECT id, finding_id, mime, filename, caption, sort_order, width_px, height_px, created_at
         FROM pentest_finding_evidence WHERE finding_id=$1 ORDER BY sort_order, id`,
      [req.params.id]
    );
    res.json({ evidence: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/redteam/findings/:id/evidence — upload a screenshot */
app.post('/api/redteam/findings/:id/evidence', (req, res) => {
  evidenceUpload.single('file')(req, res, async (uploadErr) => {
    if (uploadErr) {
      const tooBig = uploadErr.code === 'LIMIT_FILE_SIZE';
      return res.status(400).json({ error: tooBig ? 'Image must be 4 MB or smaller.' : uploadErr.message });
    }
    try {
      const { error } = await resolveFindingForTenantAccess(req, req.params.id);
      if (error) return res.status(error.status).json({ error: error.message });
      if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });

      const dims = imageDimensions(req.file.buffer, req.file.mimetype);
      const next = await pool.query(
        'SELECT COALESCE(MAX(sort_order), -1) + 1 AS n FROM pentest_finding_evidence WHERE finding_id=$1',
        [req.params.id]
      );

      const result = await pool.query(
        `INSERT INTO pentest_finding_evidence (finding_id, mime, filename, caption, sort_order, width_px, height_px, data)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         RETURNING id, finding_id, mime, filename, caption, sort_order, width_px, height_px, created_at`,
        [req.params.id, req.file.mimetype, String(req.file.originalname || '').slice(0, 255),
         String(req.body.caption || '').slice(0, 300), next.rows[0].n, dims.width, dims.height, req.file.buffer]
      );
      res.json({ evidence: result.rows[0] });
    } catch (err) { return serverError(res, err); }
  });
});

/** GET /api/redteam/evidence/:eid — the image bytes, for modal previews */
app.get('/api/redteam/evidence/:eid', requireAuth, async (req, res) => {
  try {
    const row = await pool.query('SELECT * FROM pentest_finding_evidence WHERE id=$1', [req.params.eid]);
    if (row.rows.length === 0) return res.status(404).json({ error: 'Evidence not found.' });

    const { error } = await resolveFindingForTenantAccess(req, row.rows[0].finding_id);
    if (error) return res.status(error.status).json({ error: error.message });

    res.set('Content-Type', row.rows[0].mime);
    res.set('Cache-Control', 'private, max-age=300');
    res.send(row.rows[0].data);
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/redteam/evidence/:eid — caption only; the bytes are immutable */
app.put('/api/redteam/evidence/:eid', async (req, res) => {
  try {
    const row = await pool.query('SELECT finding_id FROM pentest_finding_evidence WHERE id=$1', [req.params.eid]);
    if (row.rows.length === 0) return res.status(404).json({ error: 'Evidence not found.' });

    const { error } = await resolveFindingForTenantAccess(req, row.rows[0].finding_id);
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `UPDATE pentest_finding_evidence SET caption=$1 WHERE id=$2
       RETURNING id, finding_id, mime, filename, caption, sort_order, width_px, height_px, created_at`,
      [String(req.body.caption || '').slice(0, 300), req.params.eid]
    );
    res.json({ evidence: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/redteam/evidence/:eid */
app.delete('/api/redteam/evidence/:eid', async (req, res) => {
  try {
    const row = await pool.query('SELECT finding_id FROM pentest_finding_evidence WHERE id=$1', [req.params.eid]);
    if (row.rows.length === 0) return res.status(404).json({ error: 'Evidence not found.' });

    const { error } = await resolveFindingForTenantAccess(req, row.rows[0].finding_id);
    if (error) return res.status(error.status).json({ error: error.message });

    await pool.query('DELETE FROM pentest_finding_evidence WHERE id=$1', [req.params.eid]);
    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/redteam/projects/:id/report.docx — the client deliverable */
app.get('/api/redteam/projects/:id/report.docx', requireAuth, async (req, res) => {
  try {
    const { project, error } = await resolveProjectForTenantAccess(req);
    if (error) return res.status(error.status).json({ error: error.message });

    const metaRow = await pool.query('SELECT * FROM redteam_report_meta WHERE project_id=$1', [project.id]);
    const meta = metaRow.rows[0] || defaultReportMeta(project);

    const findingsRow = await pool.query(
      `SELECT * FROM pentest_findings WHERE project_id=$1
       ORDER BY sort_order, cvss_score DESC NULLS LAST, id`,
      [project.id]
    );
    const findings = findingsRow.rows;

    const evidenceByFinding = {};
    if (findings.length) {
      const evRows = await pool.query(
        `SELECT * FROM pentest_finding_evidence WHERE finding_id = ANY($1::int[]) ORDER BY sort_order, id`,
        [findings.map((f) => f.id)]
      );
      for (const ev of evRows.rows) {
        (evidenceByFinding[ev.finding_id] = evidenceByFinding[ev.finding_id] || []).push(ev);
      }
    }

    let logoBuffer = null;
    try { logoBuffer = fs.readFileSync(path.join(PUBLIC, 'img', 'reflex-logo.png')); } catch (_) { /* optional */ }

    const buffer = await buildPentestReport({ project, meta, findings, evidenceByFinding, logoBuffer });

    const safe = String(meta.report_title || project.title || 'Penetration-Test')
      .replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'Penetration-Test';
    const filename = `${safe}-Penetration-Test-Report-${meta.report_version || 'v1.0'}.docx`;

    res.set('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
    res.set('Content-Disposition', `attachment; filename="${filename}"`);
    res.set('Content-Length', buffer.length);
    res.send(buffer);
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
app.post('/api/ir/incidents', async (req, res) => {
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

    // The opening entry in the phase trail. Without it an incident created
    // today and never moved shows no dated history at all, which reads as
    // "nothing has happened" rather than "it is still being identified".
    await recordIrPhase(incident.id, tenantId, incident.phase, req.session.userId);

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
app.put('/api/ir/incidents/:id', async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, description, severity, status, assigned_to, phase, incident_type } = req.body;
    const incidentType = IR_VALID_TYPES.includes(incident_type) ? incident_type : 'other';
    const result = await pool.query(
      `WITH prev AS (
         SELECT phase FROM ir_incidents WHERE id=$8 AND tenant_id=$9 FOR UPDATE
       )
       UPDATE ir_incidents
       SET title=$1, description=$2, severity=$3, status=$4::varchar, assigned_to=$5, phase=$6, incident_type=$7, updated_at=NOW(),
           closed_at = CASE WHEN $4::varchar IN ('resolved','closed') AND closed_at IS NULL THEN NOW()
                            WHEN $4::varchar NOT IN ('resolved','closed') THEN NULL
                            ELSE closed_at END
       WHERE id=$8 AND tenant_id=$9
       RETURNING *, (SELECT phase FROM prev) AS previous_phase`,
      [title, description || '', severity, status, assigned_to || '', phase || 'identification', incidentType, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });

    // Editing the incident can move its phase too. Recorded here as well, or
    // a transition made through the edit form would leave no trace while the
    // same move via the phase control would.
    if (result.rows[0].previous_phase !== result.rows[0].phase) {
      await recordIrPhase(result.rows[0].id, tenantId, result.rows[0].phase, req.session.userId);
    }
    res.json({ incident: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/**
 * Record that an incident entered a phase.
 *
 * Append-only and written ONLY on an actual move: re-saving a form without
 * touching the phase must not add a row, or the trail fills with transitions
 * that never happened. Best-effort — a missing history table must never stop
 * an operator from advancing an incident.
 */
async function recordIrPhase(incidentId, tenantId, phase, userId) {
  try {
    await pool.query(
      `INSERT INTO ir_phase_events (incident_id, tenant_id, phase, changed_by)
       VALUES ($1, $2, $3, $4)`,
      [incidentId, tenantId, phase, userId || null]
    );
  } catch (err) {
    if (err.code !== '42P01') throw err;   // history table not migrated yet
  }
}

/** PATCH /api/ir/incidents/:id/phase — quick-set the IR lifecycle phase */
app.patch('/api/ir/incidents/:id/phase', async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { phase } = req.body;
    if (!IR_VALID_PHASES.includes(phase)) return res.status(400).json({ error: 'invalid phase.' });

    // The old phase comes from a CTE, not from a subquery inside RETURNING: a
    // RETURNING subquery would read the row this statement has just written and
    // always report the NEW value, so every save would look like a no-op and
    // nothing would ever be recorded. A CTE sees the snapshot taken at
    // statement start, and FOR UPDATE locks the row against a concurrent move.
    const result = await pool.query(
      `WITH prev AS (
         SELECT phase FROM ir_incidents WHERE id=$2 AND tenant_id=$3 FOR UPDATE
       )
       UPDATE ir_incidents SET phase=$1, updated_at=NOW()
        WHERE id=$2 AND tenant_id=$3
        RETURNING *, (SELECT phase FROM prev) AS previous_phase`,
      [phase, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });

    if (result.rows[0].previous_phase !== phase) {
      await recordIrPhase(result.rows[0].id, tenantId, phase, req.session.userId);
    }
    res.json({ incident: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/ir/incidents/:id/status — quick-set the incident status (used by the Remediation Tracker) */
app.patch('/api/ir/incidents/:id/status', async (req, res) => {
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
app.delete('/api/ir/incidents/:id', async (req, res) => {
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
app.post('/api/ir/activities', async (req, res) => {
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
app.put('/api/ir/activities/:id', async (req, res) => {
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
app.patch('/api/ir/activities/:id/phase', async (req, res) => {
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
app.delete('/api/ir/activities/:id', async (req, res) => {
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

/*
 * ══ Comments on playbook steps ══
 *
 * A thread per step, append-only — there is deliberately no edit or delete
 * route. An incident record is evidence that can end up in front of a client,
 * an insurer or a regulator; a correction is a later comment, not a rewrite.
 *
 * WRITE-GATED WITHOUT A GUARD HERE. app.use('/api', pageGate) maps the `ir`
 * prefix to the incident-response page and requires WRITE for any POST, so a
 * read-only role can see a thread and cannot add to it — the same rule every
 * other /api/ir write already relies on.
 *
 * STAFF-ONLY. lib/portal-routes.js never reads ir_activity_comments; the portal
 * shows only that a phase completed. tests/ir-step-comments.test.js holds it.
 *
 * DEGRADE-OPEN. On a database that has not run migrate-ir-step-comments.sql the
 * read returns an empty, `available: false` thread rather than a 500, so the
 * playbook still loads; a write says which migration to run.
 */
const IR_COMMENT_MAX = 4000;

/** GET /api/ir/incidents/:id/comments — every step's thread, in one request */
app.get('/api/ir/incidents/:id/comments', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const incidentId = parseInt(req.params.id, 10);
    if (!Number.isInteger(incidentId)) return res.status(404).json({ error: 'Incident not found.' });

    const incRes = await pool.query(
      'SELECT id FROM ir_incidents WHERE id=$1 AND tenant_id=$2', [incidentId, tenantId]);
    if (incRes.rows.length === 0) return res.status(404).json({ error: 'Incident not found.' });

    try {
      // One query for the whole incident rather than one per step: a phishing
      // playbook has a dozen steps, and N requests to open one incident is a
      // board that paints its threads in piecemeal.
      const r = await pool.query(
        `SELECT c.id, c.activity_id, c.body, c.created_at, u.username AS author
           FROM ir_activity_comments c
           LEFT JOIN users u ON u.id = c.author_id
          WHERE c.incident_id = $1 AND c.tenant_id = $2
          ORDER BY c.created_at ASC, c.id ASC`,
        [incidentId, tenantId]
      );
      return res.json({ available: true, comments: r.rows });
    } catch (err) {
      if (err.code !== '42P01') throw err;   // comments table not migrated yet
      return res.json({ available: false, comments: [] });
    }
  } catch (err) { return serverError(res, err); }
});

/** POST /api/ir/activities/:id/comments — add to one step's thread */
app.post('/api/ir/activities/:id/comments', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveIrTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const activityId = parseInt(req.params.id, 10);
    if (!Number.isInteger(activityId)) return res.status(404).json({ error: 'Activity not found.' });

    // Trimmed before the length check, so a comment of only whitespace is
    // empty rather than a blank entry in the thread with an author and a time.
    const text = typeof (req.body || {}).body === 'string' ? req.body.body.trim() : '';
    if (!text) return res.status(400).json({ error: 'Comment cannot be empty.' });
    if (text.length > IR_COMMENT_MAX) {
      return res.status(400).json({ error: `Comment is limited to ${IR_COMMENT_MAX} characters.` });
    }

    // OWNERSHIP THROUGH THE INCIDENT. The step id alone proves nothing — step
    // ids are sequential across every tenant — so the step must belong to an
    // incident in the caller's tenant, checked in the same statement.
    const act = await pool.query(
      `SELECT a.id, a.incident_id
         FROM ir_activities a
         JOIN ir_incidents i ON i.id = a.incident_id
        WHERE a.id = $1 AND i.tenant_id = $2`,
      [activityId, tenantId]
    );
    if (act.rows.length === 0) return res.status(404).json({ error: 'Activity not found.' });

    try {
      // The author comes from the session and never from the request body, so
      // a comment cannot be posted under someone else's name.
      const ins = await pool.query(
        `WITH ins AS (
           INSERT INTO ir_activity_comments (activity_id, incident_id, tenant_id, body, author_id)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, activity_id, body, created_at, author_id
         )
         SELECT ins.id, ins.activity_id, ins.body, ins.created_at, u.username AS author
           FROM ins LEFT JOIN users u ON u.id = ins.author_id`,
        [act.rows[0].id, act.rows[0].incident_id, tenantId, text, req.session.userId || null]
      );
      return res.json({ comment: ins.rows[0] });
    } catch (err) {
      if (err.code !== '42P01') throw err;
      return res.status(503).json({
        error: 'Step comments are not available yet — run db/migrate-ir-step-comments.sql.',
      });
    }
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

/**
 * Resolve an optional risks.vendor_id from a request body.
 *
 * The foreign key only proves the vendor exists, not that it belongs to this
 * tenant, so the ownership check has to happen here — otherwise one tenant
 * could attribute a risk to another tenant's vendor and the Third-Party tab
 * would render a name it should never see.
 *
 * Returns { vendorId } (possibly null) or { error }.
 */
async function resolveRiskVendorId(raw, tenantId) {
  if (raw === undefined || raw === null || raw === '') return { vendorId: null };
  const id = parseInt(raw, 10);
  if (isNaN(id) || id < 1) return { error: 'invalid vendor_id.' };
  const owned = await pool.query(
    'SELECT id FROM vendors WHERE id=$1 AND tenant_id=$2', [id, tenantId]
  );
  if (owned.rows.length === 0) return { error: 'vendor_id not found for this client.' };
  return { vendorId: id };
}

/** POST /api/risks */
app.post('/api/risks', async (req, res) => {
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

    const vend = await resolveRiskVendorId(req.body.vendor_id, tenantId);
    if (vend.error) return res.status(400).json({ error: vend.error });

    const result = await pool.query(
      `INSERT INTO risks (tenant_id, title, description, category, likelihood, impact, risk_score, owner, mitigation_plan, stage, start_date, due_date, created_by, vendor_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [tenantId, title, description || '', category || 'operational', lk, im, lk * im, owner || '', mitigation_plan || '', stage || 'identified', start_date, due_date || null, req.session.userId, vend.vendorId]
    );
    res.json({ risk: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/risks/:id */
app.put('/api/risks/:id', async (req, res) => {
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

    const vend = await resolveRiskVendorId(req.body.vendor_id, tenantId);
    if (vend.error) return res.status(400).json({ error: vend.error });

    const result = await pool.query(
      `UPDATE risks
       SET title=$1, description=$2, category=$3, likelihood=$4, impact=$5, risk_score=$6, owner=$7,
           mitigation_plan=$8, stage=$9, start_date=$10, due_date=$11, vendor_id=$12, updated_at=NOW(),
           closed_at = CASE WHEN $9::varchar = 'closed' AND closed_at IS NULL THEN NOW()
                            WHEN $9::varchar != 'closed' THEN NULL
                            ELSE closed_at END
       WHERE id=$13 AND tenant_id=$14 RETURNING *`,
      [title, description || '', category || 'operational', lk, im, lk * im, owner || '', mitigation_plan || '', stage || 'identified', start_date, due_date || null, vend.vendorId, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Risk not found.' });
    res.json({ risk: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/risks/:id/stage — used by kanban drag-and-drop */
app.patch('/api/risks/:id/stage', async (req, res) => {
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
app.delete('/api/risks/:id', async (req, res) => {
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

// ── Third-Party Risk (vendor inventory) routes ────────────────────────────

function resolveVendorTenant(req, source) {
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

// Mirror the CHECK constraints in db/migrate-third-party-risk.sql. Validating
// here turns a 500 from Postgres into a 400 that names the bad field.
const VENDOR_CRITICALITY = ['critical', 'high', 'medium', 'low'];
const VENDOR_DATA_ACCESS = ['none', 'internal', 'confidential', 'pii', 'regulated'];
const VENDOR_ASSURANCE   = ['none', 'questionnaire', 'soc2', 'iso27001', 'both'];
const VENDOR_STATUS      = ['onboarding', 'active', 'under_review', 'offboarding', 'terminated'];

// Assurance values that count as evidence held. 'questionnaire' is a
// self-attestation by the vendor, not independent evidence, so it is not one.
const VENDOR_EVIDENCE = ['soc2', 'iso27001', 'both'];

/**
 * Validate and normalise a vendor payload, then derive its scores.
 * Returns { error } or { fields } — the caller never reads req.body directly,
 * so a client-sent inherent_score/residual_score simply cannot reach the table.
 */
function prepareVendor(body) {
  const name = String(body.name || '').trim();
  if (!name) return { error: 'name is required.' };

  const criticality = body.criticality || 'medium';
  const dataAccess  = body.data_access || 'none';
  const assurance   = body.assurance   || 'none';
  const status      = body.status      || 'active';

  if (!VENDOR_CRITICALITY.includes(criticality)) return { error: 'invalid criticality.' };
  if (!VENDOR_DATA_ACCESS.includes(dataAccess))  return { error: 'invalid data_access.' };
  if (!VENDOR_ASSURANCE.includes(assurance))     return { error: 'invalid assurance.' };
  if (!VENDOR_STATUS.includes(status))           return { error: 'invalid status.' };

  const fields = {
    name,
    service:           String(body.service || '').trim(),
    owner:             String(body.owner   || '').trim(),
    criticality,
    data_access:       dataAccess,
    network_access:    body.network_access === true || body.network_access === 'true',
    assurance,
    assurance_expires: body.assurance_expires || null,
    contract_start:    body.contract_start    || null,
    contract_end:      body.contract_end      || null,
    last_review_date:  body.last_review_date  || null,
    next_review_date:  body.next_review_date  || null,
    status,
    notes:             String(body.notes || '').trim(),
  };

  // Derived server-side on every write, exactly as POST /api/risks computes
  // risk_score rather than trusting the body.
  const scored = scoreVendor(fields);
  fields.inherent_score = scored.inherent;
  fields.residual_score = scored.residual;

  return { fields };
}

/** GET /api/vendors/stats */
app.get('/api/vendors/stats', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveVendorTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    // 'terminated' relationships are history, not inventory — every tile
    // except the total counts only vendors still engaged.
    const live = `status != 'terminated'`;

    const [totalRes, tierRes, overdueRes, noEvidenceRes, expiringRes] = await Promise.all([
      pool.query(`SELECT COUNT(*) FROM vendors WHERE tenant_id=$1 AND ${live}`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM vendors WHERE tenant_id=$1 AND ${live}
                    AND criticality IN ('critical','high')`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM vendors WHERE tenant_id=$1 AND ${live}
                    AND next_review_date IS NOT NULL AND next_review_date < CURRENT_DATE`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM vendors WHERE tenant_id=$1 AND ${live}
                    AND (assurance NOT IN ('soc2','iso27001','both')
                         OR (assurance_expires IS NOT NULL AND assurance_expires < CURRENT_DATE))`, [tenantId]),
      pool.query(`SELECT COUNT(*) FROM vendors WHERE tenant_id=$1 AND ${live}
                    AND assurance_expires IS NOT NULL
                    AND assurance_expires >= CURRENT_DATE
                    AND assurance_expires < CURRENT_DATE + INTERVAL '90 days'`, [tenantId]),
    ]);

    res.json({
      total:            parseInt(totalRes.rows[0].count, 10) || 0,
      highTier:         parseInt(tierRes.rows[0].count, 10) || 0,
      reviewsOverdue:   parseInt(overdueRes.rows[0].count, 10) || 0,
      noEvidence:       parseInt(noEvidenceRes.rows[0].count, 10) || 0,
      expiringSoon:     parseInt(expiringRes.rows[0].count, 10) || 0,
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/vendors */
app.get('/api/vendors', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveVendorTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const result = await pool.query(
      `SELECT * FROM vendors WHERE tenant_id = $1 ORDER BY residual_score DESC, name ASC`,
      [tenantId]
    );
    res.json({ vendors: result.rows });
  } catch (err) { return serverError(res, err); }
});

/** POST /api/vendors */
app.post('/api/vendors', async (req, res) => {
  try {
    const { tenantId, error } = resolveVendorTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const prepared = prepareVendor(req.body);
    if (prepared.error) return res.status(400).json({ error: prepared.error });
    const f = prepared.fields;

    const result = await pool.query(
      `INSERT INTO vendors (tenant_id, name, service, owner, criticality, data_access, network_access,
                            assurance, assurance_expires, contract_start, contract_end,
                            last_review_date, next_review_date, status,
                            inherent_score, residual_score, notes, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING *`,
      [tenantId, f.name, f.service, f.owner, f.criticality, f.data_access, f.network_access,
       f.assurance, f.assurance_expires, f.contract_start, f.contract_end,
       f.last_review_date, f.next_review_date, f.status,
       f.inherent_score, f.residual_score, f.notes, req.session.userId]
    );
    res.json({ vendor: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/vendors/:id */
app.put('/api/vendors/:id', async (req, res) => {
  try {
    const { tenantId, error } = resolveVendorTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const prepared = prepareVendor(req.body);
    if (prepared.error) return res.status(400).json({ error: prepared.error });
    const f = prepared.fields;

    const result = await pool.query(
      `UPDATE vendors
       SET name=$1, service=$2, owner=$3, criticality=$4, data_access=$5, network_access=$6,
           assurance=$7, assurance_expires=$8, contract_start=$9, contract_end=$10,
           last_review_date=$11, next_review_date=$12, status=$13,
           inherent_score=$14, residual_score=$15, notes=$16, updated_at=NOW()
       WHERE id=$17 AND tenant_id=$18 RETURNING *`,
      [f.name, f.service, f.owner, f.criticality, f.data_access, f.network_access,
       f.assurance, f.assurance_expires, f.contract_start, f.contract_end,
       f.last_review_date, f.next_review_date, f.status,
       f.inherent_score, f.residual_score, f.notes, req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Vendor not found.' });
    res.json({ vendor: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/vendors/:id */
app.delete('/api/vendors/:id', async (req, res) => {
  try {
    const { tenantId, error } = resolveVendorTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    // risks.vendor_id is ON DELETE SET NULL, so any register entries raised
    // against this vendor survive with their attribution cleared.
    const result = await pool.query(
      'DELETE FROM vendors WHERE id=$1 AND tenant_id=$2 RETURNING id',
      [req.params.id, tenantId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Vendor not found.' });
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
app.post('/api/pentest-findings', async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, severity, description, recommendation, owner, due_date, status, notes, project_id } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (severity !== undefined && !PENTEST_SEVERITIES.includes(severity)) return res.status(400).json({ error: 'invalid severity.' });
    if (status !== undefined && !PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const rep = parseReportFields(req.body);
    if (rep.error) return res.status(400).json({ error: rep.error });

    const result = await pool.query(
      `INSERT INTO pentest_findings (tenant_id, project_id, title, severity, description, recommendation, owner, due_date, status, notes, created_by,
                                     cvss_vector, cvss_score, classification, affected_endpoints, business_impact, sort_order)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) RETURNING *`,
      [tenantId, project_id || null, title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', req.session.userId,
       rep.cvss_vector, rep.cvss_score, rep.classification, rep.affected_endpoints, rep.business_impact, rep.sort_order]
    );
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PUT /api/pentest-findings/:id */
app.put('/api/pentest-findings/:id', async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const { title, severity, description, recommendation, owner, due_date, status, notes, project_id } = req.body;
    if (!title) return res.status(400).json({ error: 'title is required.' });
    if (severity !== undefined && !PENTEST_SEVERITIES.includes(severity)) return res.status(400).json({ error: 'invalid severity.' });
    if (status !== undefined && !PENTEST_STATUSES.includes(status)) return res.status(400).json({ error: 'invalid status.' });

    const rep = parseReportFields(req.body);
    if (rep.error) return res.status(400).json({ error: rep.error });

    // Callers that know nothing about the report fields (e.g. the Remediation
    // Tracker) must not blank them out, so only write them when they were sent.
    const REPORT_KEYS = ['cvss_vector', 'cvss_score', 'classification', 'affected_endpoints', 'business_impact', 'sort_order'];
    const sendsReportFields = REPORT_KEYS.some((k) => req.body[k] !== undefined);
    const params = [title, severity || 'medium', description || '', recommendation || '', owner || '', due_date || null, status || 'open', notes || '', project_id || null, req.params.id, tenantId];
    let reportSet = '';
    if (sendsReportFields) {
      reportSet = `, cvss_vector=$12, cvss_score=$13, classification=$14, affected_endpoints=$15,
                     business_impact=$16, sort_order=$17`;
      params.push(rep.cvss_vector, rep.cvss_score, rep.classification, rep.affected_endpoints, rep.business_impact, rep.sort_order);
    }

    const result = await pool.query(
      `UPDATE pentest_findings
       SET title=$1, severity=$2, description=$3, recommendation=$4, owner=$5, due_date=$6, status=$7, notes=$8,
           project_id=$9, updated_at=NOW()${reportSet},
           status_updated_at = CASE WHEN $7::varchar IS DISTINCT FROM status THEN NOW() ELSE status_updated_at END
       WHERE id=$10 AND tenant_id=$11 RETURNING *`,
      params
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Finding not found.' });
    res.json({ finding: result.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** PATCH /api/pentest-findings/:id/status */
app.patch('/api/pentest-findings/:id/status', async (req, res) => {
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
app.delete('/api/pentest-findings/:id', async (req, res) => {
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
                status_updated_at AS "statusUpdatedAt", first_seen_at AS "firstSeenAt",
                due_date AS "dueDate"
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

// ── Risk acceptances (client-requested, staff-reviewed) ───────────────────
//
// Clients request from the portal (lib/portal-routes.js); the request changes
// nothing until it is approved here. Approval sets the finding accepted, which
// removes it from the vulnerability counts and so raises the Secure Score —
// the reason this is a staff decision and not a client one. Gated on WRITE to
// the Remediation Tracker page via API_PREFIX_TO_PAGE['risk-acceptances'].

/** Run fn inside a transaction on one client; always releases. */
async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query(out && out.rollback ? 'ROLLBACK' : 'COMMIT');
    return out;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/**
 * The finding rows an acceptance applies to.
 *
 * Pentest findings have a stable id. A vulnerability is followed by its
 * plugin|host|port key into the LATEST scan — the same key the upload
 * carry-forward uses — because the row it was raised against may have been
 * replaced by a newer upload while the request waited for review. Only when an
 * old row carried no identity at all does it fall back to the id.
 */
function acceptanceFindingMatch(row) {
  if (row.plugin_id == null && row.host == null && row.port == null) {
    return { sql: 'id = $4', params: [row.finding_id] };
  }
  return {
    sql: 'plugin_id IS NOT DISTINCT FROM $4 AND host IS NOT DISTINCT FROM $5 AND port IS NOT DISTINCT FROM $6',
    params: [row.plugin_id, row.host, row.port],
  };
}

/**
 * Move a finding between statuses on behalf of an acceptance, inside the
 * caller's transaction. Returns the number of finding rows changed.
 *
 * `fromStatuses` is the guard: approval only accepts a finding that is still
 * open, and expiry only reopens one that is still accepted — if staff have
 * since marked it fixed, the expiry must not resurrect it.
 */
async function moveAcceptanceFinding(client, row, fromStatuses, toStatus, note) {
  if (row.source === 'pentest') {
    const u = await client.query(
      `UPDATE pentest_findings
          SET status = $1,
              notes = CASE WHEN notes = '' THEN $2 ELSE notes || E'\\n' || $2 END,
              status_updated_at = NOW(), updated_at = NOW()
        WHERE id = $3 AND tenant_id = $4 AND status = ANY($5::text[])
        RETURNING id`,
      [toStatus, note, row.finding_id, row.tenant_id, fromStatuses]);
    return u.rows.length;
  }

  const scan = await client.query(
    'SELECT id FROM vuln_scans WHERE tenant_id = $1 ORDER BY month_key DESC LIMIT 1',
    [row.tenant_id]);
  if (!scan.rows.length) return 0;
  const scanId = scan.rows[0].id;

  const match = acceptanceFindingMatch(row);
  const u = await client.query(
    `UPDATE vuln_findings
        SET status = $1,
            notes = CASE WHEN notes = '' THEN $2 ELSE notes || E'\\n' || $2 END,
            status_updated_at = NOW()
      WHERE scan_id = $3 AND ${match.sql} AND status = ANY($${4 + match.params.length}::text[])
      RETURNING id`,
    [toStatus, note, scanId].concat(match.params, [fromStatuses]));

  // The score reads the summary, not the findings. Same transaction, for the
  // reason given at resyncVulnSummary().
  if (u.rows.length) await resyncVulnSummary(client, scanId);
  return u.rows.length;
}

const RISK_ACCEPTANCES_NOT_MIGRATED =
  'Risk acceptances are not set up on this database yet. Run db/migrate-risk-acceptances.sql.';

/** GET /api/risk-acceptances?status=pending — the review queue and the register. */
app.get('/api/risk-acceptances', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolvePentestTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const params = [tenantId];
    let where = 'ra.tenant_id = $1';
    if (riskAcceptance.STATUSES.includes(req.query.status)) {
      params.push(req.query.status);
      where += ' AND ra.status = $2';
    }

    const r = await pool.query(
      `SELECT ra.id, ra.source, ra.finding_id, ra.plugin_id, ra.host, ra.port,
              ra.finding_title, ra.finding_severity, ra.approver_name, ra.approver_role,
              ra.justification, ra.expires_on, ra.status, ra.requested_at,
              ra.reviewed_at, ra.review_note, ra.closed_at,
              ru.username AS requested_by_name, vu.username AS reviewed_by_name
         FROM risk_acceptances ra
         LEFT JOIN users ru ON ru.id = ra.requested_by
         LEFT JOIN users vu ON vu.id = ra.reviewed_by
        WHERE ${where}
        ORDER BY (ra.status = 'pending') DESC, ra.requested_at DESC
        LIMIT 200`,
      params);

    res.json({
      available: true,
      acceptances: r.rows.map(row =>
        Object.assign(row, { expires_on: riskAcceptance.dateOnly(row.expires_on) })),
    });
  } catch (err) {
    if (err.code === '42P01') return res.json({ available: false, acceptances: [] });
    return serverError(res, err);
  }
});

/** POST /api/risk-acceptances/:id/approve — { note? } */
app.post('/api/risk-acceptances/:id/approve', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id < 1) return res.status(404).json({ error: 'Acceptance not found.' });

    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const note = riskAcceptance.validateReviewNote(req.body && req.body.note, false);
    if (note.error) return res.status(400).json({ error: note.error });

    const out = await withTransaction(async (client) => {
      // Locked, and owned by this tenant in the WHERE clause.
      const r = await client.query(
        'SELECT * FROM risk_acceptances WHERE id = $1 AND tenant_id = $2 FOR UPDATE',
        [id, tenantId]);
      if (!r.rows.length) return { rollback: true, status: 404, error: 'Acceptance not found.' };
      const row = r.rows[0];

      if (row.status !== 'pending') {
        return { rollback: true, status: 409, error: 'This acceptance is already ' + row.status + '.' };
      }
      if (riskAcceptance.dateOnly(row.expires_on) <= riskAcceptance.todayUtc(new Date())) {
        return { rollback: true, status: 409,
          error: 'Its review date has already passed. Reject it and ask the client to resubmit.' };
      }

      const moved = await moveAcceptanceFinding(client, row,
        riskAcceptance.OPEN_STATUSES, riskAcceptance.SOURCES[row.source].acceptedStatus,
        riskAcceptance.acceptedNote(row));
      if (!moved) {
        return { rollback: true, status: 409,
          error: 'The finding is no longer open in the latest data, so there is nothing to accept. ' +
                 'Reject this request with a note to the client instead.' };
      }

      await client.query(
        `UPDATE risk_acceptances
            SET status = 'approved', reviewed_by = $1, reviewed_at = NOW(), review_note = $2
          WHERE id = $3 AND tenant_id = $4`,
        [req.session.userId, note.value, id, tenantId]);
      return { ok: true, findingsUpdated: moved };
    });

    if (out.error) return res.status(out.status).json({ error: out.error });
    res.json(out);
  } catch (err) {
    if (err.code === '42P01') return res.status(503).json({ error: RISK_ACCEPTANCES_NOT_MIGRATED });
    return serverError(res, err);
  }
});

/** POST /api/risk-acceptances/:id/reject — { note } (required: the client is owed a reason) */
app.post('/api/risk-acceptances/:id/reject', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || id < 1) return res.status(404).json({ error: 'Acceptance not found.' });

    const { tenantId, error } = resolvePentestTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const note = riskAcceptance.validateReviewNote(req.body && req.body.note, true);
    if (note.error) return res.status(400).json({ error: note.error });

    const r = await pool.query(
      `UPDATE risk_acceptances
          SET status = 'rejected', reviewed_by = $1, reviewed_at = NOW(),
              review_note = $2, closed_at = NOW()
        WHERE id = $3 AND tenant_id = $4 AND status = 'pending'
        RETURNING id`,
      [req.session.userId, note.value, id, tenantId]);
    if (!r.rows.length) return res.status(404).json({ error: 'No pending acceptance with that id.' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === '42P01') return res.status(503).json({ error: RISK_ACCEPTANCES_NOT_MIGRATED });
    return serverError(res, err);
  }
});

/**
 * Expire approved acceptances whose review date has passed, and reopen their
 * findings so they are scored again.
 *
 * One transaction per acceptance: one finding failing to reopen must not hold
 * every other client's expiry hostage. A finding staff have since marked fixed
 * is left fixed — the acceptance still expires, but nothing is reopened.
 */
async function expireRiskAcceptances() {
  let due;
  try {
    due = await pool.query(
      `SELECT * FROM risk_acceptances
        WHERE status = 'approved' AND expires_on < (NOW() AT TIME ZONE 'UTC')::date
        ORDER BY id LIMIT 500`);
  } catch (err) {
    if (err.code === '42P01') return 0;   // not migrated
    throw err;
  }

  let expired = 0;
  for (const row of due.rows) {
    try {
      await withTransaction(async (client) => {
        const still = await client.query(
          `SELECT id FROM risk_acceptances WHERE id = $1 AND status = 'approved' FOR UPDATE`,
          [row.id]);
        if (!still.rows.length) return { rollback: true };

        await moveAcceptanceFinding(client, row,
          [riskAcceptance.SOURCES[row.source].acceptedStatus], 'open',
          'Risk acceptance RA-' + row.id + ' expired on ' +
            riskAcceptance.dateOnly(row.expires_on) + '; reopened for review.');

        await client.query(
          `UPDATE risk_acceptances SET status = 'expired', closed_at = NOW() WHERE id = $1`,
          [row.id]);
        expired++;
        return { ok: true };
      });
    } catch (err) {
      console.error('[risk-acceptance] expiry failed for RA-' + row.id + ' —', err.message);
    }
  }
  return expired;
}

const RISK_ACCEPTANCE_SWEEP_MS = 6 * 60 * 60 * 1000;
function runRiskAcceptanceExpiry() {
  expireRiskAcceptances()
    .then(n => { if (n) console.log('[risk-acceptance] expired ' + n + ' acceptance(s); findings reopened'); })
    .catch(err => console.error('[risk-acceptance] expiry sweep failed —', err.message));
}
if (process.env.NODE_ENV !== 'test') {
  setTimeout(runRiskAcceptanceExpiry, 2 * 60 * 1000);
  setInterval(runRiskAcceptanceExpiry, RISK_ACCEPTANCE_SWEEP_MS);
}

// ── Client report deck ─────────────────────────────────────────────────────

function resolveReportTenant(req, source) {
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

/** Current month as 'YYYY-MM'. */
function currentPeriod() {
  return new Date().toISOString().slice(0, 7);
}

function normalisePeriod(raw) {
  return /^\d{4}-\d{2}$/.test(raw || '') ? raw : currentPeriod();
}

/**
 * GET /api/reports/metrics?tenantId&period=YYYY-MM
 * Overview tile values for the client deck. Every tile is the uniform triple
 * { derived, source, override } — the effective value is override ?? derived.
 */
app.get('/api/reports/metrics', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const period   = normalisePeriod(req.query.period);
    const warnings = [];

    const [tenantRes, ticketRes, uploadRes, overrideRes] = await Promise.all([
      pool.query('SELECT name FROM tenants WHERE id = $1', [tenantId]),
      pool.query(
        `SELECT COUNT(*) FILTER (WHERE t.status IN ('open','pending'))::int AS open_tickets,
                COUNT(*)::int                                              AS ticketed_incidents
           FROM mdr_tickets t
           JOIN mdr_uploads u ON u.id = t.upload_id
          WHERE u.tenant_id = $1
            AND to_char(t.created_at, 'YYYY-MM') = $2`,
        [tenantId, period]
      ).catch(() => ({ rows: [{ open_tickets: null, ticketed_incidents: null }] })),
      pool.query(
        `SELECT to_char(uploaded_at, 'YYYY-MM') AS upload_period
           FROM mdr_uploads WHERE tenant_id = $1 ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      ).catch(() => ({ rows: [] })),
      pool.query(
        `SELECT metric_id, value FROM report_metrics
          WHERE tenant_id = $1 AND period = $2 AND source = 'manual'`,
        [tenantId, period]
      ).catch(() => ({ rows: [] })),
    ]);

    const tenantName = (tenantRes.rows[0] || {}).name || null;
    const tickets    = ticketRes.rows[0] || {};

    // MDR data is stored latest-snapshot-only, so a period older than the most
    // recent sync legitimately has no tickets. Say so rather than reporting 0.
    const uploadPeriod = (uploadRes.rows[0] || {}).upload_period;
    if (!uploadPeriod) {
      warnings.push('No MDR ticket data has been synced for this client yet.');
    } else if (uploadPeriod !== period) {
      warnings.push(`MDR tickets were last synced in ${uploadPeriod}; ticket counts for ${period} are drawn from that snapshot and may be incomplete.`);
    }

    // Tiles Arctic Wolf owns. Cache-only — never block report generation on the
    // Reports API poll window.
    const aw = await arcticWolfMetricsAdapter
      .fetchDeckMetrics({ pool, tenantId, period, decrypt: decryptKey, refresh: false })
      .catch(err => ({ metrics: {}, warnings: ['Arctic Wolf metrics unavailable: ' + err.message] }));
    warnings.push(...(aw.warnings || []));

    const overrides = {};
    overrideRes.rows.forEach(r => {
      if (r.value != null && r.value !== '') overrides[r.metric_id] = r.value;
    });

    const awValue = id => (aw.metrics[id] ? aw.metrics[id].value : null);

    function tile(id, derived, source) {
      const fromAw = awValue(id);
      return {
        derived:  fromAw != null ? fromAw : (derived === undefined ? null : derived),
        source:   fromAw != null ? 'arctic-wolf' : (derived === null || derived === undefined ? 'unavailable' : source),
        override: overrides[id] != null ? overrides[id] : null,
      };
    }

    const tiles = {
      openTickets:       tile('openTickets',       tickets.open_tickets,       'mdr-tickets'),
      ticketedIncidents: tile('ticketedIncidents', tickets.ticketed_incidents, 'mdr-tickets'),
      // Derived value is filled in client-side from /api/secure-score so the
      // scoring engine lives in exactly one place; only the override is ours.
      secureScore:       tile('secureScore',       null,                       'secure-score'),
    };

    res.json({ tenantId, tenantName, period, tiles, warnings });
  } catch (err) { return serverError(res, err); }
});

/**
 * PUT /api/reports/metrics
 * Body: { tenantId?, period, overrides: { metricId: value|null } }
 * Manual tile overrides. Null / empty clears the override.
 */
app.put('/api/reports/metrics', async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const period    = normalisePeriod(req.body.period);
    const overrides = req.body.overrides;
    if (!overrides || typeof overrides !== 'object') {
      return res.status(400).json({ error: 'overrides object is required.' });
    }

    for (const [metricId, raw] of Object.entries(overrides)) {
      const value = raw == null ? '' : String(raw).trim();
      if (value === '') {
        await pool.query(
          `DELETE FROM report_metrics
            WHERE tenant_id=$1 AND period=$2 AND metric_id=$3 AND source='manual'`,
          [tenantId, period, metricId]
        );
      } else {
        await pool.query(
          `INSERT INTO report_metrics (tenant_id, period, metric_id, value, source, updated_by, updated_at)
                VALUES ($1, $2, $3, $4, 'manual', $5, NOW())
           ON CONFLICT (tenant_id, period, metric_id, source)
             DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
          [tenantId, period, metricId, value, req.session.userId]
        );
      }
    }

    res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

/**
 * POST /api/reports/metrics/sync
 * Body: { tenantId?, period }   Query: ?debug=1 to include the raw payload.
 *
 * Pulls the Arctic Wolf tiles live and caches them in report_metrics. Separate
 * from report generation because each report can take up to two minutes to
 * generate on Arctic Wolf's side.
 */
app.post('/api/reports/metrics/sync', async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const period = normalisePeriod(req.body.period);
    const debug  = req.query.debug === '1' || req.body.debug === true;

    const result = await arcticWolfMetricsAdapter.syncDeckMetrics({
      pool, tenantId, period, decrypt: decryptKey, debug,
    });

    const values = {};
    Object.keys(result.metrics || {}).forEach(k => { values[k] = result.metrics[k].value; });

    res.json({
      ok:       true,
      period,
      written:  result.written,
      values,
      warnings: result.warnings || [],
      raw:      debug ? (result.raw || {}) : undefined,
    });
  } catch (err) { return serverError(res, err); }
});

// The deck's awareness slide groups the raw rows from /api/awareness client-side
// (see groupSessions in public/js/report-sections.js) rather than using a bespoke
// aggregate here, so it can never disagree with the Awareness tab.

/**
 * POST /api/reports/pptx - the board deck as an editable PowerPoint file.
 *
 * The client sends the section HTML it has ALREADY rendered for the on-screen
 * deck, and lib/report-pptx.js translates that into native slides. It works this
 * way on purpose: the browser is where the data, the users overrides and the
 * typed narrative come together, and re-fetching it here would create a second
 * assembly path that could disagree with the deck the user is looking at.
 *
 * The HTML is never executed, only parsed with node-html-parser, and the only
 * image embedded is the logo this server reads off its own disk - a
 * client-supplied data URI never reaches the file.
 *
 * The handler lives in lib/report-pptx-route.js so a test can mount it over real
 * HTTP without a database. Access is gated on the Reports page by the API prefix
 * map in lib/pages.js.
 */
app.post('/api/reports/pptx', requireAuth, pptxRoute.createPptxHandler({
  logoDataUri: pptxRoute.makeLogoReader(__dirname),
  log:         msg => console.log(msg),
  onError:     (res, err) => serverError(res, err),
}));

// ── Published report archive ───────────────────────────────────────────────
//
// These sit under /api/reports, which lib/pages.js already maps to the reports
// page, so pageGate requires read for the listings and write for the publish
// and withdraw. No change to the page catalog was needed.
//
// The archive is what the client portal serves: staff assemble a deck, review
// it, and publish the artefact they approved. See lib/report-archive.js.

/** POST /api/reports/publish — archive the deck staff are looking at. */
app.post('/api/reports/publish', requireAuth, reportArchive.createPublishHandler({
  pool,
  resolveTenant: req => resolveReportTenant(req, 'body'),
  logoDataUri:   pptxRoute.makeLogoReader(__dirname),
  onError:       (res, err) => serverError(res, err),
}));

/** GET /api/reports/publications — every version, withdrawn ones included. */
app.get('/api/reports/publications', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const publications = await reportArchive.listPublications(pool, {
      tenantId, period: req.query.period || null,
    });
    return res.json({ tenantId, publications });
  } catch (err) {
    if (err.code === '42P01') {
      return res.status(503).json({
        error: 'Report archive not available. Run db/migrate-report-archive.sql.',
      });
    }
    return serverError(res, err);
  }
});

/** GET /api/reports/publications/:id/pptx — staff download. */
app.get('/api/reports/publications/:id/pptx', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const row = await reportArchive.getPublication(pool, parseInt(req.params.id, 10), tenantId);
    if (!row) return res.status(404).json({ error: 'Report not found.' });

    res.on('finish', () => reportArchive.noteDownload(pool, row.id));
    return reportArchive.sendPublicationPptx(res, row);
  } catch (err) { return serverError(res, err); }
});

/** GET /api/reports/publications/:id/view — exactly what the client sees. */
app.get('/api/reports/publications/:id/view', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'query');
    if (error) return res.status(error.status).json({ error: error.message });

    const row = await reportArchive.getPublication(pool, parseInt(req.params.id, 10),
      tenantId, { withHtml: true });
    if (!row) return res.status(404).json({ error: 'Report not found.' });
    return reportArchive.sendPublicationHtml(res, row);
  } catch (err) { return serverError(res, err); }
});

/**
 * POST /api/reports/publications/:id/withdraw
 *
 * A state transition, not an edit: the row and the file stay, so the record of
 * what was published and later retracted survives. The client stops seeing it.
 */
app.post('/api/reports/publications/:id/withdraw', requireAuth, async (req, res) => {
  try {
    const { tenantId, error } = resolveReportTenant(req, 'body');
    if (error) return res.status(error.status).json({ error: error.message });

    const reason = String((req.body && req.body.reason) || '').slice(0, 1000);
    if (!reason.trim()) {
      return res.status(400).json({ error: 'A reason is required to withdraw a report.' });
    }

    const r = await pool.query(
      `UPDATE report_publications
          SET status = 'withdrawn', withdrawn_at = NOW(),
              withdrawn_by = $1, withdraw_reason = $2
        WHERE id = $3 AND tenant_id = $4 AND status = 'published'
        RETURNING id, period, version, status`,
      [req.session.userId || null, reason, parseInt(req.params.id, 10), tenantId]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Report not found.' });
    return res.json({ ok: true, publication: r.rows[0] });
  } catch (err) { return serverError(res, err); }
});

/** DELETE /api/reports/publications/:id — hard delete. Superadmin only. */
app.delete('/api/reports/publications/:id', requireAuth, requireSuperAdmin, async (req, res) => {
  try {
    const r = await pool.query(
      'DELETE FROM report_publications WHERE id = $1 RETURNING pptx_path',
      [parseInt(req.params.id, 10)]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Report not found.' });

    // Row first, file second: an orphan file is swept, an orphan row is not.
    const abs = reportArchive.resolveArchivePath(r.rows[0].pptx_path);
    if (abs) { try { fs.unlinkSync(abs); } catch (_) { /* swept at boot */ } }
    return res.json({ ok: true });
  } catch (err) { return serverError(res, err); }
});

// ── Secure Score routes ────────────────────────────────────────────────────

/**
 * GET /api/secure-score
 * Get the latest Secure Score for the current tenant.
 * Calculates on-the-fly from latest vuln/awareness/mdr data.
 */
/**
 * Superadmins have no tenant on the session, so both score routes must accept
 * ?tenantId= the way every other tenant-scoped route does. Without this the
 * Reports tab gets a 400 for superadmins even though it sends the parameter.
 */
function resolveScoreTenant(req) {
  if (req.session.role === 'superadmin') {
    const tid = parseInt(req.query.tenantId, 10);
    return (isNaN(tid) || tid < 1) ? null : tid;
  }
  return req.session.tenantId || null;
}

/** Last day of a 'YYYY-MM' month, as an ISO instant. */
function monthEnd(monthKey) {
  const [y, m] = monthKey.split('-').map(Number);
  return new Date(Date.UTC(y, m, 1) - 1).toISOString();
}

/** The last `n` calendar months ending at the current one, newest first. */
function recentMonths(n) {
  const out = [];
  const now = new Date();
  for (let i = 0; i < n; i++) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    out.push(d.toISOString().slice(0, 7));
  }
  return out;
}

/**
 * Rebuild the awareness and incident-response components for past months.
 *
 * Both are reconstructable even though awareness_uploads and mdr_uploads keep
 * only the latest snapshot: the child rows are dated. A session knows when it
 * was sent and when it was completed; a ticket knows when it was raised and
 * resolved. Counting each as at a month end therefore recovers what the score
 * would have been then.
 *
 * The caveat is that it reconstructs from TODAY'S export: a user who has since
 * left, or a ticket purged upstream, is no longer in the data and so is absent
 * from past months too. Stored snapshots are authoritative where they exist;
 * this fills the gap before snapshots start accumulating.
 *
 * Phishing simulations are excluded to match the live score in /api/secure-score.
 */
async function reconstructComponents(tenantId, months) {
  const out = new Map();
  if (!months.length) return out;

  let sessions = [];
  try {
    const r = await pool.query(
      `SELECT s.sent_date, s.completed_date, s.status
         FROM awareness_sessions s
         JOIN awareness_uploads u ON u.id = s.upload_id
        WHERE u.tenant_id = $1
          AND s.sent_date IS NOT NULL
          AND (s.session_type IS NULL OR LOWER(s.session_type) NOT LIKE '%phishing simulation%')`,
      [tenantId]
    );
    sessions = r.rows;
  } catch (_) { /* not migrated, or summary-format upload — no session history */ }

  let tickets = [];
  let feedExists = false;
  try {
    // ticket_type selected so the cohort can filter to incidents — see the
    // matching note in loadScoreInputs().
    const r = await pool.query(
      `SELECT t.created_at, t.resolved_at, t.ticket_type
         FROM mdr_tickets t
         JOIN mdr_uploads u ON u.id = t.upload_id
        WHERE u.tenant_id = $1 AND t.created_at IS NOT NULL`,
      [tenantId]
    );
    tickets = r.rows;
    feedExists = tickets.length > 0;
  } catch (_) { /* not migrated */ }

  months.forEach(monthKey => {
    const rec = { awarenessScore: null, mdrScore: null, evidence: {} };

    // Sessions issued by the end of the month, and those completed by then.
    // Counted in lib/score-evidence.js so the explanation beside the trend and
    // the score it explains cannot be counting different sessions.
    const aw = scoreEvidence.awarenessEvidence(sessions, monthKey);
    rec.evidence.awareness = aw;
    if (aw) {
      rec.awarenessScore = calculateAwarenessScore({
        upload: { total_users: aw.assigned, total_incomplete: aw.assigned - aw.completed },
      });
    }
    rec.evidence.incidentResponse = scoreEvidence.incidentEvidence(tickets, monthKey, { feedExists });

    /*
     * THE TICKETS RAISED IN THAT MONTH — not every ticket raised up to it.
     *
     * This counted cumulatively: every ticket the client had ever raised by the
     * month end, with its resolved state frozen at that date. Two things were
     * wrong with it. A single good month could barely move a figure averaged
     * over the client's whole history, so the trend flattened out the longer a
     * client stayed with us; and it measured a different thing from the live
     * score beside it, which meant a rising trend line could be an artefact of
     * the two definitions rather than of anything the client did.
     *
     * Now each point is that month's own cohort, through the same module the
     * live score and the report KPIs use — so the trend and the headline are
     * finally comparable.
     *
     * Resolution is NOT frozen at the month end here either, matching the
     * report: a ticket raised in June and closed in July counts as resolved for
     * June. Reconstruction already carries the caveat that it is built from
     * today's export; this is the same caveat, and the trend chart states it.
     */
    const stat = mdrMetrics.cohortStats(tickets, monthKey);
    if (stat.raised) {
      rec.mdrScore = calculateMdrScore({ upload: mdrMetrics.scoreInput(stat) });
    }

    out.set(monthKey, rec);
  });

  return out;
}

/**
 * Persist a daily snapshot of the score and its components.
 *
 * Scores are computed on the fly from whatever data is currently loaded, so
 * without this there is no way to ever answer "what was awareness last month" —
 * the inputs are overwritten by the next upload. One row per tenant per day;
 * re-running on the same day updates it. Best-effort: a snapshot failure must
 * never fail the request that produced the score.
 */
async function snapshotSecureScore(tenantId, score) {
  try {
    const c = score.components || {};
    const n = v => (v == null ? null : Math.max(0, Math.min(100, Math.round(v))));
    await pool.query(
      `INSERT INTO secure_scores
         (tenant_id, score_date, composite_score, vuln_score, awareness_score, mdr_score, calculated_at)
       VALUES ($1, CURRENT_DATE, $2, $3, $4, $5, NOW())
       ON CONFLICT (tenant_id, score_date) DO UPDATE
         SET composite_score = EXCLUDED.composite_score,
             vuln_score      = EXCLUDED.vuln_score,
             awareness_score = EXCLUDED.awareness_score,
             mdr_score       = EXCLUDED.mdr_score,
             calculated_at   = NOW()`,
      [
        tenantId,
        n(score.score),
        n((c.vulnerabilities  || {}).score),
        n((c.awareness        || {}).score),
        n((c.incidentResponse || {}).score),
      ]
    );
  } catch (err) {
    // Table may not be migrated yet — the score itself is unaffected.
    console.warn('[secure-score] snapshot skipped —', err.message);
  }
}

/* ─────────────────────────────────────────────────────────────────────────────
 * CLIENT PROFILE — the estate and the service mix, as one thing.
 *
 * These used to be two cards on the Admin tab behind two routes on two
 * different page gates (/api/secure-score/estate on `secure-score`,
 * /api/tenants/:id/services on `admin`), with two save buttons, answering the
 * same question: who is this client? They are now one page, one gate, one
 * audited write path.
 *
 * NOTE THE GATE MOVED. Editing the estate used to require write on the
 * secure-score page; it now requires write on `client-profile`. That is the
 * right home — this is client configuration, not score analysis — but it is a
 * live permission change, not a refactor.
 * ───────────────────────────────────────────────────────────────────────────── */

/** Tenant scoping is identical to the score's, and deliberately shares its code. */
const resolveProfileTenant = resolveScoreTenant;

/** The last few profile changes, newest first. Empty on an un-migrated database. */
async function loadProfileHistory(tenantId, limit) {
  if (!await hasProfileEventsTable()) return [];
  try {
    const r = await pool.query(
      `SELECT e.id, e.changed_at, e.kind, e.diff, e.score_before, e.score_after,
              u.username AS changed_by
         FROM tenant_profile_events e
         LEFT JOIN users u ON u.id = e.changed_by
        WHERE e.tenant_id = $1
        ORDER BY e.changed_at DESC
        LIMIT $2`,
      [tenantId, limit || 10]
    );
    return r.rows.map(row => ({
      id: row.id,
      changedAt: row.changed_at,
      changedBy: row.changed_by || null,
      kind: row.kind,
      diff: row.diff || {},
      scoreBefore: row.score_before,
      scoreAfter: row.score_after,
    }));
  } catch (_) { return []; }
}

/**
 * The whole profile, in the one shape every response uses.
 *
 * GET returns it, and so does a successful PUT — so the page can never end up
 * rendering a save response that is subtly different from a fresh load, which
 * is how "it looked right until I refreshed" bugs are made.
 */
async function buildClientProfile(tenantId) {
  // What was TYPED, kept separate from what is in effect. The form has to
  // round-trip the declaration exactly, blanks included: a blank that comes
  // back as the derived figure would turn "not recorded" into a declaration
  // the moment anyone pressed Save.
  let declared = null;
  let estateAvailable = true;
  try {
    const reviewedCol = await hasEstateReviewedColumn()
      ? 'reviewed_at' : 'NULL::timestamptz AS reviewed_at';
    const awOrgCol = await hasEstateArcticWolfColumn()
      ? 'arctic_wolf_org' : 'NULL::text AS arctic_wolf_org';
    const r = await pool.query(
      `SELECT servers, public_assets, endpoints, cloud_tenancies, users,
              servers_patched, awareness_program, notes, updated_at, ${reviewedCol}, ${awOrgCol}
       FROM tenant_estate WHERE tenant_id = $1`, [tenantId]);
    if (r.rows.length) declared = r.rows[0];
  } catch (_) { estateAvailable = false; }

  // The same inputs the Secure Score runs on, so the gaps and conflicts shown
  // here describe the score the client is actually given.
  const inputs = await loadScoreInputs(tenantId);
  const estate = inputs.estate;

  const hasEdr = !!(inputs.edrHealth && inputs.edrHealth.agents &&
                    (Number(inputs.edrHealth.agents.total) || 0) > 0);

  return {
    tenantId,
    available: {
      estate:   estateAvailable,
      services: await hasTenantServicesColumn(),
      history:  await hasProfileEventsTable(),
      arcticWolfOrg: await hasEstateArcticWolfColumn(),
    },

    /*
     * The Arctic Wolf link, resolved AT EDIT TIME.
     *
     * `arcticWolfOrgs` fills a datalist so the name can be picked rather than
     * typed, and `arcticWolfCoverage` reports what the stored name currently
     * resolves to. A typo otherwise costs the client their MDR reach discount
     * silently — the failure surfaces weeks later on a board pack, if at all.
     * Showing the match here makes it a save-time correction instead.
     */
    arcticWolfOrgs: awCoverageLib.orgNamesInLatest(readData(WEEKS_FILE)),
    arcticWolfCoverage: (function () {
      const cov = awCoverageLib.coverageForOrg(
        readData(WEEKS_FILE), declared && declared.arctic_wolf_org);
      // The sentence is written once, in the module that knows the reasons, so
      // the form and the Secure Score tile cannot describe the same state
      // differently.
      return Object.assign({}, cov, { message: awCoverageLib.describe(cov) });
    })(),

    declared: declared ? {
      servers:          declared.servers,
      publicAssets:     declared.public_assets,
      endpoints:        declared.endpoints,
      cloudTenancies:   declared.cloud_tenancies,
      users:            declared.users,
      serversPatched:   declared.servers_patched,
      awarenessProgram: declared.awareness_program,
      arcticWolfOrg:    declared.arctic_wolf_org,
      notes:            declared.notes || '',
      updatedAt:        declared.updated_at,
      reviewedAt:       declared.reviewed_at,
    } : null,

    effective: estate,
    summary:   estateLib.describeEstate(estate),

    // Advisory, all three. None of them moves a score — see lib/estate.js.
    conflicts: estateLib.reconcile(estate),
    gaps:      estateLib.profileGaps(estate, {
      hasScan: secureScore.isVulnMeasured(inputs.vulnData),
      hasEdr,
      awarenessMeasured: secureScore.isAwarenessMeasured(inputs.awarenessData),
    }),
    age: estateLib.estateAge(estate),

    services:          inputs.tenantServices,
    effectiveServices: servicesLib.effectiveServices(inputs.tenantServices),
    catalogue:         servicesLib.SERVICES,
    includes:          servicesLib.SERVICE_INCLUDES,

    history: await loadProfileHistory(tenantId, 10),
  };
}

/* ─────────────────────────────────────────────────────────────────────────────
 * TRAINING — SOC analyst upskilling.
 *
 * THE ONE RULE ON THIS SURFACE: a record belongs to the person who made it.
 *
 * Every other feature in this application is tenant-scoped through one of the
 * resolve*Tenant helpers. This one is scoped to a PERSON, and an analyst must
 * never be able to read or write a colleague's record. resolveTrainingUser
 * below reads the session and nothing else — no parameter, no admin branch,
 * no override — exactly as resolvePortalTenant does in lib/portal-gate.js, and
 * for the same reason: an escape hatch that does not exist cannot be forgotten
 * about.
 *
 * The curriculum is NOT in the database. It lives in lib/training/ and is
 * versioned with the code, so there is no authoring route here and no way for
 * any request to change what is taught. The only thing a request can write is
 * the sender's own progress.
 * ───────────────────────────────────────────────────────────────────────────── */

/**
 * Whose training record this is.
 *
 * Deliberately has no superadmin branch. A superadmin who needs to see how the
 * team is doing uses GET /api/training/team, which returns aggregates; there is
 * no route anywhere that reads or writes one named analyst's answers.
 */
function resolveTrainingUser(req) {
  return (req.session && req.session.userId) || null;
}

/** Table probe, cached only on a positive answer — the hasTenantServicesColumn idiom. */
let _trainingTables = null;
async function hasTrainingTables() {
  if (_trainingTables) return true;
  try {
    const r = await pool.query(
      `SELECT COUNT(*)::int AS n FROM information_schema.tables
        WHERE table_name IN ('training_progress', 'training_attempts')`);
    if (r.rows[0].n === 2) _trainingTables = true;
    return r.rows[0].n === 2;
  } catch (_) { return false; }
}

/**
 * One person's progress, as { itemKey: {status, completedAt} }.
 *
 * Degrades to an empty object on an un-migrated database: the portal is still
 * fully readable without it, which is the right failure — a missing table
 * should cost you your bookmarks, not the curriculum.
 */
async function loadTrainingProgress(userId) {
  if (!await hasTrainingTables()) return {};
  try {
    const r = await pool.query(
      `SELECT item_key, status, completed_at
         FROM training_progress
        WHERE user_id = $1`, [userId]);
    const out = {};
    r.rows.forEach((row) => {
      out[row.item_key] = { status: row.status, completedAt: row.completed_at };
    });
    return out;
  } catch (_) { return {}; }
}

/** The best and latest attempt per module, for this person only. */
async function loadTrainingAttempts(userId, moduleId) {
  if (!await hasTrainingTables()) return [];
  try {
    const params = [userId];
    let where = 'user_id = $1';
    if (moduleId) { params.push(moduleId); where += ' AND module_id = $2'; }
    const r = await pool.query(
      `SELECT id, module_id, attempted_at, score, total, passed
         FROM training_attempts
        WHERE ${where}
        ORDER BY attempted_at DESC
        LIMIT 100`, params);
    return r.rows.map(row => ({
      id: row.id, moduleId: row.module_id, attemptedAt: row.attempted_at,
      score: row.score, total: row.total, passed: row.passed,
    }));
  } catch (_) { return []; }
}

/**
 * GET /api/training/modules — the catalogue, with my progress against it.
 *
 * Lesson bodies and the question bank are not in this response; the list view
 * has no use for them. getModule() supplies those one module at a time, and
 * neither ever carries an answer key.
 */
app.get('/api/training/modules', requireAuth, async (req, res) => {
  try {
    const userId = resolveTrainingUser(req);
    if (!userId) return res.status(401).json({ error: 'No session.' });

    const [progress, attempts] = await Promise.all([
      loadTrainingProgress(userId),
      loadTrainingAttempts(userId, null),
    ]);

    // Best attempt per module, so a card can say "passed" without the client
    // sifting the history. Computed here rather than in SQL so it behaves
    // identically on an un-migrated database, where attempts is [].
    const best = {};
    attempts.forEach((a) => {
      const cur = best[a.moduleId];
      if (!cur || a.score / a.total > cur.score / cur.total) best[a.moduleId] = a;
    });

    return res.json({
      modules: trainingLib.listModules(),
      levels: trainingLib.LEVELS,
      levelLabels: trainingLib.LEVEL_LABELS,
      passMark: trainingLib.PASS_MARK,
      progress,
      best,
      available: await hasTrainingTables(),
    });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/training/modules/:id — one module, answer key stripped. */
app.get('/api/training/modules/:id', requireAuth, async (req, res) => {
  try {
    const userId = resolveTrainingUser(req);
    if (!userId) return res.status(401).json({ error: 'No session.' });

    // getModule() returns the browser-safe shape: no `answer`, no `why`.
    const mod = trainingLib.getModule(String(req.params.id || ''));
    if (!mod) return res.status(404).json({ error: 'No such module.' });

    // Playbook blocks carry a key, not a copy of the steps. Resolve them here
    // from the live IR playbooks so a lesson can never show stale tasks.
    const playbooks = {};
    mod.lessons.forEach((l) => {
      l.body.forEach((b) => {
        if (b.playbook && !playbooks[b.playbook]) {
          const pb = trainingLib.playbookFor(b.playbook);
          if (pb) playbooks[b.playbook] = pb;
        }
      });
    });

    return res.json({
      module: mod,
      playbooks,
      progress: await loadTrainingProgress(userId),
      attempts: await loadTrainingAttempts(userId, mod.id),
      passMark: trainingLib.PASS_MARK,
    });
  } catch (err) { return serverError(res, err); }
});

/**
 * GET /api/training/playbooks — the live incident playbooks, read-only.
 *
 * Served from the same object server.js uses to seed ir_activities when an
 * incident is opened. There is no write route: if this feature ever changes
 * what a real incident's task board contains, something has gone wrong.
 */
app.get('/api/training/playbooks', requireAuth, async (req, res) => {
  try {
    return res.json({
      playbooks: trainingLib.listPlaybooks(),
      phases: trainingLib.PHASES,
      phaseLabels: trainingLib.PHASE_LABELS,
    });
  } catch (err) { return serverError(res, err); }
});

/**
 * POST /api/training/progress — mark something started or completed.
 *
 * The user id comes from the session. There is no field in this body that can
 * name a different person, which is the point: cross-user writes are not
 * refused here, they are unrepresentable.
 */
app.post('/api/training/progress', requireAuth, async (req, res) => {
  try {
    const userId = resolveTrainingUser(req);
    if (!userId) return res.status(401).json({ error: 'No session.' });

    const body = req.body || {};
    const itemKey = String(body.itemKey || '');
    // Validated against the real catalogue, so this column cannot become a
    // dumping ground for whatever a browser felt like sending.
    if (!trainingLib.isValidProgressKey(itemKey)) {
      return res.status(400).json({ error: 'Unknown training item.' });
    }
    const status = String(body.status || '');
    if (trainingLib.PROGRESS_STATUSES.indexOf(status) < 0) {
      return res.status(400).json({ error: 'Status must be started or completed.' });
    }

    if (!await hasTrainingTables()) {
      return res.status(503).json({
        error: 'Training progress is not available yet. Run db/migrate-training.sql.',
      });
    }

    await pool.query(
      `INSERT INTO training_progress (user_id, item_key, status, completed_at)
       VALUES ($1, $2, $3, CASE WHEN $3 = 'completed' THEN NOW() ELSE NULL END)
       ON CONFLICT (user_id, item_key) DO UPDATE SET
         status = EXCLUDED.status,
         -- Keep the FIRST completion. Re-reading a lesson does not move the
         -- date on which somebody learned it.
         completed_at = COALESCE(training_progress.completed_at, EXCLUDED.completed_at)`,
      [userId, itemKey, status]);

    return res.json({ ok: true, progress: await loadTrainingProgress(userId) });
  } catch (err) { return serverError(res, err); }
});

/**
 * POST /api/training/quiz/:moduleId — grade an attempt.
 *
 * GRADED HERE, NOT IN THE BROWSER. The answer key is in lib/training/questions.js
 * and never leaves the server before submission, so a score describes what
 * somebody knew rather than what they could read out of a downloaded script.
 *
 * The attempt is appended whether it passed or failed. A record that keeps only
 * successes cannot answer the question it exists to answer.
 */
app.post('/api/training/quiz/:moduleId', requireAuth, async (req, res) => {
  try {
    const userId = resolveTrainingUser(req);
    if (!userId) return res.status(401).json({ error: 'No session.' });

    const moduleId = String(req.params.moduleId || '');
    const graded = trainingLib.gradeAttempt(moduleId, (req.body || {}).answers);
    if (!graded) return res.status(404).json({ error: 'No such module, or it has no quiz.' });

    // The result is returned even when it cannot be stored: an un-migrated
    // database should cost an analyst their history, not their feedback.
    let recorded = false;
    if (await hasTrainingTables()) {
      try {
        await pool.query(
          `INSERT INTO training_attempts
             (user_id, module_id, score, total, passed, answers)
           VALUES ($1, $2, $3, $4, $5, $6::jsonb)`,
          [userId, moduleId, graded.score, graded.total, graded.passed,
           JSON.stringify((req.body || {}).answers || {})]);
        recorded = true;
      } catch (err) {
        console.warn('[training] attempt not recorded —', err.message);
      }
    }

    return res.json({ result: graded, recorded });
  } catch (err) { return serverError(res, err); }
});

/** GET /api/training/attempts — my own history, newest first. */
app.get('/api/training/attempts', requireAuth, async (req, res) => {
  try {
    const userId = resolveTrainingUser(req);
    if (!userId) return res.status(401).json({ error: 'No session.' });
    return res.json({ attempts: await loadTrainingAttempts(userId, null) });
  } catch (err) { return serverError(res, err); }
});

/**
 * GET /api/training/team — how the team is doing, in aggregate.
 *
 * For a SOC lead. Returns counts per module and per person — who has completed
 * what, and how many attempts it took — and deliberately NOT which questions
 * anyone got wrong. The point is to spot who needs support and which module is
 * not landing, neither of which requires reading somebody's answers.
 *
 * Gated on WRITE for the training page, which by ROLE_DEFAULTS means admin and
 * superadmin. pageGate enforces that; this route does not re-implement it.
 */
app.get('/api/training/team', requireAuth, requirePage('training', { write: true }),
  async (req, res) => {
    try {
      if (!await hasTrainingTables()) {
        return res.status(503).json({
          error: 'Training records are not available yet. Run db/migrate-training.sql.',
        });
      }

      const done = await pool.query(
        `SELECT u.id, u.username, p.item_key, p.completed_at
           FROM training_progress p
           JOIN users u ON u.id = p.user_id
          WHERE p.status = 'completed'
          ORDER BY u.username, p.item_key`);

      const attempts = await pool.query(
        `SELECT u.id, u.username, a.module_id,
                COUNT(*)::int AS attempts,
                MAX(a.score::float / a.total) AS best,
                BOOL_OR(a.passed) AS passed
           FROM training_attempts a
           JOIN users u ON u.id = a.user_id
          GROUP BY u.id, u.username, a.module_id
          ORDER BY u.username, a.module_id`);

      return res.json({
        modules: trainingLib.listModules(),
        completed: done.rows.map(r => ({
          userId: r.id, username: r.username,
          itemKey: r.item_key, completedAt: r.completed_at,
        })),
        attempts: attempts.rows.map(r => ({
          userId: r.id, username: r.username, moduleId: r.module_id,
          attempts: r.attempts,
          best: r.best == null ? null : Math.round(r.best * 100),
          passed: r.passed,
        })),
      });
    } catch (err) { return serverError(res, err); }
  });

/** GET /api/client-profile — estate, services, conflicts, gaps and history. */
app.get('/api/client-profile', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveProfileTenant(req);
    if (!tenantId) return res.status(400).json({ error: 'No tenant context.' });
    return res.json(await buildClientProfile(tenantId));
  } catch (err) { return serverError(res, err); }
});

/** GET /api/client-profile/history — the full audit trail, newest first. */
app.get('/api/client-profile/history', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveProfileTenant(req);
    if (!tenantId) return res.status(400).json({ error: 'No tenant context.' });
    if (!await hasProfileEventsTable()) {
      return res.status(503).json({
        error: 'Profile history is not available yet. Run db/migrate-client-profile.sql.',
      });
    }
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
    return res.json({ tenantId, history: await loadProfileHistory(tenantId, limit) });
  } catch (err) { return serverError(res, err); }
});

/**
 * What actually changed between the stored profile and the incoming one.
 *
 * Returns { field: { from, to } } over the declared estate fields, the
 * awareness programme and the service list. Only genuine differences appear:
 * a save that alters nothing produces {} and, per the mdr_ticket_events rule,
 * writes no history row at all. A table of button presses would bury the three
 * edits that mattered under three hundred that did not.
 *
 * Services compare by VALUE, not identity, and null (not recorded) is kept
 * distinct from [] (recorded as none) — clearing a record back to "we have not
 * said" is a real change and has to show up as one.
 */
function diffProfile(before, after) {
  const diff = {};

  estateLib.DECLARED_FIELDS.concat(['awarenessProgram', 'arcticWolfOrg', 'notes']).forEach((f) => {
    const from = before[f] === undefined ? null : before[f];
    const to   = after[f]  === undefined ? null : after[f];
    if (from !== to) diff[f] = { from, to };
  });

  const svcKey = (v) => (Array.isArray(v) ? v.slice().sort().join(',') : null);
  if (svcKey(before.services) !== svcKey(after.services)) {
    diff.services = { from: before.services, to: after.services };
  }

  return diff;
}

/**
 * PUT /api/client-profile — record the estate AND the service mix, together.
 *
 * null clears a field back to "not recorded"; 0 is a positive claim of "none"
 * and is what moves a client onto the endpoint yardstick. The two must stay
 * distinguishable all the way down, so empty strings become null, not 0. The
 * same distinction governs services: null is "nobody has said", [] is "none".
 *
 * ONE TRANSACTION, ONE HISTORY ROW. The estate and the services used to be
 * saved by two routes on two gates, so a change to both was two events with no
 * relationship, and neither recorded what it did to the score.
 *
 * No explicit role guard: app.use('/api', pageGate) already requires WRITE on
 * the client-profile page for any PUT (see lib/auth-middleware.js). Using that
 * rather than a hardcoded role check keeps the per-user access overrides in
 * lib/pages.js authoritative instead of quietly bypassing them.
 */
app.put('/api/client-profile', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveProfileTenant(req);
    if (!tenantId) return res.status(400).json({ error: 'No tenant context.' });

    const body = req.body || {};
    const vals = {};
    for (const f of estateLib.DECLARED_FIELDS) {
      const raw = body[f];
      if (raw === null || raw === undefined || raw === '') { vals[f] = null; continue; }
      const n = estateLib.count(raw);
      if (n === null) {
        return res.status(400).json({
          error: estateLib.FIELD_LABELS[f] + ' must be a whole number of zero or more.',
        });
      }
      vals[f] = n;
    }

    // An unrecognised programme is rejected rather than normalised to NULL: a
    // typo would otherwise cost the client their awareness relief silently.
    let program = null;
    if (body.awarenessProgram !== null && body.awarenessProgram !== undefined &&
        body.awarenessProgram !== '') {
      program = estateLib.awarenessProgram(body.awarenessProgram);
      if (program === null) {
        return res.status(400).json({
          error: 'Awareness programme must be one of: ' +
                 estateLib.AWARENESS_PROGRAMS.join(', ') + '.',
        });
      }
    }

    /*
     * The Arctic Wolf organisation name.
     *
     * NOT checked against the weekly report. A client can legitimately be
     * linked before their first report lands, and rejecting an unrecognised
     * name would make the field unusable during onboarding. The consequence of
     * a typo — no discount — is made VISIBLE instead: the profile form and the
     * Secure Score tile both report 'org_not_found' with near-miss candidates,
     * which is a better place to catch it than a save-time error that also
     * blocks the legitimate case.
     */
    let awOrg = null;
    if (body.arcticWolfOrg !== null && body.arcticWolfOrg !== undefined &&
        String(body.arcticWolfOrg).trim() !== '') {
      awOrg = estateLib.arcticWolfOrg(body.arcticWolfOrg);
      if (awOrg === null) {
        return res.status(400).json({
          error: estateLib.FIELD_LABELS.arcticWolfOrg + ' must be ' +
                 estateLib.MAX_AW_ORG + ' characters or fewer.',
        });
      }
      if (!await hasEstateArcticWolfColumn()) {
        return res.status(503).json({
          error: 'Arctic Wolf linking is not available yet. Run db/migrate-arctic-wolf-org.sql.',
        });
      }
    }

    const notes = typeof body.notes === 'string' ? body.notes.slice(0, 2000) : null;

    // `services` is optional in the body. ABSENT means "leave alone"; an
    // explicit null means "clear the record". Collapsing the two would let a
    // page that only edits the estate silently wipe the service mix.
    const servicesGiven = Object.prototype.hasOwnProperty.call(body, 'services');
    const services = servicesGiven ? servicesLib.normaliseServices(body.services) : undefined;
    const servicesColumn = await hasTenantServicesColumn();
    if (servicesGiven && !servicesColumn) {
      return res.status(503).json({
        error: 'Service selection is not available yet. Run db/migrate-tenant-services.sql.',
      });
    }

    // ── What is on file now, for the diff and the before-score ──────────────
    const before = await buildClientProfile(tenantId);
    const after = Object.assign({}, vals, {
      awarenessProgram: program,
      arcticWolfOrg: awOrg,
      notes: notes || '',
      services: servicesGiven ? services : before.services,
    });
    const diff = diffProfile(
      Object.assign({ notes: '' }, before.declared, { services: before.services }),
      after);

    // Nothing changed. Say so and write nothing — including no updated_at bump,
    // which would otherwise reset the staleness clock without anybody having
    // confirmed anything. Use the review endpoint for that; it is what it is for.
    if (!Object.keys(diff).length) {
      return res.json({ ok: true, changed: false, profile: before });
    }

    // Probed once, outside the transaction, and used by both branches below.
    const awColumn = await hasEstateArcticWolfColumn();

    const scoreBefore = await compositeScoreFor(tenantId);

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      await client.query(
        /*
         * The Arctic Wolf column is written only where it EXISTS, as two
         * fragments spliced into one statement rather than two whole copies of
         * it — a second copy of an upsert is a second thing to forget to edit.
         *
         * An unmigrated deployment still saves every other field rather than
         * failing the whole upsert, the same degrade-open rule the two estate
         * SELECTs follow. A caller that actually supplied a name on an
         * unmigrated database was already turned away with a 503 above, so
         * nothing is silently dropped here.
         */
        `INSERT INTO tenant_estate
           (tenant_id, servers, public_assets, endpoints, cloud_tenancies, users,
            servers_patched, awareness_program, notes, updated_by${awColumn ? ', arctic_wolf_org' : ''}, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10${awColumn ? ', $11' : ''}, NOW())
         ON CONFLICT (tenant_id) DO UPDATE SET
           servers           = EXCLUDED.servers,
           public_assets     = EXCLUDED.public_assets,
           endpoints         = EXCLUDED.endpoints,
           cloud_tenancies   = EXCLUDED.cloud_tenancies,
           users             = EXCLUDED.users,
           servers_patched   = EXCLUDED.servers_patched,
           awareness_program = EXCLUDED.awareness_program,
           notes             = EXCLUDED.notes,
           updated_by        = EXCLUDED.updated_by,
           ${awColumn ? 'arctic_wolf_org   = EXCLUDED.arctic_wolf_org,' : ''}
           updated_at        = NOW()`,
        [tenantId, vals.servers, vals.publicAssets, vals.endpoints,
         vals.cloudTenancies, vals.users, vals.serversPatched,
         program, notes, req.session.userId || null]
          .concat(awColumn ? [awOrg] : [])
      );

      if (servicesGiven) {
        await client.query('UPDATE tenants SET services = $1 WHERE id = $2',
          [services, tenantId]);
      }

      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      client.release();
      return res.status(503).json({
        error: 'Could not save the profile. The estate table may not be migrated ' +
               '— run db/migrate-tenant-estate.sql and db/migrate-client-profile.sql.',
      });
    }
    client.release();

    /*
     * The history row is written AFTER the commit, on purpose.
     *
     * score_after cannot be computed until the new values are readable, and
     * holding a transaction open across a dozen scoring queries to buy a
     * perfectly atomic audit row is a bad trade. The consequence is honest and
     * small: a crash in this window loses the record of a change that did
     * happen. The alternative — a change that did not happen with a record
     * saying it did — is the one that would actually mislead somebody.
     */
    const scoreAfter = await compositeScoreFor(tenantId);
    if (await hasProfileEventsTable()) {
      try {
        await pool.query(
          `INSERT INTO tenant_profile_events
             (tenant_id, changed_by, kind, diff, score_before, score_after)
           VALUES ($1, $2, 'change', $3::jsonb, $4, $5)`,
          [tenantId, req.session.userId || null, JSON.stringify(diff),
           scoreBefore, scoreAfter]);
      } catch (err) {
        console.warn('[client-profile] history not recorded —', err.message);
      }
    }

    return res.json({
      ok: true, changed: true, diff,
      scoreBefore, scoreAfter,
      profile: await buildClientProfile(tenantId),
    });
  } catch (err) { return serverError(res, err); }
});

/**
 * POST /api/client-profile/review — "I checked, this is still correct."
 *
 * Bumps reviewed_at without touching a value, which is the whole point: before
 * this, the only way to clear a staleness flag was to re-save the form, and a
 * re-save is indistinguishable from an edit in the history. Confirming and
 * changing are different acts and the record now says which one happened.
 */
app.post('/api/client-profile/review', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveProfileTenant(req);
    if (!tenantId) return res.status(400).json({ error: 'No tenant context.' });

    if (!await hasEstateReviewedColumn()) {
      return res.status(503).json({
        error: 'Profile review is not available yet. Run db/migrate-client-profile.sql.',
      });
    }

    const r = await pool.query(
      `UPDATE tenant_estate SET reviewed_at = NOW(), updated_by = $2
        WHERE tenant_id = $1 RETURNING tenant_id`,
      [tenantId, req.session.userId || null]);

    // Nothing to confirm. An absent estate is not a stale one, and inserting a
    // blank row here would create a record asserting a client has nothing.
    if (!r.rows.length) {
      return res.status(400).json({
        error: 'There is no recorded estate for this client to confirm.',
      });
    }

    if (await hasProfileEventsTable()) {
      try {
        await pool.query(
          `INSERT INTO tenant_profile_events (tenant_id, changed_by, kind, diff)
           VALUES ($1, $2, 'review', '{}'::jsonb)`,
          [tenantId, req.session.userId || null]);
      } catch (err) {
        console.warn('[client-profile] review not recorded —', err.message);
      }
    }

    return res.json({ ok: true, profile: await buildClientProfile(tenantId) });
  } catch (err) { return serverError(res, err); }
});

/**
 * Resolve a tenant's estate: what an admin declared, merged with what the
 * telemetry already knows. Declared always wins — see lib/estate.js.
 *
 * Every query is individually guarded: this must degrade to "estate unknown"
 * on an un-migrated database rather than taking the whole Secure Score with it.
 */
async function loadEstate(tenantId, scanId, trainedUsers) {
  let declared = null;
  try {
    /*
     * reviewed_at is selected only when it EXISTS.
     *
     * Naming a missing column here would fail the whole SELECT, and the catch
     * below turns any failure into "no estate declared" — which zeroes the
     * vulnerability component for every client on the deployment. Degrading
     * open is right for a table that may not be migrated; it is emphatically
     * wrong as the consequence of adding one optional column, so the probe
     * (the hasTenantServicesColumn pattern) keeps the two apart.
     */
    const reviewedCol = await hasEstateReviewedColumn()
      ? 'reviewed_at' : 'NULL::timestamptz AS reviewed_at';
    // Same rule, same reason — see db/migrate-arctic-wolf-org.sql.
    const awOrgCol = await hasEstateArcticWolfColumn()
      ? 'arctic_wolf_org' : 'NULL::text AS arctic_wolf_org';

    const r = await pool.query(
      `SELECT servers, public_assets, endpoints, cloud_tenancies, users,
              servers_patched, awareness_program, updated_at, ${reviewedCol}, ${awOrgCol}
       FROM tenant_estate WHERE tenant_id = $1`,
      [tenantId]
    );
    if (r.rows.length) {
      const row = r.rows[0];
      declared = {
        awarenessProgram: row.awareness_program,
        // Scores nothing on its own — it names which Arctic Wolf org's Coverage
        // Score belongs to this client. See lib/arctic-wolf-coverage.js.
        arcticWolfOrg:    row.arctic_wolf_org,
        servers:          row.servers,
        publicAssets:     row.public_assets,
        endpoints:        row.endpoints,
        cloudTenancies:   row.cloud_tenancies,
        users:            row.users,
        serversPatched:   row.servers_patched,
        // Drive the staleness flag only — never a score. See lib/estate.js.
        updatedAt:        row.updated_at,
        reviewedAt:       row.reviewed_at,
      };
    }
  } catch (_) { /* table not migrated yet */ }

  const derived = {};
  if (trainedUsers != null) derived.trainedUsers = trainedUsers;
  try {
    const r = await pool.query(
      `SELECT COUNT(*)::int AS n FROM edr_agents WHERE tenant_id = $1`, [tenantId]);
    if (r.rows[0].n > 0) derived.endpoints = r.rows[0].n;
  } catch (_) { /* edr not migrated */ }

  // Hosts the last scan actually reached — the denominator for density and the
  // numerator for coverage.
  //
  // This USED TO count DISTINCT host in vuln_findings, which counts hosts that
  // had findings, not hosts that were scanned: informational rows are dropped
  // at parse time, so a clean host leaves no row anywhere. The cleaner an estate
  // was, the worse its coverage looked. It now reads the scope the parser
  // recorded; a scan uploaded before that column existed reports NULL and is
  // scored without a coverage cap rather than with a fabricated one.
  if (scanId) {
    try {
      const r = await pool.query(
        `SELECT scanned_hosts FROM vuln_scans WHERE id = $1`, [scanId]);
      const n = r.rows.length ? r.rows[0].scanned_hosts : null;
      if (n != null && n > 0) {
        derived.scannedHosts = n;
        // The external estate IS what the scan addresses: Reflex scans the
        // client's public IP range, so the hosts it touched are the best
        // available statement of how many external-facing assets exist. Filling
        // it here means the coverage cap works for every scanned client instead
        // of only those whose admin remembered to type a number.
        //
        // Declared still beats derived (resolveEstate), and that is the point:
        // a declaration is a CHALLENGE to the scan. An admin who says 10 when
        // the scan reached 6 is asserting four assets the scan is missing, and
        // the cap will hold the score at 60 until they are brought into scope.
        derived.publicAssets = n;
      }
    } catch (_) { /* scanned_hosts not migrated yet — scope stays unknown */ }
  }

  return estateLib.resolveEstate(declared, derived);
}

/** Endpoint patch currency and agent health — the endpoint-only yardstick. */
async function loadEdrHealth(tenantId) {
  try {
    const r = await pool.query(
      `SELECT COUNT(*)::int                                                       AS total,
              COUNT(*) FILTER (WHERE is_up_to_date)::int                          AS up_to_date,
              COUNT(*) FILTER (WHERE last_active_at < NOW() - INTERVAL '7 days')::int AS stale,
              COALESCE(SUM(active_threats), 0)::int                               AS active_threats
       FROM edr_agents WHERE tenant_id = $1`,
      [tenantId]
    );
    const row = r.rows[0];
    if (!row || !row.total) return null;
    return {
      agents: {
        total:         row.total,
        upToDate:      row.up_to_date,
        stale:         row.stale,
        activeThreats: row.active_threats,
      },
    };
  } catch (_) { return null; }
}

/**
 * Everything the Secure Score is computed FROM, for one tenant.
 *
 * Extracted from the /api/secure-score handler so that the client profile can
 * record what an edit did to the score WITHOUT a second, drifting copy of the
 * loading logic. Two functions that both claim to assemble the score's inputs
 * is how the before/after ends up disagreeing with the score on the page.
 *
 * Every query is individually guarded, as it was in the route: a missing table
 * degrades one input to null rather than taking the whole score with it.
 */
async function loadScoreInputs(tenantId) {
  {
    // Fetch latest vulnerability scan
    let vulnData = null;
    let scanId = null;
    try {
      const vulnResult = await pool.query(
        `SELECT id, summary FROM vuln_scans WHERE tenant_id = $1 ORDER BY month_key DESC LIMIT 1`,
        [tenantId]
      );
      if (vulnResult.rows.length > 0) {
        vulnData = { summary: vulnResult.rows[0].summary };
        scanId = vulnResult.rows[0].id;
      }
    } catch (_) { /* table may not exist yet */ }

    const edrHealth = await loadEdrHealth(tenantId);

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

    /*
     * MDR, SCORED ON ONE MONTH'S TICKETS — NOT ON THE WHOLE UPLOAD.
     *
     * `mdr_uploads.total_tickets` is however much CSV somebody exported: a
     * month for most clients, two years for anyone who pulled their full
     * history. Scoring it meant a client's incident-response component was
     * partly a function of how much history they happened to upload, and a
     * strong recent month could not move a number averaged over two years.
     *
     * The cohort is the tickets RAISED in the last complete calendar month,
     * followed through to whenever they were resolved — the same rule, from the
     * same module, that the report's KPI table uses. Those two sit on the same
     * page as each other and were computing over different populations.
     *
     * The upload row is still read, and still decides `measured`: an upload
     * existing is what says this client has an MDR feed at all. A month with no
     * tickets in it is a QUIET MONTH, scored 100 by calculateMdrScore, not an
     * unmeasured one — and that distinction is only available because the
     * upload is checked separately from the cohort.
     */
    let mdrData = null;
    let mdrUploadId = null;
    let mdrPeriod = null;
    try {
      const mdrResult = await pool.query(
        `SELECT id, total_tickets, resolved_count, avg_resolution_hours, uploaded_at
         FROM mdr_uploads
         WHERE tenant_id = $1
         ORDER BY uploaded_at DESC LIMIT 1`,
        [tenantId]
      );
      if (mdrResult.rows.length > 0) {
        mdrUploadId = mdrResult.rows[0].id;
        mdrPeriod = mdrMetrics.lastCompleteMonth(new Date());

        // Joined through mdr_uploads rather than read off mdr_tickets.tenant_id,
        // matching reconstructComponents: the tenant column was backfilled by a
        // later migration and may be null on older rows.
        let cohortTickets = [];
        try {
          // ticket_type MUST be selected. cohortStats() filters to incidents
          // only when the rows carry a type; rows without the column look like
          // a feed that never classifies, and every support request and info
          // ticket was silently scored as an incident.
          const t = await pool.query(
            `SELECT t.created_at, t.resolved_at, t.ticket_type
               FROM mdr_tickets t
               JOIN mdr_uploads u ON u.id = t.upload_id
              WHERE u.tenant_id = $1 AND t.created_at IS NOT NULL`,
            [tenantId]
          );
          cohortTickets = t.rows;
        } catch (_) { /* tickets not migrated — see the fallback below */ }

        const stat = mdrMetrics.cohortStats(cohortTickets, mdrPeriod);
        mdrData = {
          // The upload row is kept for isMdrMeasured() and for anything that
          // wants to know when the feed last synced.
          upload: Object.assign({}, mdrResult.rows[0], mdrMetrics.scoreInput(stat)),
          period: mdrPeriod,
          cohort: stat,
        };
      }
    } catch (_) { /* table may not exist yet */ }

    // The estate: how much this client actually has, of what kind, and how many
    // people. Without it the vulnerability component judges everyone against
    // absolute finding counts, which is unfair at both ends of the size range.
    //
    // Loaded AFTER the awareness upload so the training roster can be compared
    // against the declared headcount: a client with 500 staff and 50 people on
    // the training list has an awareness score describing a tenth of their
    // organisation, and that gap has to be visible.
    const trainedUsers = awarenessData && awarenessData.upload
      ? (parseInt(awarenessData.upload.total_users, 10) || 0)
      : null;
    const estate = await loadEstate(tenantId, scanId, trainedUsers);

    // Calculate score. `measured` says whether each component was actually
    // assessed; an unmeasured component scores 0 and must be labelled as such,
    // or a client reads "Vulnerabilities 0/100" as a failed scan rather than as
    // a scan that was never uploaded.
    // What the client buys decides which components are in scope. NULL when
    // nobody has recorded it, which leaves the score behaving exactly as it did
    // before service scoping existed.
    const tenantServices = await loadTenantServices(tenantId);

    /*
     * How much of the estate the MDR service actually reaches, from Arctic
     * Wolf's own per-org Coverage Score in the weekly report.
     *
     * READ-ONLY, STAFF-ONLY, AND FROM A FILE. The weekly report is a global
     * data/weeks.json holding every org's figures — it is deliberately not
     * migrated into Postgres — so this read is server-side and is never
     * reached through lib/portal-routes.js. readData() already returns {} on
     * any failure, which the helper reports as 'no_report'; a missing file must
     * never be able to fail a client's Secure Score.
     */
    const mdrCoverage = awCoverageLib.coverageForOrg(
      readData(WEEKS_FILE), estate && estate.arcticWolfOrg);

    return {
      vulnData, scanId, edrHealth, awarenessData, mdrData, mdrUploadId,
      trainedUsers, estate, tenantServices, mdrCoverage,
    };
  }
}

/**
 * The composite alone, for recording what a profile edit did to it.
 *
 * Returns null rather than throwing on any failure. A score that cannot be
 * computed must never stop somebody saving a client's estate — the history row
 * simply records the change with no movement attached, which is honest, and a
 * save that failed because of a bookkeeping side effect would not be.
 */
async function compositeScoreFor(tenantId) {
  try {
    const i = await loadScoreInputs(tenantId);
    const r = calculateSecureScore(i.vulnData, i.awarenessData, i.mdrData, {
      estate: i.estate, edr: i.edrHealth,
      services: i.tenantServices, mdrCoverage: i.mdrCoverage,
    });
    return typeof r.composite === 'number' ? r.composite : null;
  } catch (err) {
    console.warn('[client-profile] score snapshot skipped —', err.message);
    return null;
  }
}

/**
 * GET /api/ms-secure-score — Microsoft's Secure Score for this tenant.
 *
 * ══ WHY THIS IS NOT PART OF /api/secure-score ══
 *
 * Microsoft's number is NOT folded into our composite, and this separate route
 * is how that stays true. Two reasons, both of which would show up on a client's
 * board pack as a lie:
 *
 *   * the denominator moves. maxScore rises whenever Microsoft publishes a new
 *     control, so a client who changed nothing loses percentage overnight. Fold
 *     that into our composite and a Microsoft product decision reads as the
 *     client's posture degrading — with no way to show otherwise.
 *
 *   * it is not ours to defend. Every component of lib/secure-score.js can be
 *     explained control by control to a client who disputes it. Microsoft's
 *     weighting cannot, because we do not know it.
 *
 * So it is reported ALONGSIDE, clearly attributed, and the two are allowed to
 * disagree. A client whose Microsoft score is 71% and whose composite is 48% is
 * being told something true and useful: their Microsoft tenancy is in better
 * shape than the rest of their estate.
 */
app.get('/api/ms-secure-score', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveScoreTenant(req);
    if (!tenantId) return res.status(400).json({ error: 'No tenant context.' });

    // Degrade open, exactly like the email tab: an unrun migration must read as
    // "not set up" rather than as a 500.
    if (!await hasMsScoreTables()) {
      return res.json({
        available: false,
        reason: 'not_migrated',
        message: 'Microsoft Secure Score storage is not set up — run db/migrate-ms-secure-score.sql.',
      });
    }

    const intRow = await pool.query(
      `SELECT is_enabled, last_synced_at, last_sync_status, last_sync_message
         FROM integrations WHERE tenant_id = $1 AND provider = $2`,
      [tenantId, MSGRAPH_PROVIDER]
    );
    const integration = intRow.rows[0] || null;

    const snapRes = await pool.query(
      `SELECT score_date, current_score, max_score, azure_tenant_id,
              active_user_count, licensed_user_count, enabled_services,
              comparative_json, synced_at
         FROM ms_secure_scores
        WHERE tenant_id = $1
        ORDER BY score_date DESC
        LIMIT 90`,
      [tenantId]
    );

    if (!snapRes.rows.length) {
      /*
       * Three different nothings, told apart. "Not configured", "configured but
       * never synced" and "synced but Microsoft published nothing" need
       * completely different actions from whoever reads the tab, and collapsing
       * them into an empty panel sends people hunting for the wrong problem.
       */
      const reason = !integration ? 'not_configured'
        : !integration.last_synced_at ? 'never_synced'
        : 'no_snapshots';
      return res.json({
        available: false,
        reason,
        isEnabled: integration ? integration.is_enabled : false,
        lastSyncedAt: integration ? integration.last_synced_at : null,
        lastSyncStatus: integration ? integration.last_sync_status : null,
        lastSyncMessage: integration ? integration.last_sync_message : null,
      });
    }

    const rows = snapRes.rows;
    const latest = rows[0];

    const ctlRes = await pool.query(
      `SELECT control_name, control_category, score, max_score, score_in_percentage,
              implementation_status, title, rank, tier, service, action_type, action_url,
              remediation, remediation_impact, user_impact, implementation_cost,
              threats, deprecated, control_state, description
         FROM ms_secure_score_controls
        WHERE tenant_id = $1 AND score_date = $2`,
      [tenantId, latest.score_date]
    );

    const pctOf = (c, m) => msGraphAdapter.percentage(c, m);

    const controls = ctlRes.rows.map(r => {
      const score = r.score === null ? null : Number(r.score);
      const max   = r.max_score === null ? null : Number(r.max_score);
      return {
        controlName: r.control_name,
        title: r.title,
        category: r.control_category,
        score, maxScore: max,
        // Null, not zero, when either half is unknown — "no gap" and "gap
        // unknown" must not sort together in a remediation list.
        gap: (score !== null && max !== null) ? Math.max(0, Math.round((max - score) * 1000) / 1000) : null,
        scoreInPercentage: r.score_in_percentage === null ? null : Number(r.score_in_percentage),
        implementationStatus: r.implementation_status,
        description: r.description,
        rank: r.rank,
        tier: r.tier,
        service: r.service,
        actionType: r.action_type,
        actionUrl: r.action_url,
        remediation: r.remediation,
        remediationImpact: r.remediation_impact,
        userImpact: r.user_impact,
        implementationCost: r.implementation_cost,
        threats: r.threats || [],
        deprecated: r.deprecated === true,
        controlState: r.control_state,
      };
    });

    /*
     * The remediation list: real, actionable gaps only.
     *
     * Excluded, and each for a reason that costs credibility if got wrong:
     *   deprecated            Microsoft has retired it; nobody can action it.
     *   controlState ThirdParty  the client covers this with a non-Microsoft
     *                         product. Microsoft still scores it zero. Telling
     *                         them to remediate it is telling them to buy
     *                         something they already own.
     *   controlState Ignored  a recorded risk ACCEPTANCE. It belongs in the
     *                         risk register, not in a to-do list — but it is
     *                         returned separately below rather than hidden,
     *                         because an acceptance nobody revisits is a risk
     *                         nobody owns.
     *   gap === null          we could not measure it; see above.
     */
    const isExcluded = c => c.deprecated ||
      c.controlState === 'ThirdParty' || c.controlState === 'Ignored';

    const gaps = controls
      .filter(c => !isExcluded(c) && c.gap !== null && c.gap > 0)
      .sort((a, b) => (b.gap - a.gap) ||
        // Microsoft's own rank breaks ties: equal points, their priority wins.
        ((a.rank === null ? 1e9 : a.rank) - (b.rank === null ? 1e9 : b.rank)));

    const accepted = controls.filter(c => c.controlState === 'Ignored');
    const thirdParty = controls.filter(c => c.controlState === 'ThirdParty');

    // Per-category rollup, so the panel can say WHERE the points are missing.
    const byCategory = {};
    for (const c of controls) {
      if (isExcluded(c)) continue;
      const key = c.category || 'Uncategorised';
      const b = byCategory[key] || (byCategory[key] = { category: key, score: 0, maxScore: 0, controls: 0, unmeasured: 0 });
      b.controls++;
      // Only fully-measured controls contribute to a category total. A category
      // whose numerator counted a control its denominator skipped would report
      // a percentage no set of controls could produce.
      if (c.score === null || c.maxScore === null) { b.unmeasured++; continue; }
      b.score += c.score;
      b.maxScore += c.maxScore;
    }
    const categories = Object.values(byCategory).map(b => ({
      ...b,
      percentage: pctOf(b.score, b.maxScore),
    })).sort((a, b) => (a.category < b.category ? -1 : 1));

    const trend = rows.map(r => ({
      date: r.score_date instanceof Date ? r.score_date.toISOString().slice(0, 10) : String(r.score_date),
      currentScore: r.current_score === null ? null : Number(r.current_score),
      maxScore: r.max_score === null ? null : Number(r.max_score),
      percentage: pctOf(r.current_score, r.max_score),
    })).reverse();   // oldest first, for plotting

    res.json({
      available: true,
      isEnabled: integration ? integration.is_enabled : null,
      lastSyncedAt: integration ? integration.last_synced_at : null,
      lastSyncStatus: integration ? integration.last_sync_status : null,
      lastSyncMessage: integration ? integration.last_sync_message : null,

      latest: {
        date: latest.score_date instanceof Date ? latest.score_date.toISOString().slice(0, 10) : String(latest.score_date),
        currentScore: latest.current_score === null ? null : Number(latest.current_score),
        maxScore: latest.max_score === null ? null : Number(latest.max_score),
        percentage: pctOf(latest.current_score, latest.max_score),
        azureTenantId: latest.azure_tenant_id,
        activeUserCount: latest.active_user_count,
        licensedUserCount: latest.licensed_user_count,
        enabledServices: latest.enabled_services || [],
        comparative: latest.comparative_json || [],
        syncedAt: latest.synced_at,
      },

      /*
       * The staleness caveat is DATA, not a UI nicety. Microsoft publishes one
       * snapshot a day; if the newest is a fortnight old the integration is
       * broken and the gauge on screen is a fortnight-old claim about a live
       * tenancy. The tab must be able to say so without recomputing this.
       */
      ageDays: Math.floor((Date.now() - new Date(latest.score_date).getTime()) / 86400000),

      trend,
      categories,
      gaps,
      accepted,
      thirdParty,
      controlCount: controls.length,
    });
  } catch (err) { return serverError(res, err); }
});

app.get('/api/secure-score', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveScoreTenant(req);
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant context.' });
    }

    const {
      vulnData, edrHealth, awarenessData, mdrData,
      estate, tenantServices, mdrCoverage,
    } = await loadScoreInputs(tenantId);

    const {
      composite, vulnScore, awarenessScore, mdrScore,
      measured, unmeasured, maxAchievable, vulnDetail, weights,
      serviceScore, coverage, coverageNominal, scope, overall,
    } = calculateSecureScore(vulnData, awarenessData, mdrData,
                             { estate, edr: edrHealth,
                               services: tenantServices, mdrCoverage });
    // Services passed through: advice about a control the client does not buy
    // reads on their board pack as a failing of theirs.
    const recommendations = generateRecommendations(
      vulnScore, awarenessScore, mdrScore, measured, vulnDetail, estate,
      { services: tenantServices });

    // Determine rating
    let rating = 'Critical';
    if (composite >= 80) rating = 'Excellent';
    else if (composite >= 70) rating = 'Good';
    else if (composite >= 50) rating = 'Fair';
    else rating = 'Poor';

    /*
     * Three numbers, because one cannot answer both questions.
     *
     *   score / overall  their whole posture, from all available evidence.
     *                    Unchanged, and still the `score` field every existing
     *                    consumer reads.
     *   serviceScore     how the services they actually buy are performing.
     *   coverage         how much of their weighted posture those services
     *                    reach at all.
     *
     * All three are null-safe: with no recorded services, serviceScore and
     * coverage are null and callers fall back to `score`.
     */
    const serviceRating = serviceScore == null ? null
      : serviceScore >= 80 ? 'Excellent'
      : serviceScore >= 70 ? 'Good'
      : serviceScore >= 50 ? 'Fair' : 'Poor';

    res.json({
      tenantId,
      score: composite,
      rating,
      overall,
      serviceScore,
      serviceRating,
      coverage,
      // Coverage before the Arctic Wolf reach discount. Returned beside the
      // headline so the page can show the arithmetic rather than a figure that
      // moved for reasons the reader cannot see. `scope` already carries the
      // discount detail and the vendor result.
      coverageNominal,
      scope,
      // Weights come from `weights`, not the flat WEIGHTS table: they follow the
      // client's exposure. Anything that reports a weight must read the same
      // object the composite was computed from, or the breakdown will not
      // reconcile with the score printed beside it.
      components: {
        vulnerabilities:  {
          score: vulnScore, weight: weights.vulnerabilities, measured: measured.vulnerabilities,
          // Which yardstick applied, and the workings behind it. A client shown
          // a number they cannot interrogate will not trust it.
          basis: vulnDetail.basis,
          detail: vulnDetail,
        },
        awareness:        { score: awarenessScore, weight: weights.awareness,        measured: measured.awareness },
        incidentResponse: {
          score: mdrScore, weight: weights.incidentResponse,
          measured: measured.incidentResponse,
          /*
           * WHICH MONTH THIS SCORE IS ABOUT. The component is computed from the
           * tickets raised in the last complete calendar month, not from the
           * whole uploaded feed — so the page has to be able to say so. A
           * figure whose window is invisible is one a client cannot argue with,
           * and this one used to silently cover however much CSV was exported.
           */
          period: mdrData ? mdrData.period : null,
          detail: mdrData ? mdrData.cohort : null,
        },
      },
      weights,
      estate: {
        servers:          estate.servers,
        publicAssets:     estate.publicAssets,
        endpoints:        estate.endpoints,
        cloudTenancies:   estate.cloudTenancies,
        users:            estate.users,
        serversPatched:   estate.serversPatched,
        scannedHosts:     estate.scannedHosts,
        trainedUsers:     estate.trainedUsers,
        awarenessProgram: estate.awarenessProgram,
        infraAssets:      estate.infraAssets,
        // The scan is external-facing only, so coverage and the internal gap are
        // different numbers and the UI has to be able to tell them apart.
        scannableAssets:   estate.scannableAssets,
        unscannableAssets: estate.unscannableAssets,
        sources:          estate.sources,
        recorded:         estate.anyDeclared,
        summary:          estateLib.describeEstate(estate),
        // How old the declaration is. ADVISORY ONLY — the score above was
        // computed from it exactly as recorded, with nothing discounted for
        // age. The Secure Score tab says so when it shows this.
        age:              estateLib.estateAge(estate),
        // What the declaration and the telemetry disagree about. Also
        // advisory: the declared figure is the one the score used.
        conflicts:        estateLib.reconcile(estate),
      },
      // Which components have no data behind them, what each is worth, and the
      // ceiling the score cannot pass until they are supplied.
      unmeasured,
      maxAchievable,
      dataAge: {
        vulns: vulnData ? 'current' : 'no data',
        awareness: awarenessData ? awarenessData.upload.uploaded_at : 'no data',
        mdr: mdrData ? mdrData.upload.uploaded_at : 'no data',
      },
      recommendations,
    });

    // After responding: today's components become tomorrow's history.
    snapshotSecureScore(tenantId, {
      score: composite,
      components: {
        vulnerabilities:  { score: vulnScore },
        awareness:        { score: awarenessScore },
        incidentResponse: { score: mdrScore },
      },
    });
  } catch (err) {
    return serverError(res, err);
  }
});

/**
 * GET /api/secure-score/history
 * Get historical Secure Score trend (last 90 days by fetching latest scan each month).
 */
/**
 * GET /api/secure-score/history
 *
 * Returns NEWEST-FIRST: history[0] is the most recent month, history[1] the one
 * before it. Callers index on that (see generateExcoReport's delta and the
 * report deck's trend arrows).
 *
 * Two kinds of row:
 *   source: 'snapshot'      — a stored measurement from secure_scores, taken at
 *                             the time. Authoritative.
 *   source: 'reconstructed' — rebuilt from dated source rows: that month's vuln
 *                             scan (carried forward if none), sessions sent and
 *                             completed by the month end, and tickets raised and
 *                             resolved by then. Accurate, but derived from
 *                             today's data, so anything since deleted upstream
 *                             is missing from past months too.
 *
 * A component is null only when its source genuinely has nothing for that month
 * (no scan yet, summary-format awareness upload, no tickets). The composite is
 * then re-weighted over the components that do exist.
 */
app.get('/api/secure-score/history', requireAuth, async (req, res) => {
  try {
    const tenantId = resolveScoreTenant(req);
    if (!tenantId) {
      return res.status(400).json({ error: 'No tenant context.' });
    }

    /*
     * ONE WEIGHTING FUNCTION FOR THE TREND AND THE HEADLINE.
     *
     * This route used to reconstruct months with a hardcoded 0.40/0.35/0.25
     * while the live score used estate-driven weights. Nothing asserted the two
     * agreed, and for most clients they did not — so a client's trend changed
     * methodology at the boundary between a stored snapshot and a reconstructed
     * month, and the step was invisible.
     *
     * CAVEAT THAT MUST REACH THE PAGE: tenants.services is a single CURRENT
     * value, not a dated one. Restating an old month therefore applies the mix
     * the client is on TODAY. If they bought Vulnerability Management in June,
     * March is restated as though they always had it. The response carries
     * mixAsOf so no consumer can render the trend without being able to say so.
     */
    const historyServices = await loadTenantServices(tenantId);
    const historyWeights  = secureScore.resolveWeights(historyServices);

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

    // Awareness and MDR for past months are reconstructed from dated child rows
    // rather than back-filled with today's figures — see reconstructComponents().

    // Real stored measurements: the last snapshot taken in each month.
    let snapshots = [];
    try {
      const snapRes = await pool.query(
        `SELECT DISTINCT ON (to_char(score_date, 'YYYY-MM'))
                to_char(score_date, 'YYYY-MM') AS month_key,
                composite_score, vuln_score, awareness_score, mdr_score
           FROM secure_scores
          WHERE tenant_id = $1
          ORDER BY to_char(score_date, 'YYYY-MM') DESC, score_date DESC
          LIMIT 12`,
        [tenantId]
      );
      snapshots = snapRes.rows;
    } catch (_) { /* table not migrated — fall back to derived months only */ }

    // Cover the last 6 calendar months plus any month that has a vuln scan, so
    // the trend is continuous even when scans are irregular. Snapshot months
    // are included too, so every point on the chart — stored or reconstructed —
    // has the evidence behind it and can be explained.
    const months = [...new Set(
      recentMonths(6)
        .concat(vulnTrendRows.map(r => r.month_key))
        .concat(snapshots.map(s => s.month_key))
    )].sort().reverse().slice(0, 12);

    const reconstructed = await reconstructComponents(tenantId, months);

    // Vulnerability posture carries forward: findings persist until the next
    // scan, so a month without one inherits the most recent earlier scan.
    const scansAsc = [...vulnTrendRows].sort((a, b) => (a.month_key < b.month_key ? -1 : 1));
    const vulnAsOf = monthKey => {
      let found = null;
      scansAsc.forEach(r => { if (r.month_key <= monthKey) found = r; });
      return found;
    };

    const byMonth = new Map();

    /*
     * The facts behind each month — findings, completion, incidents — for the
     * "what moved the score" explanations beside the chart. Attached to
     * snapshot rows as well as reconstructed ones: a stored score is exactly
     * the one a client has already seen, and the one most likely to be asked
     * about.
     */
    const evidenceOf = monthKey => Object.assign(
      { vulnerabilities: scoreEvidence.vulnerabilityEvidence(vulnTrendRows, monthKey) },
      (reconstructed.get(monthKey) || {}).evidence || {}
    );

    // Reconstructed first, so a real stored snapshot overwrites it below.
    months.forEach(monthKey => {
      const scan = vulnAsOf(monthKey);
      const rec  = reconstructed.get(monthKey) || {};
      // Nothing measurable for this month at all — skip rather than emit zeroes.
      if (!scan && rec.awarenessScore == null && rec.mdrScore == null) return;

      const vulnScore = scan ? calculateVulnScore({ summary: scan.summary }) : null;
      // The same weights the live score uses — see the note at the top of this
      // route. Renormalised over the components that actually exist, so a month
      // missing one is not scored as though that component were zero.
      const parts = [
        { v: vulnScore,          w: historyWeights.vulnerabilities },
        { v: rec.awarenessScore, w: historyWeights.awareness },
        { v: rec.mdrScore,       w: historyWeights.incidentResponse },
      ].filter(p => p.v != null);
      const den = parts.reduce((a, p) => a + p.w, 0);

      byMonth.set(monthKey, {
        monthKey,
        score:          den ? Math.round(parts.reduce((a, p) => a + p.v * p.w, 0) / den) : null,
        vulnScore,
        awarenessScore: rec.awarenessScore,
        mdrScore:       rec.mdrScore,
        source:         'reconstructed',
        evidence:       evidenceOf(monthKey),
      });
    });

    snapshots.forEach(s => {
      byMonth.set(s.month_key, {
        monthKey:       s.month_key,
        score:          s.composite_score,
        vulnScore:      s.vuln_score,
        awarenessScore: s.awareness_score,
        mdrScore:       s.mdr_score,
        source:         'snapshot',
        evidence:       evidenceOf(s.month_key),
      });
    });

    // Newest first — every consumer indexes [0] as current, [1] as previous.
    const history = [...byMonth.values()]
      .sort((a, b) => (a.monthKey < b.monthKey ? 1 : -1))
      .slice(0, 12);

    res.json({
      tenantId,
      history,
      /*
       * The weighting the whole series was computed on, and the caveat that
       * comes with it. Returned as DATA rather than left to the page to infer,
       * so nothing can render this trend without being able to state that
       * earlier months are restated on today's service mix.
       */
      weights: historyWeights,
      weightsBasis: historyWeights.basis,
      mixAsOf: 'current',
      restatedNote: 'Earlier months are restated on the current weighting so the ' +
        'trend is comparable end to end. Weights follow the service mix, and the ' +
        'mix is not dated — if it changed during this period, earlier months are ' +
        'shown as if the current contract had always applied.',
    });
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
