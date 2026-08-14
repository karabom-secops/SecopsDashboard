'use strict';

/**
 * lib/pages.js
 * Single source of truth for roles, the page catalog, and the default page
 * access each role gets.
 *
 * Access model:
 *   Every page has a level for each user — 'none', 'read' or 'write'.
 *   The level comes from ROLE_DEFAULTS[role], unless the user has a row in
 *   user_page_access for that page, which overrides it. That lets an admin
 *   grant or revoke a single page without changing someone's role.
 *
 * The role literals that used to be duplicated across server.js,
 * lib/auth-middleware.js, public/js/app.js and public/js/tab-admin.js now
 * live here. The browser gets PAGES and its resolved access map from
 * GET /api/auth/me, so nothing is duplicated client-side either.
 */

const ROLES = ['superadmin', 'admin', 'manager', 'sales', 'readonly'];

const ROLE_LABELS = {
  superadmin: 'Super Admin',
  admin:      'Admin',
  manager:    'Manager',
  sales:      'Sales',
  readonly:   'Read-only',
};

const NONE  = 'none';
const READ  = 'read';
const WRITE = 'write';

const LEVELS = [NONE, READ, WRITE];

// Rank used when comparing two levels (higher wins).
const LEVEL_RANK = { none: 0, read: 1, write: 2 };

/**
 * The catalog. `type: 'tab'` entries are panels inside index.html and must
 * match the data-tab attributes in public/index.html; `type: 'page'` entries
 * are standalone HTML pages.
 */
const PAGES = [
  { key: 'operations',           label: 'Operations',           type: 'tab' },
  { key: 'metrics',              label: 'Metrics & Trends',     type: 'tab' },
  { key: 'redteam',              label: 'Red Team',             type: 'tab' },
  { key: 'vulns',                label: 'Vulnerabilities',      type: 'tab' },
  { key: 'awareness',            label: 'Awareness',            type: 'tab' },
  { key: 'incident-response',    label: 'Incident Response',    type: 'tab' },
  { key: 'grc',                  label: 'GRC',                  type: 'tab' },
  { key: 'risk-register',        label: 'Risk Register',        type: 'tab' },
  { key: 'third-party-risk',     label: 'Third-Party Risk',     type: 'tab' },
  { key: 'remediation-tracker',  label: 'Remediation Tracker',  type: 'tab' },
  { key: 'secure-score',         label: 'Secure Score',         type: 'tab' },
  { key: 'edr',                  label: 'Managed EDR',          type: 'tab' },
  { key: 'ndr',                  label: 'Managed NDR',          type: 'tab' },
  { key: 'o365',                 label: 'Managed Identity',     type: 'tab' },
  { key: 'mdr-pricing',          label: 'MDR Pricing',          type: 'tab' },
  { key: 'reports',              label: 'Reports',              type: 'tab' },
  { key: 'admin',                label: 'Admin',                type: 'tab' },
  { key: 'manager',              label: 'Manager Dashboard',    type: 'page' },
  { key: 'upload',               label: 'Data Upload',          type: 'page' },
];

const PAGE_KEYS = PAGES.map(p => p.key);

// Every tab except Admin — the set a plain viewer is expected to see.
const VIEWER_TABS = PAGES
  .filter(p => p.type === 'tab' && p.key !== 'admin')
  .map(p => p.key);

function buildDefaults(level, keys) {
  const map = {};
  keys.forEach(k => { map[k] = level; });
  return map;
}

/**
 * Role defaults. These reproduce the behaviour the app had before per-page
 * access existed, so upgrading changes nothing until an override is set:
 *
 *  - superadmin / admin  — full write everywhere (requireAdmin routes).
 *  - sales               — read across the dashboard, write on the Risk
 *                          Register only (this is what requireRiskWrite did).
 *  - manager             — the manager dashboard and nothing else; auth.js
 *                          has always redirected managers straight to it.
 *  - readonly            — read on every tab, no Admin, no Upload.
 */
const ROLE_DEFAULTS = {
  superadmin: buildDefaults(WRITE, PAGE_KEYS),

  admin: buildDefaults(WRITE, PAGE_KEYS),

  // The remediation tracker edits risks and pentest findings in place, which
  // sales could already do, so it gets write here too. Its per-item calls hit
  // the owning page's API (vulns, ir, …) and are gated by that page.
  sales: Object.assign(
    buildDefaults(READ, VIEWER_TABS),
    {
      'risk-register':       WRITE,
      'remediation-tracker': WRITE,
      manager:               READ,
      admin:                 NONE,
      upload:                NONE,
    }
  ),

  // manager.html loads tab-awareness.js, which reads GET /api/awareness — so
  // the manager role needs read on 'awareness' for its own dashboard to work.
  manager: Object.assign(
    buildDefaults(NONE, PAGE_KEYS),
    { manager: READ, awareness: READ }
  ),

  readonly: Object.assign(
    buildDefaults(READ, VIEWER_TABS),
    {
      admin:   NONE,
      manager: NONE,
      upload:  NONE,
    }
  ),
};

/**
 * Maps the first segment of an /api/... path to the page that owns it.
 * Prefixes that are absent from this table are left alone by the gate, so
 * adding a route without touching this file keeps the old behaviour
 * (authenticated users only).
 */
const API_PREFIX_TO_PAGE = {
  weeks:                  'operations',
  week:                   'operations',
  metrics:                'metrics',
  redteam:                'redteam',
  vulns:                  'vulns',
  awareness:              'awareness',
  ir:                     'incident-response',
  grc:                    'grc',
  risks:                  'risk-register',
  'pentest-findings':     'risk-register',
  vendors:                'third-party-risk',
  'remediation-tracker':  'remediation-tracker',
  'secure-score':         'secure-score',
  edr:                    'edr',
  ndr:                    'ndr',
  o365:                   'o365',
  mdr:                    'mdr-pricing',
  reports:                'reports',
  users:                  'admin',
  integrations:           'admin',
  // POST /api/upload (weekly report) previously had no guard beyond a valid
  // session; it now requires write on the Upload page.
  upload:                 'upload',
};

/**
 * resolveAccess — merge a role's defaults with the user's override rows into
 * a flat { pageKey: level } map covering every page.
 *
 * @param {string} role
 * @param {Array<{page_key: string, access: string}>} overrideRows
 * @returns {Object<string, string>}
 */
function resolveAccess(role, overrideRows) {
  const defaults = ROLE_DEFAULTS[role] || ROLE_DEFAULTS.readonly;
  const map = {};
  PAGE_KEYS.forEach(k => { map[k] = defaults[k] || NONE; });

  (overrideRows || []).forEach(row => {
    const key   = row.page_key !== undefined ? row.page_key : row.pageKey;
    const level = row.access;
    if (PAGE_KEYS.includes(key) && LEVELS.includes(level)) {
      map[key] = level;
    }
  });

  return map;
}

/**
 * hasAccess — does this access map allow the page at the required level?
 *
 * @param {Object<string, string>} map   from resolveAccess
 * @param {string}  key                  page key
 * @param {boolean} needWrite            true for mutating actions
 */
function hasAccess(map, key, needWrite) {
  const level = (map && map[key]) || NONE;
  return LEVEL_RANK[level] >= (needWrite ? LEVEL_RANK.write : LEVEL_RANK.read);
}

/**
 * pageForApiPath — page key that owns an /api path, or null if unmapped.
 * Accepts the path as seen after the '/api' mount, e.g. '/vulns/latest'.
 */
function pageForApiPath(apiPath) {
  const segment = String(apiPath || '').split('?')[0].split('/').filter(Boolean)[0];
  if (!segment) return null;
  return API_PREFIX_TO_PAGE[segment] || null;
}

module.exports = {
  ROLES,
  ROLE_LABELS,
  LEVELS,
  LEVEL_RANK,
  NONE,
  READ,
  WRITE,
  PAGES,
  PAGE_KEYS,
  ROLE_DEFAULTS,
  API_PREFIX_TO_PAGE,
  resolveAccess,
  hasAccess,
  pageForApiPath,
};
