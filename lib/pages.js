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

const ROLES = ['superadmin', 'admin', 'manager', 'sales', 'readonly', 'analyst', 'client'];

const ROLE_LABELS = {
  superadmin: 'Super Admin',
  admin:      'Admin',
  manager:    'Manager',
  sales:      'Sales',
  readonly:   'Read-only',
  analyst:    'SOC Analyst',
  client:     'Client (Portal)',
};

/**
 * Roles that belong to someone OUTSIDE Reflex.
 *
 * The distinction matters because this file's access model is a page catalog
 * with a fail-open gate (see pageGate in lib/auth-middleware.js: an /api path
 * whose prefix is absent from API_PREFIX_TO_PAGE falls through to
 * authenticated-only). That is a reasonable convenience for staff and quite
 * wrong for customers, so external roles are confined to /api/portal by
 * lib/portal-gate.js and never rely on this catalog at all.
 */
const EXTERNAL_ROLES = ['client'];

function isExternalRole(role) {
  return EXTERNAL_ROLES.indexOf(role) >= 0;
}

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
  { key: 'email',                label: 'Managed Email Security', type: 'tab' },
  // Label only. The key stays 'mdr-pricing' because per-user grants are stored
  // against it; the page now holds both the MDR and the vISO calculators.
  { key: 'mdr-pricing',          label: 'Pricing',              type: 'tab' },
  { key: 'reports',              label: 'Reports',              type: 'tab' },
  { key: 'training',             label: 'Training',             type: 'tab' },
  { key: 'firewall',             label: 'Firewall Audit',       type: 'tab' },
  { key: 'client-profile',       label: 'Client Profile',       type: 'tab' },
  { key: 'admin',                label: 'Admin',                type: 'tab' },
  { key: 'manager',              label: 'Manager Dashboard',    type: 'page' },
  { key: 'upload',               label: 'Data Upload',          type: 'page' },
];

const PAGE_KEYS = PAGES.map(p => p.key);

/*
 * Tabs a plain viewer is NOT expected to see.
 *
 * VIEWER_TABS below is an allowlist by exclusion, which is a trap worth naming:
 * a page key added to PAGES lands in it automatically and is silently granted
 * to sales and readonly. That is the right default for a tab that shows client
 * data, and quite wrong for one that decides how the Secure Score is computed —
 * or for one aimed at a specific job function.
 *
 * Named NON_VIEWER_TABS rather than CONFIG_TABS because it is no longer only
 * about configuration: `training` is on it because it belongs to analysts, not
 * because it configures anything.
 *
 * Every key here is ALSO set to NONE explicitly in the role maps below. Belt
 * and braces, deliberately: the exclusion sets the default, and the explicit
 * NONE survives anyone reworking this list.
 */
const NON_VIEWER_TABS = ['admin', 'client-profile', 'training', 'firewall'];

const VIEWER_TABS = PAGES
  .filter(p => p.type === 'tab' && NON_VIEWER_TABS.indexOf(p.key) < 0)
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
      // Client configuration, not client data. Sales reads the dashboard; it
      // does not get to change how a client's Secure Score is computed.
      'client-profile':      NONE,
      // Internal SOC upskilling. Nothing here is client-facing or commercial.
      training:              NONE,
      // Firewall configuration review is delivery work, not a sales surface.
      firewall:              NONE,
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
      admin:            NONE,
      'client-profile': NONE,
      training:         NONE,
      firewall:         NONE,
      manager:          NONE,
      upload:           NONE,
    }
  ),

  /*
   * A SOC analyst: read-only across the dashboard, plus the two tabs that are
   * the job — Training and Firewall Audit.
   *
   * Defined as readonly's map plus those grants rather than as its own list, so
   * the two cannot drift — an analyst should see whatever a read-only user
   * sees, and the ONLY differences are the things that make them an analyst.
   *
   * `training` is WRITE, and the reason is worth stating because it looks
   * generous: pageGate requires write for any POST, and an analyst has to POST
   * their own progress and quiz attempts. It does not grant authorship — the
   * curriculum is a file in lib/, unreachable from any route. The one thing an
   * analyst can write here is their own record, enforced by
   * resolveTrainingUser reading the session and nothing else.
   */
  analyst: Object.assign(
    buildDefaults(READ, VIEWER_TABS),
    {
      admin:            NONE,
      'client-profile': NONE,
      manager:          NONE,
      upload:           NONE,
      training:         WRITE,
      // Analysts run firewall reviews; uploading a config is the work itself.
      firewall:         WRITE,
    }
  ),

  // A portal client has NO access to any staff page, by construction rather
  // than by omission. They are already confined to /api/portal by
  // requirePortalConfinement; this empty map means that even if that
  // confinement were bypassed, every gated route still refuses them.
  //
  // Deliberately NOT modelled as "readonly minus some tabs": readonly defaults
  // to read on every VIEWER_TAB, so any tab added in future would be granted to
  // clients silently. Starting from none inverts that — a new page is closed.
  client: buildDefaults(NONE, PAGE_KEYS),
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
  redteam:                'redteam',
  vulns:                  'vulns',
  awareness:              'awareness',
  ir:                     'incident-response',
  grc:                    'grc',
  risks:                  'risk-register',
  'pentest-findings':     'risk-register',
  vendors:                'third-party-risk',
  'remediation-tracker':  'remediation-tracker',
  // Client-submitted risk acceptances are reviewed from the Remediation
  // Tracker, so approving one needs WRITE there — pageGate enforces it for
  // every POST under this prefix. Approval moves a finding out of the Secure
  // Score, which is exactly the kind of change that must not be ungated.
  'risk-acceptances':     'remediation-tracker',
  'secure-score':         'secure-score',
  // Microsoft Secure Score. A SEPARATE prefix on the SAME page: it renders as
  // a panel on the Secure Score tab, so anyone who can see that tab can see
  // Microsoft's number, and nobody gains a page by this existing. Read-only —
  // the figures are Microsoft's and nothing here writes them.
  'ms-secure-score':      'secure-score',
  edr:                    'edr',
  ndr:                    'ndr',
  o365:                   'o365',
  // Managed Email Security. Read-only for everyone: the tab shows what the
  // Acronis sync stored, and nothing on it writes. Mapped anyway rather than
  // left to pageGate's fail-open branch, so a future write route is closed by
  // default instead of reachable by any authenticated staff user.
  email:                  'email',
  mdr:                    'mdr-pricing',
  reports:                'reports',
  users:                  'admin',
  integrations:           'admin',
  // The estate and the service mix, which used to be gated on two different
  // pages (secure-score and admin) despite being one question about one
  // client. Now one prefix, one page, one write path.
  'client-profile':       'client-profile',
  // Analyst upskilling. Writes are an analyst recording their OWN progress —
  // the curriculum is a file in lib/ and no route can change it.
  training:               'training',
  // Config upload and audit results.
  firewall:               'firewall',
  // Reads short-circuit in pageGate before this map is consulted (every user
  // needs GET /tenants for the client dropdowns), so this gates WRITES only.
  // Without the entry a write fell through pageGate's no-mapping branch and
  // was reachable by any authenticated staff user — the fail-open case.
  tenants:                'admin',
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
  EXTERNAL_ROLES,
  isExternalRole,
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
