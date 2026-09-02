'use strict';

/**
 * Middleware ORDER and route wiring in server.js.
 *
 * WHY A SOURCE-LEVEL SUITE
 *
 * portal-gate.test.js drives the real middleware over real HTTP, but through a
 * miniature app it builds itself. That proves the middleware is correct and
 * proves nothing about whether server.js actually mounts it — deleting one
 * `app.use` line would leave every one of those 43 checks green while the
 * membrane was gone from production.
 *
 * server.js needs a database to start, and Postgres is unreachable here, so
 * these are static assertions over the source. They are weaker than behavioural
 * tests and should be replaced by them once there is a database to run against.
 * They catch deletion and reordering, which is the failure mode that matters.
 *
 *   node tests/server-wiring.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('server-wiring');
const src = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');

/** Character offset of a snippet, or -1. Order is compared on these. */
const at = (needle) => src.indexOf(needle);

section('the membrane is mounted, and mounted in the right order');

const authAt      = at("app.use('/api', requireAuth)");
const activeAt    = at("app.use('/api', portalGate.requireActiveUser)");
const confineAt   = at("app.use('/api', portalGate.requirePortalConfinement)");
const pageGateAt  = at("app.use('/api', pageGate)");

check('requireAuth is mounted on /api', authAt > -1);
check('requireActiveUser is mounted on /api', activeAt > -1);
check('requirePortalConfinement is mounted on /api', confineAt > -1);
check('pageGate is still mounted on /api', pageGateAt > -1);

check('confinement comes AFTER authentication', authAt > -1 && confineAt > authAt);
// THE ordering assertion. pageGate fails open on an unmapped prefix, so a
// client must be stopped before reaching it, not by it.
check('confinement comes BEFORE pageGate — pageGate fails open',
  confineAt > -1 && pageGateAt > -1 && confineAt < pageGateAt,
  'confine@' + confineAt + ' pageGate@' + pageGateAt);
check('the active-account check runs before both gates',
  activeAt > authAt && activeAt < confineAt);

/*
 * ── Static code assets must revalidate ────────────────────────────────────
 *
 * The script tags in index.html are unversioned, so a file's URL never changes
 * when its contents do. Express's default `public, max-age=0` lets the nginx
 * in front of this app hold and serve a copy, and a correctly deployed fix
 * then sits on disk while everyone loads the old build.
 *
 * Behavioural checks would need a live server; these prove the header is set
 * and, more importantly, that it is set for the file types that carry code.
 */
section('a deployed front-end fix actually reaches the browser');

check('express.static sets response headers at all',
  /express\.static\(PUBLIC,\s*\{[\s\S]{0,200}setHeaders/.test(src));
check('code assets are marked no-cache',
  /Cache-Control['"],\s*['"]no-cache/.test(src));

// The pattern is the load-bearing part: miss .js and the whole thing is
// decorative, since JS is where the behaviour lives.
const revalidate = (src.match(/const REVALIDATE = (\/[^\n]*\/[a-z]*);/) || [])[1];
check('the pattern exists', !!revalidate, revalidate);
if (revalidate) {
  // eslint-disable-next-line no-eval
  const re = eval(revalidate);
  ['app.js', 'report-sections.js', 'index.html', 'styles.css']
    .forEach(f => check(f + ' revalidates', re.test(f)));
  // Content-addressed assets would pay a needless round trip; they change name
  // when they change at all.
  ['logo.png', 'brand.woff2'].forEach(f =>
    check(f + ' is left cacheable', !re.test(f)));
}

section('login hardening');

check('lib/portal-gate is required', /require\(['"]\.\/lib\/portal-gate['"]\)/.test(src));
check('the session id is regenerated on login',
  /await regenerateSession\(req\);/.test(src));
check('regeneration happens before anything is written to the session',
  at('await regenerateSession(req);') > -1 &&
  at('await regenerateSession(req);') < at('req.session.mfaPending = pending;'),
  'regen@' + at('await regenerateSession(req);'));
check('a suspended account cannot log in',
  /user\.is_active === false/.test(src));
check('suspension is checked AFTER the password, not before',
  at('await bcrypt.compare(password, user.password_hash)') <
  at('user.is_active === false'));
check('the login query tolerates an un-migrated database',
  /if \(err\.code !== '42703'\) throw err;/.test(src));

section('MFA covers external roles, and is rate limited');

// Anchored on the whole assignment, not just the call. Matching
// `isExternalRole(user.role)` anywhere in the file passed even when it had been
// stripped from this line, because it still appears in the enrolment branch
// below — a check that could not fail is worse than no check.
check('MFA branching includes external roles',
  /const mfaRoles = user\.role === 'superadmin' \|\| pagesLib\.isExternalRole\(user\.role\);/.test(src));
check('an unenrolled client is forced into enrolment, not let through',
  /user\.totp_required \|\| pagesLib\.isExternalRole\(user\.role\)/.test(src));
['mfa-verify', 'enroll-totp/confirm', 'totp-confirm', 'totp-disable'].forEach((route) => {
  check('POST /api/auth/' + route + ' is rate limited',
    new RegExp("'/api/auth/" + route.replace('/', '\\/') + "', mfaLimiter").test(src));
});
check('the MFA limiter is stricter than the login limiter',
  /const mfaLimiter = rateLimit\(\{[\s\S]{0,200}max: 10,/.test(src));

section('self-service password change');

check('the route exists', /app\.post\('\/api\/auth\/change-password'/.test(src));
check('it is rate limited', /'\/api\/auth\/change-password', mfaLimiter/.test(src));
check('it re-proves the current password',
  /bcrypt\.compare\(current, r\.rows\[0\]\.password_hash\)/.test(src));
check('it clears the forced-change flag',
  /must_change_password = FALSE/.test(src));
check('it refuses a password shorter than 8 characters',
  /next\.length < 8/.test(src));
check('it refuses reusing the current password',
  /next === current/.test(src));
check('it hashes at the same cost as the rest of the app',
  /bcrypt\.hash\(next, 12\)/.test(src));

section('a client is routed to the portal, not the dashboard');

// A client's page-access map is empty by design, so every one of these paths
// would otherwise land them on "you do not have access to any pages" instead of
// their portal. All four were broken until tested end to end.
const loginJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'login.js'), 'utf8');
const authJs  = fs.readFileSync(path.join(ROOT, 'public', 'js', 'auth.js'), 'utf8');

check('the server names a landing page per role', /function landingFor\(role\)/.test(src));
check('and sends clients to the portal', /return '\/secops\/portal\.html'/.test(src));
check('the login response carries a redirect after MFA',
  (src.match(/redirect: landingFor\(pending\.role\)/g) || []).length === 2,
  (src.match(/redirect: landingFor\(pending\.role\)/g) || []).length);

check('an already-signed-in client is sent to the portal',
  /me\.role === 'client' \? CLIENT_HOME/.test(loginJs));
check('the MFA step honours the redirect rather than assuming the dashboard',
  !/if \(res\.ok\) \{\s*location\.replace\(''\);/.test(loginJs));
check('every post-login redirect uses the server value',
  (loginJs.match(/location\.replace\(data\.redirect \|\| ''\)/g) || []).length === 3,
  (loginJs.match(/location\.replace\(data\.redirect \|\| ''\)/g) || []).length);
check('and the dashboard bounces a client that reaches it anyway',
  /user\.role === 'client'[\s\S]{0,80}portal\.html/.test(authJs));
check('that bounce runs BEFORE the manager rule, so a client cannot fall through',
  authJs.indexOf("user.role === 'client'") < authJs.indexOf('onManagerPage'),
  authJs.indexOf("user.role === 'client'") + ' < ' + authJs.indexOf('onManagerPage'));

section('the forced-change dead end is avoided');

const gateSrc = fs.readFileSync(path.join(ROOT, 'lib', 'portal-gate.js'), 'utf8');
check('a user owing a password change may still reach change-password',
  /change-password\|me\|logout/.test(gateSrc));
check('and is blocked everywhere else with 428',
  /status\(428\)/.test(gateSrc));
check('requireActiveUser degrades open on an un-migrated database',
  /err\.code === '42703' \|\| err\.code === '42P01'/.test(gateSrc));



section('the /secops base path reaches the API, not just static files');

// Every page carries <base href="/secops/"> and calls the API relatively, so
// the browser requests /secops/api/… In production nginx strips the prefix;
// hitting node directly it was never stripped, so static worked under /secops
// while every API call 404'd — including the URL this server prints at startup.
check('the prefix is stripped before routing',
  /req\.url\.startsWith\('\/secops\/'\)/.test(src));
check('and a bare /secops maps to the root', /req\.url === '\/secops'/.test(src));
// The tempting alternative — a second app.use('/secops/api', …) mount — would
// have been completely ungated, because requireAuth, requirePortalConfinement
// and pageGate are all bound to '/api'.
check('the API is NOT re-mounted under a second, ungated prefix',
  !/app\.use\('\/secops\/api'/.test(src));
/*
 * Anchored on the mount, not on its exact argument list. This read
 * `app.use(express.static(PUBLIC))` verbatim and broke the moment options were
 * added to it — and the failure mode of an indexOf anchor that stops matching
 * is -1, which quietly satisfies any `<` comparison it appears on the right of.
 * Both offsets are asserted to exist before they are compared.
 */
const stripAt  = src.indexOf("req.url.startsWith('/secops/')");
const staticAt = src.indexOf('app.use(express.static(PUBLIC');
check('both the strip and the static mount are present',
  stripAt > -1 && staticAt > -1, 'strip@' + stripAt + ' static@' + staticAt);
check('stripping happens before the static mount',
  stripAt > -1 && staticAt > -1 && stripAt < staticAt,
  'strip@' + stripAt + ' static@' + staticAt);
check('and before the auth gate',
  src.indexOf("req.url.startsWith('/secops/')") < src.indexOf("app.use('/api', requireAuth)"));

done();
