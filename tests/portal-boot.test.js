'use strict';

/**
 * Sign out, and the ordering that broke it.
 *
 * THE BUG
 *
 * portal-boot.js wired the chrome — the sign-out button and the hashchange
 * handler — at the END of boot, after `await P.get('me')`. That call has an
 * early return on failure, so any error from /api/portal/me left the button
 * rendered, enabled, and attached to nothing. Clicking it did nothing at all.
 *
 * The state in which it failed is exactly the state in which someone wants it:
 * the portal is showing an error they cannot act on. It was also inert for the
 * whole of a slow first load.
 *
 * Verified in a real browser during development (headless Chrome, stubbed
 * fetch, addEventListener wrapped to record registrations): with the original
 * ordering the button was wired on the happy path and NOT wired when /me
 * failed. These are the static invariants that keep it that way, because there
 * is no browser in this suite.
 *
 *   node tests/portal-boot.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('portal-boot');

const boot = fs.readFileSync(path.join(ROOT, 'public', 'portal', 'js', 'portal-boot.js'), 'utf8');
const auth = fs.readFileSync(path.join(ROOT, 'public', 'js', 'auth.js'), 'utf8');

section('the portal wires sign out before it needs the server');

const wireDef  = boot.indexOf('function wireChrome()');
const wireCall = boot.indexOf('wireChrome();');
const meFetch  = boot.indexOf("await P.get('me')");

check('wireChrome() exists', wireDef > -1);
check('it is called', wireCall > -1);
check('the session call exists', meFetch > -1);

// The whole fix, as an ordering assertion. A string-presence check would have
// passed throughout the bug: the call was always there, just too late.
check('wiring happens BEFORE the session call, not after',
  wireCall > -1 && meFetch > -1 && wireCall < meFetch,
  'wireChrome@' + wireCall + ' vs me@' + meFetch);

// Guard the specific regression: the early return that stranded it.
const failBranch = boot.slice(meFetch, meFetch + 700);
check('the error path still returns early', /return;/.test(failBranch));
check('and no longer has to wire anything on the way out',
  !/wireChrome/.test(failBranch));

check('wireChrome is called exactly once',
  (boot.match(/wireChrome\(\);/g) || []).length === 1,
  (boot.match(/wireChrome\(\);/g) || []).length);

section('signing out does not depend on the server answering');

for (const [name, src] of [['portal-boot.js', boot], ['auth.js', auth]]) {
  // An awaited fetch that never settles skips the redirect that follows it, so
  // a hung server produces a button that looks broken rather than one that
  // signs you out.
  check(name + ' races the logout request against a timeout',
    /Promise\.race\(\[[\s\S]{0,400}setTimeout\(r, 3000\)/.test(src));
  check(name + ' redirects to login regardless of the outcome',
    /catch[\s\S]{0,120}location\.replace\([^)]*login\.html/.test(src));
  check(name + ' disables the button so it cannot be double-clicked',
    /(logout|logoutBtn)\.disabled = true/.test(src));
}

section('the logout route is reachable without a working session');

const server = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const logoutAt = server.indexOf("app.post('/api/auth/logout'");
const authAt   = server.indexOf("app.use('/api', requireAuth)");
const activeAt = server.indexOf("app.use('/api', portalGate.requireActiveUser)");

check('the route is registered', logoutAt > -1);
// Express matches in registration order. Registering logout after the gates
// would mean a suspended or password-blocked user could not sign out — the one
// action that should always work.
check('and registered before requireAuth', logoutAt < authAt,
  'logout@' + logoutAt + ' vs requireAuth@' + authAt);
check('and before the active-user check', logoutAt < activeAt,
  'logout@' + logoutAt + ' vs requireActiveUser@' + activeAt);
check('it destroys the session rather than just clearing the cookie',
  /app\.post\('\/api\/auth\/logout'[\s\S]{0,240}session\.destroy/.test(server));

done();
