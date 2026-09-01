'use strict';

/**
 * Account lifecycle: suspend, force a password change, reset MFA.
 *
 * WHY THESE MATTER
 *
 * Before this, the only way to revoke a user was DELETE — which destroys the
 * record of who had access along with the access. For an external client
 * account that is the wrong tool: contracts lapse, people leave, and you still
 * want to know who could see what last March.
 *
 * The three risks worth asserting:
 *   - an admin locking THEMSELVES out (suspend or MFA-reset on own account)
 *   - a suspension that only takes effect at session expiry rather than now
 *   - an admin-set password that the user can never change
 *
 * server.js needs a database to load, so the route body is asserted at source
 * level and the middleware behaviour is driven for real.
 *
 *   node tests/user-lifecycle.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');

const portalGate = require(path.join(ROOT, 'lib', 'portal-gate.js'));
const { createChecker } = require('./helpers/check');
const { check, section, done } = createChecker('user-lifecycle');

const src     = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const adminJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-admin.js'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-user-lifecycle.sql'), 'utf8');

/** The PUT /api/users/:id body, so assertions cannot match elsewhere in the file. */
const putRoute = (() => {
  const start = src.indexOf("app.put('/api/users/:id'");
  const end = src.indexOf("app.delete('/api/users/:id'", start);
  return start > -1 && end > start ? src.slice(start, end) : '';
})();

section('the migration is additive and safe to re-run');
check('columns use ADD COLUMN IF NOT EXISTS',
  (migration.match(/ADD COLUMN IF NOT EXISTS/g) || []).length === 3);
check('accounts default to active, so the migration cannot lock anyone out',
  /is_active\s+BOOLEAN NOT NULL DEFAULT TRUE/.test(migration));
check('and nobody is retroactively forced to change their password',
  /must_change_password BOOLEAN NOT NULL DEFAULT FALSE/.test(migration));
// A fabricated timestamp would make a five-year-old password look fresh.
check('password age is left unknown rather than invented',
  !/password_changed_at[^;]*DEFAULT NOW\(\)/.test(migration));

section('the route accepts the lifecycle fields');
check('the route body was found', putRoute.length > 500, putRoute.length);
check('isActive is handled', /if \(isActive !== undefined\)/.test(putRoute));
check('mustChangePassword is handled',
  /if \(mustChangePassword !== undefined && !targetIsExternal\)/.test(putRoute));
check('resetMfa is handled', /if \(resetMfa\)/.test(putRoute));
check('resetMfa clears the secret AND the enabled flag',
  /totp_secret = NULL', 'totp_enabled = FALSE/.test(putRoute), 'both must go');
// Leaving totp_required alone matters: for a client MFA is implied by the
// role, so re-enrolment is forced by the login branch, not by this flag.
// Checks for an ASSIGNMENT, not the word: the bare string also matches the
// comment above the code explaining why it is left alone, so the crude version
// failed on its own documentation.
check('but leaves totp_required alone', !/totp_required\s*=/.test(putRoute));

section('an admin cannot lock themselves out');
check('suspending your own account is refused',
  /You cannot suspend your own account/.test(putRoute));
check('resetting your own MFA is refused',
  /Reset your own MFA from the security settings/.test(putRoute));
check('and both checks compare against the session, not a parameter',
  (putRoute.match(/targetId === req\.session\.userId/g) || []).length >= 3,
  (putRoute.match(/targetId === req\.session\.userId/g) || []).length);
check('the UI does not offer them either',
  /const lifecycleBtns = isSelf \? '' :/.test(adminJs));

section('an admin-set password is a handover credential');
// Someone else typed it and probably read it out. It is not the user's own.
check('a password reset forces a change at next sign-in',
  /if \(mustChangePassword === undefined && targetId !== req\.session\.userId\) \{\s*updates\.push\('must_change_password = TRUE'\)/.test(putRoute));
check('unless the caller explicitly says otherwise',
  /mustChangePassword === undefined/.test(putRoute));
check('and never for your own password change',
  /targetId !== req\.session\.userId/.test(putRoute));

section('but a client account works the moment the admin resets it');
/*
 * Clients have no self-service reset — that is the product decision — so the
 * credential an admin issues has to be usable as issued. Forcing a change on
 * an account with no change screen produced a 428 on every portal call and an
 * error page with nothing to click.
 */
check('the role is read before deciding, and a role change in the same request wins',
  /const targetIsExternal = pagesLib\.isExternalRole\(\s*role !== undefined \? role : targetRole\)/.test(putRoute));
check('a client password reset clears the flag rather than setting it',
  /if \(targetIsExternal\) \{\s*updates\.push\('must_change_password = FALSE'\)/.test(putRoute));
check('so an account stranded by an earlier reset is repaired by the next one',
  /must_change_password = FALSE/.test(putRoute));
check('and an explicit mustChangePassword is refused for a client',
  /mustChangePassword !== undefined && !targetIsExternal/.test(putRoute));
check('the target role is actually selected from the database',
  /SELECT tenant_id, auth_type, role FROM users/.test(putRoute) &&
  /SELECT auth_type, role FROM users/.test(putRoute));

// The admin list would otherwise promise a step that never comes.
check('the admin badge is not shown for a client',
  /u\.must_change_password && u\.role !== 'client'/.test(adminJs));

section('suspension bites on the next request, not at session expiry');
check('requireActiveUser is mounted globally on /api',
  /app\.use\('\/api', portalGate\.requireActiveUser\)/.test(src));
{
  // Role and tenant are snapshotted onto the session at login, so without a
  // per-request check a suspended user keeps working for up to eight hours.
  const gateSrc = fs.readFileSync(path.join(ROOT, 'lib', 'portal-gate.js'), 'utf8');
  check('it reads is_active fresh from the database each request',
    /SELECT role, is_active, must_change_password FROM users WHERE id = \$1/.test(gateSrc));
  check('a suspended session is destroyed, not merely refused',
    /is_active === false[\s\S]{0,120}session\.destroy/.test(gateSrc));
  check('a deleted account is handled too', /no longer available/.test(gateSrc));
}

section('the forced-change block leaves a way out');
{
  const calls = [];
  const res = {
    statusCode: 0, body: null,
    status(c) { res.statusCode = c; return res; },
    json(o) { res.body = o; return res; },
  };
  // Stand in for the pool: the user owes a password change. `stubRow` is
  // reassigned below to run the same middleware as a staff user and as a
  // client, because the two must NOT behave the same way.
  let stubRow = { role: 'admin', is_active: true, must_change_password: true };
  const gatePath = require.resolve(path.join(ROOT, 'lib', 'portal-gate.js'));
  const dbPath = require.resolve(path.join(ROOT, 'lib', 'db.js'));
  require.cache[dbPath] = {
    id: dbPath, filename: dbPath, loaded: true, exports: {
      async query(sql, params) {
        calls.push(params);
        return { rows: [stubRow] };
      },
    },
  };
  delete require.cache[gatePath];
  const gate = require(gatePath);

  const run = (p) => new Promise((resolve) => {
    let nexted = false;
    gate.requireActiveUser(
      // destroy() is needed for the suspended path, which tears the session
      // down rather than merely answering 403.
      { session: { userId: 1, destroy(cb) { cb(); } }, path: p },
      Object.assign({}, res, {
        status(c) { res.statusCode = c; return this; },
        json(o) { res.body = o; resolve({ blocked: true, status: res.statusCode, body: o }); return this; },
      }),
      () => { nexted = true; resolve({ blocked: false }); }
    );
    if (nexted) resolve({ blocked: false });
  });

  (async () => {
    const blocked = await run('/vulns/latest');
    check('an ordinary route is blocked with 428', blocked.blocked && blocked.status === 428,
      blocked.status);
    check('and the client is told why', blocked.body && blocked.body.mustChangePassword === true);

    // Blocking these too would leave the user with no way to comply.
    for (const p of ['/auth/change-password', '/auth/me', '/auth/logout']) {
      const r = await run(p);
      check('but ' + p + ' stays reachable', r.blocked === false, r.status);
    }

    /* ── The client case ──────────────────────────────────────────────────
       Portal password resets are admin-only, so a client has NO screen on
       which to satisfy a forced change. Enforcing the flag would answer 428
       on every portal call and leave them looking at an error with nothing
       to click — an account the admin has just reset would arrive broken.

       The flag is refused here as well as at the point it is written,
       because a row stranded by an earlier reset is already in the database
       and no future write will visit it. */
    stubRow = { role: 'client', is_active: true, must_change_password: true };

    const clientOrdinary = await run('/portal/incidents');
    check('a client owing a password change is NOT blocked',
      clientOrdinary.blocked === false, clientOrdinary.status);

    const clientScore = await run('/portal/secure-score');
    check('and the rest of the portal stays reachable too',
      clientScore.blocked === false, clientScore.status);

    // Suspension is a different thing and must still bite for a client.
    stubRow = { role: 'client', is_active: false, must_change_password: false };
    const suspended = await run('/portal/incidents');
    check('but a SUSPENDED client is still refused',
      suspended.blocked === true && suspended.status === 403, suspended.status);

    delete require.cache[dbPath];
    delete require.cache[gatePath];

    section('the client role is visible as external in the admin UI');
    // It previously fell through the badge chain to "Read-only" — a staff role
    // with read on every tab. An external account must never read as one.
    check('a client gets its own badge', /role-badge role-client">Client</.test(adminJs));
    check('and is not rendered as Read-only',
      /u\.role === 'client'[\s\S]{0,120}role-client/.test(adminJs));
    check('suspended rows are marked', /admin-row-suspended/.test(adminJs));
    check('MFA state is shown where the role requires MFA',
      /u\.role === 'client' \|\| u\.role === 'superadmin'/.test(adminJs));
    check('Reset MFA is disabled when nothing is enrolled',
      /u\.totp_enabled \? '' : 'disabled/.test(adminJs));
    check('SSO users are not offered an MFA reset we do not control',
      /\$\{isSso \? '' :/.test(adminJs));
    check('delete points at suspend as the reversible option',
      /use Suspend instead/.test(adminJs));

    section('the user list degrades on an un-migrated database');
    check('the columns are probed rather than assumed',
      /hasUserLifecycleColumns/.test(src));
    check('and defaulted when absent',
      /TRUE AS is_active, FALSE AS must_change_password/.test(src));
    check('the probe is not cached on a negative answer',
      /Deliberately NOT cached on false/.test(src));

    done();
  })();
}
