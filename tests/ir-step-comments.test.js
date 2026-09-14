'use strict';

/**
 * Comments on incident response playbook steps.
 *
 * A step had a status, an assignee and a completion time, and nowhere to say
 * anything. The sentence that matters most in a response — "trace run, 14
 * recipients, 2 submitted" — lived in someone's head or a chat thread,
 * detached from the step it belonged to.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   one step, one tenant        a comment can only be attached to a step whose
 *                               incident belongs to the caller's tenant
 *   the author is the session   never a field the request can set
 *   append-only                 no edit or delete route exists
 *   staff-only                  the client portal never reads the table
 *   read-only roles read        and cannot write, by the page gate
 *   degrade-open                an un-migrated database still loads the board
 *   escaped                     a comment is text, never markup
 *
 *   node tests/ir-step-comments.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('ir-step-comments');

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-ir-step-comments.sql'), 'utf8');
const tabJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-incident-response.js'), 'utf8');
const portalJs  = fs.readFileSync(path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');
const P         = require(path.join(ROOT, 'lib', 'pages'));

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlOnly(sql) { return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1'); }

const srvCode = codeOnly(serverJs);
const sql     = sqlOnly(migration);

/** One route's handler source, from its registration to the next route. */
function routeBody(method, route) {
  const start = srvCode.indexOf(`app.${method}('${route}'`);
  if (start < 0) return '';
  const next = srvCode.slice(start + 10).search(/\napp\.(get|post|put|patch|delete)\(/);
  return next < 0 ? srvCode.slice(start) : srvCode.slice(start, start + 10 + next);
}

// ── The table ──────────────────────────────────────────────────────────────

section('the table');

check('it is created', /CREATE TABLE IF NOT EXISTS ir_activity_comments/.test(sql));
check('a comment belongs to a step, and goes with it',
  /activity_id\s+INT NOT NULL REFERENCES ir_activities\(id\) ON DELETE CASCADE/.test(sql));
check('it carries its incident and tenant, so ownership is one WHERE clause',
  /incident_id\s+INT NOT NULL REFERENCES ir_incidents\(id\) ON DELETE CASCADE/.test(sql) &&
  /tenant_id\s+INT REFERENCES tenants\(id\) ON DELETE CASCADE/.test(sql));
/*
 * What was recorded during a response does not stop being true when someone
 * leaves. CASCADE here would delete an incident's evidence along with an
 * account.
 */
check('a comment outlives its author\'s account',
  /author_id\s+INT REFERENCES users\(id\) ON DELETE SET NULL/.test(sql));
check('a blank or runaway comment cannot reach the table by any path',
  /CHECK \(char_length\(btrim\(body\)\) BETWEEN 1 AND 4000\)/.test(sql));
check('the constraint is re-runnable', /EXCEPTION WHEN duplicate_object THEN NULL/.test(sql));
check('both lookups are indexed',
  /idx_ir_activity_comments_incident/.test(sql) && /idx_ir_activity_comments_activity/.test(sql));

// ── The routes ─────────────────────────────────────────────────────────────

section('reading every step\'s thread');

const getRoute = routeBody('get', '/api/ir/incidents/:id/comments');
check('the route exists', getRoute.length > 200, getRoute.length + ' chars');
check('it requires a session', /requireAuth/.test(getRoute));
check('the incident must belong to the caller\'s tenant before anything is read',
  /SELECT id FROM ir_incidents WHERE id=\$1 AND tenant_id=\$2/.test(getRoute));
check('and the comments are scoped by tenant as well as incident',
  /c\.incident_id = \$1 AND c\.tenant_id = \$2/.test(getRoute));
check('in one query for the whole incident, not one per step',
  (getRoute.match(/FROM ir_activity_comments/g) || []).length === 1);
check('a non-numeric id is a 404, not a database error',
  /Number\.isInteger\(incidentId\)/.test(getRoute));

section('adding to a step\'s thread');

const postRoute = routeBody('post', '/api/ir/activities/:id/comments');
check('the route exists', postRoute.length > 200, postRoute.length + ' chars');

/*
 * THE ONE THAT MATTERS. Step ids are sequential across every tenant. Checking
 * the step exists is not checking the caller may comment on it.
 */
check('a step is only commentable through an incident in the caller\'s tenant',
  /JOIN ir_incidents i ON i\.id = a\.incident_id\s+WHERE a\.id = \$1 AND i\.tenant_id = \$2/.test(postRoute));
check('and the stored tenant is the resolved one, not a client-supplied value',
  /resolveIrTenant\(req, 'body'\)/.test(postRoute) &&
  /\[act\.rows\[0\]\.id, act\.rows\[0\]\.incident_id, tenantId, text, req\.session\.userId/.test(postRoute));

check('the author comes from the session',
  /req\.session\.userId/.test(postRoute));
check('and never from the request',
  !/req\.body\.(author|author_id|authorId|userId|username)/.test(postRoute));

check('whitespace is trimmed before the emptiness check',
  /\.trim\(\)/.test(postRoute) && /Comment cannot be empty/.test(postRoute));
check('and the length is capped to match the database constraint',
  /IR_COMMENT_MAX = 4000/.test(srvCode) && /text\.length > IR_COMMENT_MAX/.test(postRoute));

section('append-only');

/*
 * An incident record is evidence. A note that can be rewritten after the fact
 * is worth less than one that cannot; a correction is a later comment.
 */
['put', 'patch', 'delete'].forEach((m) => {
  check('there is no ' + m.toUpperCase() + ' route for a comment',
    !new RegExp(`app\\.${m}\\('\\/api\\/ir\\/[^']*comments`).test(srvCode));
});
check('and nothing on the server updates or deletes one',
  !/UPDATE ir_activity_comments/.test(srvCode) && !/DELETE FROM ir_activity_comments/.test(srvCode));
check('nor does the tab offer to',
  !/method:\s*'(PUT|PATCH|DELETE)'[^}]*comments/.test(codeOnly(tabJs)));

section('an un-migrated database still loads the board');

check('the read degrades to an empty, unavailable thread',
  /err\.code !== '42P01'/.test(getRoute) && /available: false, comments: \[\]/.test(getRoute));
check('a write says which migration to run',
  /err\.code !== '42P01'/.test(postRoute) && /migrate-ir-step-comments\.sql/.test(postRoute));
check('and only a missing table is swallowed — every other error still surfaces',
  (getRoute.match(/if \(err\.code !== '42P01'\) throw err/g) || []).length === 1 &&
  (postRoute.match(/if \(err\.code !== '42P01'\) throw err/g) || []).length === 1);

// ── Who may do what ────────────────────────────────────────────────────────

section('read-only roles read, and cannot write');

/*
 * No role guard in the route, by design: app.use('/api', pageGate) maps the
 * `ir` prefix to the incident-response page and requires WRITE for a POST.
 * If that mapping moved, this route would silently become writable by every
 * role that can see the tab.
 */
check('the /api/ir prefix is gated on the incident-response page',
  P.API_PREFIX_TO_PAGE.ir === 'incident-response', P.API_PREFIX_TO_PAGE.ir);
check('and both routes sit under that prefix',
  /app\.get\('\/api\/ir\//.test(getRoute) && /app\.post\('\/api\/ir\//.test(postRoute));

// ── Staff-only ─────────────────────────────────────────────────────────────

section('comments never reach the client portal');

check('the portal does not read the comments table',
  !/ir_activity_comments/.test(portalJs));
/*
 * The portal already reads steps, for phase completion. Asserted as an exact
 * column list: a `SELECT *` or an added column there is the first place an
 * internal working note would leak to a client.
 */
check('and still reads only phase, status and completion from the steps',
  /SELECT phase, status, completed_at FROM ir_activities/.test(portalJs) &&
  !/SELECT \* FROM ir_activities/.test(portalJs));

// ── The renderer ───────────────────────────────────────────────────────────

section('the thread renders as text, for the right people');

let writer = true;
const sandbox = { console };
sandbox.window = sandbox;
sandbox.canWrite = () => writer;
sandbox.document = {
  getElementById: () => null, querySelector: () => null, querySelectorAll: () => [],
};
vm.createContext(sandbox);
vm.runInContext(tabJs, sandbox);
const IR = sandbox.IrTab;

check('the tab exposes its thread renderer',
  !!IR && typeof IR._renderStepComments === 'function' && typeof IR._setState === 'function');

const XSS = '<img src=x onerror=alert(1)>';
const step = { id: 7, entry: 'Run a message trace', status: 'pending', phase: 'identification' };

IR._setState({
  available: true, open: [7],
  comments: [
    { id: 1, activity_id: 7, body: XSS + '\nsecond line', author: '<b>eve</b>', created_at: '2026-09-14T08:00:00Z' },
    { id: 2, activity_id: 7, body: 'Trace run — 14 recipients', author: null, created_at: '2026-09-14T09:00:00Z' },
  ],
});
const openHtml = IR._renderStepComments(step);

check('a comment body is escaped', openHtml.indexOf('<img') < 0 && openHtml.indexOf('&lt;img') >= 0,
  openHtml.slice(openHtml.indexOf('ir-step-comment-body'), openHtml.indexOf('ir-step-comment-body') + 70));
check('and so is an author name', openHtml.indexOf('<b>eve') < 0 && openHtml.indexOf('&lt;b&gt;eve') >= 0);
check('line breaks are kept as text, not converted to markup',
  /second line/.test(openHtml) && !/<br>/.test(openHtml));
check('a comment whose author has left still shows, attributed honestly',
  /Former user/.test(openHtml));
check('the count is on the toggle', /Comments \(2\)/.test(openHtml));
check('a writer gets a box to add to it', /ir-step-comment-input/.test(openHtml));
check('capped to the server\'s limit', /maxlength="4000"/.test(openHtml));

writer = false;
const readOnlyHtml = IR._renderStepComments(step);
check('a read-only role still sees the thread', /Trace run/.test(readOnlyHtml));
check('but gets no box to write in', !/ir-step-comment-input/.test(readOnlyHtml) &&
  !/ir-step-comment-post/.test(readOnlyHtml));

IR._setState({ available: true, open: [], comments: [] });
check('a read-only role with nothing to read gets no affordance at all',
  IR._renderStepComments(step) === '', JSON.stringify(IR._renderStepComments(step)));

writer = true;
const closedHtml = IR._renderStepComments(step);
check('a writer can start a thread on any step', /Add comment/.test(closedHtml));
check('and a closed thread shows the toggle only',
  !/ir-step-thread/.test(closedHtml) && /aria-expanded="false"/.test(closedHtml));

// Every step gets one — not only the current step, which is the only tile with
// an action button today.
['is-done', 'is-current', 'is-upcoming'].forEach((state, i) => {
  const s = { id: 20 + i, entry: 'x', status: state === 'is-done' ? 'done' : 'pending', phase: 'containment' };
  check('a ' + state.replace('is-', '') + ' step can be commented on',
    /ir-step-comments-toggle/.test(IR._renderStepComments(s)));
});

IR._setState({ available: false, open: [7], comments: [] });
check('an un-migrated server shows no thread, rather than a box it will refuse',
  IR._renderStepComments(step) === '');

section('the tab is wired');

const tabCode = codeOnly(tabJs);
check('every tile carries a thread',
  /\$\{renderStepComments\(t\)\}/.test(tabCode));
check('comments load with the steps, in one request for the incident',
  /api\/ir\/incidents\/\$\{id\}\/comments/.test(tabCode));
check('a slow response for a previous incident cannot overwrite the current one',
  /if \(_selectedId !== id\) return/.test(tabCode));
check('a comment is shown only once the server has stored it',
  /if \(!res\.ok \|\| !data\.comment\) throw/.test(tabCode) &&
  tabCode.indexOf('.push(data.comment)') > tabCode.indexOf('if (!res.ok || !data.comment) throw'));
/*
 * The upcoming-step fade used to be opacity on the whole tile, which would fade
 * the thread and the box with it. A note against a future step is often the
 * one that most needs reading.
 */
const css = fs.readFileSync(path.join(ROOT, 'public', 'css', 'styles.css'), 'utf8');
check('an upcoming step\'s comments are not faded with it',
  /\.ir-playbook-tile\.is-upcoming > :not\(\.ir-step-comments\)/.test(css) &&
  !/\.ir-playbook-tile\.is-upcoming \{\s*opacity/.test(css));

done();
