'use strict';

/**
 * The SOC analyst training portal.
 *
 * THE FOUR THINGS THIS SUITE EXISTS TO PROTECT
 *
 *   the answer key never reaches the browser   or every score is theatre
 *   grading is correct and hostile to junk     an unanswered question is wrong
 *   a record belongs to one person             no cross-user read or write
 *   playbooks are read-only                    training must not touch live IR
 *
 * lib/training.js is exercised behaviourally — it is pure and takes no
 * database. The routes need Postgres, which is unreachable here, so their
 * wiring is asserted over the source: weaker, and said so plainly. It catches
 * deletion and rewiring, which is the failure mode that matters for a rule
 * about whose data you can write.
 *
 *   node tests/training.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('training');

const T = require(path.join(ROOT, 'lib', 'training'));
const P = require(path.join(ROOT, 'lib', 'pages'));
const { QUESTIONS, PASS_MARK } = require(path.join(ROOT, 'lib', 'training', 'questions'));
const { PLAYBOOKS } = require(path.join(ROOT, 'public', 'js', 'ir-playbooks-data'));

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const tabJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-training.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-training.sql'), 'utf8');

/** Source with comments stripped — this repo documents its own rules in prose. */
function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const srvCode = codeOnly(serverJs);
const tabCode = codeOnly(tabJs);

/* ══ The answer key ═════════════════════════════════════════════════════════ */

section('the answer key never leaves the server');

/** Every key name anywhere in a structure, however deep. */
function allKeys(node, out) {
  out = out || [];
  if (Array.isArray(node)) { node.forEach(n => allKeys(n, out)); return out; }
  if (node && typeof node === 'object') {
    Object.keys(node).forEach((k) => { out.push(k); allKeys(node[k], out); });
  }
  return out;
}

// A recursive walk over EVERY module, not a spot check on the first one. The
// bank grows; a check that only looks at modules[0] stops covering it.
const catalogueKeys = allKeys(T.listModules());
check('the catalogue carries no answer', catalogueKeys.indexOf('answer') < 0);
check('and no explanation', catalogueKeys.indexOf('why') < 0);

let leaked = [];
T.MODULES.forEach((m) => {
  const keys = allKeys(T.getModule(m.id));
  if (keys.indexOf('answer') >= 0 || keys.indexOf('why') >= 0) leaked.push(m.id);
});
check('no module leaks its answers when opened', leaked.length === 0, leaked.join(','));

// And the questions really do have answers to leak — otherwise the check above
// would pass on an empty bank, which is the vacuous version of it.
check('the bank genuinely holds an answer key',
  Object.keys(QUESTIONS).length > 0 &&
  Object.keys(QUESTIONS).every(k => QUESTIONS[k].every(q => Number.isInteger(q.answer))),
  Object.keys(QUESTIONS).length + ' modules with questions');

// The allowlist, tested as an allowlist: a field added to the bank tomorrow is
// withheld by default rather than shipped because nobody updated a blocklist.
const withExtra = T.publicQuiz('phishing-response');
check('publicQuiz emits exactly id, q and options',
  withExtra.every(q => JSON.stringify(Object.keys(q).sort()) === '["id","options","q"]'),
  JSON.stringify(Object.keys(withExtra[0] || {})));

// The file itself must be unreachable: public/ is served before auth.
check('the question bank lives outside public/',
  fs.existsSync(path.join(ROOT, 'lib', 'training', 'questions.js')) &&
  !fs.existsSync(path.join(ROOT, 'public', 'js', 'training-questions.js')));
/*
 * The tab reads `.answer` only off a GRADED RESULT (`r.answer`), which is
 * correct — that is where the correct option is supposed to appear. It must
 * never read it off a quiz question (`q.answer`), because a question that
 * carries one has arrived with the key attached.
 *
 * An earlier version of this check searched for `answer:` and failed on the
 * string "Your answer: " in the results view — a check that cannot tell a label
 * from a data structure.
 */
check('the browser never reads an answer off a question',
  !/\bq\.answer\b/.test(tabCode), 'tab-training.js');
check('and never loads the question bank',
  !/questions/i.test(tabCode.replace(/quizCount|quiz|question\b/gi, '')),
  'tab-training.js');

/* ══ Grading ════════════════════════════════════════════════════════════════ */

section('grading is server-side, correct, and hostile to junk input');

const MOD = 'phishing-response';
const bank = QUESTIONS[MOD];
const rightAnswers = {};
bank.forEach((q) => { rightAnswers[q.id] = q.answer; });

const perfect = T.gradeAttempt(MOD, rightAnswers);
check('all correct scores full marks',
  perfect.score === bank.length && perfect.total === bank.length, perfect.score);
check('and passes', perfect.passed === true);
check('and reports 100%', perfect.pct === 100, perfect.pct);

const wrongAnswers = {};
bank.forEach((q) => { wrongAnswers[q.id] = (q.answer + 1) % q.options.length; });
const zero = T.gradeAttempt(MOD, wrongAnswers);
check('all wrong scores nothing', zero.score === 0, zero.score);
check('and does not pass', zero.passed === false);

/*
 * THE ONE THAT MATTERS MOST.
 *
 * Scoring only the questions that were answered would let somebody answer the
 * single question they were sure of and score 100%. An unanswered question is
 * wrong, and `total` is the size of the BANK, never the size of the submission.
 */
const oneOnly = {};
oneOnly[bank[0].id] = bank[0].answer;
const partial = T.gradeAttempt(MOD, oneOnly);
check('an unanswered question is wrong, not skipped',
  partial.score === 1 && partial.total === bank.length,
  partial.score + '/' + partial.total);
check('so a single right answer does not pass', partial.passed === false);

check('an empty submission scores zero',
  T.gradeAttempt(MOD, {}).score === 0);
check('a null submission does not crash',
  T.gradeAttempt(MOD, null).score === 0);

// Junk types must be wrong rather than throwing — the input comes from a
// browser, and being hostile to it is not the same as crashing on it.
const junk = {};
junk[bank[0].id] = String(bank[0].answer);      // '1' is not 1
junk[bank[1].id] = 999;                          // out of range
junk[bank[2].id] = true;                         // not an index at all
const junked = T.gradeAttempt(MOD, junk);
check('a stringified index does not count', junked.results[0].correct === false);
check('an out-of-range index does not count', junked.results[1].correct === false);
check('a boolean does not count', junked.results[2].correct === false);
check('and none of it throws', junked.score === 0, junked.score);

/*
 * `correct` is not enough on its own. An out-of-range index can never EQUAL the
 * answer, so a grader that failed to bound it would still mark the question
 * wrong and this section would stay green — which is exactly what a mutation
 * removing the bounds check demonstrated.
 *
 * What the bound actually protects is `picked`: the result says which option
 * somebody chose, and the browser renders `options[picked]`. An unbounded 999
 * comes back as a pick that does not exist.
 */
check('junk is normalised to "not answered", not echoed back',
  junked.results.every(r => r.picked === null),
  JSON.stringify(junked.results.map(r => r.picked)));
check('while a real choice is preserved',
  T.gradeAttempt(MOD, rightAnswers).results.every(r => Number.isInteger(r.picked)));

// The pass boundary, either side. Rounding for display must not decide it.
check('the pass mark is a ratio, not a rounded percentage',
  PASS_MARK > 0 && PASS_MARK < 1, PASS_MARK);
const twoOfThree = {};
twoOfThree[bank[0].id] = bank[0].answer;
twoOfThree[bank[1].id] = bank[1].answer;
const boundary = T.gradeAttempt(MOD, twoOfThree);
check('2 of 3 is graded against the raw ratio',
  boundary.passed === ((2 / 3) >= PASS_MARK),
  boundary.pct + '% vs ' + (PASS_MARK * 100) + '%');

check('an unknown module has no quiz to grade',
  T.gradeAttempt('does-not-exist', {}) === null);

/*
 * The pass rule as a property, over every module and every achievable score,
 * rather than one hand-picked case: `passed` must equal the raw ratio against
 * PASS_MARK, with rounding used for display only.
 */
let passBroken = [];
Object.keys(QUESTIONS).forEach((id) => {
  const qs = QUESTIONS[id];
  for (let n = 0; n <= qs.length; n++) {
    const a = {};
    qs.forEach((q, i) => { a[q.id] = i < n ? q.answer : (q.answer + 1) % q.options.length; });
    const g = T.gradeAttempt(id, a);
    if (g.score !== n) passBroken.push(id + ' scored ' + g.score + ' for ' + n);
    if (g.passed !== ((n / qs.length) >= PASS_MARK)) {
      passBroken.push(id + ' passed=' + g.passed + ' at ' + n + '/' + qs.length);
    }
  }
});
check('every achievable score grades and passes consistently',
  passBroken.length === 0, passBroken.join('; '));

// The graded result IS where the answers appear — that is the point of it.
check('the graded result reveals the correct option',
  perfect.results.every(r => Number.isInteger(r.answer)));
check('and the explanation, which is where the learning is',
  perfect.results.every(r => typeof r.why === 'string' && r.why.length > 20));

/* ══ Playbooks stay read-only ═══════════════════════════════════════════════ */

section('playbooks are the live ones, and are never written');

const phishing = T.playbookFor('phishing');
check('a playbook resolves', !!phishing && phishing.key === 'phishing');

// Compared against the SOURCE, not against a copy in this test. Restating the
// tasks here would let both drift together and prove nothing.
check('its tasks are exactly the ones that seed a real incident',
  JSON.stringify(phishing.phases.find(p => p.key === 'containment').tasks) ===
  JSON.stringify(PLAYBOOKS.phishing.containment),
  phishing.phases.find(p => p.key === 'containment').tasks.length + ' tasks');

check('every incident type is covered',
  T.listPlaybooks().length === Object.keys(PLAYBOOKS).length,
  T.listPlaybooks().length);

// Mutating what comes out must not reach the source object.
const copy = T.playbookFor('phishing');
copy.phases[0].tasks.push('INJECTED');
check('the returned tasks are a copy, not the live array',
  PLAYBOOKS.phishing.identification.indexOf('INJECTED') < 0,
  PLAYBOOKS.phishing.identification.length + ' tasks still');

// No training route may write anything IR-related.
check('no training route touches ir_activities',
  !/training[\s\S]{0,4000}(INSERT INTO ir_activities|UPDATE ir_activities)/.test(srvCode));
check('the playbooks route is a GET only',
  /app\.get\('\/api\/training\/playbooks'/.test(srvCode) &&
  !/app\.(post|put|delete)\('\/api\/training\/playbooks/.test(srvCode));

check('an unknown incident type resolves to nothing, not a guess',
  T.playbookFor('not-a-type') === null);

/* ══ A record belongs to one person ═════════════════════════════════════════ */

section('progress is per-user and cannot be forged');

check('resolveTrainingUser exists', /function resolveTrainingUser\(req\)/.test(srvCode));

/*
 * The rule, asserted structurally: the resolver reads the session and nothing
 * else. A superadmin branch or a `req.query.userId` here would be the whole
 * defence gone, and it would look like a convenience while it was being added.
 */
const resolver = (srvCode.match(
  /function resolveTrainingUser\(req\)\s*\{[\s\S]*?\n\}/) || [''])[0];
check('it reads the session', /req\.session[\s\S]*userId/.test(resolver), resolver.trim());
check('and takes no user id from the request',
  !/req\.(params|query|body)/.test(resolver), resolver.trim());

// And no handler anywhere in the training block reads one either.
const trainingBlock = (srvCode.match(
  /function resolveTrainingUser[\s\S]*?app\.get\('\/api\/client-profile'/) || [''])[0];
check('the training block is found', trainingBlock.length > 2000, trainingBlock.length);
check('no training handler reads a user id from the request',
  !/(params|query|body)\.userId/.test(trainingBlock));

// Ownership in the WHERE clause, not as a post-fetch filter.
check('progress is selected by user_id', /FROM training_progress\s+WHERE user_id = \$1/.test(srvCode));
check('attempts are selected by user_id', /where = 'user_id = \$1'/.test(srvCode));
check('progress is written against the session user',
  /INSERT INTO training_progress[\s\S]{0,900}\[userId, itemKey, status\]/.test(srvCode));

// The team view is aggregate and gated.
check('the team view is gated on write access',
  /app\.get\('\/api\/training\/team', requireAuth, requirePage\('training', \{ write: true \}\)/
    .test(srvCode));
check('and requirePage is actually imported',
  /require\('\.\/lib\/auth-middleware'\)/.test(serverJs) &&
  /\brequirePage\b[^=]*\}\s*=\s*require\('\.\/lib\/auth-middleware'\)/.test(serverJs));
check('the team view never returns individual answers',
  !/a\.answers/.test(trainingBlock));

/* ══ Progress keys are validated ════════════════════════════════════════════ */

section('the progress table cannot become a dumping ground');

check('a real module key is accepted',
  T.isValidProgressKey('module:phishing-response'));
check('a real lesson key is accepted',
  T.isValidProgressKey('lesson:phishing-response/first-moves'));
check('an unknown module is refused',
  !T.isValidProgressKey('module:not-a-module'));
check('an unknown lesson within a real module is refused',
  !T.isValidProgressKey('lesson:phishing-response/nope'));
check('a bare id with no namespace is refused',
  !T.isValidProgressKey('phishing-response'));
check('junk is refused', !T.isValidProgressKey('../../etc/passwd') &&
  !T.isValidProgressKey('') && !T.isValidProgressKey(null));

check('only two statuses exist',
  JSON.stringify(T.PROGRESS_STATUSES) === '["started","completed"]');

/* ══ Attempts are append-only ═══════════════════════════════════════════════ */

section('a failure survives a later pass');

const sql = migration.replace(/(^|\n)\s*--[^\n]*/g, '$1');
check('attempts are inserted, never upserted',
  /INSERT INTO training_attempts/.test(srvCode) &&
  !/INSERT INTO training_attempts[\s\S]{0,300}ON CONFLICT/.test(srvCode));
check('the table has no uniqueness that would prevent a retake',
  !/UNIQUE[\s\S]{0,80}training_attempts/i.test(sql) &&
  !/PRIMARY KEY \(user_id, module_id\)/.test(sql));
check('progress, by contrast, is keyed per item', /PRIMARY KEY \(user_id, item_key\)/.test(sql));
// Re-reading a lesson must not move the date somebody learned it.
check('a re-completion keeps the first completion date',
  /completed_at = COALESCE\(training_progress\.completed_at/.test(srvCode));

check('a failed attempt is still recorded',
  /INSERT INTO training_attempts[\s\S]{0,400}graded\.passed/.test(srvCode));
// Feedback must survive a database that cannot store the attempt.
check('the result is returned even when it cannot be stored',
  /recorded = false[\s\S]{0,1200}return res\.json\(\{ result: graded, recorded \}\)/.test(srvCode));

/* ══ Access ═════════════════════════════════════════════════════════════════ */

section('analysts, and nobody else');

check('the analyst role exists', P.ROLES.indexOf('analyst') >= 0);
check('and is internal, not a portal role', !P.isExternalRole('analyst'));
check('the page is in the catalogue',
  P.PAGES.some(p => p.key === 'training' && p.type === 'tab'));
check('the API prefix maps to it', P.API_PREFIX_TO_PAGE.training === 'training');

check('an analyst can use it', P.ROLE_DEFAULTS.analyst.training === 'write');
check('admins can see the team view', P.ROLE_DEFAULTS.admin.training === 'write');

// VIEWER_TABS is an allowlist by exclusion, so a new tab is granted to these
// silently unless somebody remembers. This is the check for "somebody
// remembered" — the same trap client-profile hit.
['sales', 'readonly', 'manager', 'client'].forEach((r) => {
  check(r + ' gets nothing', P.ROLE_DEFAULTS[r].training === 'none',
    P.ROLE_DEFAULTS[r].training);
});

/*
 * BOTH LAYERS, not just the outcome.
 *
 * The role maps above are belt; the exclusion list is braces. Because both are
 * in place, removing `training` from the exclusion list changes no role's
 * access — so the outcome checks alone cannot see it, and the protection would
 * quietly become single-layered. Asserted at the source.
 */
const pagesJs = fs.readFileSync(path.join(ROOT, 'lib', 'pages.js'), 'utf8');
check('training is excluded from the viewer allowlist',
  /NON_VIEWER_TABS = \[[^\]]*'training'[^\]]*\]/.test(pagesJs));
check('and so is every other non-viewer tab',
  /NON_VIEWER_TABS = \[[^\]]*'admin'[^\]]*\]/.test(pagesJs) &&
  /NON_VIEWER_TABS = \[[^\]]*'client-profile'[^\]]*\]/.test(pagesJs));

// An analyst is readonly plus training, so the two cannot drift apart.
const diffs = P.PAGE_KEYS.filter(k =>
  P.ROLE_DEFAULTS.analyst[k] !== P.ROLE_DEFAULTS.readonly[k]);
check('an analyst differs from readonly in exactly one page',
  diffs.length === 1 && diffs[0] === 'training', diffs.join(','));

check('the role migration widens the constraint',
  /CHECK \(role IN \([^)]*'analyst'[^)]*\)\)/.test(
    fs.readFileSync(path.join(ROOT, 'db', 'migrate-analyst-role.sql'), 'utf8')));

/* ══ The browser module ═════════════════════════════════════════════════════ */

section('the renderer escapes everything it is given');

const sandbox = { console };
sandbox.window = sandbox;
sandbox.document = {
  getElementById: () => null,
  querySelectorAll: () => [],
  querySelector: (s) => (s === 'base' ? { href: 'https://secops.reflex.co.za/secops/' } : null),
};
vm.createContext(sandbox);
vm.runInContext(tabJs, sandbox);
const TT = sandbox.window.TrainingTab;

check('the module loads', !!TT && typeof TT.loadAndRender === 'function');

/*
 * Content is data, and the renderer is the boundary that keeps it data. Each
 * block type is fed hostile input directly rather than through whatever path a
 * page render happens to take.
 */
const XSS = '<script>alert(1)</script>';
const ATTR = '"><img src=x onerror=alert(1)>';

[['p', { p: XSS }], ['h', { h: XSS }],
 ['list', { list: [XSS] }], ['steps', { steps: [XSS] }],
 ['code', { code: XSS }], ['callout', { callout: { tone: 'info', text: XSS } }],
].forEach(([name, block]) => {
  const html = TT._renderBlock(block, {});
  check(name + ' escapes a script tag',
    html.indexOf('<script') < 0 && html.indexOf('&lt;script') >= 0, html.slice(0, 70));
});

const attrHtml = TT._renderBlock({ p: ATTR }, {});
check('an attribute breakout is escaped',
  attrHtml.indexOf('<img') < 0 && attrHtml.indexOf('&quot;') >= 0, attrHtml);

// The closed set IS the boundary — there must be no fallback that renders
// whatever it was given.
check('an unknown block type renders nothing',
  TT._renderBlock({ rawHtml: '<b>x</b>' }, {}) === '');
check('a null block renders nothing', TT._renderBlock(null, {}) === '');
check('a string is not a block', TT._renderBlock('<b>x</b>', {}) === '');

// Tone is an attribute value, so it is constrained rather than escaped:
// escaping keeps it safe but still lets content invent class names.
const badTone = TT._renderBlock({ callout: { tone: 'evil', text: 'x' } }, {});
check('an unknown callout tone falls back to a known one',
  /tr-info/.test(badTone) && !/tr-evil/.test(badTone), badTone);

// A playbook block carries a key, not content — it must render nothing when the
// data is absent rather than an empty frame implying there are no steps.
check('a playbook block with no data renders nothing',
  TT._renderBlock({ playbook: 'phishing' }, {}) === '');
const pbHtml = TT._renderBlock({ playbook: 'phishing' }, { phishing: phishing });
check('and renders the live tasks when present',
  pbHtml.indexOf('live playbook') > 0 &&
  pbHtml.indexOf(PLAYBOOKS.phishing.containment[0].slice(0, 25)) > 0);

section('every request keeps the /secops/ base path');

check('the URL builder keeps the base',
  TT._apiUrl('training/modules') ===
    'https://secops.reflex.co.za/secops/api/training/modules',
  TT._apiUrl('training/modules'));
check('no module-local fallback invents a path', !/window\.apiUrl/.test(tabCode));
check('and no request is hard-coded to a bare root',
  !/fetch\(['"]\/api\//.test(tabCode));

section('the tab is wired into the shell');

check('the script is loaded', /js\/tab-training\.js/.test(indexHtml));
check('the panel exists', /id="tab-training"/.test(indexHtml));
check('the nav entry exists', /data-tab="training"/.test(indexHtml));
check('the stylesheet is linked', /css\/training\.css/.test(indexHtml));

const appJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'app.js'), 'utf8');
check('the panel is in the tab map', /training:\s*document\.getElementById\('tab-training'\)/.test(appJs));
check('and it is dispatched on open',
  /target === 'training'[\s\S]{0,120}TrainingTab\.loadAndRender\(\)/.test(appJs));

done();
