'use strict';

/**
 * The Publish control on the Reports tab.
 *
 * WHY THIS SUITE EXISTS
 *
 * The whole publish pipeline — route, handler, archive, portal read — was built
 * and tested, and no one could use it, because the button ships `hidden` in the
 * markup and the writable branch only ever attached a click handler. `hidden`
 * was cleared for nobody, so the feature was complete and invisible. Every
 * server-side test stayed green throughout.
 *
 * These are static assertions over the source: tab-reports.js is a 1000-line
 * IIFE bound to the dashboard's globals, and standing it up headlessly costs
 * more than it returns here. They are weaker than behavioural tests and catch
 * exactly the failure that happened — a control wired but never revealed.
 *
 *   node tests/report-publish-ui.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('report-publish-ui');

const html = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const js = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-reports.js'), 'utf8');

section('the control exists in the markup and starts hidden');

const btnTag = (html.match(/<button[^>]*id="rpt-publish-btn"[^>]*>/) || [])[0] || '';
check('the Publish button is in the Reports toolbar', btnTag !== '');
// Hidden by default is deliberate: a reader must never see a control they
// cannot use flash on screen before the role check resolves.
check('it ships hidden', /\bhidden\b/.test(btnTag));
check('it is a button, not a link that would navigate away',
  /type="button"/.test(btnTag));

const wrapTag = (html.match(/<details[^>]*id="rpt-published-wrap"[^>]*>/) || [])[0] || '';
check('the published-archive panel is in the markup', wrapTag !== '');

section('the writable branch REVEALS it, not merely wires it');

// The bug: `if (canPersist()) pub.onclick = …` with no matching unhide. Assert
// on the visibility assignment specifically — a handler alone is what shipped.
const revealed = /pub\.hidden\s*=\s*!canPersist\(\)/.test(js);
check('the button\'s hidden state is driven by canPersist()', revealed);
check('and the click handler is still attached',
  /pub\.onclick\s*=\s*publishReport/.test(js));

// Guard against the regression re-appearing in its original shape: a branch
// that hides for readonly and never unhides for anyone else.
check('the button is never left hidden with no path back',
  !/else\s+pub\.hidden\s*=\s*true;/.test(js));

check('the archive panel is hidden from users who cannot publish',
  /pubWrap\.hidden\s*=\s*!canPersist\(\)/.test(js));

section('the archive follows the selected client');

// Superadmins switch tenants from the same page. A stale table is not just
// misleading: its Withdraw buttons carry the previous client's publication ids.
const onChange = (js.match(/clientEl\.onchange\s*=\s*function[\s\S]*?\n      \};/) || [])[0] || '';
check('the client selector has a change handler', onChange !== '');
check('changing client re-renders the publications table',
  /renderPublications\(\)/.test(onChange));
check('and it is gated on write, matching the initial render',
  /canPersist\(\)\)\s*renderPublications\(\)/.test(onChange));

section('publish and download cannot diverge');

// The archived artefact must be the deck that was previewed and approved.
// Re-fetching at publish time would let them differ with nobody the wiser.
const publishFn = (js.match(/async function publishReport\(\)[\s\S]*?\n  \}\n/) || [])[0] || '';
check('publishReport() is defined', publishFn !== '');
check('it builds the deck through the shared assembleDeck()',
  /await assembleDeck\(\)/.test(publishFn));
check('it refuses to publish an empty deck',
  /!model\.rendered\.length/.test(publishFn));
check('it re-enables the button on every exit path',
  /finally\s*\{[\s\S]*btn\.disabled\s*=\s*false/.test(publishFn));
check('it posts to the publish route',
  /fetch\('api\/reports\/publish'/.test(publishFn));
check('and refreshes the archive after a successful publish',
  publishFn.indexOf('renderPublications()') > publishFn.indexOf('notice(\'Published'));

section('the archived HTML is a real deck, not stringified records');

/*
 * WHAT WENT WRONG
 *
 * renderDeck(slidesHtml, ctx) takes an array of rendered slide HTML strings.
 * assembleDeck() returns {label, bodies} RECORDS. The first publish passed the
 * records straight through, so slidesHtml[0] stringified to "[object Object]",
 * the paginator found no .slide elements in what followed, and the client was
 * served a blank white page with "[object Object]" in the corner. Nothing threw
 * — the two shapes are both arrays, and string concatenation accepts anything.
 *
 * This part is behavioural: report-deck.js is loaded and called for real, so
 * the sentinel the publish guard looks for is the one renderDeck actually
 * produces rather than a string someone assumed.
 */
const vm = require('vm');
const sandbox = { console };
sandbox.window = sandbox;
vm.createContext(sandbox);
for (const f of ['report-shell.js', 'report-deck.js']) {
  vm.runInContext(fs.readFileSync(path.join(ROOT, 'public', 'js', f), 'utf8'), sandbox);
}
const D = sandbox.window.ReportDeck;
const ctx = { clientName: 'Acme', periodLabel: 'August 2026', period: '2026-08',
              author: 'A. N. Other', dateStr: '2026/08/31' };

check('report-deck.js exposes renderDeck', typeof D.renderDeck === 'function');

const fromRecords = D.renderDeck([{ label: 'Overview', bodies: ['<p>hi</p>'] }], ctx);
check('passing assembleDeck records produces the blank-deck sentinel',
  fromRecords.indexOf('[object Object]') > -1);

const fromHtml = D.renderDeck(
  ['<section class="slide">cover</section>', '<section class="slide">two</section>'], ctx);
check('passing slide HTML produces a clean document',
  fromHtml.indexOf('[object Object]') === -1);
check('and a complete one', fromHtml.indexOf('</head>') > -1);

section('both deck paths build their slides the same way');

// The extracted helper is the guarantee. While Generate built the slide array
// inline, Publish had its own idea of the shape and nobody could see the two
// had drifted until a client opened the report.
check('buildSlides() exists', /function buildSlides\(model\)/.test(js));
check('it renders a cover slide first', /buildSlides[\s\S]{0,300}D\.coverSlide/.test(js));
check('Generate renders through it',
  /deckWindow\.write\(D\.renderDeck\(buildSlides\(model\)/.test(js));
check('Publish renders through it',
  /D\.renderDeck\(buildSlides\(model\), model\.full\)/.test(publishFn));
check('Publish no longer passes the record array to renderDeck',
  !/renderDeck\(model\.slides \|\| model\.rendered/.test(js));

check('a deck that failed to render is not published',
  /\[object Object\][\s\S]{0,200}return;/.test(publishFn));
check('nor an incomplete document',
  /indexOf\('<\/head>'\) === -1[\s\S]{0,200}return;/.test(publishFn));
check('and the failure is reported rather than swallowed',
  /Publish aborted/.test(publishFn) && !/carry on/.test(publishFn));

section('every escape call resolves');

// `esc` is not defined in this module — it is S.esc. Two bare calls shipped in
// renderPublications(), so the archive panel died with "esc is not defined" for
// every user, on the happy path as well as the error path.
check('tab-reports.js does not define its own esc',
  !/function esc\(|var esc\s*=/.test(js));
check('and never calls a bare esc()', !/(^|[^.A-Za-z0-9_])esc\(/m.test(js));

done();
