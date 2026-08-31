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

done();
