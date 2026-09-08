'use strict';

/**
 * PowerPoint recommendation layout — nothing may overlap anything.
 *
 * THE DEFECT THIS EXISTS FOR
 *
 * Every recommendation on the Executive Decisions slide printed its impact
 * label ("Moderate", "Commercial") on top of its own last line of text, its
 * accent bar stopped short of its content, and each item began before the
 * previous one had finished.
 *
 * The cause was three disagreements between measure() and drawRecs() about how
 * tall a recommendation is:
 *
 *   measure()   wrapped at TYPE.body (14pt) across BODY_W - 1.7
 *   drawRecs()  wrapped at a hardcoded 10pt across BODY_W - 1.7, at a
 *               hardcoded 0.20in per line — then DREW at TYPE.tableBody (11pt)
 *               into a box of BODY_W - 1.9
 *
 * The point size used to estimate the wrap, the width used to estimate it, and
 * the line height were each wrong, and each wrong in the direction that makes
 * the box too small. It stayed invisible while recommendations were one line
 * long and appeared the moment one ran to four.
 *
 * lib/report-pptx.js had NO test coverage of any kind, which is why a geometry
 * bug reached a client-facing deck. These checks are arithmetic on the shared
 * helpers rather than a rendered file: they run in milliseconds and they fail
 * on the thing that actually went wrong.
 *
 *   node tests/report-pptx-layout.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('report-pptx-layout');

const X = require(path.join(ROOT, 'lib', 'report-pptx'));
const src = fs.readFileSync(path.join(ROOT, 'lib', 'report-pptx.js'), 'utf8');

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
const code = codeOnly(src);

// The entry that exposed the bug: it names every service in the catalogue, so
// it is the longest recommendation the report can produce.
const LONG = {
  area: 'Services not currently consumed',
  impact: 'Commercial',
  chip: 'Option',
  text: 'The following are not part of the current engagement: Vulnerability ' +
        'Management; Security Awareness Training; Managed Email Security; ' +
        'Penetration Testing; Firewall Configuration Review; vISO. Each is ' +
        'available under the existing agreement and would extend coverage ' +
        'beyond what is reported here. This is a commercial option for ' +
        'consideration, not a finding against the controls in place.',
};

const SHORT = {
  area: 'Investment to reach target',
  impact: 'Moderate',
  chip: 'Decision',
  text: 'Managed detection and response is below the agreed target score.',
};

// ── The stacking invariant ─────────────────────────────────────────────────

section('an item is tall enough for everything drawn inside it');

/*
 * THE INVARIANT. drawRecs() stacks area, then text, then impact, and draws an
 * accent bar of recItemH(). If the parts total more than the whole, the impact
 * label lands on the text and the bar stops short — which is precisely what
 * shipped.
 */
function partsOf(it) {
  return (it.area ? X.REC_AREA_H : 0) +
         X.recTextH(it, X.BODY_W) +
         (it.impact ? X.REC_IMPACT_H : 0);
}

[['the long catalogue entry', LONG], ['a one-line decision', SHORT]].forEach(function (pair) {
  const label = pair[0], it = pair[1];
  check(label + ' fits inside its own height',
    X.recItemH(it, X.BODY_W) >= partsOf(it),
    'item ' + X.recItemH(it, X.BODY_W).toFixed(3) +
    ' >= parts ' + partsOf(it).toFixed(3));
});

check('and the impact label starts below the last line of text',
  (LONG.area ? X.REC_AREA_H : 0) + X.recTextH(LONG, X.BODY_W) + X.REC_IMPACT_H
    <= X.recItemH(LONG, X.BODY_W),
  'impact bottom ' +
  ((LONG.area ? X.REC_AREA_H : 0) + X.recTextH(LONG, X.BODY_W) + X.REC_IMPACT_H).toFixed(3) +
  ' within ' + X.recItemH(LONG, X.BODY_W).toFixed(3));

section('a longer recommendation is a taller one');

/*
 * Guards the specific arithmetic that failed: the old draw path used a fixed
 * 0.20in per line at a point size it never drew at, so text height barely
 * tracked text length.
 */
check('the catalogue entry is taller than the one-liner',
  X.recItemH(LONG, X.BODY_W) > X.recItemH(SHORT, X.BODY_W),
  X.recItemH(SHORT, X.BODY_W).toFixed(3) + ' -> ' + X.recItemH(LONG, X.BODY_W).toFixed(3));

check('and it wraps to more than one line',
  X.recTextH(LONG, X.BODY_W) > X.recTextH(SHORT, X.BODY_W) * 2,
  X.recTextH(LONG, X.BODY_W).toFixed(3));

// Text length must move the height monotonically — no step where adding words
// makes the box the same size or smaller.
let prevH = 0, monotonic = true;
for (let n = 40; n <= 600; n += 40) {
  const h = X.recTextH({ text: 'x'.repeat(n) }, X.BODY_W);
  if (h < prevH) monotonic = false;
  prevH = h;
}
check('height never shrinks as text grows', monotonic, 'monotonic to 600 chars');

// ── Nothing collides with the chip ─────────────────────────────────────────

section('the text column never reaches the chip');

const textRight = X.MARGIN + X.REC_INSET + X.recTextW(X.BODY_W);
const chipLeft  = X.MARGIN + X.BODY_W - X.REC_CHIP_W;

check('the body text stops clear of the chip column',
  textRight <= chipLeft,
  'text ends ' + textRight.toFixed(3) + ', chip starts ' + chipLeft.toFixed(3));
check('with a real gap, not a hairline',
  chipLeft - textRight >= 0.2,
  (chipLeft - textRight).toFixed(3) + ' in');

// ── Measure and draw are the same function ─────────────────────────────────

section('measurement and drawing cannot disagree again');

/*
 * The root cause was two independent height calculations. A source check is
 * the right tool here: there is no seam that can observe drawRecs() returning
 * a height, and the property to protect is that it does not compute one.
 */
check('drawRecs asks the shared helper for its height',
  /function drawRecs[\s\S]{0,700}recItemH\(it, BODY_W\)/.test(code), 'shared');
check('and for its text height',
  /function drawRecs[\s\S]{0,700}recTextH\(it, BODY_W\)/.test(code), 'shared');
check('measure uses the same helper',
  /case 'recs':\s*return b\.items\.reduce\(\(h, i\) => h \+ recItemH\(i, W\)/.test(code),
  'shared');

// The literals that caused it, gone rather than merely unused.
check('the hardcoded 0.20in line height is gone',
  !/lineCount\(it\.text, BODY_W - 1\.7, 10\) \* 0\.20/.test(code), 'removed');
check('and drawRecs no longer wraps at a size it does not draw at',
  !/lineCount\([^)]*,\s*10\)/.test(
    (code.match(/function drawRecs[\s\S]*?\n\}/) || [''])[0]), 'removed');

/*
 * measure() drives pagination. If it under-reports, a slide silently clips at
 * .pg-body overflow:hidden — the trap the file's own header comment describes.
 */
const measured = X.measure({ type: 'recs', items: [SHORT, LONG] }, X.BODY_W);
const drawn = X.recItemH(SHORT, X.BODY_W) + X.REC_GAP +
              X.recItemH(LONG, X.BODY_W) + X.REC_GAP;
check('measure reserves at least what drawing consumes',
  measured >= drawn - 1e-9,
  'measured ' + measured.toFixed(3) + ', drawn ' + drawn.toFixed(3));

// ── The estimate errs long, on purpose ─────────────────────────────────────

section('the wrap estimate errs long');

/*
 * charsPerLine() assumes ~0.51em per character; Montserrat averages nearer
 * 0.57em, so the generic estimate returns about a tenth too many characters
 * per line. On the four-line entry that lost a whole line. Over-estimating
 * costs white space; under-estimating overlaps text.
 */
check('a safety factor is applied and documented',
  /REC_WRAP_SAFETY\s*=\s*1\.1/.test(code), 'present');
check('it makes the estimate longer, never shorter',
  X.recTextH({ text: 'x'.repeat(500) }, X.BODY_W) >
  X.lineCount('x'.repeat(500), X.recTextW(X.BODY_W), X.REC_TEXT_PT) * 0.20,
  'conservative');

// A recommendation with no text at all must still occupy a sane box rather
// than collapsing to nothing under the accent bar.
check('an empty recommendation still has height',
  X.recItemH({ area: 'A', text: '', impact: '' }, X.BODY_W) > X.REC_AREA_H,
  X.recItemH({ area: 'A', text: '', impact: '' }, X.BODY_W).toFixed(3));

done();
