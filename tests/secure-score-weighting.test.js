'use strict';

/**
 * Secure Score weighting — fixed by service mix, not by the Client Profile.
 *
 * THE DEFECT THIS SUITE EXISTS TO PREVENT COMING BACK
 *
 * The component weights used to ride curves over the DECLARED estate: exposure
 * points over public assets, servers and cloud tenancies, and a headcount curve
 * over the declared user count. Nothing else moved them — telemetry alone left
 * `anyDeclared` false, so the weighting was in practice one hundred per cent
 * typed. Measured on one fixed set of findings, changing only what was typed:
 *
 *   nothing declared    composite 31
 *   publicAssets: 1     composite 40      <- +9 for typing one digit
 *   publicAssets: 50    composite 26
 *   users: 20 -> 2000   composite 29 -> 41
 *
 * A board-reported number moved fourteen points on data entry, and an analyst
 * correcting a typo rewrote the client's security posture.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   the estate cannot move a weight    the regression, asserted directly
 *   every profile sums to exactly 1    coverage is Σ weights × 100; a composite
 *                                      over 100 is a wrong number on a board pack
 *   every component keeps weight       or `coverage` degenerates to 100% for
 *                                      everyone and stops measuring anything
 *   not recorded is not none           null and [] give the same numbers and
 *                                      must stay distinguishable by `basis`
 *   MDR's implications resolve first   and unknown service keys are ignored
 *   the trend uses the same function   live and reconstructed months agreed on
 *                                      nothing before this
 *
 *   node tests/secure-score-weighting.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('secure-score-weighting');

const SS = require(path.join(ROOT, 'lib', 'secure-score'));
const estateLib = require(path.join(ROOT, 'lib', 'estate'));
const servicesLib = require(path.join(ROOT, 'lib', 'services'));

const serverJs = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const scoreJs  = fs.readFileSync(path.join(ROOT, 'lib', 'secure-score.js'), 'utf8');
const estateJs = fs.readFileSync(path.join(ROOT, 'lib', 'estate.js'), 'utf8');
const tabJs    = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-secure-score.js'), 'utf8');
const portalJs = fs.readFileSync(path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}

const KEYS = ['vulnerabilities', 'awareness', 'incidentResponse'];
const MIXES = [
  [],
  ['mdr'],
  ['vuln'],
  ['awareness'],
  ['mdr', 'vuln'],
  ['awareness', 'mdr'],
  ['awareness', 'vuln'],
  ['awareness', 'mdr', 'vuln'],
];

// ── The invariants ─────────────────────────────────────────────────────────

section('every profile sums to exactly 1');

MIXES.forEach((mix) => {
  const w = SS.resolveWeights(mix);
  const sum = w.vulnerabilities + w.awareness + w.incidentResponse;
  check('[' + (mix.join('+') || 'none') + '] sums to exactly 1',
    sum === 1, String(sum));
});

check('and so does the not-recorded profile',
  (() => { const w = SS.resolveWeights(null);
    return w.vulnerabilities + w.awareness + w.incidentResponse === 1; })(), '1');

section('every component keeps a non-zero weight');

/*
 * Load-bearing. `coverage` is the sum of the weights of the components a
 * client's services cover, so if weight collapsed onto only what they buy,
 * every client would cover 100% of their own weighting by construction and the
 * figure would stop meaning anything.
 */
MIXES.concat([null]).forEach((mix) => {
  const w = SS.resolveWeights(mix);
  check('[' + (mix === null ? 'not recorded' : (mix.join('+') || 'none')) + '] no component is zero',
    KEYS.every(k => w[k] > 0), KEYS.map(k => w[k]).join(' / '));
});

// ── The regression this change exists for ──────────────────────────────────

section('THE REGRESSION — the estate cannot move a weight or a score');

const V = { total: 12, critical: 1, high: 3, medium: 5, low: 3 };
const A = { upload: { total_users: 100, total_incomplete: 12 } };
const M = { total_tickets: 40, resolved_count: 37, avg_resolution_hours: 6 };

const scoreFor = (declared, services) => SS.calculateSecureScore(V, A, M, {
  estate: estateLib.resolveEstate(declared, {}),
  services: services === undefined ? ['mdr', 'vuln', 'awareness'] : services,
});

const ESTATES = [
  ['nothing declared',        {}],
  ['publicAssets 1',          { publicAssets: 1, users: 100 }],
  ['publicAssets 50',         { publicAssets: 50, users: 100 }],
  ['users 20',                { users: 20 }],
  ['users 2000',              { users: 2000 }],
  ['a large mixed estate',    { servers: 99, publicAssets: 60, cloudTenancies: 9, users: 2400 }],
];

const baseline = scoreFor(ESTATES[0][1]);
ESTATES.slice(1).forEach(([label, declared]) => {
  const got = scoreFor(declared);
  check(label + ' scores the same as nothing declared',
    got.composite === baseline.composite,
    got.composite + ' vs ' + baseline.composite);
  check(label + ' weights the same as nothing declared',
    JSON.stringify(KEYS.map(k => got.weights[k])) ===
    JSON.stringify(KEYS.map(k => baseline.weights[k])),
    KEYS.map(k => got.weights[k]).join('/'));
});

/*
 * The old basis cliff: declaring one field flipped 'default' -> 'exposure' and
 * moved the composite nine points. There is no estate-derived basis any more.
 */
check('no weighting basis is derived from the estate',
  ['default', 'exposure'].indexOf(baseline.weights.basis) < 0,
  baseline.weights.basis);

// ── Keying ─────────────────────────────────────────────────────────────────

section('keying — implications, unknown keys, ordering');

const wMdr = SS.resolveWeights(['mdr']);
check("MDR's implied services resolve before keying",
  JSON.stringify(SS.resolveWeights(['mdr', 'edr', 'ndr', 'identity'])) === JSON.stringify(wMdr),
  'identical to plain mdr');
check('an unknown service key is ignored, not rejected',
  JSON.stringify(SS.resolveWeights(['mdr', 'banana'])) === JSON.stringify(wMdr), 'ignored');
check('services that weigh nothing key as none',
  SS.resolveWeights(['viso', 'pentest', 'firewall', 'email']).basis === 'none',
  SS.resolveWeights(['viso', 'pentest', 'firewall', 'email']).basis);
check('order does not matter',
  JSON.stringify(SS.resolveWeights(['vuln', 'mdr', 'awareness'])) ===
  JSON.stringify(SS.resolveWeights(['awareness', 'mdr', 'vuln'])), 'canonical');

section('not recorded is not none');

const wNull = SS.resolveWeights(null);
const wNone = SS.resolveWeights([]);
check('they produce the same three numbers',
  KEYS.every(k => wNull[k] === wNone[k]), KEYS.map(k => wNull[k]).join('/'));
check('but they are distinguishable by basis',
  wNull.basis === 'not-recorded' && wNone.basis === 'none',
  wNull.basis + ' vs ' + wNone.basis);
check('and the not-recorded case reports no mix at all',
  wNull.weightedServices === null && Array.isArray(wNone.weightedServices),
  String(wNull.weightedServices));

// ── Coverage stays a real gap ──────────────────────────────────────────────

section('coverage — computed from the two tables, never from literals');

/*
 * Derived from SERVICE_COVERS and the weight table together, so the two cannot
 * drift apart without this failing.
 */
MIXES.filter(m => m.length).forEach((mix) => {
  const w = SS.resolveWeights(mix);
  const cov = Math.round(KEYS.reduce(
    (sum, k) => sum + (servicesLib.coversComponent(mix, k) ? w[k] : 0), 0) * 100);
  const expected = mix.length === 1 ? 50 : mix.length === 2 ? 80 : 100;
  check('[' + mix.join('+') + '] covers ' + expected + '%', cov === expected, String(cov));
});

check('a client who buys nothing covers 0%',
  scoreFor({}, []).coverage === 0, String(scoreFor({}, []).coverage));
check('and an unrecorded mix has NULL coverage, not 0',
  scoreFor({}, null).coverage === null, String(scoreFor({}, null).coverage));

// ── The removed levers ─────────────────────────────────────────────────────

section('the estate-driven levers are gone, not merely unused');

['exposure', 'users', 'serverPatchCoverage', 'incidentPull', 'incidentRate', 'awarenessRelief']
  .forEach((f) => {
    check('weights.' + f + ' is gone', baseline.weights[f] === undefined,
      String(baseline.weights[f]));
  });

['exposurePoints', 'humanShare', 'awarenessRelief', 'AWARENESS_RELIEF',
 'HEADCOUNT_SHARE', 'PATCH_RELIEF'].forEach((n) => {
  check('estate no longer exports ' + n, estateLib[n] === undefined, String(estateLib[n]));
});

check('no live reference to awarenessRelief survives',
  !/awarenessRelief/.test(codeOnly(estateJs)) &&
  !/awarenessRelief/.test(codeOnly(scoreJs)) &&
  !/awarenessRelief/.test(codeOnly(tabJs)), 'clean');
check('nor to incidentPull as a weighting lever',
  !/incidentPull/.test(codeOnly(scoreJs)), 'clean');

/*
 * patchCoverage is NOT dead — it is still shown on the Client Profile. It only
 * stopped explaining a weight. Deleting it with the weighting would have taken
 * a working control with it.
 */
check('patchCoverage survives — it was never the dead one',
  typeof estateLib.patchCoverage === 'function', 'kept');

// ── History uses the same function ─────────────────────────────────────────

section('the trend and the headline agree');

check('the hardcoded 40/35/25 in the history route is gone',
  !/\{\s*v:[^}]*w:\s*0\.40\s*\}/.test(codeOnly(serverJs)), 'removed');
check('the history route resolves weights from the service mix',
  /historyWeights\s*=\s*secureScore\.resolveWeights\(/.test(codeOnly(serverJs)), 'wired');
check('and reconstructs months with them',
  /w:\s*historyWeights\.vulnerabilities/.test(codeOnly(serverJs)), 'wired');
check('the response states the mix is undated',
  /mixAsOf/.test(codeOnly(serverJs)) && /restatedNote/.test(codeOnly(serverJs)),
  'caveat returned as data');

// ── Still off-limits to the client portal ──────────────────────────────────

section('weights never reach a customer payload');

check('the portal does not reference weights',
  !/weight/i.test(codeOnly(portalJs)), 'clean');
check('nor the profile key or mix',
  !/profileKey/.test(portalJs) && !/weightedServices/.test(portalJs), 'clean');

// ── The awareness programme still gets said, it just moves nothing ─────────

section('an unevidenced client-run programme is reported, not weighted');

const internal = SS.calculateSecureScore(V, { upload: null }, M, {
  estate: estateLib.resolveEstate({ awarenessProgram: 'internal' }, {}),
  services: ['mdr', 'vuln', 'awareness'],
});
const noProg = SS.calculateSecureScore(V, { upload: null }, M, {
  estate: estateLib.resolveEstate({}, {}),
  services: ['mdr', 'vuln', 'awareness'],
});

check('it no longer changes the weights',
  internal.weights.awareness === noProg.weights.awareness,
  internal.weights.awareness + ' vs ' + noProg.weights.awareness);
check('nor the composite',
  internal.composite === noProg.composite,
  internal.composite + ' vs ' + noProg.composite);

const reason = (internal.unmeasured.find(u => u.key === 'awareness') || {}).reason;
check('but it IS still reported, as a measurement state',
  reason === 'client-run programme, unverified', String(reason));
check('and a client with no programme gets no such claim',
  (noProg.unmeasured.find(u => u.key === 'awareness') || {}).reason === undefined,
  'no claim');

done();
