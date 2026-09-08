'use strict';

/**
 * FortiGate configuration audit.
 *
 * THE FOUR PROPERTIES THIS SUITE EXISTS TO PROTECT
 *
 *   the config is never stored        a compromise here must not hand somebody
 *                                     a client's firewall
 *   no finding carries a secret       evidence is identifiers and counts
 *   masking never causes a failure    the responsible way to send a config must
 *                                     not be punished for it
 *   not-assessable is not a fail      and leaves the denominator
 *
 * The libraries are exercised behaviourally against a real fixture. The routes
 * need Postgres, which is unreachable here, so their wiring is asserted over the
 * source — weaker, and said so. It catches deletion and rewiring, which is the
 * failure mode that matters for "does this write the config to a table".
 *
 *   node tests/fortigate.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('fortigate');

const parser = require(path.join(ROOT, 'lib', 'fortigate-parser'));
const checks = require(path.join(ROOT, 'lib', 'fortigate-checks'));
const score  = require(path.join(ROOT, 'lib', 'fortigate-score'));
const grc    = require(path.join(ROOT, 'lib', 'grc-score'));
const P      = require(path.join(ROOT, 'lib', 'pages'));
const svcLib = require(path.join(ROOT, 'lib', 'services'));

const serverJs  = fs.readFileSync(path.join(ROOT, 'server.js'), 'utf8');
const portalJs  = fs.readFileSync(path.join(ROOT, 'lib', 'portal-routes.js'), 'utf8');
const tabJs     = fs.readFileSync(path.join(ROOT, 'public', 'js', 'tab-firewall.js'), 'utf8');
const indexHtml = fs.readFileSync(path.join(ROOT, 'public', 'index.html'), 'utf8');
const migration = fs.readFileSync(path.join(ROOT, 'db', 'migrate-firewall-audit.sql'), 'utf8');
const RAW = fs.readFileSync(path.join(ROOT, 'tests', 'fixtures', 'fortigate-unmasked.yaml'), 'utf8');

function codeOnly(js) {
  return js.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
}
function sqlOnly(sql) { return sql.replace(/(^|\n)\s*--[^\n]*/g, '$1'); }

const srvCode = codeOnly(serverJs);
const tabCode = codeOnly(tabJs);

/**
 * The fake secrets planted in the fixture. Every one must be unreachable from
 * anything this feature produces.
 */
const CANARIES = [
  'CANARY_ADMIN_HASH_1a2b3c4d5e6f',
  'CANARY_ADMIN_HASH_9z8y7x6w5v',
  'CANARY_SNMP_COMMUNITY',
  'CANARY_IPSEC_PSK_correcthorse',
];

const model = parser.parseConfig(RAW, { fileName: 'fortigate-unmasked.yaml' });
const results = checks.runChecks(model);
const scored = score.scoreResults(results);

/* ══ Parsing ════════════════════════════════════════════════════════════════ */

section('the backup is read, whatever shape the tables arrived in');

check('the device is identified',
  model.device.model === 'FGT60F' && model.device.firmware === '7.6.0' &&
  model.device.hostname === 'FG-EDGE-01', JSON.stringify(model.device));
check('policies are read from a map keyed by policy id',
  model.policies.length === 3, model.policies.length);
check('reference fields flatten to names',
  JSON.stringify(model.policies[0].srcaddr) === '["all"]' &&
  JSON.stringify(model.policies[0].service) === '["ALL"]',
  JSON.stringify(model.policies[0].srcaddr));
check('administrators are read from a map keyed by name',
  model.system.admins.map(a => a._key).sort().join(',') === 'admin,kmoloi');

// A table is a sequence in some exports and a map in others. Both, or the
// parser reports an empty ruleset on half the estate and scores it clean.
const asList = parser.parseConfig(
  'firewall:\n  policy:\n    - policyid: 7\n      name: seq-form\n      action: accept\n');
check('a policy table given as a sequence reads too',
  asList.policies.length === 1 && asList.policies[0].id === '7',
  JSON.stringify(asList.policies.map(p => p.id)));

// FortiOS omits `status` when a policy is enabled.
check('a policy with no status is treated as enabled',
  asList.policies[0].status === 'enable');

section('what the parser did not read is named, not dropped');

check('an unrecognised section appears in unread',
  model.unread.indexOf('router') >= 0, JSON.stringify(model.unread));
check('and recognised ones do not',
  model.unread.indexOf('firewall') < 0 && model.unread.indexOf('system') < 0,
  JSON.stringify(model.unread));
check('the count travels with it', model.counts.unread === model.unread.length);

section('a bad file is a 400, never a 500');

/*
 * `want` is not optional decoration. Asserting only the error TYPE let a
 * mutation delete the empty-file guard and still pass: YAML.parse('') returns
 * null, the mapping check throws the same class, and the user is told their
 * file "is not a FortiGate configuration" when the truth is that it is empty.
 * Same status code, materially worse answer.
 */
const bad = (text, label, want) => {
  let threw = null;
  try { parser.parseConfig(text); } catch (e) { threw = e; }
  const ok = threw instanceof parser.FortigateParseError &&
             (!want || want.test(threw.message));
  check(label, ok,
    threw ? threw.constructor.name + ': ' + threw.message.slice(0, 60) : 'did not throw');
};
bad('', 'an empty file is refused, and says so', /empty/i);
bad('   \n  ', 'whitespace only is refused as empty', /empty/i);
bad('- one\n- two\n', 'a top-level list is refused', /not a FortiGate/i);
bad('just a string', 'a scalar is refused', /not a FortiGate/i);
bad('key: [unclosed\n', 'malformed YAML is refused', /could not read/i);
// The reason this uses `yaml` over `js-yaml`: a few nested anchors expand to
// gigabytes, which on an upload endpoint is a denial of service.
bad('a: &a [1,1]\nb: &b [*a,*a]\nc: &c [*b,*b]\nd: &d [*c,*c]\ne: &e [*d,*d]\n' +
    'f: &f [*e,*e]\ng: &g [*f,*f]\nh: [*g,*g]\n', 'an alias bomb is refused');

check('JSON is accepted — the same tree, different notation',
  parser.parseConfig('{"system":{"global":{"hostname":"J1"}}}').device.hostname === 'J1');

/* ══ FortiOS writes YAML it cannot read back ════════════════════════════════ */

/*
 * Both constructs below came from a REAL export, not from imagination:
 *
 *   - *.bat:              a file-extension pattern. `*` opens a YAML alias.
 *   - FAZ : 100.71.0.161: a name containing " : ", which reads as a mapping
 *                         nested inside a compact mapping.
 *
 * A strict parser is right to refuse both, and the client cannot fix their
 * firewall's exporter. So they are repaired — narrowly, by quoting an already
 * ambiguous KEY — and the repair is reported rather than hidden.
 */
section('the malformed lines a real FortiGate emits');

/*
 * Both fixtures carry one recognisable section alongside the malformed lines.
 *
 * Not decoration. parseConfig now REFUSES a file in which not one section was
 * recognised, because returning a model from such a file is exactly what
 * produced 37 findings against a config nobody had read. What these fixtures
 * exercise — repairing the malformed lines FortiOS emits — is unchanged; they
 * simply have to be configs now, rather than two lines of YAML that happen to
 * be broken.
 */
const stub = 'firewall_policy:\n  - 1:\n      name: stub\n      action: accept\n';
const aliasKey = stub + 'antivirus:\n  entries:\n    - *.bat:\n    - *.exe:\n';
const colonKey = stub + 'log:\n  fortianalyzer:\n    - FAZ : 100.71.0.161:\n';

const fixedAlias = parser.parseConfig(aliasKey);
check('a file-extension pattern key is read',
  fixedAlias.repaired.length === 2, JSON.stringify(fixedAlias.repaired));
check('and is reported as a repair, not hidden',
  fixedAlias.repaired.every(r => r.kind === 'alias-like-key' && r.line > 0),
  JSON.stringify(fixedAlias.repaired));

const fixedColon = parser.parseConfig(colonKey);
check('a name containing " : " is read',
  fixedColon.repaired.length === 1, JSON.stringify(fixedColon.repaired));
// Derived from the stub rather than hardcoded: the property is that the repair
// reports the line it happened on, not that that line is number 3.
const stubLines = stub.split('\n').length - 1;
check('and reported with its line number',
  fixedColon.repaired[0].kind === 'colon-in-key' &&
  fixedColon.repaired[0].line === stubLines + 3,
  JSON.stringify(fixedColon.repaired) + ' expected line ' + (stubLines + 3));

// A clean file must be touched by none of this.
check('a well-formed config is never "repaired"',
  parser.parseConfig(RAW).repaired.length === 0);

/*
 * THE REPAIR MUST NOT BECOME A WAY TO ACCEPT ANYTHING.
 *
 * It only quotes ambiguous keys; a genuinely broken file still has to fail, or
 * the audit is of a structure nobody read.
 */
bad('a: [1,\n', 'unbalanced flow syntax still fails', /could not read/i);
bad('  bad:\n indent: wrong\n', 'bad indentation still fails', /could not read/i);
check('repairing a file with no repairable lines is not attempted',
  (() => { try { parser.parseConfig('a: [1,\n'); return false; } catch (e) {
    return /Could not read the file as YAML or JSON:/.test(e.message); } })());

/*
 * The case that needs its own fixture: a file with a repairable line that is
 * ALSO broken some other way. The repair runs, the retry still fails, and the
 * file must be refused — with a message saying repairs were attempted, so
 * nobody hunts for a problem on the line that was already fixed.
 */
const repairableButBroken = 'a:\n  - *.bat:\n b: [1,\n';
let brokenErr = null;
try { parser.parseConfig(repairableButBroken); } catch (e) { brokenErr = e; }
check('a repairable line does not rescue an otherwise broken file',
  brokenErr instanceof parser.FortigateParseError,
  brokenErr ? brokenErr.message.slice(0, 60) : 'PARSED — should not have');
check('and the message says repairs were tried',
  !!brokenErr && /even after repairing/i.test(brokenErr.message),
  brokenErr && brokenErr.message.slice(0, 90));

/*
 * ── THE LOG-LEAK PROPERTY ─────────────────────────────────────────────────
 *
 * The YAML library reports oddities via process.emitWarning, and the warning
 * text QUOTES THE OFFENDING SOURCE LINE. A real export produced hundreds. On a
 * line carrying a pre-shared key that writes the secret to this server's
 * stderr — breaking the one promise this feature makes.
 *
 * Driven by capturing warnings for real rather than grepping for an option
 * name, because the option that silences them was ALSO found to suppress real
 * parse errors, and a source-level check cannot tell those apart.
 */
section('parsing never writes the configuration to a log');

const warnings = [];
const onWarn = (w) => warnings.push(String(w && w.message || w));
process.on('warning', onWarn);

// A config whose ambiguous line also carries a canary value.
parser.parseConfig('vpn:\n  entries:\n    - *.bat:\n' +
                   '  ipsec:\n    phase1-interface:\n      t1:\n' +
                   '        name: t1\n        psksecret: CANARY_IPSEC_PSK_correcthorse\n');

// emitWarning is asynchronous, so let the queue drain before asserting.
const warnCheck = new Promise((resolve) => setImmediate(() => {
  process.removeListener('warning', onWarn);
  const text = warnings.join('\n');
  check('no warning was emitted while parsing a malformed config',
    warnings.length === 0, warnings.length + ' warning(s)');
  check('and nothing resembling a config line reached one',
    text.indexOf('*.bat') < 0 && CANARIES.every(c => text.indexOf(c) < 0),
    text.slice(0, 80));
  resolve();
}));

/*
 * The option that silences the warnings ALSO makes YAML.parse swallow real
 * errors and return a guessed structure — verified against
 * "Nested mappings are not allowed in compact mappings", which parses
 * "successfully" with it set. So the parser must not use YAML.parse at all.
 */
const parserSrc = fs.readFileSync(path.join(ROOT, 'lib', 'fortigate-parser.js'), 'utf8');
check('the parser reads errors itself rather than trusting parse() to throw',
  /YAML\.parseDocument\(/.test(codeOnly(parserSrc)) &&
  !/YAML\.parse\(/.test(codeOnly(parserSrc)));
check('and an error surfacing only at conversion time is still caught',
  /try \{[\s\S]{0,120}doc\.toJS\(/.test(parserSrc));
check('warnings are counted, never carried — their text quotes the source',
  /warnings: \(doc\.warnings \|\| \[\]\)\.length/.test(parserSrc));

// A repaired parse is a weaker claim than a clean one, so the analyst is told.
// Applying the repair and saying nothing would make the two indistinguishable.
check('the route surfaces the repair to the analyst',
  /parseNote: model\.repaired && model\.repaired\.length/.test(srvCode));
check('and the tab renders it',
  /parseNotice\(\)/.test(tabCode) && /_parseNote/.test(tabCode));
// The unmasked-credentials warning outranks a quoting quirk.
check('but the mask warning still takes precedence',
  /j\.maskWarning \?[\s\S]{0,120}j\.parseNote/.test(tabJs));

/* ══ Secrets ════════════════════════════════════════════════════════════════ */

section('nothing this feature produces contains a secret');

/** Every string anywhere in a structure, however deep. */
function allStrings(node, out) {
  out = out || [];
  if (typeof node === 'string') { out.push(node); return out; }
  if (Array.isArray(node)) { node.forEach(n => allStrings(n, out)); return out; }
  if (node && typeof node === 'object') {
    Object.keys(node).forEach((k) => { out.push(k); allStrings(node[k], out); });
  }
  return out;
}

// The fixture really does contain them, or every check below is vacuous.
check('the fixture genuinely contains the canaries',
  CANARIES.every(c => RAW.indexOf(c) >= 0), CANARIES.length + ' planted');

// A recursive walk over EVERY finding, not a spot check on the first one.
const findingText = allStrings(results).join(' ');
CANARIES.forEach((c) => {
  check('no finding contains ' + c.slice(0, 22),
    findingText.indexOf(c) < 0);
});

const scoreText = allStrings(scored).join(' ');
check('nor does the score payload',
  CANARIES.every(c => scoreText.indexOf(c) < 0));

// redact() is the net under the rule, tested as a net.
const red = parser.redact({
  psksecret: 'CANARY_IPSEC_PSK_correcthorse',
  nested: { password: 'CANARY_ADMIN_HASH_1a2b3c4d5e6f', name: 'keep-me' },
  list: [{ 'pre-shared-key': 'CANARY_IPSEC_PSK_correcthorse' }],
});
const redText = allStrings(red).join(' ');
check('redact strips secrets at any depth',
  CANARIES.every(c => redText.indexOf(c) < 0), JSON.stringify(red));
check('and leaves everything else alone', redText.indexOf('keep-me') >= 0);
check('secret field names are recognised',
  parser.isSecretField('psksecret') && parser.isSecretField('PASSWORD') &&
  parser.isSecretField('auth-pwd') && !parser.isSecretField('hostname'));

// The one check that reads a credential-bearing field names a COUNT, not the
// value — SNMP community strings are the credential.
const snmp = results.filter(r => r.id === 'snmp-v1v2c')[0];
check('the SNMP finding reports a count, never the community string',
  snmp.detail.indexOf('CANARY') < 0 &&
  JSON.stringify(snmp.evidence).indexOf('CANARY') < 0,
  snmp.detail);

section('the configuration is never stored');

// The property whose violation is silent, so it is asserted three ways.
check('the migration declares no column for a config',
  !/config\s+(text|bytea|jsonb)/i.test(sqlOnly(migration)) &&
  !/raw_config|config_text|config_body|config_data/i.test(sqlOnly(migration)));
check('nor for anything file-shaped',
  !/file_data|file_bytes|contents\s+text/i.test(sqlOnly(migration)));

// The route inserts named columns; none of them is the config.
const insertAudit = (srvCode.match(/INSERT INTO firewall_audits[\s\S]*?RETURNING \*/) || [''])[0];
check('the audit INSERT was found', insertAudit.length > 100, insertAudit.length);
check('and stores no configuration',
  !/config_version.*raw|body|buffer|yaml/i.test(insertAudit) &&
  insertAudit.indexOf('req.file') < 0, insertAudit.slice(0, 60));
check('the parsed model is never inserted',
  !/INSERT INTO firewall_[a-z_]+[\s\S]{0,600}JSON\.stringify\(model\)/.test(srvCode));

/*
 * The whole POST handler, anchored on the NEXT route rather than on the first
 * `\n});`. The non-greedy version stopped at the first inner closing brace and
 * extracted about a third of the handler — so a mutation that added the parsed
 * config to the response landed outside the slice and escaped.
 */
const postBlock = (srvCode.match(
  /app\.post\('\/api\/firewall\/audits'[\s\S]*?app\.get\('\/api\/firewall\/audits'/) || [''])[0];
check('the POST handler was extracted whole',
  postBlock.length > 2000 && postBlock.indexOf('res.json') > 0, postBlock.length);
check('the parsed model is not returned to the browser',
  !/res\.json\(\{\s*\n\s*model[,\s}]/.test(postBlock) &&
  !/\bmodel,\s*$/m.test(postBlock.match(/res\.json\(\{[\s\S]*$/) || ''));

/*
 * The net under the rule that checks never put a secret in evidence: redact
 * has to actually run on the way into the database.
 *
 * Anchored on the INSERT's own parameter array, ending at its `]);`. A looser
 * `INSERT ...[\s\S]{0,900}redact` matched the redact call in the RESPONSE
 * shaping further down, so deleting it from the INSERT left the check green —
 * the same wrong-occurrence failure as matching the second of two identical
 * call sites.
 */
const findingsInsert = (srvCode.match(
  /INSERT INTO firewall_findings[\s\S]*?\]\);/) || [''])[0];
check('the findings INSERT was extracted',
  findingsInsert.length > 200 && findingsInsert.indexOf('audit.id') > 0,
  findingsInsert.length);
check('evidence is redacted on the way into the database',
  /fortigateParser\.redact\(r\.evidence\)/.test(findingsInsert),
  findingsInsert.slice(-90).replace(/\s+/g, ' '));
check('and again on the way back to the browser',
  /evidence: fortigateParser\.redact\(r\.evidence\)/.test(srvCode));

/* ══ Masking ════════════════════════════════════════════════════════════════ */

section('masking is detected, and never punished');

/** The same config as the device would write it with Password mask ticked. */
const MASKED = RAW
  .replace(/^(\s*)(password|psksecret):.*$/gmi, '$1$2: ')
  .replace(/^(\s*)name: CANARY_SNMP_COMMUNITY\s*$/gm, '$1name: ');

const maskedModel = parser.parseConfig(MASKED);
const maskedResults = checks.runChecks(maskedModel);
const maskedScored = score.scoreResults(maskedResults);

check('an unmasked config is detected as unmasked', model.masked === false,
  JSON.stringify(model.maskDetail));
check('a masked one as masked', maskedModel.masked === true,
  JSON.stringify(maskedModel.maskDetail));
// Tri-state: a config with no secret fields at all cannot be judged either way.
check('a config with no secret fields reports null, not false',
  parser.parseConfig('system:\n  global:\n    hostname: X\n').masked === null);

/*
 * THE GUARANTEE. Masking must never turn a pass into a fail or introduce one.
 *
 * NOT that the score is identical: dropping a check from the denominator moves
 * the percentage in whichever direction that check was pointing, so losing a
 * PASS from a mostly-failing config lowers the score slightly. That is a
 * different subset being scored, and `coverage` says so. Asserting equality
 * here would be asserting something arithmetically false.
 */
const flipped = [];
results.forEach((r, i) => {
  const m = maskedResults[i];
  if (r.id !== m.id) { flipped.push('order changed at ' + i); return; }
  if (r.status === m.status) return;
  if (m.status !== 'not-assessable') flipped.push(r.id + ': ' + r.status + ' -> ' + m.status);
});
check('masking never changes a result to anything but not-assessable',
  flipped.length === 0, flipped.join('; '));
check('and never introduces a failure',
  maskedScored.failed <= scored.failed,
  maskedScored.failed + ' vs ' + scored.failed);
check('what it hides becomes not-assessable',
  maskedScored.notAssessable > scored.notAssessable,
  maskedScored.notAssessable + ' vs ' + scored.notAssessable);
check('and coverage reports the cost',
  maskedScored.coverage < scored.coverage,
  maskedScored.coverage + '% vs ' + scored.coverage + '%');

// The specific case: for v1/v2c the community name IS the credential.
const maskedSnmp = maskedResults.filter(r => r.id === 'snmp-default-community')[0];
check('a masked community name cannot be checked for a default',
  maskedSnmp.status === 'not-assessable', maskedSnmp.status);
check('and says to confirm it on the device',
  /confirm/i.test(maskedSnmp.detail || ''), maskedSnmp.detail);

/* ══ Scoring ════════════════════════════════════════════════════════════════ */

section('not-assessable leaves the denominator');

check('the severity weights are the GRC ones, not a second scale',
  score.pointsFor('critical') === grc.WEIGHT_POINTS.critical &&
  score.pointsFor('high')     === grc.WEIGHT_POINTS.high &&
  score.pointsFor('medium')   === grc.WEIGHT_POINTS.medium &&
  score.pointsFor('low')      === grc.WEIGHT_POINTS.low);

const synth = [
  { id: 'a', severity: 'critical', status: 'pass' },
  { id: 'b', severity: 'critical', status: 'fail' },
  { id: 'c', severity: 'critical', status: 'not-assessable' },
];
const s3 = score.scoreResults(synth);
check('an unassessable check is in neither numerator nor denominator',
  s3.points.possible === grc.WEIGHT_POINTS.critical * 2 &&
  s3.points.earned === grc.WEIGHT_POINTS.critical,
  JSON.stringify(s3.points));
check('so the score is over what was assessed', s3.score === 50, s3.score);
check('and coverage says how much that was', s3.coverage === 67, s3.coverage);
check('counts are reported separately',
  s3.passed === 1 && s3.failed === 1 && s3.notAssessable === 1 && s3.assessed === 2);

/*
 * NULL, NOT ZERO. A config where nothing could be assessed did not fail
 * everything — the same distinction the Secure Score makes between an
 * unmeasured control and a failed one.
 */
const none = score.scoreResults([
  { id: 'a', severity: 'high', status: 'not-assessable' },
  { id: 'b', severity: 'low',  status: 'not-assessable' },
]);
check('nothing assessable scores null, not zero', none.score === null, none.score);
check('and bands as "not assessed"', none.band.key === 'unknown', none.band.label);
check('with zero coverage', none.coverage === 0);
check('an empty result set also scores null', score.scoreResults([]).score === null);

check('severity weighting actually bites',
  score.scoreResults([{ severity: 'critical', status: 'fail' },
                      { severity: 'low', status: 'pass' }]).score <
  score.scoreResults([{ severity: 'critical', status: 'pass' },
                      { severity: 'low', status: 'fail' }]).score);

section('the fixture is audited the way an analyst would');

const byId = {};
results.forEach(r => { byId[r.id] = r; });

// The fixture is deliberately bad. A fixture where everything passes tests
// nothing, so these assert the checks actually fire.
[['admin-telnet', 'fail'], ['admin-idle-timeout', 'fail'],
 ['admin-trusted-hosts', 'fail'], ['admin-default-account', 'fail'],
 ['policy-any-any', 'fail'], ['policy-logging', 'fail'],
 ['wan-management', 'fail'], ['snmp-v1v2c', 'fail'],
 ['vpn-ipsec-proposal', 'fail'], ['log-offbox', 'fail'],
 ['policy-named', 'pass'], ['profile-ips', 'pass'],
 ['system-ntp', 'pass'], ['log-destination', 'pass'],
].forEach(([id, want]) => {
  check(id + ' is ' + want, byId[id] && byId[id].status === want,
    byId[id] ? byId[id].status : 'missing');
});

check('the any/any finding names the offending policy',
  JSON.stringify(byId['policy-any-any'].evidence) === '{"policies":["1"]}',
  JSON.stringify(byId['policy-any-any'].evidence));
// A disabled any/any rule is hygiene, not exposure — policy 3 is disabled.
check('a disabled policy is not counted as live exposure',
  JSON.stringify(byId['policy-any-any'].evidence.policies) === '["1"]');
check('but is reported as clutter',
  JSON.stringify(byId['policy-disabled-present'].evidence) === '{"policies":["3"]}');

// Firmware currency cannot be decided from a file, and says so rather than
// hard-coding a cutoff that quietly starts passing vulnerable devices.
check('firmware currency is reported, not graded',
  byId['system-firmware'].status === 'not-assessable');
check('and names the version so a human can check it',
  /7\.6\.0/.test(byId['system-firmware'].detail));

/*
 * ── Cases the shared fixture cannot reach ─────────────────────────────────
 *
 * One realistic config cannot contain every edge at once, and stuffing more
 * into it makes every other assertion harder to read. These build the minimum
 * model each check needs. A mutation campaign found all five of these: each was
 * a rule the fixture happened not to exercise, so the rule could be deleted
 * with the suite still green.
 */
section('the edges one fixture cannot hold');

/** Run a single check against a purpose-built model. */
function runOne(id, partial) {
  const base = {
    device: {}, system: { global: {}, admins: [], interfaces: [], snmpCommunity: [] },
    policies: [], profiles: {}, vpn: {}, logging: {},
  };
  const m = Object.assign({}, base, partial);
  m.system = Object.assign({}, base.system, partial.system || {});
  return checks.runChecks(m).filter(r => r.id === id)[0];
}

const pol = (o) => Object.assign({
  id: '1', name: 'p', srcintf: ['lan'], dstintf: ['wan'],
  srcaddr: ['all'], dstaddr: ['all'], service: ['ALL'],
  action: 'accept', status: 'enable', logtraffic: 'all',
  profiles: {}, hasProfiles: true,
}, o);

/*
 * K1: a disabled rule is clutter, not exposure. Counting it would report a
 * firewall as permitting traffic it does not permit.
 *
 * The model needs a live policy alongside the disabled one. With ONLY a
 * disabled rule there are no live accept policies at all, and the check
 * correctly returns not-assessable — which is right, and not what this
 * assertion is about.
 */
const narrow = pol({ id: '9', dstaddr: ['WEB01'], service: ['HTTPS'] });
const disabledAnyAny = { policies: [pol({ status: 'disable' }), narrow] };
check('a DISABLED any/any policy is not counted as live exposure',
  runOne('policy-any-any', disabledAnyAny).status === 'pass',
  runOne('policy-any-any', disabledAnyAny).status + ' — ' +
  runOne('policy-any-any', disabledAnyAny).detail);
check('while an enabled one is',
  runOne('policy-any-any', { policies: [pol({}), narrow] }).status === 'fail');
check('and with no live accept policies at all it is not-assessable',
  runOne('policy-any-any', { policies: [pol({ status: 'disable' })] }).status
    === 'not-assessable');
check('and the disabled one is still reported as clutter',
  runOne('policy-disabled-present', { policies: [pol({ status: 'disable' })] }).status === 'fail');

// K3: any/any means all three are wildcards. A rule that is any-source to ONE
// host on ONE port is a normal rule, and calling it any/any would bury the real
// ones in noise.
check('any source to a specific host and service is not any/any',
  runOne('policy-any-any',
    { policies: [pol({ dstaddr: ['WEB01'], service: ['HTTPS'] })] }).status === 'pass');
check('nor is any-service to a specific destination',
  runOne('policy-any-any', { policies: [pol({ dstaddr: ['WEB01'] })] }).status === 'pass');

// K2: FortiOS omits logtraffic in some exports. Absent must read as unlogged —
// the safe direction — or a policy nobody can investigate is reported clean.
check('a policy with NO logtraffic field is treated as unlogged',
  runOne('policy-logging', { policies: [pol({ logtraffic: null })] }).status === 'fail',
  runOne('policy-logging', { policies: [pol({ logtraffic: null })] }).detail);
check('an explicitly disabled one too',
  runOne('policy-logging', { policies: [pol({ logtraffic: 'disable' })] }).status === 'fail');
check('and one that logs passes',
  runOne('policy-logging', { policies: [pol({ logtraffic: 'all' })] }).status === 'pass');

// K6: a trusted host of 0.0.0.0/0 trusts everybody. Counting it as a
// restriction would clear the exact configuration the check exists to find.
const wideOpen = { system: { admins: [{ _key: 'a1', trusthost1: '0.0.0.0 0.0.0.0' }] } };
check('a trusted host of 0.0.0.0/0 is no restriction at all',
  runOne('admin-trusted-hosts', wideOpen).status === 'fail',
  runOne('admin-trusted-hosts', wideOpen).detail);
check('while a real subnet is',
  runOne('admin-trusted-hosts',
    { system: { admins: [{ _key: 'a1', trusthost1: '10.0.0.0 255.255.255.0' }] } })
    .status === 'pass');

// K5: the try/catch around every check. A model shaped wrongly must degrade to
// not-assessable, not take the whole audit down with it.
let crashed = null;
try {
  const r = checks.runChecks({
    device: {}, policies: [],
    // A string where an array belongs — .filter does not exist on it.
    system: { global: {}, admins: 'not-an-array', interfaces: 'not-an-array' },
    profiles: {}, vpn: {}, logging: {},
  });
  crashed = r.every(x => ['pass', 'fail', 'not-assessable'].indexOf(x.status) >= 0)
    ? null : 'a check returned an invalid status';
} catch (err) { crashed = err.message; }
check('a check that throws becomes not-assessable rather than a 500',
  crashed === null, crashed);

section('partial masking is not a boolean');

/*
 * M2. A config where SOME secrets are masked and others are not is neither
 * "masked" nor "unmasked" — collapsing it to a boolean would tell an analyst a
 * file was safe when half of it was not. Only the fully-unmasked case triggers
 * the rotate-your-credentials warning, so getting this wrong in the other
 * direction is equally bad.
 */
const partial = parser.parseConfig(
  'system:\n' +
  '  admin:\n' +
  '    a:\n      password: \n' +          // masked
  '    b:\n      password: ENC abc123\n');  // not
check('a partially masked config reports null, not a verdict',
  partial.masked === null, JSON.stringify(partial.maskDetail));
check('and the detail says how many of each',
  partial.maskDetail.secretFields === 2 && partial.maskDetail.maskedFields === 1,
  JSON.stringify(partial.maskDetail));

check('every check has a rationale and a remediation',
  results.every(r => r.rationale && r.rationale.length > 20 &&
                     r.remediation && r.remediation.length > 5));
check('every CIS-mapped check carries its reference',
  results.filter(r => r.source === 'cis').every(r => r.cis));
check('and ours are marked as ours',
  results.some(r => r.source === 'reflex'));
check('a check that throws is not-assessable, not a crash',
  checks.runChecks({ system: {}, policies: null, profiles: {}, vpn: {}, logging: {}, device: {} })
    .every(r => ['pass', 'fail', 'not-assessable'].indexOf(r.status) >= 0));

/* ══ Client-facing ══════════════════════════════════════════════════════════ */

section('the client gets the finding and the fix, not the map');

const pub = score.publicFinding(byId['policy-any-any']);
check('the finding survives', pub.title && pub.severity && pub.remediation);
check('the rationale survives, so they can argue with it', !!pub.rationale);
// Together, evidence is a map of where this firewall is weakest.
check('evidence is withheld', pub.evidence === undefined,
  JSON.stringify(Object.keys(pub)));
check('and so is the internal detail', pub.detail === undefined);
/*
 * The exact key set, pinned. This is the check that makes the allowlist worth
 * having: a field added to a finding cannot reach a client until somebody
 * changes this line and has to justify it.
 *
 * `category` is on the list deliberately. It is the finding's HEADING — which
 * kind of weakness this is — and the client needs it to read a report grouped
 * by category. It names no policy, port or interface, so it is not part of the
 * map that `evidence` is.
 */
check('the projection is an allowlist, not a delete-list',
  JSON.stringify(Object.keys(pub).sort()) ===
  '["category","cis","id","rationale","remediation","severity","source","status","title"]',
  JSON.stringify(Object.keys(pub).sort()));
check('the category travels as a label, never as evidence',
  typeof pub.category === 'string' && pub.category.indexOf('policy') >= 0 &&
  JSON.stringify(pub).indexOf('policyid') < 0);

check('the portal uses that projection rather than its own',
  /fortigateScore\.publicFinding\(/.test(codeOnly(portalJs)));
check('and never selects evidence from the database',
  !/evidence[\s\S]{0,200}FROM firewall_findings/.test(codeOnly(portalJs)) &&
  !/SELECT[\s\S]{0,200}evidence[\s\S]{0,200}firewall_findings/.test(codeOnly(portalJs)));
check('the portal route is scoped by tenant in the WHERE clause',
  /FROM firewall_audits\s+WHERE tenant_id = \$1/.test(portalJs) &&
  /WHERE audit_id = \$1 AND tenant_id = \$2/.test(portalJs));

check('the report section withholds evidence too',
  !/\.evidence/.test(codeOnly(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8')
      .match(/function renderFirewallAudit[\s\S]*?\n  \}/)[0])));

/* ══ Wiring ═════════════════════════════════════════════════════════════════ */

section('routes, access and the tab');

['POST /api/firewall/audits', 'GET /api/firewall/audits',
 'GET /api/firewall/audits/latest', 'GET /api/firewall/audits/:id',
].forEach((r) => {
  const [m, p] = r.split(' ');
  check(r + ' is mounted',
    new RegExp('app\\.' + m.toLowerCase() + "\\('" + p.replace(/[/:]/g, '\\$&') + "'").test(srvCode));
});
// Express matches in registration order, so /latest must be registered before
// /:id or it is swallowed as an id.
check('/latest is registered before /:id',
  srvCode.indexOf("'/api/firewall/audits/latest'") <
  srvCode.indexOf("'/api/firewall/audits/:id'"));

check('ownership is in the WHERE clause, not a post-fetch check',
  /WHERE a\.id = \$1 AND a\.tenant_id = \$2/.test(srvCode));
check('deletion is superadmin only',
  /app\.delete\('\/api\/firewall\/audits\/:id', requireSuperAdmin/.test(srvCode));

check('the page is in the catalogue',
  P.PAGES.some(p => p.key === 'firewall' && p.type === 'tab'));
check('the API prefix maps to it', P.API_PREFIX_TO_PAGE.firewall === 'firewall');
check('analysts can run an audit', P.ROLE_DEFAULTS.analyst.firewall === 'write');
['sales', 'readonly', 'manager', 'client'].forEach((r) => {
  check(r + ' gets nothing', P.ROLE_DEFAULTS[r].firewall === 'none',
    P.ROLE_DEFAULTS[r].firewall);
});
const pagesJs = fs.readFileSync(path.join(ROOT, 'lib', 'pages.js'), 'utf8');
check('and it is excluded from the viewer allowlist',
  /NON_VIEWER_TABS = \[[^\]]*'firewall'[^\]]*\]/.test(pagesJs));

/*
 * The service covers no Secure Score component, deliberately: coverage is
 * MDR + Vulnerability Management + Security Awareness, and a fourth entry here
 * would silently re-weight every existing client's coverage figure.
 */
check('the firewall service is in the catalogue',
  svcLib.SERVICE_KEYS.indexOf('firewall') >= 0);
check('and covers no Secure Score component',
  JSON.stringify(svcLib.SERVICE_COVERS.firewall) === '[]');
check('so it cannot appear in a coverage gap',
  svcLib.COMPONENT_KEYS.every(k =>
    svcLib.servicesCovering(k).indexOf('firewall') < 0));

check('the tab is loaded', /js\/tab-firewall\.js/.test(indexHtml));
check('its panel exists', /id="tab-firewall"/.test(indexHtml));
check('its stylesheet is linked', /css\/firewall\.css/.test(indexHtml));

/*
 * WHERE the nav entry sits, not merely that one exists.
 *
 * "Has a nav entry" passes wherever the button happens to be, so it cannot
 * notice an item sitting in the footer beside Admin when it belongs under
 * Governance & Risk — which is exactly where this one started. The sidebar is
 * how an analyst finds the feature, so its placement is a property worth
 * pinning.
 */
function navGroupOf(tab) {
  const groups = [...indexHtml.matchAll(
    /data-label="([^"]+)"[\s\S]*?<div class="side-nav-group-items"[^>]*>([\s\S]*?)<\/div>/g)];
  for (const g of groups) {
    if (new RegExp('data-tab="' + tab + '"').test(g[2])) {
      return g[1].replace('&amp;', '&');
    }
  }
  const footer = indexHtml.slice(indexHtml.indexOf('side-nav-footer'));
  return new RegExp('data-tab="' + tab + '"').test(footer) ? 'footer' : null;
}

check('the nav entry is under Governance & Risk',
  navGroupOf('firewall') === 'Governance & Risk', navGroupOf('firewall'));
check('and appears exactly once',
  (indexHtml.match(/data-tab="firewall"/g) || []).length === 1,
  (indexHtml.match(/data-tab="firewall"/g) || []).length);
// The neighbours it was grouped with, so a future reshuffle is a deliberate act.
check('beside the other governance surfaces',
  ['grc', 'risk-register', 'third-party-risk']
    .every(t => navGroupOf(t) === 'Governance & Risk'),
  ['grc', 'risk-register', 'third-party-risk'].map(navGroupOf).join(', '));
const appJs = fs.readFileSync(path.join(ROOT, 'public', 'js', 'app.js'), 'utf8');
check('the panel is in the tab map',
  /firewall:\s*document\.getElementById\('tab-firewall'\)/.test(appJs));
check('and it is dispatched on open',
  /target === 'firewall'[\s\S]{0,140}FirewallTab\.loadAndRender\(\)/.test(appJs));

/* ══ The browser module ═════════════════════════════════════════════════════ */

section('the tab escapes what it renders');

const sandbox = { console };
sandbox.window = sandbox;
sandbox.document = {
  getElementById: () => null,
  querySelectorAll: () => [],
  querySelector: (s) => (s === 'base' ? { href: 'https://secops.reflex.co.za/secops/' } : null),
};
vm.createContext(sandbox);
vm.runInContext(tabJs, sandbox);
const FT = sandbox.window.FirewallTab;

check('the module loads', !!FT && typeof FT.loadAndRender === 'function');

const XSS = '<script>alert(1)</script>';
const row = FT._findingRow({
  severity: 'high', status: 'fail', title: XSS, detail: XSS,
  rationale: XSS, remediation: XSS, cis: XSS,
  evidence: { policies: [XSS] },
});
check('a finding title is escaped',
  row.indexOf('<script') < 0 && row.indexOf('&lt;script') >= 0, row.slice(0, 80));
check('so is evidence — it comes from a parsed config',
  (row.match(/&lt;script/g) || []).length >= 4,
  (row.match(/&lt;script/g) || []).length + ' escaped occurrences');

section('the mask notice tells the truth about a tri-state');

check('unmasked is stated loudly', /NOT/.test(FT._maskNotice({ appearedMasked: false })));
check('and says to rotate', /rotate/i.test(FT._maskNotice({ appearedMasked: false })));
check('and says it was not stored',
  /not been stored/i.test(FT._maskNotice({ appearedMasked: false })));
check('masked is stated calmly',
  /appeared to be/i.test(FT._maskNotice({ appearedMasked: true })) &&
  !/NOT/.test(FT._maskNotice({ appearedMasked: true })));
// A guess presented as a fact sends someone rotating credentials for nothing.
check('unknown says it could not be determined',
  /could not be determined/i.test(FT._maskNotice({ appearedMasked: null })));

/* ══ Deleting an audit ══════════════════════════════════════════════════════ */

section('deletion is scoped, complete, and asked about first');

const delRoute = (() => {
  const at = srvCode.indexOf("app.delete('/api/firewall/audits/:id'");
  const rest = srvCode.slice(at);
  return rest.slice(0, rest.indexOf('\n});') + 4);
})();

check('the delete route was found in server.js', delRoute.length > 100, delRoute.length);
/*
 * Superadmin may delete any tenant's audit; that is not a reason to let a
 * mistyped id delete a tenant they are not looking at. Same rule as the GETs.
 */
check('the delete is scoped by tenant in the WHERE clause',
  /WHERE id = \$1 AND tenant_id = \$2/.test(delRoute));
check('the tenant comes from resolveVulnTenant, not from the id alone',
  /resolveVulnTenant\(req, 'query'\)/.test(delRoute));
check('an unknown id and another tenant\'s id both 404',
  (delRoute.match(/status\(404\)/g) || []).length >= 1 &&
  !/status\(403\)/.test(delRoute));
check('it names what it deleted rather than just saying "deleted"',
  /RETURNING id, device_name, uploaded_at/.test(delRoute) &&
  /deleted:\s*\{/.test(delRoute));

/*
 * The findings go with the audit by ON DELETE CASCADE. A second DELETE in the
 * route would be a second statement that could half-succeed, leaving findings
 * pointing at an audit that no longer exists — and those findings are the only
 * thing this feature stores.
 */
check('findings cascade from the audit in the schema',
  /audit_id\s+INT NOT NULL REFERENCES firewall_audits\(id\) ON DELETE CASCADE/
    .test(sqlOnly(migration)));
check('so the route issues exactly one DELETE',
  (delRoute.match(/DELETE FROM/g) || []).length === 1,
  (delRoute.match(/DELETE FROM/g) || []).length);
check('and does not delete findings by hand',
  !/firewall_findings/.test(delRoute));

section('the tab only offers deletion to someone the server would allow');

check('the button is gated on superadmin, matching requireSuperAdmin',
  /role === 'superadmin'/.test(codeOnly(
    tabJs.match(/function canDelete\(\)[\s\S]*?\n  \}/)[0])));
/*
 * Analysts have WRITE on this page so they can run audits. Producing a record
 * and erasing one are not the same right, and canWrite() would conflate them.
 */
check('and not on canWrite, which analysts also have',
  !/canWrite/.test(tabJs.match(/function canDelete\(\)[\s\S]*?\n  \}/)[0]));
check('deletion goes through confirm() first',
  /function doDelete[\s\S]{0,600}confirm\(/.test(tabCode));
check('and the prompt says the audit cannot be recreated',
  /cannot be undone[\s\S]{0,200}never stored/.test(tabJs));
check('the request uses the DELETE method',
  /method: 'DELETE'/.test(tabCode));
check('and carries the tenant, or a superadmin delete 400s',
  /firewall\/audits\/' \+ encodeURIComponent\(id\) \+ tenantParam\('\?'\)[\s\S]{0,120}method: 'DELETE'/
    .test(tabCode));
/*
 * Deleting the newest audit promotes the one before it. Blanking the view would
 * read as "this client has no firewall review" when one still stands.
 */
check('deleting the audit on screen re-fetches rather than blanking',
  /_audit = null[\s\S]{0,400}audits\/latest/.test(tabCode));

section('the delete control is real markup, not a nested button');

sandbox.currentUser = { role: 'superadmin' };
const DEV_XSS = 'Edge"><img src=x onerror=alert(1)>';
FT._setHistory([{
  id: 7, uploadedAt: '2026-01-02T00:00:00Z', score: 61,
  failed: 3, coverage: 80, device: { name: DEV_XSS },
}]);
const hist = FT._historyBlock();

check('a superadmin gets a delete control', /class="fw-h-del"/.test(hist));
check('it carries the audit id', /data-del="7"/.test(hist));
// A <button> inside a <button> is invalid HTML; browsers drop one of them.
const firstRow = hist.slice(hist.indexOf('fw-h-row'));
check('the delete button is a sibling of the row, not nested inside it',
  firstRow.slice(0, firstRow.indexOf('</button>')).indexOf('fw-h-del') < 0);
// The device name comes from an uploaded config and lands in an attribute.
check('the device name is escaped in the confirmation label',
  hist.indexOf(DEV_XSS) < 0 && /data-label="[^"]*&quot;/.test(hist), hist.slice(0, 200));
check('and nothing unescaped survives anywhere in the row',
  hist.indexOf('<img') < 0);

sandbox.currentUser = { role: 'analyst' };
check('an analyst gets no delete control', !/fw-h-del/.test(FT._historyBlock()));
sandbox.currentUser = undefined;
check('and neither does a caller with no session',
  !/fw-h-del/.test(FT._historyBlock()));

section('every request keeps the /secops/ base path');

check('the URL builder keeps the base',
  FT._apiUrl('firewall/audits') ===
    'https://secops.reflex.co.za/secops/api/firewall/audits',
  FT._apiUrl('firewall/audits'));
check('no request is hard-coded to a bare root',
  !/fetch\(['"]\/api\//.test(tabCode));
check('and the base comes from <base href> like every other module',
  /document\.querySelector\('base'\)/.test(tabCode));

/*
 * The warning-capture checks are async — process.emitWarning fires on the next
 * tick, so asserting immediately would assert against an empty array and pass
 * for the wrong reason. done() calls process.exit, so it has to wait for them.
 *
 * The exit hook is the guard: if the async block never ran, the suite must fail
 * rather than report green having made fewer assertions than it printed.
 */
/* ══ Policy analysis — the rulebase, not the device ═════════════════════════
 *
 * These are the checks behind the five report categories. The risk they guard
 * against is specific: a rulebase we could only half read reporting as a
 * rulebase we read and found clean.
 */

const policyLib = require(path.join(ROOT, 'lib', 'fortigate-policy'));

/** Build a config around a policy table, so each case states only what matters. */
function cfgWith(policies, extra) {
  return parser.parseConfig(JSON.stringify(Object.assign({
    system: {
      interface: {
        wan1:     { name: 'wan1', role: 'wan' },
        internal: { name: 'internal', role: 'lan' },
      },
    },
    firewall: Object.assign({ policy: policies }, (extra && extra.firewall) || {}),
  }, extra && extra.root)));
}

function resultsFor(model) {
  const out = {};
  checks.runChecks(model).forEach((r) => { out[r.id] = r; });
  return out;
}

section('a service name is resolved to ports, not matched as a string');

/*
 * THE CHECK THIS WHOLE MODULE EXISTS FOR.
 *
 * Almost nobody references the predefined 'RDP' service. They define
 * `Remote-Desktop` as tcp/3389 and put it in a group. Matching on the string
 * 'RDP' would report that firewall as clean while it published RDP to the
 * internet — the exact finding the audit is bought to produce.
 */
const customRdp = cfgWith({
  1: { policyid: 1, srcintf: 'wan1', dstintf: 'internal', srcaddr: 'all',
       dstaddr: 'srv', service: 'Publish', action: 'accept' },
}, {
  firewall: {
    service: {
      custom: {
        'Remote-Desktop': { name: 'Remote-Desktop', protocol: 'TCP', 'tcp-portrange': '3389' },
        Web: { name: 'Web', protocol: 'TCP', 'tcp-portrange': '80 443' },
      },
      /*
       * A LIST, not the space-separated scalar this fixture used to carry.
       *
       * A bare scalar is now exactly one reference however much punctuation it
       * contains, because FortiGate object names routinely contain spaces —
       * "SHARED SERVERS : 100.71.0.1" is one object, and splitting it produced
       * four fragments that resolved to nothing. Multiplicity comes from a YAML
       * list, or from FortiOS's own quoted form ("a" "b"); an unquoted
       * `Remote-Desktop Web` is indistinguishable from a genuine name and is
       * read as one. This fixture now uses the shape a real export writes.
       */
      group: { Publish: { name: 'Publish', member: ['Remote-Desktop', 'Web'] } },
    },
  },
});

const rdpAnalysis = policyLib.analysePolicies(customRdp);
check('a custom service resolves through a group to its ports',
  JSON.stringify(rdpAnalysis.policies[0].resolved.tcp.sort((a, b) => a[0] - b[0])) ===
  '[[80,80],[443,443],[3389,3389]]',
  JSON.stringify(rdpAnalysis.policies[0].resolved.tcp));
check('and nothing was left unresolved',
  rdpAnalysis.policies[0].resolved.unresolved.length === 0);

const rdpResults = resultsFor(customRdp);
check('so an RDP exposure hidden behind a custom name is still found',
  rdpResults['ric-critical-services'].status === 'fail',
  rdpResults['ric-critical-services'].status + ' — ' + rdpResults['ric-critical-services'].detail);
check('and it names the policy, not the port',
  JSON.stringify(rdpResults['ric-critical-services'].evidence).indexOf('3389') < 0 &&
  JSON.stringify(rdpResults['ric-critical-services'].evidence).indexOf('"policy"') >= 0);
check('an "all" source over a risky service is a blanket finding',
  rdpResults['rib-blanket-risky'].status === 'fail');

check('port ranges parse, source halves ignored',
  JSON.stringify(policyLib.parsePortRanges('80 443 1000-2000 8080:1024-65535')) ===
  '[[80,80],[443,443],[1000,2000],[8080,8080]]',
  JSON.stringify(policyLib.parsePortRanges('80 443 1000-2000 8080:1024-65535')));
check('an unparseable port range yields nothing rather than zero',
  policyLib.parsePortRanges('not-a-port').length === 0);
// A self-referencing service group is a config a device will happily hold.
check('a recursive service group does not hang the parser',
  (() => {
    const idx = policyLib.buildServiceIndex({
      services: { custom: {}, groups: { A: { name: 'A', member: 'B' }, B: { name: 'B', member: 'A' } } },
    });
    return policyLib.resolveServices(idx, ['A']).tcp.length === 0;
  })());

section('what could not be read is never reported as clean');

const unreadable = cfgWith({
  1: { policyid: 1, srcintf: 'wan1', dstintf: 'internal', srcaddr: 'net',
       dstaddr: 'srv', service: 'Made-Up-Service', action: 'accept' },
});
const unreadableResults = resultsFor(unreadable);
/*
 * The policy references a service this audit cannot resolve. We did not look
 * inside it, so "no critical services exposed" is a stronger claim than the
 * evidence supports.
 */
check('an unresolvable service makes an inbound check not-assessable, not pass',
  unreadableResults['ric-critical-services'].status === 'not-assessable',
  unreadableResults['ric-critical-services'].status);
check('and it says which policy it could not read',
  JSON.stringify(unreadableResults['ric-critical-services'].evidence)
    .indexOf('unreadPolicies') >= 0);
check('the coverage gap is its own finding',
  unreadableResults['rpc-services-resolved'].status === 'not-assessable');
/*
 * NOT a fail. Nothing is wrong with the device — the audit could not see far
 * enough, and grading that as a failure penalises a client for our gap.
 */
check('reported as a limit of the audit rather than a fault of the firewall',
  unreadableResults['rpc-services-resolved'].status !== 'fail');
check('and it names the service it could not resolve',
  JSON.stringify(unreadableResults['rpc-services-resolved'].evidence)
    .indexOf('Made-Up-Service') >= 0);

section('a policy whose direction cannot be determined is not silently dropped');

/*
 * srcintf and dstintf both 'any' touches the WAN at both ends, so direction is
 * undeterminable — and that rule is usually the most dangerous on the device.
 * Before the guard, it appeared in neither set and the inbound checks reported
 * "no inbound policies found" as a PASS.
 */
const anyAny = cfgWith({
  1: { policyid: 1, srcintf: 'any', dstintf: 'any', srcaddr: 'all',
       dstaddr: 'all', service: 'ALL', action: 'accept' },
});
check('its direction is unknown rather than guessed',
  policyLib.analysePolicies(anyAny).policies[0].direction === 'unknown',
  policyLib.analysePolicies(anyAny).policies[0].direction);

const anyAnyResults = resultsFor(anyAny);
check('so the inbound checks report not-assessable, never pass',
  anyAnyResults['ric-critical-services'].status === 'not-assessable',
  anyAnyResults['ric-critical-services'].status);
check('and the outbound checks too',
  anyAnyResults['roc-risky-egress'].status === 'not-assessable');
check('naming the policies that could not be placed',
  JSON.stringify(anyAnyResults['ric-critical-services'].evidence)
    .indexOf('unplacedPolicies') >= 0);
// It is still caught by the direction-agnostic checks, so it is not lost.
check('but it is still found by the permissiveness checks',
  anyAnyResults['rpc-any-source'].status === 'fail' &&
  anyAnyResults['policy-any-any'].status === 'fail');

section('direction, when the interface roles allow it');

const bothWays = cfgWith({
  1: { policyid: 1, srcintf: 'wan1', dstintf: 'internal', srcaddr: 'net', dstaddr: 'srv',
       service: 'HTTPS', action: 'accept', logtraffic: 'all' },
  2: { policyid: 2, srcintf: 'internal', dstintf: 'wan1', srcaddr: 'all', dstaddr: 'all',
       service: 'TELNET', action: 'accept', logtraffic: 'all' },
});
const bw = policyLib.analysePolicies(bothWays);
check('wan -> lan is inbound', bw.policies[0].direction === 'inbound');
check('lan -> wan is outbound', bw.policies[1].direction === 'outbound');

const bwResults = resultsFor(bothWays);
check('outbound telnet is a risky-egress finding',
  bwResults['roc-risky-egress'].status === 'fail');
check('but inbound HTTPS is not a critical exposure',
  bwResults['ric-critical-services'].status === 'pass',
  bwResults['ric-critical-services'].detail);

/*
 * Interface roles are cosmetic on many deployments. Where none is declared,
 * assuming which interface faces the internet would invent findings.
 */
const noRoles = parser.parseConfig(JSON.stringify({
  system: { interface: { port1: { name: 'port1' } } },
  firewall: { policy: { 1: { policyid: 1, srcintf: 'port1', dstintf: 'port2',
    srcaddr: 'all', dstaddr: 'all', service: 'ALL', action: 'accept' } } },
}));
const noRoleResults = resultsFor(noRoles);
check('with no wan role declared, direction checks are not-assessable',
  noRoleResults['ric-critical-services'].status === 'not-assessable');
check('and say so rather than guessing an interface',
  /role: wan/.test(noRoleResults['ric-critical-services'].detail));

section('every check belongs to a category');

const allResults = checks.runChecks(model);
check('no check is uncategorised',
  allResults.every(r => r.category),
  allResults.filter(r => !r.category).map(r => r.id).join(','));
check('and every category used is in the catalogue',
  allResults.every(r => checks.CATEGORY_KEYS.indexOf(r.category) >= 0),
  [...new Set(allResults.map(r => r.category))]
    .filter(c => checks.CATEGORY_KEYS.indexOf(c) < 0).join(','));
check('the five report categories all exist',
  ['risky-policy-conditions', 'policy-attribute', 'risky-inbound-blanket',
   'risky-inbound-conditions', 'risky-outbound-conditions']
    .every(k => checks.CATEGORY_KEYS.indexOf(k) >= 0));
check('and each of them has at least one check',
  ['risky-policy-conditions', 'policy-attribute', 'risky-inbound-blanket',
   'risky-inbound-conditions', 'risky-outbound-conditions']
    .every(k => allResults.some(r => r.category === k)));
/*
 * Three older policy- checks carry an explicit category because they are risk
 * findings, not hygiene, and the id prefix cannot know that.
 */
check('an explicit category beats the prefix map',
  allResults.find(r => r.id === 'policy-any-any').category === 'risky-policy-conditions',
  allResults.find(r => r.id === 'policy-any-any').category);
check('while an un-overridden policy- check is hygiene',
  allResults.find(r => r.id === 'policy-named').category === 'policy-attribute');
// A check matching no prefix must resolve to null, not to a plausible bucket.
check('an unrecognised id is uncategorised rather than misfiled',
  checks.categoryFor({ id: 'zzz-something' }) === null);

section('category scores use the same arithmetic as the overall score');

const scoredAll = score.scoreResults(allResults);
check('every category present is scored', scoredAll.byCategory.length > 0);
check('and they come back in report order',
  scoredAll.byCategory.every((c, i, arr) => i === 0 || arr[i - 1].order <= c.order));
check('nothing is uncategorised in the rollup',
  scoredAll.uncategorised.length === 0, scoredAll.uncategorised.join(','));

/*
 * The recursion that computes a category score must terminate. It did not, the
 * first time: a single-category subset still matches its own category, so the
 * inner call rolled up again forever.
 */
check('computing a category score does not recurse forever',
  Array.isArray(scoredAll.byCategory));
check('and the inner call does not roll up again',
  scoredAll.byCategory.every(c => c.byCategory === undefined));

// Same rule as the overall score: nothing assessable means null, not zero.
const allNa = score.scoreResults([
  { severity: 'high', status: 'not-assessable', category: 'risky-inbound-blanket' },
]);
check('a category with nothing assessable scores null, not 0',
  allNa.byCategory[0].score === null, String(allNa.byCategory[0].score));
check('and reports zero coverage rather than a clean result',
  allNa.byCategory[0].coverage === 0);

const catFail = score.scoreResults([
  { severity: 'high', status: 'fail', category: 'risky-inbound-blanket' },
  { severity: 'high', status: 'pass', category: 'risky-inbound-blanket' },
]);
check('a real 0 and a null are different states',
  catFail.byCategory[0].score === 50 && allNa.byCategory[0].score === null);

section('the category reaches storage and the screens');

const catMigration = fs.readFileSync(
  path.join(ROOT, 'db', 'migrate-firewall-categories.sql'), 'utf8');
check('the column is added by a migration',
  /ADD COLUMN IF NOT EXISTS category TEXT/.test(sqlOnly(catMigration)));
/*
 * Nullable and un-backfilled: a finding stored before categorisation was never
 * categorised, and inventing a category for it would be inventing data about an
 * audit nobody re-ran.
 */
check('and is nullable rather than back-filled with a guess',
  !/category TEXT NOT NULL/.test(sqlOnly(catMigration)) &&
  !/UPDATE firewall_findings/.test(sqlOnly(catMigration)));
check('the insert only names the column where it exists',
  /hasFirewallCategoryColumn/.test(srvCode) &&
  /withCategory \? ', category' : ''/.test(serverJs));
check('the column probe caches only a positive answer',
  /_firewallCategoryColumn = true;[\s\S]{0,120}return false;/.test(srvCode));
check('the rollup is recomputed on read, not frozen into the audit row',
  /byCategory: fortigateScore\.scoreResults\(/.test(srvCode));
check('the tab groups findings by category',
  /groupByCategory/.test(codeOnly(tabJs)));
check('and an uncategorised finding is labelled, not hidden',
  /Not categorised/.test(tabJs));
check('the report section carries a category table',
  /Posture by category/.test(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8')));
check('which prints "Not assessed" rather than 0 for an unscored category',
  /r\.score == null[\s\S]{0,80}Not assessed/.test(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'report-sections.js'), 'utf8')));

let warnRan = false;
process.on('exit', () => {
  if (!warnRan) {
    console.log('FAIL  the warning-capture checks never ran — the suite exited early');
    process.exitCode = 1;
  }
});

warnCheck.then(() => { warnRan = true; done(); },
  (err) => {
    check('the warning-capture checks ran to completion', false, err && err.message);
    warnRan = true;
    done();
  });
