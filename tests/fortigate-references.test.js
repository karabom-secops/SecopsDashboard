'use strict';

/**
 * FortiGate reference fields — an object name is one atomic string.
 *
 * THE DEFECT THIS SUITE PINS DOWN
 *
 * normaliseReferenceField (then called `names`) ended with:
 *
 *     return String(node).trim().split(/\s+/).filter(Boolean);
 *
 * so every object name containing a space was shredded into fragments. Real
 * names from a real export, and what they became:
 *
 *   "RFX-DC01 - 10.69.10.8"       -> ["RFX-DC01", "-", "10.69.10.8"]
 *   "SHARED SERVERS : 100.71.0.1" -> ["SHARED", "SERVERS", ":", "100.71.0.1"]
 *   "RFX-AW-VL1765 address"       -> ["RFX-AW-VL1765", "address"]
 *   "SSL-VPN :10.44.1.0/24"       -> ["SSL-VPN", ":10.44.1.0/24"]
 *
 * Not one fragment is an object, so every reference failed to resolve — which
 * is why an audit of a config that defines its objects perfectly well reported
 * "defined address objects are unresolved" and marked the rulebase un-assessed.
 *
 * THE RULES
 *
 *   a scalar is EXACTLY ONE reference, whatever punctuation it contains
 *   a list carries multiplicity; a scalar never does
 *   the only multi-value scalar is FortiOS's own quoted form: "a" "b"
 *   exact case and punctuation are the primary lookup; normalisation is a
 *     fallback, never the first attempt
 *
 *   node tests/fortigate-references.test.js <repoRoot>
 */

const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('fortigate-references');

const parser = require(path.join(ROOT, 'lib', 'fortigate-parser'));
const A = require(path.join(ROOT, 'lib', 'fortigate-address'));
const S = require(path.join(ROOT, 'lib', 'fortigate-sections'));
const checks = require(path.join(ROOT, 'lib', 'fortigate-checks'));

const ref = parser.normaliseReferenceField;

// ── The exact names from the report ────────────────────────────────────────

section('a scalar is one reference, whatever punctuation it carries');

const ATOMIC = [
  'RFX-DC01 - 10.69.10.8',
  'SHARED SERVERS : 100.71.0.1',
  'RFX-AW-VL1765 address',
  'SSL-VPN :10.44.1.0/24',
  'RFX-OFFICE -- POC-VHI',
  'EC Fiber IPSEC',
  'RFX -OFFICE - INSIDE',
];

ATOMIC.forEach((name) => {
  const out = ref(name, null);
  check(JSON.stringify(name) + ' stays one string',
    out.length === 1 && out[0] === name, JSON.stringify(out));
});

check('surrounding whitespace is trimmed, and only that',
  ref('  SHARED SERVERS : 100.71.0.1  ', null)[0] === 'SHARED SERVERS : 100.71.0.1',
  JSON.stringify(ref('  SHARED SERVERS : 100.71.0.1  ', null)));

check('internal spacing is preserved exactly',
  ref('RFX -OFFICE - INSIDE', null)[0] === 'RFX -OFFICE - INSIDE',
  JSON.stringify(ref('RFX -OFFICE - INSIDE', null)));

check('case is preserved', ref('SHARED Servers', null)[0] === 'SHARED Servers',
  ref('SHARED Servers', null)[0]);

// ── The contract ───────────────────────────────────────────────────────────

section('normaliseReferenceField contract');

check('null -> []', ref(null, null).length === 0, JSON.stringify(ref(null, null)));
check('undefined -> []', ref(undefined, null).length === 0, JSON.stringify(ref(undefined, null)));
check('empty string -> []', ref('', null).length === 0, JSON.stringify(ref('', null)));
check('a scalar integer -> its string form',
  ref(81, null).length === 1 && ref(81, null)[0] === '81', JSON.stringify(ref(81, null)));

const list = ref(['RFX-DC01 - 10.69.10.8', 'SHARED SERVERS : 100.71.0.1'], null);
check('a list carries one complete entry per member',
  list.length === 2 && list[0] === 'RFX-DC01 - 10.69.10.8' &&
  list[1] === 'SHARED SERVERS : 100.71.0.1', JSON.stringify(list));

check('a list of {name:} members reads their names',
  ref([{ name: 'SHARED SERVERS : 100.71.0.1' }], null)[0] === 'SHARED SERVERS : 100.71.0.1',
  JSON.stringify(ref([{ name: 'x : y' }], null)));

check('q_origin_key is a fallback for name, not a second reference',
  ref([{ q_origin_key: 'OLD NAME : 1.2.3.4' }], null).length === 1,
  JSON.stringify(ref([{ q_origin_key: 'OLD NAME : 1.2.3.4' }], null)));

const warn = [];
ref({ 'SOME MAP': { a: 1 } }, warn);
check('a nested mapping produces a warning, not tokenisation',
  warn.length > 0, JSON.stringify(warn));

// ── The one legitimate multi-value scalar ──────────────────────────────────

section('FortiOS quoted form is the only multi-value scalar');

const quoted = ref('"Remote-Desktop" "Web"', null);
check('a fully quoted scalar carries one reference per quoted segment',
  quoted.length === 2 && quoted[0] === 'Remote-Desktop' && quoted[1] === 'Web',
  JSON.stringify(quoted));

check('quoted segments containing spaces stay whole',
  ref('"SHARED SERVERS : 100.71.0.1" "RFX-DC01 - 10.69.10.8"', null).length === 2 &&
  ref('"SHARED SERVERS : 100.71.0.1" "RFX-DC01 - 10.69.10.8"', null)[0] === 'SHARED SERVERS : 100.71.0.1',
  JSON.stringify(ref('"SHARED SERVERS : 100.71.0.1" "A - B"', null)));

check('an UNQUOTED scalar with spaces is still one reference',
  ref('Remote-Desktop Web', null).length === 1,
  JSON.stringify(ref('Remote-Desktop Web', null)));

check('a name merely containing a quote is not treated as the quoted form',
  ref('RACK 19" CONSOLE', null).length === 1,
  JSON.stringify(ref('RACK 19" CONSOLE', null)));

// ── YAML splitting a colon name, and the rejoin ────────────────────────────

section('a colon name split by YAML is rejoined, not dropped');

/*
 * `- SHARED SERVERS : 100.71.0.1` is VALID YAML meaning
 * { 'SHARED SERVERS': '100.71.0.1' } — so the name arrives already torn in half
 * with no parse error to warn anybody. Dropping it loses a real reference.
 */
const rejoinWarn = [];
const rejoined = ref([{ 'SHARED SERVERS': '100.71.0.1' }], rejoinWarn);
check('the two halves are rejoined',
  rejoined.length === 1 && rejoined[0] === 'SHARED SERVERS : 100.71.0.1',
  JSON.stringify(rejoined));
check('and the reconstruction is reported',
  rejoinWarn.some(w => w.indexOf('rejoined') >= 0), JSON.stringify(rejoinWarn));

check('the normalised fallback ignores spacing around a colon',
  A.fallbackKey('SHARED SERVERS : 100.71.0.1') === A.fallbackKey('SHARED SERVERS:100.71.0.1'),
  A.fallbackKey('SHARED SERVERS : 100.71.0.1'));
check('but it does NOT collapse hyphens or other punctuation',
  A.fallbackKey('RFX-DC01') !== A.fallbackKey('RFX DC01'),
  A.fallbackKey('RFX-DC01') + ' vs ' + A.fallbackKey('RFX DC01'));

// ── Alias registry: underscore is a delimiter, hyphen is a name ────────────

section('underscore delimits the path; hyphen belongs to the command name');

check('vpn_ipsec_phase1-interface -> vpn.ipsec.phase1-interface',
  S.canonicalPathFor('vpn_ipsec_phase1-interface') === 'vpn.ipsec.phase1-interface',
  String(S.canonicalPathFor('vpn_ipsec_phase1-interface')));
check('and NOT vpn.ipsec.phase1.interface',
  S.canonicalPathFor('vpn_ipsec_phase1-interface') !== 'vpn.ipsec.phase1.interface', 'distinct');
check('firewall_ssl-ssh-profile -> firewall.ssl-ssh-profile',
  S.canonicalPathFor('firewall_ssl-ssh-profile') === 'firewall.ssl-ssh-profile',
  String(S.canonicalPathFor('firewall_ssl-ssh-profile')));
check('log_syslogd_override-setting -> log.syslogd.override-setting',
  S.canonicalPathFor('log_syslogd_override-setting') === 'log.syslogd.override-setting',
  String(S.canonicalPathFor('log_syslogd_override-setting')));
check('vpn_ssl_web_portal -> vpn.ssl.web.portal',
  S.canonicalPathFor('vpn_ssl_web_portal') === 'vpn.ssl.web.portal',
  String(S.canonicalPathFor('vpn_ssl_web_portal')));
check('vpn_ssl_settings -> vpn.ssl.settings',
  S.canonicalPathFor('vpn_ssl_settings') === 'vpn.ssl.settings',
  String(S.canonicalPathFor('vpn_ssl_settings')));
check('an underscore variant of a hyphenated command still resolves, by explicit alias',
  S.canonicalPathFor('vpn_ipsec_phase1_interface') === 'vpn.ipsec.phase1-interface',
  String(S.canonicalPathFor('vpn_ipsec_phase1_interface')));

// ── End to end ─────────────────────────────────────────────────────────────

section('the reported failures, end to end');

const CFG =
  '#config-version=FG10E1-7.4.11-FW-build2878-260126:opmode=0:vdom=1:user=ENTERPRISE-ENGINEERS\n' +
  '#global_vdom=0:vd_name=RFX-OFFICE/RFX-OFFICE\n' +
  'system_interface:\n' +
  '  - wan1:\n      role: wan\n' +
  '  - RFX -OFFICE - INSIDE:\n      role: lan\n' +
  'firewall_address:\n' +
  '  - RFX-DC01 - 10.69.10.8:\n      subnet: "10.69.10.8 255.255.255.255"\n' +
  '  - SSL-VPN :10.44.1.0/24:\n      subnet: "10.44.1.0 255.255.255.0"\n' +
  'firewall_addrgrp:\n' +
  '  - RFX-AW-VL1765 address:\n      member:\n        - RFX-DC01 - 10.69.10.8\n' +
  'firewall_service_custom:\n' +
  '  - RFX Remote Desktop:\n      protocol: TCP\n      tcp-portrange: "3389"\n' +
  'firewall_service_group:\n' +
  '  - Published Apps:\n      member:\n        - RFX Remote Desktop\n' +
  'firewall_policy:\n' +
  '  - 81:\n      name: "RFX-OFFICE -- POC-VHI"\n      srcintf: "wan1"\n' +
  '      dstintf: "RFX -OFFICE - INSIDE"\n      action: accept\n      srcaddr: "all"\n' +
  '      dstaddr: "RFX-AW-VL1765 address"\n      service: "Published Apps"\n      logtraffic: all\n' +
  '  - 96:\n      name: "Block"\n      srcintf: "RFX -OFFICE - INSIDE"\n      dstintf: "wan1"\n' +
  '      action: deny\n      srcaddr: "RFX-DC01 - 10.69.10.8"\n      dstaddr: "all"\n      service: "ALL"\n' +
  'vpn_ipsec_phase1-interface:\n' +
  '  - OFFICE-SHARED:\n      interface: wan1\n      proposal: aes256-sha256\n      dhgrp: 14\n' +
  '  - EC Fiber IPSEC:\n      interface: wan1\n      proposal: aes256-sha256\n      dhgrp: 14\n' +
  'vpn_ipsec_phase2-interface:\n' +
  '  - OFFICE-SHARED-P2:\n      phase1name: OFFICE-SHARED\n      proposal: aes256-sha256\n' +
  'vpn_ssl_settings:\n  servercert: "Fortinet_Factory"\n  source-interface: wan1\n' +
  'log_setting:\n  fwpolicy-implicit-log: enable\n' +
  'log_disk_setting:\n  status: enable\n' +
  'log_syslogd_override-setting:\n  status: enable\n  server: "10.69.10.50"\n';

const m = parser.parseConfig(CFG);

check('IPsec phase 1 interfaces are found',
  m.vpn.ipsecPhase1.length === 2, String(m.vpn.ipsecPhase1.length));
check('their exact names survive, spaces and all',
  m.vpn.ipsecPhase1.map(x => x._key).indexOf('EC Fiber IPSEC') >= 0,
  JSON.stringify(m.vpn.ipsecPhase1.map(x => x._key)));
check('phase 2 is found and links through phase1name',
  m.vpn.ipsecPhase2.length === 1 &&
  String(m.vpn.ipsecPhase2[0].phase1name) === 'OFFICE-SHARED',
  JSON.stringify(m.vpn.ipsecPhase2.map(x => x.phase1name)));
check('SSL-VPN settings are found',
  !!(m.vpn.sslSettings && m.vpn.sslSettings.servercert), JSON.stringify(m.vpn.sslSettings));
check('log settings are found', !!m.logging.setting, JSON.stringify(m.logging.setting));
check('the syslog override-setting counts as an off-box destination',
  m.logging.syslog.length >= 1, String(m.logging.syslog.length));
check('address object names are intact',
  m.addresses.objects.map(a => a._key).indexOf('SSL-VPN :10.44.1.0/24') >= 0,
  JSON.stringify(m.addresses.objects.map(a => a._key)));
check('a deny policy is found', m.policies.some(p => p.action === 'deny'),
  JSON.stringify(m.policies.map(p => p.action)));
check('nothing failed reconciliation',
  m.reconciliation.length === 0, JSON.stringify(m.reconciliation));

const results = checks.runChecks(m);
const byId = id => results.find(r => r.id === id);

check('addresses resolve — no "defined objects are unresolved"',
  byId('rpc-addresses-resolved').status === 'pass',
  byId('rpc-addresses-resolved').detail);
check('services resolve',
  byId('rpc-services-resolved').status === 'pass',
  byId('rpc-services-resolved').detail);
check('the deny-logging check is no longer blind to deny rules',
  byId('rpc-deny-unlogged').status !== 'not-assessable' ||
  !/No enabled deny policies were found/.test(byId('rpc-deny-unlogged').detail || ''),
  byId('rpc-deny-unlogged').detail);
check('IPsec checks are no longer "not configured"',
  !/No IPsec phase 1 interfaces are configured/.test(
    (byId('vpn-ipsec-proposals') || {}).detail || ''),
  (byId('vpn-ipsec-proposals') || {}).detail);
check('SSL-VPN checks are no longer "not present"',
  !/No SSL-VPN settings are present/.test((byId('vpn-sslvpn-interface') || {}).detail || ''),
  (byId('vpn-sslvpn-interface') || {}).detail);
check('logging checks are no longer "not present"',
  !/No log settings are present/.test((byId('log-destination') || {}).detail || ''),
  (byId('log-destination') || {}).detail);

const notAssessed = results.filter(r => r.status === 'not-assessable').length;
check('coverage is materially better than the reported run',
  results.length - notAssessed >= results.length * 0.6,
  (results.length - notAssessed) + ' of ' + results.length + ' assessed');

// ── The reconciliation guard ───────────────────────────────────────────────

section('raw entries that vanish in normalisation are a PARSER error');

/*
 * "No IPsec phase 1 interfaces are configured" is a claim about the DEVICE.
 * "We failed to read the section" is a claim about US. When a section arrives
 * with entries and none survive, only the second is true, and the audit must
 * say so rather than reporting the first.
 */
check('the model carries a reconciliation record',
  Array.isArray(m.reconciliation), 'present');
check('and section states expose parse_error as distinct from absent',
  S.STATE.PARSE_ERROR === 'parse_error' && S.STATE.ABSENT === 'absent', 'distinct');

done();
