'use strict';

/**
 * FortiGate ingestion — layouts, metadata, collection shapes and section state.
 *
 * WHAT WENT WRONG, AND WHAT THIS SUITE HOLDS IN PLACE
 *
 * An upload produced 37 findings against a config the parser had not read.
 * Each finding was individually defensible — "admin-telnet is not present in
 * this config" — and together they were a fabrication, because the parser
 * assumed one hierarchy (`system:` / `firewall:` maps), found neither in a
 * flattened export, defaulted every section to {} and carried on.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   no single canonical hierarchy   flat, nested and VDOM layouts all read
 *   layout is detected and recorded never inferred from one key's presence
 *   metadata is read BEFORE YAML    firmware lives in comments, which every
 *                                   YAML parser discards
 *   ids are ids, not positions      `- 81:` is policy 81, never policy 0
 *   present_empty != absent         and neither is a statement about the device
 *   nothing recognised -> refuse    a report that invents findings from an
 *                                   empty model is worth less than nothing
 *   global and VDOM stay separate   global objects are not copied into VDOMs
 *
 *   node tests/fortigate-ingestion.test.js <repoRoot>
 */

const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('fortigate-ingestion');

const M = require(path.join(ROOT, 'lib', 'fortigate-metadata'));
const S = require(path.join(ROOT, 'lib', 'fortigate-sections'));
const parser = require(path.join(ROOT, 'lib', 'fortigate-parser'));
const checks = require(path.join(ROOT, 'lib', 'fortigate-checks'));

// ── Metadata, read before the YAML loader ──────────────────────────────────

section('metadata comes from the header comments, which YAML discards');

const HEADER =
  '#config-version=FG10E1-7.4.11-FW-build2878-260126:opmode=0:vdom=1:user=ENTERPRISE-ENGINEERS\n' +
  '#conf_file_ver=987654321\n' +
  '#buildno=2878\n' +
  '#global_vdom=0:vd_name=RFX-OFFICE/RFX-OFFICE\n';

const meta = M.parseMetadata(HEADER + 'firewall_policy:\n');

check('the FortiOS version is read', meta.version === '7.4.11', meta.version);
check('the build is read', meta.build === '2878', meta.build);
check('the model token is read', meta.model === 'FG10E1', meta.model);
check('the full config-version is preserved verbatim',
  meta.configVersion.indexOf('FG10E1-7.4.11-FW-build2878-260126') === 0, meta.configVersion);
check('operating mode is read', meta.opMode === '0', meta.opMode);
check('VDOM mode is read as a boolean', meta.vdomEnabled === true, String(meta.vdomEnabled));
check('the current VDOM is read, and the name/name form is split',
  meta.currentVdom === 'RFX-OFFICE', meta.currentVdom);
check('the global-vdom indicator is read', meta.globalVdom === '0', meta.globalVdom);
check('the exporting user is read',
  meta.exportUser === 'ENTERPRISE-ENGINEERS', meta.exportUser);
check('the raw header lines are kept', meta.raw.length === 4, String(meta.raw.length));

/*
 * Model names contain a varying number of dashes, so splitting the token on '-'
 * by POSITION put a firmware string in the model field on exactly the platforms
 * nobody tested against.
 */
const vmToken = M.parseVersionToken('FGT_VM64_KVM-7.2.8-FW-build1639-240402');
check('a model name containing separators survives',
  vmToken.model === 'FGT_VM64_KVM', vmToken.model);
check('and its version is still found', vmToken.version === '7.2.8', vmToken.version);

const noHeader = M.parseMetadata('firewall_policy:\n');
check('a file with no header warns rather than asserting firmware is absent',
  noHeader.warnings.length > 0 && /could not be read/.test(noHeader.warnings[0]),
  noHeader.warnings[0]);
check('and infers nothing it was not told',
  noHeader.version === null && noHeader.model === null && noHeader.vdomEnabled === null,
  'all null');

const badVersion = M.parseMetadata('#config-version=GARBAGE-TOKEN\n');
check('an unparseable version warns and quotes the raw line',
  badVersion.warnings.some(w => w.indexOf('#config-version=GARBAGE-TOKEN') >= 0),
  badVersion.warnings.join(' | '));

// ── The alias registry ─────────────────────────────────────────────────────

section('flattened keys map to canonical FortiGate command paths');

const EXPECTED = {
  'system_interface':            'system.interface',
  'system_admin':                'system.admin',
  'system_settings':             'system.settings',
  'system_zone':                 'system.zone',
  'firewall_policy':             'firewall.policy',
  'firewall_address':            'firewall.address',
  'firewall_addrgrp':            'firewall.addrgrp',
  'firewall_service_custom':     'firewall.service.custom',
  'firewall_service_group':      'firewall.service.group',
  'firewall_ssl-ssh-profile':    'firewall.ssl-ssh-profile',
  'vpn_ssl_settings':            'vpn.ssl.settings',
  'vpn_ipsec_phase1-interface':  'vpn.ipsec.phase1-interface',
  'router_static':               'router.static',
  'router_bgp':                  'router.bgp',
  'log_setting':                 'log.setting',
  'user_local':                  'user.local',
  'user_group':                  'user.group',
};

Object.keys(EXPECTED).forEach((k) => {
  check(k + ' -> ' + EXPECTED[k],
    S.canonicalPathFor(k) === EXPECTED[k], String(S.canonicalPathFor(k)));
});

check('hyphens and underscores are interchangeable at lookup',
  S.canonicalPathFor('firewall_ssl_ssh_profile') === 'firewall.ssl-ssh-profile',
  String(S.canonicalPathFor('firewall_ssl_ssh_profile')));
check('the canonical path resolves to itself',
  S.canonicalPathFor('firewall.policy') === 'firewall.policy', 'idempotent');
check('an unknown key resolves to null rather than a guess',
  S.canonicalPathFor('something_invented') === null,
  String(S.canonicalPathFor('something_invented')));

// ── Collection shapes ──────────────────────────────────────────────────────

section('policy ids are ids, never list positions');

/*
 * THE BUG THIS PINS DOWN. A list of one-key wrappers is the shape the reported
 * export uses. The old reader looked for name/policyid/id ON THE WRAPPER, found
 * none, and fell back to the ARRAY INDEX — so policy 81 became policy 0 and
 * every field sat one level deeper than anything looked.
 */
const wrapped = S.normaliseCollection([
  { 81: { name: 'RFX-OFFICE -- POC-VHI', action: 'accept' } },
  { 96: { name: 'Second', action: 'accept' } },
], { canonicalPath: 'firewall.policy', originalKey: 'firewall_policy' });

check('a list of one-key wrappers is read', wrapped.state === S.STATE.WITH_DATA, wrapped.state);
check('ids are preserved exactly, not renumbered',
  wrapped.records.map(r => r.object_id).join(',') === '81,96',
  wrapped.records.map(r => r.object_id).join(','));
check('and are NOT the list positions',
  wrapped.records[0].object_id !== '0', wrapped.records[0].object_id);
check('the body is unwrapped, not left nested',
  wrapped.records[0].raw_object.name === 'RFX-OFFICE -- POC-VHI',
  wrapped.records[0].raw_object.name);
check('source_index is recorded separately from the id',
  wrapped.records[0].source_index === 0 && wrapped.records[0].object_id === '81',
  'index 0, id 81');
check('non-sequential ids survive',
  S.normaliseCollection([{ 1: {} }, { 2: {} }, { 5: {} }, { 81: {} }, { 96: {} }], {})
    .records.map(r => r.object_id).join(',') === '1,2,5,81,96',
  S.normaliseCollection([{ 1: {} }, { 2: {} }, { 5: {} }, { 81: {} }, { 96: {} }], {})
    .records.map(r => r.object_id).join(','));

check('a map keyed by id is read too',
  S.normaliseCollection({ 81: { name: 'x' } }, {}).records[0].object_id === '81', '81');
check('a list of plain objects is read too',
  S.normaliseCollection([{ policyid: 81, name: 'x' }], {}).records[0].object_id === '81', '81');

check('every record carries its canonical path and original key',
  wrapped.records[0].canonical_path === 'firewall.policy' &&
  wrapped.records[0].original_top_level_key === 'firewall_policy', 'both');

// ── Section state ──────────────────────────────────────────────────────────

section('present-but-empty is not absent, and neither means the device lacks it');

check('a null section is present_empty',
  S.normaliseCollection(null, {}).state === S.STATE.EMPTY,
  S.normaliseCollection(null, {}).state);
check('an empty list is present_empty',
  S.normaliseCollection([], {}).state === S.STATE.EMPTY,
  S.normaliseCollection([], {}).state);
check('an empty map is present_empty',
  S.normaliseCollection({}, {}).state === S.STATE.EMPTY,
  S.normaliseCollection({}, {}).state);

// ── Layouts, end to end ────────────────────────────────────────────────────

section('every layout reads, and the layout is recorded');

const FLAT = HEADER +
  'system_interface:\n' +
  '  - RFX-OFFICE-INSIDE:\n      vdom: "RFX-OFFICE"\n      role: lan\n' +
  '  - wan1:\n      vdom: "RFX-OFFICE"\n      role: wan\n' +
  'system_admin:\n' +
  'firewall_policy:\n' +
  '  - 81:\n' +
  '      name: "RFX-OFFICE -- POC-VHI"\n      srcintf: "wan1"\n      dstintf: "RFX-OFFICE-INSIDE"\n' +
  '      action: accept\n      srcaddr: "all"\n      dstaddr: "all"\n      service: "ALL"\n' +
  '  - 96:\n' +
  '      name: "Looks scoped"\n      srcintf: "RFX-OFFICE-INSIDE"\n      dstintf: "wan1"\n' +
  '      action: accept\n      srcaddr: "Internal_Servers"\n      dstaddr: "all"\n      service: "HTTPS"\n' +
  'firewall_address:\n' +
  '  - Internal_Servers:\n      subnet: "0.0.0.0 0.0.0.0"\n';

const flat = parser.parseConfig(FLAT);

check('the flattened layout is detected',
  flat.layout.detected.indexOf('flat') >= 0, JSON.stringify(flat.layout.detected));
check('and the detection records why',
  flat.layout.signals.length > 0, JSON.stringify(flat.layout.signals));
check('policies are read with their real ids',
  flat.policies.map(p => p.id).join(',') === '81,96',
  flat.policies.map(p => p.id).join(','));
check('interfaces are read', flat.system.interfaces.length === 2,
  String(flat.system.interfaces.length));
check('the WAN role is visible, so direction checks can run',
  flat.system.interfaces.some(i => String(i.role).toLowerCase() === 'wan'), 'wan found');
check('address objects are read', flat.addresses.objects.length === 1,
  String(flat.addresses.objects.length));

check('firmware is read from the header comment',
  flat.device.firmware === '7.4.11', String(flat.device.firmware));
check('model too', flat.device.model === 'FG10E1', String(flat.device.model));
check('and the build', flat.device.build === '2878', String(flat.device.build));

check('objects are scoped to the VDOM they declare',
  flat.layout.vdoms.join(',') === 'RFX-OFFICE', flat.layout.vdoms.join(','));
check('and the VDOM assignment carries an evidence note',
  !!(flat.layout.vdomAssignment && flat.layout.vdomAssignment.note),
  flat.layout.vdomAssignment && flat.layout.vdomAssignment.basis);

check('an empty system_admin is present_empty, not absent',
  flat.sectionStates['system.admin'] === 'present_empty',
  flat.sectionStates['system.admin']);
check('a populated section is present_with_data',
  flat.sectionStates['firewall.policy'] === 'present_with_data',
  flat.sectionStates['firewall.policy']);
check('a section the file never mentions is absent',
  flat.sectionStates['vpn.ssl.settings'] === 'absent',
  flat.sectionStates['vpn.ssl.settings']);

// Nested layout still reads — the shape originally assumed must not regress.
const nested = parser.parseConfig(
  'system:\n  interface:\n    wan1:\n      role: wan\n' +
  'firewall:\n  policy:\n    - policyid: 7\n      name: n\n      action: accept\n');
check('the nested layout still reads',
  nested.policies.length === 1 && nested.policies[0].id === '7',
  JSON.stringify(nested.policies.map(p => p.id)));
check('and is detected as nested',
  nested.layout.detected.indexOf('nested') >= 0, JSON.stringify(nested.layout.detected));

// VDOM layout.
const vdom = parser.parseConfig(
  'global:\n  system:\n    global:\n      admin-telnet: disable\n' +
  'vdom:\n  - VDOM-A:\n      firewall:\n        policy:\n          - 12:\n              name: v\n              action: accept\n');
check('the VDOM layout is detected',
  vdom.layout.detected.indexOf('vdom') >= 0, JSON.stringify(vdom.layout.detected));
check('a VDOM is named', vdom.layout.vdoms.indexOf('VDOM-A') >= 0,
  JSON.stringify(vdom.layout.vdoms));
check('a policy inside a VDOM is read with its id',
  vdom.policies.length === 1 && vdom.policies[0].id === '12',
  JSON.stringify(vdom.policies.map(p => p.id)));
check('a global setting is read from the global scope',
  vdom.system.global['admin-telnet'] === 'disable',
  String(vdom.system.global['admin-telnet']));
check('and global objects are NOT duplicated into the VDOM',
  vdom.policies.length === 1, 'one policy, not two');

// ── The vacuous-audit guard ────────────────────────────────────────────────

section('a file we recognised nothing in is refused, not audited');

let refused = null;
try {
  parser.parseConfig('some_tool_export:\n  things:\n    - a: 1\n');
} catch (err) { refused = err; }

check('a YAML file with no recognisable sections throws',
  refused instanceof parser.FortigateParseError, refused && refused.constructor.name);
check('and the message names what it DID find, so the sender can act',
  refused && /some_tool_export/.test(refused.message), refused && refused.message);
check('and says which layouts are expected',
  refused && /firewall_policy/.test(refused.message), 'names an expected key');

check('a file with one recognisable section is NOT refused',
  parser.parseConfig('firewall_policy:\n  - 1:\n      name: x\n      action: accept\n')
    .counts.recognisedSections >= 1, 'accepted');

// ── The findings that used to be fabricated ────────────────────────────────

section('the misleading findings are gone');

const results = checks.runChecks(flat);
const byId = id => results.find(r => r.id === id);

const fw = byId('system-firmware');
check('firmware is no longer reported as unreadable',
  fw && !/could not be read/.test(fw.detail || ''), fw && fw.detail);
check('and it names the running version',
  fw && /7\.4\.11/.test(fw.detail || ''), fw && fw.detail);

const adminDefault = byId('admin-default-account');
check('an empty admin section does not claim the device has no administrators',
  adminDefault && !/No administrator accounts were found/.test(adminDefault.detail || ''),
  adminDefault && adminDefault.detail);
check('it says the section was present but empty',
  adminDefault && /present but contained no entries/.test(adminDefault.detail || ''),
  adminDefault && adminDefault.detail);
check('and it is not-assessable rather than a pass',
  adminDefault && adminDefault.status === 'not-assessable', adminDefault && adminDefault.status);
check('the section state travels as evidence',
  adminDefault && adminDefault.evidence &&
  adminDefault.evidence.section_state === 'present_empty',
  JSON.stringify(adminDefault && adminDefault.evidence));

const anyAny = byId('policy-any-any');
check('the any/any/ALL rule is now found',
  anyAny && anyAny.status === 'fail', anyAny && anyAny.status);

const anySrc = byId('rpc-any-source');
check('and the group-hidden 0.0.0.0/0 source is found too',
  anySrc && anySrc.status === 'fail', anySrc && anySrc.detail);

/*
 * The headline number. Before this work the same file produced 37
 * not-assessable findings and no usable coverage; the audit now answers most of
 * the benchmark, and where it cannot it says which section was missing.
 */
const notAssessable = results.filter(r => r.status === 'not-assessable').length;
check('most checks now produce a real answer',
  results.length - notAssessable > results.length / 2,
  (results.length - notAssessable) + ' of ' + results.length + ' assessed');

done();
