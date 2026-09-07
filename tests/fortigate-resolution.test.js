'use strict';

/**
 * FortiGate object resolution — addresses, groups, zones and VIPs.
 *
 * THE DEFECT THIS SUITE EXISTS TO PREVENT COMING BACK
 *
 * The audit used to decide whether a rule was scoped by reading the NAME in the
 * policy. isAny() matched the literals 'all', 'any' and '*' and nothing else,
 * so every other name was taken to mean "restricted" — and the audit never
 * looked inside an address object or a group at all.
 *
 *   config firewall address
 *       edit "Internal_Servers"
 *           set subnet 0.0.0.0 0.0.0.0
 *
 * That rule permits the entire internet and was reported as properly scoped.
 * The failure is silent and it points the wrong way: towards a clean report.
 *
 * THE PROPERTIES PROTECTED HERE
 *
 *   scope comes from contents        never from the object's name
 *   a group is as wide as its widest member
 *   groups expand recursively        and a cycle terminates rather than hangs
 *   unresolved is not narrow         a name we cannot find must never read as
 *                                    a restriction
 *   zones expand to interfaces       or every direction check silently stops
 *                                    running on a zone-based firewall
 *   the finding says WHICH object    "Group → Legacy_Any → 0.0.0.0/0", because
 *                                    a policy id alone gets disputed
 *
 *   node tests/fortigate-resolution.test.js <repoRoot>
 */

const fs = require('fs');
const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('fortigate-resolution');

const A = require(path.join(ROOT, 'lib', 'fortigate-address'));
const P = require(path.join(ROOT, 'lib', 'fortigate-policy'));
const C = require(path.join(ROOT, 'lib', 'fortigate-checks'));

// ── Subnet and mask arithmetic ─────────────────────────────────────────────

section('subnet parsing — the shapes FortiOS actually writes');

check('space-separated mask', JSON.stringify(A.parseSubnet('10.0.0.0 255.255.255.0'))
  === JSON.stringify({ ip: 167772160, prefix: 24 }), JSON.stringify(A.parseSubnet('10.0.0.0 255.255.255.0')));
check('CIDR notation', A.parseSubnet('10.0.0.0/24').prefix === 24, A.parseSubnet('10.0.0.0/24').prefix);
check('bare address is a /32', A.parseSubnet('10.0.0.1').prefix === 32, A.parseSubnet('10.0.0.1').prefix);
check('garbage is null, not a default', A.parseSubnet('not-an-ip') === null,
  String(A.parseSubnet('not-an-ip')));

check('0.0.0.0 0.0.0.0 is ANY', A.subnetIsAny(A.parseSubnet('0.0.0.0 0.0.0.0')) === true, 'any');
check('0.0.0.0/0 is ANY', A.subnetIsAny(A.parseSubnet('0.0.0.0/0')) === true, 'any');
check('a real subnet is not ANY', A.subnetIsAny(A.parseSubnet('10.0.0.0/8')) === false, 'not any');

check('a non-contiguous mask is refused rather than guessed',
  A.maskToPrefix('255.0.255.0') === null, String(A.maskToPrefix('255.0.255.0')));

check('a wildcard with an all-zero mask matches everything',
  A.wildcardIsAny('10.0.0.0 0.0.0.0') === true, 'any');
check('a wildcard with a real mask does not',
  A.wildcardIsAny('10.0.0.0 0.0.0.255') === false, 'not any');

check('an iprange spanning the space is ANY',
  A.rangeIsAny('0.0.0.0', '255.255.255.255') === true, 'any');
check('a real iprange is not',
  A.rangeIsAny('10.0.0.1', '10.0.0.50') === false, 'not any');

check('::/0 is ANY', A.ip6IsAny('::/0') === true, 'any');

// ── The headline defect ────────────────────────────────────────────────────

section('an object is judged by its CONTENTS, never its name');

/*
 * The user-reported case, verbatim: an object whose name reads as restrictive
 * and whose subnet is the whole internet.
 */
check('an object named "Internal_Servers" holding 0.0.0.0/0 is ANY',
  A.addressIsAny({ name: 'Internal_Servers', subnet: '0.0.0.0 0.0.0.0' }) === true,
  'ANY — the name is prose, the subnet is the fact');

check('the same object with a real subnet is not ANY',
  A.addressIsAny({ name: 'Internal_Servers', subnet: '10.10.10.0 255.255.255.0' }) === false,
  'scoped');

check('an object literally named "Any" but scoped to a /24 is NOT any',
  A.addressIsAny({ name: 'Any_Internal', subnet: '10.10.10.0 255.255.255.0' }) === false,
  'the name cuts both ways');

check('type: all is ANY', A.addressIsAny({ name: 'x', type: 'all' }) === true, 'any');

check('a VIP with extip 0.0.0.0 answers on every address',
  A.addressIsAny({ name: 'vip1', extip: '0.0.0.0', mappedip: '10.0.0.5' }) === true, 'any');
check('a VIP with a real extip does not',
  A.addressIsAny({ name: 'vip2', extip: '196.1.1.5', mappedip: '10.0.0.5' }) === false, 'scoped');

// ── Group expansion ────────────────────────────────────────────────────────

section('a group is as wide as its widest member');

const model = {
  addresses: {
    objects: [
      { name: 'Web01',       subnet: '10.10.10.5 255.255.255.255' },
      { name: 'Host2',       subnet: '10.10.10.6 255.255.255.255' },
      { name: 'Legacy_Any',  subnet: '0.0.0.0 0.0.0.0' },
      { name: 'Host3',       subnet: '10.10.20.7 255.255.255.255' },
      { name: 'Host4',       subnet: '10.10.20.8 255.255.255.255' },
    ],
    groups: [
      // The user's Phase 2 example: Group A contains hosts and Group B.
      { name: 'Group_A', member: ['Web01', 'Host2', 'Group_B'] },
      { name: 'Group_B', member: ['Host3', 'Host4'] },
      // The user's Phase 3 example: one wide member among precise ones.
      { name: 'Servers_Group', member: ['Web01', 'Legacy_Any'] },
      // A cycle. A device will hold this quite happily.
      { name: 'Loop_A', member: ['Loop_B'] },
      { name: 'Loop_B', member: ['Loop_A'] },
      { name: 'Empty_Group', member: [] },
    ],
    vips: [{ name: 'PublishedApp', extip: '196.1.1.5', mappedip: '10.10.10.5' }],
  },
  system: {
    zones: [{ name: 'ZONE_WAN', interface: ['wan1', 'wan2'] }],
    interfaces: [
      { name: 'wan1', role: 'wan' },
      { name: 'wan2', role: 'wan' },
      { name: 'internal', role: 'lan' },
    ],
  },
};

const idx = A.buildAddressIndex(model);

const groupA = A.resolveAddresses(idx, ['Group_A']);
check('a nested group expands recursively',
  groupA.members.sort().join(',') === 'Host2,Host3,Host4,Web01',
  groupA.members.sort().join(','));
check('and a fully precise group is NOT any', groupA.any === false, String(groupA.any));
check('nothing in it is unresolved', groupA.unresolved.length === 0, String(groupA.unresolved.length));

const servers = A.resolveAddresses(idx, ['Servers_Group']);
check('a group with ONE wide member is ANY, however precise the rest',
  servers.any === true, 'ANY');
check('and the finding can name the chain that did it',
  servers.anyVia === 'Servers_Group → Legacy_Any', servers.anyVia);

const loop = A.resolveAddresses(idx, ['Loop_A']);
check('a self-referencing group terminates rather than hanging',
  Array.isArray(loop.members), 'returned');

const empty = A.resolveAddresses(idx, ['Empty_Group']);
check('an EMPTY group is unresolved, not narrow',
  empty.unresolved.indexOf('Empty_Group') >= 0 && empty.any === false,
  'unresolved: ' + JSON.stringify(empty.unresolved));

// ── Unresolved is not narrow ───────────────────────────────────────────────

section('a name we cannot find must never read as a restriction');

const missing = A.resolveAddresses(idx, ['Object_That_Does_Not_Exist']);
check('an unknown name is reported unresolved',
  missing.unresolved.length === 1, JSON.stringify(missing.unresolved));
check('and is NOT silently treated as any', missing.any === false, String(missing.any));
check('and contributes no members it cannot vouch for',
  missing.members.length === 0, String(missing.members.length));

const literal = A.resolveAddresses(idx, ['all']);
check('the literal "all" is still ANY without any lookup',
  literal.any === true, 'any');

check('an empty list resolves to nothing rather than to any',
  A.resolveAddresses(idx, []).any === false, 'not any');

// ── Zones ──────────────────────────────────────────────────────────────────

section('zones expand to interfaces');

const zones = A.buildZoneIndex(model);
check('a zone expands to its member interfaces',
  A.expandInterfaces(['ZONE_WAN'], zones).sort().join(',') === 'wan1,wan2',
  A.expandInterfaces(['ZONE_WAN'], zones).join(','));
check('a bare interface passes through unchanged',
  A.expandInterfaces(['internal'], zones).join(',') === 'internal', 'internal');

/*
 * The consequence, and the reason this matters: without zone expansion the WAN
 * test compared "ZONE_WAN" against ['wan1','wan2'], never matched, and every
 * policy on a zone-based firewall resolved to direction 'unknown' — which
 * silently switched off every inbound and outbound check in the audit.
 */
const zonedPolicy = { srcintf: ['ZONE_WAN'], dstintf: ['internal'], srcaddr: ['all'], dstaddr: ['Web01'] };
check('a zone-based policy is now classified as inbound, not unknown',
  P.policyDirection(model, zonedPolicy, null, zones) === 'inbound',
  P.policyDirection(model, zonedPolicy, null, zones));

check('the reverse direction is classified too',
  P.policyDirection(model, { srcintf: ['internal'], dstintf: ['ZONE_WAN'] }, null, zones) === 'outbound',
  P.policyDirection(model, { srcintf: ['internal'], dstintf: ['ZONE_WAN'] }, null, zones));

// ── End to end through analysePolicies ─────────────────────────────────────

section('the analysis uses resolved scope, not names');

const fullModel = Object.assign({}, model, {
  policies: [
    { id: '1', name: 'Looks scoped', status: 'enable', action: 'accept',
      srcintf: ['ZONE_WAN'], dstintf: ['internal'],
      srcaddr: ['Servers_Group'], dstaddr: ['Web01'], service: ['HTTPS'] },
    { id: '2', name: 'Genuinely scoped', status: 'enable', action: 'accept',
      srcintf: ['internal'], dstintf: ['ZONE_WAN'],
      srcaddr: ['Group_A'], dstaddr: ['Web01'], service: ['HTTPS'] },
    { id: '3', name: 'Undefined object', status: 'enable', action: 'accept',
      srcintf: ['internal'], dstintf: ['ZONE_WAN'],
      srcaddr: ['Nowhere_To_Be_Found'], dstaddr: ['Web01'], service: ['HTTPS'] },
  ],
  services: { custom: [], groups: [] },
});

const analysis = P.analysePolicies(fullModel);
const byId = id => analysis.policies.find(a => a.id === id);

check('a rule scoped to a group containing 0.0.0.0/0 is flagged as any-source',
  byId('1').anySrc === true, 'FLAGGED — this is the bug that was reported');
check('and the evidence names the object chain',
  byId('1').anySrcVia === 'Servers_Group → Legacy_Any', byId('1').anySrcVia);

check('a genuinely scoped rule is NOT flagged',
  byId('2').anySrc === false, 'clean');

check('a rule naming an undefined object is not called scoped',
  byId('3').addressesResolved === false, 'unresolved');
check('and it is not called any-source either — unknown is its own state',
  byId('3').anySrc === false, 'neither');
check('so it is excluded from clean, via fullyResolved',
  byId('3').fullyResolved === false, 'excluded');

check('service resolution is tracked separately from address resolution',
  byId('3').servicesResolved === true && byId('3').addressesResolved === false,
  'independent — each check gates on what it actually needs');

check('the analysis exposes address-unresolved policies for the coverage check',
  analysis.unresolvedAddressPolicies().map(a => a.id).join(',') === '3',
  analysis.unresolvedAddressPolicies().map(a => a.id).join(','));

// ── The coverage check ─────────────────────────────────────────────────────

section('the new coverage check');

const addrCheck = C.CHECKS.find(c => c.id === 'rpc-addresses-resolved');
check('rpc-addresses-resolved exists', !!addrCheck, addrCheck ? 'present' : 'MISSING');
check('it is categorised', C.categoryFor(addrCheck) === 'risky-policy-conditions',
  C.categoryFor(addrCheck));

const addrRes = addrCheck.run(fullModel, { analysis });
check('an undefined address object is NOT-ASSESSABLE, not a failure',
  addrRes.status === 'not-assessable', addrRes.status);
check('because the device is not at fault — our coverage is',
  /not defined in this config/.test(addrRes.detail), addrRes.detail);
check('and the offending name is reported so it can be sent',
  JSON.stringify(addrRes.evidence || {}).indexOf('Nowhere_To_Be_Found') >= 0,
  JSON.stringify(addrRes.evidence));

const anySrcCheck = C.CHECKS.find(c => c.id === 'rpc-any-source');
const anySrcRes = anySrcCheck.run(fullModel, { analysis });
check('the any-source check now FAILS on the group-hidden case',
  anySrcRes.status === 'fail', anySrcRes.status);
check('and its evidence carries the resolution chain',
  JSON.stringify(anySrcRes.evidence).indexOf('Legacy_Any') >= 0,
  JSON.stringify(anySrcRes.evidence));

// ── Parser indexing ────────────────────────────────────────────────────────

section('the parser indexes what the resolver needs');

const parserJs = fs.readFileSync(path.join(ROOT, 'lib', 'fortigate-parser.js'), 'utf8');
const code = parserJs.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

['address', 'addrgrp', 'vip', 'vipgrp', 'address6', 'addrgrp6'].forEach((table) => {
  check("firewall '" + table + "' is indexed",
    new RegExp("pick\\(firewall, '" + table + "'\\)").test(code), 'indexed');
});
check("system 'zone' is indexed", /pick\(system, 'zone'\)/.test(code), 'indexed');
check('schedules are indexed', /schedules:/.test(code), 'indexed');
check('identity tables are indexed', /identity:/.test(code), 'indexed');

done();
