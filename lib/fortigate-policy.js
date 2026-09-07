'use strict';

/**
 * lib/fortigate-policy.js — reading the rulebase rather than the device.
 *
 * The device-hardening checks in lib/fortigate-checks.js ask whether telnet is
 * off and whether admins have trusted hosts. This module answers a different
 * question: what does the POLICY TABLE actually allow, in which direction, and
 * how permissively.
 *
 * ══ WHY SERVICE RESOLUTION IS THE WHOLE GAME ══
 *
 * "Does this firewall expose RDP to the internet" cannot be answered by looking
 * for a policy whose service list contains the string 'RDP'. A site that defined
 * `Remote-Desktop` as tcp/3389 — which is what most sites do — would read as
 * clean. So every policy's service list is resolved through the custom service
 * and service group tables down to actual protocol/port ranges, and risk is
 * matched on PORTS, with predefined service names as a second route in.
 *
 * ══ WHAT IS NOT KNOWN IS NOT SAFE ══
 *
 * A service name that resolves to nothing — a predefined name we do not carry,
 * a group referencing a missing member, a masked table — is reported as
 * UNRESOLVED, and every caller treats an unresolved policy as un-assessed
 * rather than clean. A rulebase we could only half read must not score like a
 * rulebase that was fully read and found tidy.
 */

const { asEntries, names, str, pick, isAny, isAnyService } = require('./fortigate-parser');
const {
  buildAddressIndex, resolveAddresses, buildZoneIndex, expandInterfaces,
} = require('./fortigate-address');

/* ── Predefined FortiGate services ─────────────────────────────────────────
 *
 * The subset that carries risk, plus the common ones needed so a policy is not
 * reported as unresolved for referencing DNS. Ports are the DESTINATION ports.
 *
 * Not exhaustive on purpose: anything missing surfaces as unresolved, which is
 * visible, rather than as an empty port set, which would read as harmless.
 */
const PREDEFINED = {
  ALL:          { any: true },
  ANY:          { any: true },
  ALL_TCP:      { tcp: [[1, 65535]] },
  ALL_UDP:      { udp: [[1, 65535]] },
  ALL_ICMP:     { icmp: true },
  PING:         { icmp: true },
  TRACEROUTE:   { icmp: true },

  FTP:          { tcp: [[21, 21]] },
  FTP_GET:      { tcp: [[21, 21]] },
  FTP_PUT:      { tcp: [[21, 21]] },
  SSH:          { tcp: [[22, 22]] },
  TELNET:       { tcp: [[23, 23]] },
  SMTP:         { tcp: [[25, 25]] },
  SMTPS:        { tcp: [[465, 465]] },
  DNS:          { tcp: [[53, 53]], udp: [[53, 53]] },
  DHCP:         { udp: [[67, 68]] },
  TFTP:         { udp: [[69, 69]] },
  HTTP:         { tcp: [[80, 80]] },
  POP3:         { tcp: [[110, 110]] },
  POP3S:        { tcp: [[995, 995]] },
  'ONC-RPC':    { tcp: [[111, 111]], udp: [[111, 111]] },
  NNTP:         { tcp: [[119, 119]] },
  NTP:          { udp: [[123, 123]] },
  'DCE-RPC':    { tcp: [[135, 135]] },
  NetBIOS:      { tcp: [[139, 139]], udp: [[137, 138]] },
  SAMBA:        { tcp: [[139, 139]] },
  IMAP:         { tcp: [[143, 143]] },
  IMAPS:        { tcp: [[993, 993]] },
  SNMP:         { udp: [[161, 162]] },
  BGP:          { tcp: [[179, 179]] },
  LDAP:         { tcp: [[389, 389]] },
  HTTPS:        { tcp: [[443, 443]] },
  SMB:          { tcp: [[445, 445]] },
  SYSLOG:       { udp: [[514, 514]] },
  RSH:          { tcp: [[514, 514]] },
  IKE:          { udp: [[500, 500]] },
  RIP:          { udp: [[520, 520]] },
  LDAP_UDP:     { udp: [[389, 389]] },
  SOCKS:        { tcp: [[1080, 1080]] },
  WINFRAME:     { tcp: [[1494, 1494]] },
  L2TP:         { udp: [[1701, 1701]] },
  PPTP:         { tcp: [[1723, 1723]] },
  H323:         { tcp: [[1720, 1720]] },
  'MS-SQL':     { tcp: [[1433, 1434]] },
  MYSQL:        { tcp: [[3306, 3306]] },
  RDP:          { tcp: [[3389, 3389]] },
  SQUID:        { tcp: [[3128, 3128]] },
  SIP:          { udp: [[5060, 5060]] },
  'PC-Anywhere': { tcp: [[5631, 5632]] },
  VNC:          { tcp: [[5900, 5900]] },
  IRC:          { tcp: [[6660, 6669]] },
  'X-WINDOWS':  { tcp: [[6000, 6063]] },
  VDOLIVE:      { tcp: [[7000, 7010]] },
  WAIS:         { tcp: [[210, 210]] },
};

/* ── Risky attributes ──────────────────────────────────────────────────────
 *
 * Ports first, names second. A definition matches a policy when the policy's
 * resolved ports overlap ANY of its ranges, or when the policy references one
 * of its predefined names directly.
 */
const RISKY_INBOUND = [
  { key: 'rdp',      label: 'Remote Desktop (RDP)',            severity: 'critical',
    tcp: [[3389, 3389]], names: ['RDP'] },
  { key: 'smb',      label: 'SMB / NetBIOS file sharing',      severity: 'critical',
    tcp: [[139, 139], [445, 445]], udp: [[137, 138]], names: ['SMB', 'SAMBA', 'NetBIOS'] },
  { key: 'telnet',   label: 'Telnet',                          severity: 'critical',
    tcp: [[23, 23]], names: ['TELNET'] },
  { key: 'database', label: 'Database services',               severity: 'critical',
    tcp: [[1433, 1434], [1521, 1521], [3306, 3306], [5432, 5432],
          [6379, 6379], [27017, 27017], [9200, 9200]],
    names: ['MS-SQL', 'MYSQL'] },
  { key: 'vnc',      label: 'VNC remote control',              severity: 'critical',
    tcp: [[5900, 5910]], names: ['VNC'] },
  { key: 'ftp',      label: 'FTP',                             severity: 'high',
    tcp: [[21, 21]], names: ['FTP', 'FTP_GET', 'FTP_PUT'] },
  { key: 'rpc',      label: 'Windows RPC / WinRM',             severity: 'high',
    tcp: [[135, 135], [5985, 5986]], names: ['DCE-RPC', 'ONC-RPC'] },
  { key: 'snmp',     label: 'SNMP',                            severity: 'high',
    udp: [[161, 162]], names: ['SNMP'] },
  { key: 'ldap',     label: 'Directory services',              severity: 'high',
    tcp: [[389, 389], [636, 636], [3268, 3269]], names: ['LDAP', 'LDAP_UDP'] },
  { key: 'legacy',   label: 'Legacy remote control',           severity: 'high',
    tcp: [[5631, 5632], [1494, 1494], [512, 514]], names: ['PC-Anywhere', 'WINFRAME', 'RSH'] },
  { key: 'ssh',      label: 'SSH',                             severity: 'medium',
    tcp: [[22, 22]], names: ['SSH'] },
];

const RISKY_OUTBOUND = [
  { key: 'smb-egress', label: 'SMB leaving the network',       severity: 'high',
    tcp: [[139, 139], [445, 445]], names: ['SMB', 'SAMBA', 'NetBIOS'],
    why: 'outbound SMB leaks NTLM credentials to any host that answers' },
  { key: 'telnet',     label: 'Telnet',                        severity: 'high',
    tcp: [[23, 23]], names: ['TELNET'],
    why: 'credentials cross the internet in clear text' },
  { key: 'tftp',       label: 'TFTP',                          severity: 'high',
    udp: [[69, 69]], names: ['TFTP'],
    why: 'unauthenticated file transfer, commonly used to stage tooling' },
  { key: 'smtp-direct', label: 'Direct SMTP from clients',     severity: 'medium',
    tcp: [[25, 25]], names: ['SMTP'],
    why: 'bypasses the mail gateway; the usual route for a compromised host to send mail' },
  { key: 'irc',        label: 'IRC',                           severity: 'medium',
    tcp: [[6660, 6669], [6697, 6697]], names: ['IRC'],
    why: 'long-standing command-and-control channel with no business use here' },
  { key: 'tor',        label: 'Tor',                           severity: 'medium',
    tcp: [[9001, 9001], [9030, 9030], [9050, 9051]], names: [],
    why: 'anonymised egress defeats every other outbound control' },
  { key: 'ftp',        label: 'FTP',                           severity: 'medium',
    tcp: [[21, 21]], names: ['FTP', 'FTP_GET', 'FTP_PUT'],
    why: 'clear-text transfer, and a common exfiltration path' },
];

// ── Port parsing ───────────────────────────────────────────────────────────

/**
 * FortiOS writes `tcp-portrange` as `dst[-dst][:src[-src]]`, space-separated
 * for multiples: "80 443", "1000-2000", "80:1024-65535".
 *
 * Only the DESTINATION half is read. The source half is the client's ephemeral
 * range and matching risk against it would flag every rule on the device.
 */
function parsePortRanges(raw) {
  if (raw === null || raw === undefined) return [];
  const tokens = (Array.isArray(raw) ? raw : String(raw).split(/[\s,]+/))
    .map(t => String(t).trim()).filter(Boolean);

  const out = [];
  for (const token of tokens) {
    const dst = token.split(':')[0];
    const m = /^(\d+)(?:-(\d+))?$/.exec(dst);
    if (!m) continue;                       // unparseable: not a silent 0
    const lo = parseInt(m[1], 10);
    const hi = m[2] === undefined ? lo : parseInt(m[2], 10);
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) continue;
    out.push(lo <= hi ? [lo, hi] : [hi, lo]);
  }
  return out;
}

function rangesOverlap(a, b) {
  return a[0] <= b[1] && b[0] <= a[1];
}

// ── Service resolution ─────────────────────────────────────────────────────

/**
 * Index every service the device knows about: predefined, custom, and groups.
 *
 * Groups are expanded with a visited set, because a service group that contains
 * itself is a config a device will happily hold and a recursive resolver will
 * not survive.
 */
function buildServiceIndex(model) {
  const svc = (model && model.services) || {};
  const index = new Map();

  Object.keys(PREDEFINED).forEach((k) => {
    index.set(k.toLowerCase(), { kind: 'predefined', def: PREDEFINED[k] });
  });

  asEntries(svc.custom).forEach((c) => {
    const key = String(pick(c, 'name') || c._key || '').toLowerCase();
    if (!key) return;
    const protocol = String(pick(c, 'protocol') || '').toUpperCase();
    const def = {
      tcp: parsePortRanges(pick(c, 'tcp-portrange')),
      udp: parsePortRanges(pick(c, 'udp-portrange')),
      sctp: parsePortRanges(pick(c, 'sctp-portrange')),
      icmp: protocol === 'ICMP' || protocol === 'ICMP6' || pick(c, 'icmptype') !== undefined,
      protocol: protocol || null,
    };
    /*
     * An IP-protocol service (protocol-number set, no ports) is real and is not
     * "no ports". Marked so it resolves rather than looking like an empty
     * custom service nobody finished defining.
     */
    def.ipProtocol = str(pick(c, 'protocol-number'));
    index.set(key, { kind: 'custom', def });
  });

  const groups = new Map();
  asEntries(svc.groups).forEach((g) => {
    const key = String(pick(g, 'name') || g._key || '').toLowerCase();
    if (!key) return;
    groups.set(key, names(pick(g, 'member')).map(n => String(n).toLowerCase()));
  });

  return { index, groups };
}

const EMPTY = { any: false, tcp: [], udp: [], icmp: false, ipProtocol: false };

function mergeInto(acc, def) {
  if (!def) return acc;
  if (def.any) acc.any = true;
  (def.tcp || []).forEach(r => acc.tcp.push(r));
  (def.udp || []).forEach(r => acc.udp.push(r));
  if (def.icmp) acc.icmp = true;
  if (def.ipProtocol) acc.ipProtocol = true;
  return acc;
}

/**
 * Resolve a policy's service list to ports.
 *
 * @returns {{ any, tcp, udp, icmp, unresolved: string[], resolvedNames: string[] }}
 *
 * `unresolved` is the honest part. A name that resolved to nothing is listed,
 * and callers must not treat a policy carrying one as assessed.
 */
function resolveServices(serviceIndex, list) {
  const acc = { any: false, tcp: [], udp: [], icmp: false, ipProtocol: false };
  const unresolved = [];
  const resolvedNames = [];

  const seen = new Set();

  function walk(rawName, depth) {
    const key = String(rawName || '').toLowerCase().trim();
    if (!key) return;
    // Self-referencing or mutually-referencing groups exist in real configs.
    if (seen.has(key) || depth > 10) return;
    seen.add(key);

    if (key === 'all' || key === 'any') { acc.any = true; resolvedNames.push(rawName); return; }

    const hit = serviceIndex.index.get(key);
    if (hit) { mergeInto(acc, hit.def); resolvedNames.push(rawName); return; }

    const group = serviceIndex.groups.get(key);
    if (group) { resolvedNames.push(rawName); group.forEach(m => walk(m, depth + 1)); return; }

    unresolved.push(String(rawName));
  }

  (list || []).forEach(n => walk(n, 0));

  return {
    any: acc.any, tcp: acc.tcp, udp: acc.udp, icmp: acc.icmp,
    ipProtocol: acc.ipProtocol,
    unresolved, resolvedNames,
  };
}

/**
 * Does a resolved service set permit anything in this risky definition?
 *
 * A policy whose service is ALL permits everything, so it matches every
 * definition — that is not a false positive, it is the point.
 */
function matchesRisk(resolved, risk, rawNames) {
  if (!resolved) return false;
  if (resolved.any) return true;

  const overlaps = (mine, theirs) =>
    (mine || []).some(a => (theirs || []).some(b => rangesOverlap(a, b)));

  if (overlaps(resolved.tcp, risk.tcp)) return true;
  if (overlaps(resolved.udp, risk.udp)) return true;

  // Second route in: the policy referenced a predefined name directly.
  const wanted = (risk.names || []).map(n => n.toLowerCase());
  return (rawNames || []).some(n => wanted.indexOf(String(n).toLowerCase()) >= 0);
}

// ── Direction ──────────────────────────────────────────────────────────────

/** Interface names facing the internet, lower-cased, by declared role. */
function wanInterfaceNames(model) {
  return ((model.system && model.system.interfaces) || [])
    .filter(i => String(pick(i, 'role') || '').toLowerCase() === 'wan')
    .map(i => String(pick(i, 'name') || i._key || '').toLowerCase())
    .filter(Boolean);
}

/*
 * Both interface tests expand ZONES before comparing.
 *
 * A policy on a zone-based firewall names a zone, not an interface. Comparing
 * that zone name against the list of WAN interface names never matched, so
 * every policy resolved to direction 'unknown' — which silently switched off
 * every inbound and outbound check on exactly the larger, zone-using estates
 * where they matter most. The expansion is what makes those checks run.
 */
function listTouchesWan(list, wan, zoneIndex) {
  const l = expandInterfaces(list, zoneIndex);
  if (!l.length) return false;
  // 'any' spans every interface, so it includes the WAN.
  if (l.some(n => n === 'any' || n === 'all')) return true;
  return l.some(n => wan.indexOf(n) >= 0);
}

function listIsPurelyInternal(list, wan, zoneIndex) {
  const l = expandInterfaces(list, zoneIndex);
  if (!l.length) return false;
  if (l.some(n => n === 'any' || n === 'all')) return false;
  return l.every(n => wan.indexOf(n) < 0);
}

/**
 * Which way a policy faces.
 *
 * 'unknown' is returned when no interface carries role: wan — and that is a
 * common, legitimate config, because role is cosmetic on many deployments.
 * Direction-specific checks report not-assessable on it instead of guessing;
 * assuming the first interface is the internet would invent findings.
 *
 * @returns {'inbound'|'outbound'|'internal'|'unknown'}
 */
function policyDirection(model, policy, wanNames, zoneIndex) {
  const wan = wanNames || wanInterfaceNames(model);
  if (!wan.length) return 'unknown';
  const zones = zoneIndex || buildZoneIndex(model);

  const srcWan = listTouchesWan(policy.srcintf, wan, zones);
  const dstWan = listTouchesWan(policy.dstintf, wan, zones);

  if (srcWan && !dstWan) return 'inbound';
  if (!srcWan && dstWan) return 'outbound';
  if (listIsPurelyInternal(policy.srcintf, wan, zones) &&
      listIsPurelyInternal(policy.dstintf, wan, zones)) {
    return 'internal';
  }
  // Both ends touch the WAN, or one end is 'any' on both sides: ambiguous.
  return 'unknown';
}

// ── Policy analysis ────────────────────────────────────────────────────────

/**
 * Annotate every policy with what this module can work out about it.
 *
 * Done once and handed to the checks, so twenty checks do not each rebuild the
 * service index — and, more importantly, so they all agree about what a policy
 * permits and which way it faces.
 */
function analysePolicies(model) {
  const serviceIndex = buildServiceIndex(model);
  const addressIndex = buildAddressIndex(model);
  const zoneIndex    = buildZoneIndex(model);
  const wan = wanInterfaceNames(model);

  const policies = (model.policies || []).map((p) => {
    const resolved = resolveServices(serviceIndex, p.service);

    /*
     * Source and destination scope come from what the referenced objects
     * CONTAIN, not from what they are called.
     *
     * isAny() — the old test, and still the right one for the literal 'all' —
     * only ever matched the strings 'all', 'any' and '*'. An address object
     * named `Internal_Servers` holding 0.0.0.0/0 defeated it completely, and so
     * did any group with one wide member. Both are ordinary configurations, and
     * both produced a rule the audit called properly scoped while it permitted
     * the whole internet.
     *
     * The literal check is kept as a floor: a policy whose srcaddr IS 'all'
     * stays 'any' even on a config whose address table did not survive the
     * export.
     */
    const srcScope = resolveAddresses(addressIndex, p.srcaddr);
    const dstScope = resolveAddresses(addressIndex, p.dstaddr);

    const anySrc = isAny(p.srcaddr) || srcScope.any;
    const anyDst = isAny(p.dstaddr) || dstScope.any;

    /*
     * An address name we could not find is NOT a narrow address.
     *
     * Same rule the service resolver has always applied: a policy that could
     * only be half read must not score like one read in full and found tidy.
     * These policies are reported as un-assessed rather than counted clean.
     */
    const addrUnresolved = srcScope.unresolved.concat(dstScope.unresolved);

    return {
      policy: p,
      id: p.id,
      live: p.status !== 'disable' && p.action === 'accept',
      enabled: p.status !== 'disable',
      accept: p.action === 'accept',
      direction: policyDirection(model, p, wan, zoneIndex),
      resolved,
      srcScope,
      dstScope,
      addrUnresolved,
      // A policy we could not fully resolve — in services OR addresses — is not
      // a clean policy.
      fullyResolved: resolved.unresolved.length === 0 && addrUnresolved.length === 0,
      servicesResolved: resolved.unresolved.length === 0,
      addressesResolved: addrUnresolved.length === 0,
      anySrc,
      anyDst,
      anyService: isAnyService(p.service) || resolved.any,
      blanket: anySrc || anyDst,
      /*
       * How the rule became wide open, for the finding text. "srcaddr is all"
       * is an assertion; "Servers_Group → Legacy_Any → 0.0.0.0/0" is a work
       * instruction, and it is the difference between a finding that gets
       * actioned and one that gets argued with.
       */
      anySrcVia: srcScope.anyVia,
      anyDstVia: dstScope.anyVia,
    };
  });

  return {
    policies,
    wanKnown: wan.length > 0,
    serviceIndex,
    addressIndex,
    zoneIndex,
    /** Policies whose ADDRESSES could not be fully resolved. */
    unresolvedAddressPolicies() {
      return policies.filter(a => a.live && !a.addressesResolved);
    },
    /** Live accept policies facing one way, for the direction-scoped checks. */
    facing(direction) {
      return policies.filter(a => a.live && a.direction === direction);
    },
    /** Policies whose services could not be fully resolved, in any direction. */
    unresolvedPolicies() {
      return policies.filter(a => a.live && !a.fullyResolved);
    },
  };
}

/** Which risky definitions a policy matches, from a given table. */
function risksOn(analysed, table) {
  return table.filter(r => matchesRisk(analysed.resolved, r, analysed.policy.service));
}

module.exports = {
  PREDEFINED,
  RISKY_INBOUND,
  RISKY_OUTBOUND,
  buildAddressIndex,
  resolveAddresses,
  buildZoneIndex,
  expandInterfaces,
  parsePortRanges,
  rangesOverlap,
  buildServiceIndex,
  resolveServices,
  matchesRisk,
  wanInterfaceNames,
  policyDirection,
  analysePolicies,
  risksOn,
};
