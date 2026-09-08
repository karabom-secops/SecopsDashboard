'use strict';

/**
 * lib/fortigate-address.js — resolve what a policy's addresses actually cover.
 *
 * ══ WHY THIS EXISTS ══
 *
 * The audit used to decide whether a rule was scoped by looking at the NAME in
 * the policy: `isAny()` in the parser returns true only for the literal strings
 * `all`, `any` and `*`. Every other name was taken to mean "restricted".
 *
 * That is not a conservative reading. It is a wrong one, and it fails in the
 * direction that matters:
 *
 *     config firewall address
 *         edit "Internal_Servers"
 *             set subnet 0.0.0.0 0.0.0.0
 *
 * A policy with `srcaddr: Internal_Servers` was reported as properly scoped.
 * It permits the entire internet. The name was doing all the work, and the name
 * is the one part of a firewall configuration that is guaranteed to be prose.
 *
 * The same hole exists one level up:
 *
 *     config firewall addrgrp
 *         edit "Servers_Group"
 *             set member "Web01" "Legacy_Any"
 *
 * A group is as wide as its widest member. One member covering 0.0.0.0/0 makes
 * the whole group ANY, however many precise members sit beside it.
 *
 * lib/fortigate-policy.js has done this properly for SERVICES since it was
 * written — it expands service groups with a visited set and resolves names to
 * ports. This module is the same discipline applied to addresses, which were
 * simply never indexed.
 *
 * ══ UNRESOLVED IS NOT CLEAN ══
 *
 * The governing rule, shared with the service resolver: a name this module
 * cannot find is reported UNRESOLVED, never assumed narrow. A rulebase we could
 * only half read must not score like one that was read in full and found tidy.
 *
 * That matters more here than for services, because the failure is silent: a
 * missing service name produces a policy nobody can classify, whereas a missing
 * ADDRESS name would previously produce a policy that looked precisely scoped.
 */

const { asEntries, names, str, pick } = require('./fortigate-parser');

/** Names that mean "everywhere" before any lookup happens. */
const ANY_NAMES = ['all', 'any', '*'];

/**
 * The FALLBACK lookup key — never the primary one.
 *
 * Exact case and punctuation are matched first, because two objects may differ
 * only by them and collapsing that would resolve a reference to the wrong
 * object. This is tried only when the exact match fails, and it exists for one
 * specific, known distortion: a name containing a colon is split by YAML into a
 * mapping and rejoined by the parser as `KEY : VALUE`, which may differ from
 * the original by the spaces around the colon.
 *
 * So it collapses whitespace only — runs of spaces to one, and spaces around a
 * colon removed. It does NOT strip punctuation, hyphens or case beyond
 * lowercasing, because those distinguish real objects from each other.
 */
function fallbackKey(name) {
  return String(name == null ? '' : name)
    .trim().toLowerCase()
    .replace(/\s*:\s*/g, ':')
    .replace(/\s+/g, ' ');
}

// ── IP helpers ─────────────────────────────────────────────────────────────

/**
 * A dotted-quad to a 32-bit integer, or null.
 *
 * Null rather than 0 for anything unparseable: 0 is a legitimate address
 * (0.0.0.0) and conflating it with "could not read this" is precisely the
 * confusion that produces a false clean result.
 */
function ipToInt(s) {
  const m = String(s || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = [m[1], m[2], m[3], m[4]].map(Number);
  if (parts.some(p => p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

/** A dotted-quad netmask to a prefix length, or null if it is not contiguous. */
function maskToPrefix(s) {
  const int = ipToInt(s);
  if (int === null) return null;
  // A netmask must be a run of 1s then a run of 0s. 255.0.255.0 is not a mask,
  // and silently accepting it would produce a prefix that means nothing.
  const inverted = (~int) >>> 0;
  if (((inverted + 1) & inverted) !== 0) return null;
  let prefix = 0;
  for (let bit = 31; bit >= 0; bit--) {
    if ((int >>> bit) & 1) prefix++;
    else break;
  }
  return prefix;
}

/**
 * FortiOS writes a subnet as `10.0.0.0 255.255.255.0`, `10.0.0.0/24`, or
 * occasionally just `10.0.0.0`. All three, plus null for anything else.
 *
 * @returns {{ip: number, prefix: number}|null}
 */
function parseSubnet(raw) {
  const s = str(raw);
  if (!s) return null;

  const slash = s.match(/^(\d{1,3}(?:\.\d{1,3}){3})\s*\/\s*(\d{1,2})$/);
  if (slash) {
    const ip = ipToInt(slash[1]);
    const prefix = Number(slash[2]);
    return (ip === null || prefix > 32) ? null : { ip, prefix };
  }

  const spaced = s.split(/\s+/);
  if (spaced.length === 2) {
    const ip = ipToInt(spaced[0]);
    const prefix = maskToPrefix(spaced[1]);
    return (ip === null || prefix === null) ? null : { ip, prefix };
  }

  const bare = ipToInt(s);
  return bare === null ? null : { ip: bare, prefix: 32 };
}

/** Does this subnet cover the entire IPv4 space? */
function subnetIsAny(sn) {
  return !!sn && sn.prefix === 0;
}

/** `::/0` and its spellings. IPv6 is checked textually — a /0 is a /0. */
function ip6IsAny(raw) {
  const s = String(str(raw) || '').trim().toLowerCase().replace(/\s+/g, '');
  return s === '::/0' || s === '::' || s === '0:0:0:0:0:0:0:0/0';
}

/**
 * A wildcard address whose mask is all zeros matches every address.
 *
 * FortiOS writes `set wildcard <ip> <mask>` where, unlike a netmask, a ZERO bit
 * means "must match". A mask of 0.0.0.0 therefore constrains nothing.
 */
function wildcardIsAny(raw) {
  const s = str(raw);
  if (!s) return false;
  const parts = s.split(/\s+/);
  if (parts.length !== 2) return false;
  return ipToInt(parts[1]) === 0;
}

/** An iprange spanning the whole space. */
function rangeIsAny(start, end) {
  const s = ipToInt(str(start));
  const e = ipToInt(str(end));
  return s === 0 && e === 0xFFFFFFFF;
}

// ── Address classification ─────────────────────────────────────────────────

/**
 * Does one address OBJECT cover everything?
 *
 * Every FortiOS address type that can express "the whole internet" is checked
 * here, because a config only has to express it once for the audit to be wrong.
 * Subnet is by far the most common; the others are rare and cost nothing to
 * cover.
 */
function addressIsAny(obj) {
  if (!obj) return false;

  const type = String(pick(obj, 'type') || '').toLowerCase();

  // The explicit types first — FortiOS 7.x can carry `type: all`.
  if (type === 'all' || type === 'any') return true;

  if (subnetIsAny(parseSubnet(pick(obj, 'subnet')))) return true;
  if (ip6IsAny(pick(obj, 'ip6', 'subnet6'))) return true;
  if (wildcardIsAny(pick(obj, 'wildcard'))) return true;
  if (type === 'iprange' && rangeIsAny(pick(obj, 'start-ip'), pick(obj, 'end-ip'))) return true;

  /*
   * A VIP's external side. `extip` unset, or 0.0.0.0, means the VIP answers on
   * whatever address the traffic arrived for — which on an internet-facing
   * interface is every address the device holds.
   */
  if (pick(obj, 'extip') !== undefined && ipToInt(str(pick(obj, 'extip'))) === 0) return true;

  return false;
}

// ── Index ──────────────────────────────────────────────────────────────────

/**
 * Index every address the device knows about: objects, groups, VIPs, VIP
 * groups, and IPv6 equivalents.
 *
 * Mirrors buildServiceIndex() in lib/fortigate-policy.js deliberately — same
 * shape, same group handling, so the two resolvers stay recognisably one idea.
 */
function buildAddressIndex(model) {
  const addr = (model && model.addresses) || {};
  const index = new Map();   // name -> { kind, obj, any }
  const groups = new Map();  // name -> [member names]

  const addObjects = (list, kind) => {
    asEntries(list).forEach((o) => {
      const key = String(pick(o, 'name') || o._key || '').toLowerCase();
      if (!key) return;
      const rec = { kind, obj: o, any: addressIsAny(o) };
      index.set(key, rec);
      // Fallback key, registered only where it differs and does not collide —
      // an exact name must never be shadowed by another object's fallback.
      const fb = fallbackKey(pick(o, 'name') || o._key || '');
      if (fb && fb !== key && !index.has(fb)) index.set(fb, rec);
    });
  };

  addObjects(addr.objects,  'address');
  addObjects(addr.objects6, 'address6');
  addObjects(addr.vips,     'vip');
  addObjects(addr.vips6,    'vip6');

  /*
   * Members are stored with their ORIGINAL CASING.
   *
   * Lookup is case-insensitive — FortiOS names are — so the map is keyed
   * lower-cased, but the member strings themselves are kept verbatim because
   * they end up in the finding text. A chain rendered as
   * `Servers_Group → legacy_any` sends a client looking for an object that,
   * as far as their config is concerned, does not exist under that name.
   */
  const addGroups = (list) => {
    asEntries(list).forEach((gr) => {
      const key = String(pick(gr, 'name') || gr._key || '').toLowerCase();
      if (!key) return;
      const members = names(pick(gr, 'member')).map(n => String(n));
      groups.set(key, members);
      const fbg = fallbackKey(pick(gr, 'name') || gr._key || '');
      if (fbg && fbg !== key && !groups.has(fbg)) groups.set(fbg, members);
    });
  };

  addGroups(addr.groups);
  addGroups(addr.groups6);
  addGroups(addr.vipGroups);

  return { index, groups };
}

/**
 * Resolve a policy's address list to its true scope.
 *
 * @returns {{
 *   any: boolean,           does this list permit every address?
 *   anyVia: string|null,    the object that made it so — for the finding text
 *   unresolved: string[],   names not found anywhere in the config
 *   members: string[],      leaf object names, groups expanded
 *   viaGroup: boolean       true when a group had to be expanded to decide
 * }}
 *
 * `anyVia` exists so a finding can say WHICH object opened the rule up. Telling
 * someone their rule is wide open is an argument; telling them
 * `Servers_Group -> Legacy_Any -> 0.0.0.0/0` is a work instruction, and it is
 * the difference between a report that gets actioned and one that gets
 * disputed.
 */
function resolveAddresses(addressIndex, list) {
  const { index, groups } = addressIndex;
  const out = {
    any: false, anyVia: null, unresolved: [], members: [], viaGroup: false,
  };

  const raw = (list || []).map(n => String(n));
  if (!raw.length) return out;

  const seen = new Set();

  /*
   * Depth-first with a visited set. A group that contains itself — directly or
   * through a chain — is a configuration the device will hold quite happily,
   * and a naive resolver would recurse until the stack gave out. The visited
   * set makes a cycle terminate as "already counted" rather than as a crash.
   */
  const walk = (name, trail) => {
    const key = name.toLowerCase();

    if (ANY_NAMES.indexOf(key) >= 0) {
      out.any = true;
      if (!out.anyVia) out.anyVia = trail.concat(name).join(' → ');
      return;
    }

    if (seen.has(key)) return;
    seen.add(key);

    const group = groups.get(key) || groups.get(fallbackKey(name));
    if (group) {
      out.viaGroup = true;
      /*
       * An EMPTY group is not a narrow group. It is a group whose members this
       * config did not carry, so the rule's real scope is unknown — recorded as
       * unresolved rather than passed over as "nothing to see".
       */
      if (!group.length) out.unresolved.push(name);
      group.forEach(m => walk(m, trail.concat(name)));
      return;
    }

    const hit = index.get(key) || index.get(fallbackKey(name));
    if (!hit) {
      // Not an object, not a group, not a literal. Cannot claim it is narrow.
      out.unresolved.push(name);
      return;
    }

    /*
     * The name as the OBJECT declares it, not as the group happened to spell
     * it. FortiOS matches references case-insensitively, so a group can refer
     * to `WEB01` for an object defined as `Web01`; the definition is the
     * spelling a reader will find when they go looking.
     */
    const declared = str(pick(hit.obj, 'name')) || name;
    out.members.push(declared);
    if (hit.any) {
      out.any = true;
      if (!out.anyVia) out.anyVia = trail.concat(declared).join(' → ');
    }
  };

  raw.forEach(n => walk(n, []));
  return out;
}

// ── Zones ──────────────────────────────────────────────────────────────────

/**
 * Index zones to their member interfaces.
 *
 * Without this, a policy whose srcintf is a ZONE could not be told apart from
 * one naming an interface directly, so `listTouchesWan` compared a zone name
 * against a list of interface names, never matched, and every policy on a
 * zone-based firewall came back with direction 'unknown'. On a device that uses
 * zones — which is most of the larger ones — that silently disabled every
 * inbound and outbound check in the audit.
 */
function buildZoneIndex(model) {
  const zones = new Map();
  asEntries((model && model.system && model.system.zones) || []).forEach((z) => {
    const key = String(pick(z, 'name') || z._key || '').toLowerCase();
    if (!key) return;
    zones.set(key, names(pick(z, 'interface')).map(n => String(n).toLowerCase()));
  });
  return zones;
}

/**
 * Expand an interface list through zones to the underlying interface names.
 *
 * A zone naming a zone is not valid FortiOS, but the visited set costs nothing
 * and means a malformed export cannot hang the audit.
 */
function expandInterfaces(list, zoneIndex) {
  const out = [];
  const seen = new Set();

  const walk = (name) => {
    const key = String(name).toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    const members = zoneIndex && zoneIndex.get(key);
    if (members && members.length) { members.forEach(walk); return; }
    out.push(key);
  };

  (list || []).forEach(walk);
  return out;
}

module.exports = {
  ANY_NAMES,
  fallbackKey,
  ipToInt,
  maskToPrefix,
  parseSubnet,
  subnetIsAny,
  wildcardIsAny,
  rangeIsAny,
  ip6IsAny,
  addressIsAny,
  buildAddressIndex,
  resolveAddresses,
  buildZoneIndex,
  expandInterfaces,
};
