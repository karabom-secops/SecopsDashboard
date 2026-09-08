'use strict';

/**
 * lib/fortigate-sections.js — one canonical shape, whatever the export looked
 * like.
 *
 * ══ WHY THIS EXISTS ══
 *
 * The parser assumed one hierarchy: a top-level `system` map and a top-level
 * `firewall` map. Exports in the field do not agree with that assumption, and
 * when it failed it failed SILENTLY — `take(root,'system')` returned undefined,
 * defaulted to `{}`, and every check downstream reported "not present in this
 * config" against a device whose configuration was sitting right there.
 *
 * The result was an audit that produced 37 findings on a file it had not read.
 * Each finding was individually defensible ("admin-telnet is not present") and
 * collectively they were a fabrication. That is a worse failure than crashing.
 *
 * Four layouts are known to occur:
 *
 *   FLAT      `system_interface:`, `firewall_policy:`, `vpn_ssl_settings:`
 *             Flattened FortiGate command paths as single top-level keys.
 *   NESTED    `system: { interface: … }` — the shape originally assumed.
 *   VDOM      `global: { system: … }` and `vdom: [ … ]`.
 *   MIXED     any combination, which real exporters do produce.
 *
 * Layout is DETECTED and RECORDED, never assumed, and never inferred from the
 * presence or absence of a single key.
 *
 * ══ THE ALIAS REGISTRY IS THE ONLY PLACE THAT KNOWS KEY SPELLINGS ══
 *
 * Every mapping from an export's spelling to a canonical path lives in
 * SECTION_ALIASES below. Nothing else in the audit may test a raw key name.
 * Scattering `pick(root,'firewall_policy')` through the checks is how the
 * original assumption spread far enough that nobody could see it was an
 * assumption.
 */

/**
 * Canonical section paths, and every spelling seen for them.
 *
 * The canonical path is the FortiGate command path with dots: `firewall.policy`
 * is `config firewall policy`. Exact FortiOS naming is preserved — hyphens and
 * all — because `ssl-ssh-profile` is the command, and renaming it to something
 * tidier means the next person cannot grep the device documentation for it.
 *
 * Aliases are matched case-insensitively. `_` and `.` are the same path
 * delimiter at lookup time; `-` is NOT — it is part of a command name. See
 * normKey() below for why that distinction is load-bearing.
 *
 * An exporter that writes an underscore where FortiOS uses a hyphen therefore
 * needs its own entry in the list — `firewall_ssl_ssh_profile` beside
 * `firewall_ssl-ssh-profile`. Explicit, rather than a rule that discards the
 * difference and matches things it should not.
 */
const SECTION_ALIASES = {
  // ── system ──
  'system.global':          ['system_global'],
  'system.interface':       ['system_interface'],
  'system.admin':           ['system_admin'],
  'system.accprofile':      ['system_accprofile'],
  'system.settings':        ['system_settings'],
  'system.zone':            ['system_zone'],
  'system.dns':             ['system_dns'],
  'system.ntp':             ['system_ntp'],
  'system.password-policy': ['system_password-policy', 'system_password_policy'],
  'system.snmp.community':  ['system_snmp_community'],
  'system.snmp.user':       ['system_snmp_user'],
  'system.certificate':     ['system_certificate'],
  'system.vdom':            ['system_vdom'],

  // ── firewall ──
  'firewall.policy':          ['firewall_policy'],
  'firewall.address':         ['firewall_address'],
  'firewall.address6':        ['firewall_address6'],
  'firewall.addrgrp':         ['firewall_addrgrp'],
  'firewall.addrgrp6':        ['firewall_addrgrp6'],
  'firewall.vip':             ['firewall_vip'],
  'firewall.vip6':            ['firewall_vip6'],
  'firewall.vipgrp':          ['firewall_vipgrp'],
  'firewall.service.custom':  ['firewall_service_custom'],
  'firewall.service.group':   ['firewall_service_group'],
  'firewall.schedule.onetime':   ['firewall_schedule_onetime'],
  'firewall.schedule.recurring': ['firewall_schedule_recurring'],
  'firewall.schedule.group':     ['firewall_schedule_group'],
  'firewall.ssl-ssh-profile': ['firewall_ssl-ssh-profile', 'firewall_ssl_ssh_profile'],
  'firewall.ippool':          ['firewall_ippool'],

  // ── security profiles ──
  'antivirus.profile':   ['antivirus_profile'],
  'ips.sensor':          ['ips_sensor'],
  'webfilter.profile':   ['webfilter_profile'],
  'dnsfilter.profile':   ['dnsfilter_profile'],
  'application.list':    ['application_list'],

  // ── vpn ──
  'vpn.ssl.settings':            ['vpn_ssl_settings'],
  'vpn.ssl.web.portal':          ['vpn_ssl_web_portal'],
  'vpn.ipsec.phase1-interface':  ['vpn_ipsec_phase1-interface', 'vpn_ipsec_phase1_interface'],
  'vpn.ipsec.phase2-interface':  ['vpn_ipsec_phase2-interface', 'vpn_ipsec_phase2_interface'],
  'vpn.ipsec.phase1':            ['vpn_ipsec_phase1'],
  'vpn.ipsec.phase2':            ['vpn_ipsec_phase2'],

  // ── router ──
  'router.static': ['router_static'],
  'router.bgp':    ['router_bgp'],
  'router.ospf':   ['router_ospf'],

  // ── log ──
  'log.setting':                    ['log_setting'],
  'log.disk.setting':               ['log_disk_setting'],
  'log.memory.setting':             ['log_memory_setting'],
  'log.syslogd.setting':            ['log_syslogd_setting'],
  'log.syslogd2.setting':           ['log_syslogd2_setting'],
  'log.syslogd3.setting':           ['log_syslogd3_setting'],
  'log.fortianalyzer.setting':      ['log_fortianalyzer_setting'],
  'log.syslogd.override-setting':   ['log_syslogd_override-setting', 'log_syslogd_override_setting'],
  'log.syslogd2.override-setting':  ['log_syslogd2_override-setting'],
  'log.syslogd3.override-setting':  ['log_syslogd3_override-setting'],
  'log.fortianalyzer.override-setting': ['log_fortianalyzer_override-setting'],

  // ── user ──
  'user.local':  ['user_local'],
  'user.group':  ['user_group'],
  'user.ldap':   ['user_ldap'],
  'user.radius': ['user_radius'],
};

/** Section states, per the ingestion contract. */
const STATE = {
  WITH_DATA:    'present_with_data',
  EMPTY:        'present_empty',
  ABSENT:       'absent',
  UNRECOGNISED: 'unrecognised',
  PARSE_ERROR:  'parse_error',
};

/**
 * Normalise a key for lookup.
 *
 * ══ THE UNDERSCORE IS A PATH DELIMITER; THE HYPHEN IS PART OF THE NAME ══
 *
 * This used to collapse `-`, `_` and `.` alike, which conflates two entirely
 * different things in FortiGate's naming:
 *
 *   vpn_ipsec_phase1-interface   is  vpn -> ipsec -> phase1-interface
 *                            NOT  vpn -> ipsec -> phase1 -> interface
 *   firewall_ssl-ssh-profile     is  firewall -> ssl-ssh-profile
 *                            NOT  firewall -> ssl -> ssh -> profile
 *
 * Collapsing both happened to work for the handful of aliases that existed when
 * it was written, and silently mismatched the moment a real export arrived with
 * `log_syslogd_override-setting`. Hyphens are now preserved, so a canonical
 * path means exactly the command it names.
 *
 * Exporters that write an underscore where FortiOS uses a hyphen are handled by
 * EXPLICIT alias entries below — a list of known spellings, not a rule that
 * throws away the distinction.
 */
function normKey(k) {
  return String(k == null ? '' : k).trim().toLowerCase().replace(/[_.]+/g, '.');
}

/** alias (normalised) -> canonical path. Built once. */
const ALIAS_TO_CANONICAL = (() => {
  const map = new Map();
  Object.keys(SECTION_ALIASES).forEach((canonical) => {
    map.set(normKey(canonical), canonical);
    SECTION_ALIASES[canonical].forEach(a => map.set(normKey(a), canonical));
  });
  return map;
})();

/** The canonical path for an export's key, or null if we do not know it. */
function canonicalPathFor(key) {
  return ALIAS_TO_CANONICAL.get(normKey(key)) || null;
}

// ── Collection normalisation ───────────────────────────────────────────────

/**
 * Is this a one-key wrapper of the form `{ "81": { … } }`?
 *
 * This is the shape that broke the original reader. A list entry like
 *
 *     - 81:
 *         name: "RFX-OFFICE -- POC-VHI"
 *
 * parses to `{ '81': { name: … } }`. The old asEntries() looked for `name`,
 * `policyid` and `id` ON THE WRAPPER, found none, and fell back to the ARRAY
 * INDEX — so policy 81 became policy 0, and every field was one level deeper
 * than anything looked. Policy ids are not positions and are not sequential;
 * losing them makes every finding name the wrong rule.
 */
function isOneKeyWrapper(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) return false;
  const keys = Object.keys(node);
  if (keys.length !== 1) return false;
  const inner = node[keys[0]];
  return !!inner && typeof inner === 'object' && !Array.isArray(inner);
}

/**
 * Normalise any FortiGate collection shape into records.
 *
 * Accepts:
 *   - a list of one-key wrappers      `- 81: {…}`      (id is the key)
 *   - a list of plain objects         `- {name: …}`
 *   - a map keyed by name or id       `{ "81": {…} }`
 *   - a scalar or list of scalars     (a setting, not a table)
 *   - null / empty                    (present but empty)
 *
 * @returns {{ state: string, records: Array, warnings: string[] }}
 *
 * Each record carries object_id, object_name, source_index and raw_object, so
 * a finding can name the rule the way the device names it and a reader can go
 * straight to it.
 */
function normaliseCollection(node, opts) {
  const o = opts || {};
  const canonical = o.canonicalPath || null;
  const originalKey = o.originalKey || null;
  const vdom = o.vdom === undefined ? null : o.vdom;
  const warnings = [];

  const mk = (id, name, raw, index) => ({
    object_type: canonical,
    object_id: id === null || id === undefined ? null : String(id),
    object_name: name === null || name === undefined ? null : String(name),
    vdom,
    canonical_path: canonical,
    original_top_level_key: originalKey,
    source_index: index,
    raw_object: raw,
    parse_warnings: [],
  });

  /*
   * PRESENT-BUT-EMPTY IS NOT ABSENT.
   *
   * `system_admin:` with nothing under it means the section was exported and
   * carried no entries. That is a statement about the EXPORT, not about the
   * appliance — an admin account almost certainly exists on a device somebody
   * just logged into to take a backup. Reporting "No administrator accounts
   * were found" conflates the two and tells the client something false.
   */
  if (node === null || node === undefined) {
    return { state: STATE.EMPTY, records: [], warnings };
  }

  if (Array.isArray(node)) {
    if (!node.length) return { state: STATE.EMPTY, records: [], warnings };

    const records = [];
    node.forEach((entry, i) => {
      if (entry === null || entry === undefined) return;

      if (isOneKeyWrapper(entry)) {
        const key = Object.keys(entry)[0];
        const body = entry[key];
        // The wrapper key is the mkey: a policy id, or an object name.
        const name = body.name !== undefined ? body.name : key;
        records.push(mk(key, name, body, i));
        return;
      }

      if (typeof entry === 'object') {
        const id = entry.policyid !== undefined ? entry.policyid
                 : entry.id !== undefined ? entry.id
                 : entry.name !== undefined ? entry.name : null;
        records.push(mk(id, entry.name !== undefined ? entry.name : id, entry, i));
        return;
      }

      // A bare scalar in a list — a member list rather than a table.
      records.push(mk(null, entry, entry, i));
    });

    return { state: records.length ? STATE.WITH_DATA : STATE.EMPTY, records, warnings };
  }

  if (typeof node === 'object') {
    const keys = Object.keys(node);
    if (!keys.length) return { state: STATE.EMPTY, records: [], warnings };

    /*
     * A settings block — `vpn.ssl.settings`, `system.global` — is a single
     * object of scalars, not a table of objects. Distinguished by having no
     * object-valued members, and returned as ONE record so callers that want a
     * settings map and callers that iterate records both work.
     */
    const objectValued = keys.filter(k => node[k] && typeof node[k] === 'object');
    if (!objectValued.length) {
      return { state: STATE.WITH_DATA, records: [mk(null, null, node, 0)], warnings };
    }

    const records = keys.map((k, i) => {
      const body = node[k];
      if (!body || typeof body !== 'object') return mk(k, k, body, i);
      return mk(k, body.name !== undefined ? body.name : k, body, i);
    });
    return { state: STATE.WITH_DATA, records, warnings };
  }

  // A scalar section: `log_setting: disable`, say.
  return { state: STATE.WITH_DATA, records: [mk(null, null, node, 0)], warnings };
}

// ── Layout detection ───────────────────────────────────────────────────────

/**
 * Which layout is this?
 *
 * Reports EVERY signal it found rather than the first one that matched — a
 * mixed export is a real thing, and an audit that silently picked one branch is
 * how half a config goes unread. `layouts` is therefore a list.
 */
function detectLayout(root) {
  const signals = [];
  if (!root || typeof root !== 'object' || Array.isArray(root)) {
    return { layouts: [], flatKeys: [], signals };
  }

  const keys = Object.keys(root);

  const flatKeys = keys.filter(k => canonicalPathFor(k) && normKey(k).indexOf('.') > 0);
  const hasNestedSystem   = !!(root.system && typeof root.system === 'object');
  const hasNestedFirewall = !!(root.firewall && typeof root.firewall === 'object');
  const hasVdomKey        = root.vdom !== undefined || root.vdoms !== undefined;
  const hasGlobalKey      = !!(root.global && typeof root.global === 'object');

  const layouts = [];
  if (flatKeys.length) { layouts.push('flat'); signals.push(flatKeys.length + ' flattened section key(s)'); }
  if (hasNestedSystem || hasNestedFirewall) {
    layouts.push('nested');
    signals.push('nested ' + [hasNestedSystem && 'system', hasNestedFirewall && 'firewall'].filter(Boolean).join(' and '));
  }
  if (hasVdomKey || hasGlobalKey) {
    layouts.push('vdom');
    signals.push('VDOM scoping key(s): ' + [hasVdomKey && 'vdom', hasGlobalKey && 'global'].filter(Boolean).join(', '));
  }

  return { layouts, flatKeys, signals };
}

// ── Adaptation to the canonical model ──────────────────────────────────────

function emptyScope() {
  return { sections: {}, states: {} };
}

/**
 * Record a section into a scope, merging where the same canonical path arrives
 * from more than one spelling.
 */
function putSection(scope, canonical, node, originalKey, vdom, warnings) {
  const res = normaliseCollection(node, { canonicalPath: canonical, originalKey, vdom });

  if (scope.sections[canonical]) {
    // Two spellings of the same section in one file. Merge rather than let the
    // later one win silently — a dropped table is exactly the failure this
    // module exists to stop.
    scope.sections[canonical] = scope.sections[canonical].concat(res.records);
    warnings.push('Section ' + canonical + ' appeared under more than one key ' +
      '(latest: ' + originalKey + '); the entries were merged.');
    if (res.state === STATE.WITH_DATA) scope.states[canonical] = STATE.WITH_DATA;
    return;
  }

  scope.sections[canonical] = res.records;
  scope.states[canonical] = res.state;
  res.warnings.forEach(w => warnings.push(w));
}

/**
 * Walk a nested tree (`system: { interface: … }`) recording anything whose
 * assembled path is a section we know.
 *
 * Bounded depth: FortiGate command paths are at most four segments, and an
 * unbounded walk over a hostile file is a denial of service.
 */
function walkNested(node, prefix, scope, vdom, warnings, unrecognised, depth) {
  if (!node || typeof node !== 'object' || Array.isArray(node) || depth > 4) return;

  Object.keys(node).forEach((k) => {
    const path = prefix ? prefix + '.' + k : k;
    const canonical = canonicalPathFor(path);

    if (canonical) {
      putSection(scope, canonical, node[k], path, vdom, warnings);
      return;
    }

    const child = node[k];
    if (child && typeof child === 'object' && !Array.isArray(child) && depth < 4) {
      const before = Object.keys(scope.sections).length;
      walkNested(child, path, scope, vdom, warnings, unrecognised, depth + 1);
      // A branch that yielded nothing recognisable is named, once, at the
      // shallowest point it failed — not once per leaf.
      if (Object.keys(scope.sections).length === before && depth === 0) {
        unrecognised.push(path);
      }
      return;
    }

    if (depth === 0) unrecognised.push(path);
  });
}

/**
 * Adapt any recognised layout into one canonical representation:
 *
 *   { metadata, layout, global: {sections,states}, vdoms: { name: {…} }, … }
 *
 * Global and VDOM scope are kept SEPARATE. Copying global objects into every
 * VDOM would make a single misconfigured global setting appear as N findings,
 * and would make per-VDOM counts meaningless.
 */
function adaptConfig(root, opts) {
  const o = opts || {};
  const meta = o.metadata || {};
  const warnings = [];
  const unrecognised = [];

  const detection = detectLayout(root);

  const out = {
    layout: detection.layouts.slice(),
    layoutSignals: detection.signals.slice(),
    global: emptyScope(),
    vdoms: {},
    warnings,
    unrecognised,
    /** How objects with no vdom field were scoped, and why. */
    vdomAssignment: null,
  };

  if (!root || typeof root !== 'object' || Array.isArray(root)) return out;

  const scopeFor = (name) => {
    if (!name) return out.global;
    if (!out.vdoms[name]) out.vdoms[name] = emptyScope();
    return out.vdoms[name];
  };

  /*
   * The VDOM this export belongs to, where the header declared one.
   *
   * Per the contract: if the file names a single VDOM in metadata and the
   * objects themselves carry no vdom field, they are assigned to that declared
   * VDOM — and an EVIDENCE RECORD explains the assignment, because it is an
   * inference and the reader is entitled to know it was made.
   */
  const declaredVdom = meta.currentVdom || null;

  // ── Flattened top-level keys ──
  Object.keys(root).forEach((key) => {
    const canonical = canonicalPathFor(key);
    if (!canonical) return;
    // Only treat it as flat when the alias is genuinely a multi-segment path;
    // a bare `system` key is the nested layout and is handled below.
    if (normKey(key).indexOf('.') < 0) return;

    const node = root[key];

    /*
     * Flattened objects can carry their own `vdom` field, which is the most
     * reliable scoping signal available. Records are split by it so a
     * multi-VDOM flat export does not collapse into one bucket.
     */
    const res = normaliseCollection(node, {
      canonicalPath: canonical, originalKey: key, vdom: null,
    });

    if (res.state !== STATE.WITH_DATA) {
      const scope = scopeFor(declaredVdom);
      if (!scope.sections[canonical]) {
        scope.sections[canonical] = [];
        scope.states[canonical] = res.state;
      }
      return;
    }

    const byVdom = new Map();
    res.records.forEach((rec) => {
      const own = rec.raw_object && typeof rec.raw_object === 'object'
        ? (rec.raw_object.vdom !== undefined ? String(rec.raw_object.vdom) : null)
        : null;
      const target = own || declaredVdom || null;
      rec.vdom = target;
      if (!byVdom.has(target)) byVdom.set(target, []);
      byVdom.get(target).push(rec);
    });

    byVdom.forEach((records, name) => {
      const scope = scopeFor(name);
      scope.sections[canonical] = (scope.sections[canonical] || []).concat(records);
      scope.states[canonical] = STATE.WITH_DATA;
    });
  });

  if (declaredVdom) {
    out.vdomAssignment = {
      declaredVdom,
      basis: 'metadata',
      note: 'Objects carrying no vdom field were assigned to "' + declaredVdom +
            '", the VDOM this export declares in its header. Objects that named ' +
            'their own VDOM were scoped to that instead.',
    };
  }

  // ── Nested layout ──
  ['system', 'firewall', 'vpn', 'log', 'user', 'router',
   'antivirus', 'ips', 'webfilter', 'dnsfilter', 'application'].forEach((top) => {
    if (root[top] && typeof root[top] === 'object' && !Array.isArray(root[top])) {
      walkNested({ [top]: root[top] }, '', out.global, declaredVdom, warnings, unrecognised, 0);
    }
  });

  // ── VDOM layout ──
  const vdomNode = root.vdom !== undefined ? root.vdom : root.vdoms;
  if (vdomNode && typeof vdomNode === 'object') {
    const entries = Array.isArray(vdomNode)
      ? vdomNode.map((v, i) => {
          if (isOneKeyWrapper(v)) {
            const k = Object.keys(v)[0];
            return { name: k, body: v[k] };
          }
          return { name: (v && v.name) || ('vdom' + i), body: v };
        })
      : Object.keys(vdomNode).map(k => ({ name: k, body: vdomNode[k] }));

    entries.forEach(({ name, body }) => {
      if (!body || typeof body !== 'object') return;
      const scope = scopeFor(String(name));
      walkNested(body, '', scope, String(name), warnings, unrecognised, 0);
    });
  }

  if (root.global && typeof root.global === 'object') {
    walkNested(root.global, '', out.global, null, warnings, unrecognised, 0);
  }

  return out;
}

/**
 * Did we recognise ANYTHING?
 *
 * The guard the original parser lacked. It had `unread` for keys it did not
 * consume, but no test for having consumed NOTHING — so a file it understood
 * not one section of still produced a full sheet of findings. The check that
 * matters is not "were there unknown keys" but "did we read enough to have an
 * opinion at all".
 */
function recognisedSectionCount(adapted) {
  let n = 0;
  const count = (scope) => {
    Object.keys(scope.states || {}).forEach((k) => {
      if (scope.states[k] === STATE.WITH_DATA) n++;
    });
  };
  count(adapted.global);
  Object.keys(adapted.vdoms).forEach(v => count(adapted.vdoms[v]));
  return n;
}

module.exports = {
  SECTION_ALIASES,
  STATE,
  normKey,
  canonicalPathFor,
  isOneKeyWrapper,
  normaliseCollection,
  detectLayout,
  adaptConfig,
  recognisedSectionCount,
};
