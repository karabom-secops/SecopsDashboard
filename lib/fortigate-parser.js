'use strict';

/**
 * lib/fortigate-parser.js — read a FortiGate backup into a model we can audit.
 *
 * THE INPUT
 *
 * The YAML backup a client takes from the device itself: admin menu →
 * Configuration → Backup → Local PC → File format: YAML, with "Password mask"
 * optionally ticked. JSON is accepted too — FortiOS offers it on the same
 * screen and it is the same tree in a different notation.
 *
 * THE FILE IS NEVER STORED. It is parsed here, audited, and dropped. Unmasked,
 * a FortiGate backup carries admin password hashes, IPsec pre-shared keys, SNMP
 * communities, LDAP and RADIUS bind credentials and certificate private keys —
 * so this module holds it in memory and nothing downstream persists it. See
 * db/migrate-firewall-audit.sql, which has no column it could go in.
 *
 * TOLERANCE IS THE DESIGN
 *
 * FortiOS trees move around by model, firmware and VDOM layout, and the same
 * table appears as a list in one export and as a map keyed by its mkey in
 * another. Every reader here accepts both shapes and neither throws on the
 * other.
 *
 * The corollary is `unread`. A parser that silently ignores what it does not
 * recognise will one day report a clean audit on a config it barely read, and
 * nobody will know. Anything not consumed is named, counted, and shown on the
 * page beside the score.
 */

const YAML = require('yaml');

/**
 * Alias expansion limit. The reason this uses `yaml` rather than `js-yaml`:
 * a handful of nested anchors can expand to gigabytes, and on an endpoint that
 * accepts uploads that is a denial of service rather than a curiosity.
 *
 * 100 IS THE LIBRARY DEFAULT, restated here so it is a decision rather than an
 * accident. Verified: removing this option still refuses an alias bomb, so a
 * mutation that deletes it changes nothing today — it is documentation, and it
 * is the thing that breaks visibly if a future version changes its default or
 * somebody swaps the parser for one without a limit.
 */
const MAX_ALIAS_COUNT = 100;

/** Refuse anything larger before parsing. Real configs are single-digit MB. */
const MAX_BYTES = 25 * 1024 * 1024;

/**
 * Field names whose VALUES are secret.
 *
 * Used to keep secrets out of findings even when a config arrives unmasked —
 * defence in depth behind the rule that checks report identifiers and counts,
 * never values.
 *
 * Matched as a SUBSTRING, case-insensitively, so the list is deliberately
 * over-complete: 'psksecret' is caught by 'secret' and 'authpassword' by
 * 'password' whether or not they appear in their own right. Removing an
 * individual entry therefore often changes nothing, which is the intended
 * property — a FortiOS field this list has never seen is still caught if it is
 * named like the credential it holds.
 */
const SECRET_FIELDS = [
  'password', 'passwd', 'psksecret', 'pre-shared-key', 'secret', 'key',
  'private-key', 'passphrase', 'community', 'auth-pwd', 'priv-pwd',
  'bindpw', 'ppk-secret', 'authpassword', 'privpassword', 'sharedsecret',
];

function isSecretField(name) {
  const n = String(name || '').toLowerCase();
  return SECRET_FIELDS.some(s => n === s || n.indexOf(s) >= 0);
}

/**
 * Strip anything that looks like a secret out of a structure bound for a
 * finding, a response or a log.
 *
 * A check should never put a secret in evidence in the first place; this is the
 * net under that, because "should never" is not a mechanism.
 */
function redact(node) {
  if (Array.isArray(node)) return node.map(redact);
  if (node && typeof node === 'object') {
    const out = {};
    Object.keys(node).forEach((k) => {
      out[k] = isSecretField(k) ? '[redacted]' : redact(node[k]);
    });
    return out;
  }
  return node;
}

/* ── Shape helpers ────────────────────────────────────────────────────────── */

/**
 * A FortiOS table as an array of entries, whichever shape it arrived in.
 *
 *   [ {name: 'a'}, {name: 'b'} ]          a sequence
 *   { a: {...}, b: {...} }                a map keyed by mkey
 *
 * The mkey is preserved as `_key` either way, because a policy's id is the
 * thing a finding has to name and it is the map key in one shape and a field
 * in the other.
 */
function asEntries(node) {
  if (!node) return [];
  if (Array.isArray(node)) {
    return node.filter(e => e && typeof e === 'object')
               .map((e, i) => Object.assign({ _key: String(e.name != null ? e.name
                                                : e.policyid != null ? e.policyid
                                                : e.id != null ? e.id : i) }, e));
  }
  if (typeof node === 'object') {
    return Object.keys(node)
      .filter(k => node[k] && typeof node[k] === 'object')
      .map(k => Object.assign({ _key: String(k) }, node[k]));
  }
  return [];
}

/**
 * A list of names from a reference field.
 *
 * srcaddr and friends appear as [{name:'all'}], ['all'], 'all', or the
 * space-separated 'all internal' depending on where the export came from.
 */
function names(node) {
  if (node == null) return [];
  if (Array.isArray(node)) {
    return node.map(n => (n && typeof n === 'object')
      ? String(n.name != null ? n.name : (n.q_origin_key != null ? n.q_origin_key : ''))
      : String(n)).filter(Boolean);
  }
  if (typeof node === 'object') return names(Object.values(node));
  return String(node).trim().split(/\s+/).filter(Boolean);
}

/**
 * FortiOS enable/disable as a boolean, or null when the field is absent.
 *
 * NULL IS NOT FALSE. An absent field means the check could not read it, which
 * is `not-assessable`, not a failure. Collapsing the two would turn every
 * section this parser does not understand into a list of findings against the
 * client.
 */
function flag(v) {
  if (v === null || v === undefined || v === '') return null;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  if (s === 'enable' || s === 'enabled' || s === 'on' || s === 'true' || s === '1') return true;
  if (s === 'disable' || s === 'disabled' || s === 'off' || s === 'false' || s === '0') return false;
  return null;
}

/** A number, or null when absent or unusable. Never 0 as a stand-in. */
function num(v) {
  if (v === null || v === undefined || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function str(v) {
  if (v === null || v === undefined) return null;
  const s = String(v).trim();
  return s === '' ? null : s;
}

/** Case-insensitive property lookup — exports vary on hyphens and case. */
function pick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return undefined;
  const lower = {};
  Object.keys(obj).forEach((k) => { lower[k.toLowerCase()] = obj[k]; });
  for (const k of keys) {
    const v = lower[String(k).toLowerCase()];
    if (v !== undefined) return v;
  }
  return undefined;
}

/* ── Masking ──────────────────────────────────────────────────────────────── */

/**
 * Did the client tick "Password mask"?
 *
 * TRI-STATE, and deliberately so. FortiOS writes a placeholder where a secret
 * would be; the exact placeholder varies by version, so this is a heuristic and
 * says as much. true / false / null — "appears masked", "appears unmasked",
 * "cannot tell" — because reporting a guess as a fact here would either scare
 * an analyst into rotating credentials needlessly, or reassure them wrongly
 * that a file they just uploaded was safe.
 *
 * Never scores anything. It drives advice only.
 */
function detectMasking(root) {
  let secrets = 0;
  let masked = 0;

  (function walk(node, depth) {
    if (depth > 30 || !node || typeof node !== 'object') return;
    if (Array.isArray(node)) { node.forEach(n => walk(n, depth + 1)); return; }
    Object.keys(node).forEach((k) => {
      const v = node[k];
      if (v && typeof v === 'object') { walk(v, depth + 1); return; }
      if (!isSecretField(k)) return;
      const s = String(v == null ? '' : v);
      secrets++;
      // A masked export leaves the field empty or writes a fixed placeholder.
      // An unmasked one carries an ENC blob or a hash, which is long and dense.
      if (s === '' || /^\**$/.test(s) || /^(masked|xxx+)$/i.test(s)) masked++;
    });
  })(root, 0);

  if (!secrets) return { masked: null, secretFields: 0, maskedFields: 0 };
  return {
    masked: masked === secrets ? true : (masked === 0 ? false : null),
    secretFields: secrets,
    maskedFields: masked,
  };
}

/* ── The parse ────────────────────────────────────────────────────────────── */

class FortigateParseError extends Error {}

/**
 * Parse YAML with the library's output silenced AND its errors still honoured.
 *
 * TWO THINGS HAD TO BE TRUE AT ONCE, AND THE OBVIOUS OPTION ONLY DELIVERS ONE.
 *
 * 1. Nothing may be printed. YAML.parse() reports oddities through
 *    process.emitWarning and THE WARNING TEXT QUOTES THE OFFENDING LINE. A real
 *    export produced hundreds of them. On a line carrying a pre-shared key or an
 *    SNMP community that writes the secret to this server's stderr and into
 *    whatever collects the logs — and the entire promise of this feature is that
 *    the configuration never reaches a log line.
 *
 *    parseDocument is what actually fixes this: it COLLECTS warnings on the
 *    document instead of emitting them, so nothing is printed whatever the log
 *    level. `logLevel: 'silent'` below is therefore belt-and-braces rather than
 *    the mechanism — it is what still holds if someone reverts this to
 *    YAML.parse, or if a future version starts emitting from here too.
 *
 * 2. A file we cannot read must not be audited. `logLevel: 'silent'` alone
 *    achieves (1) and quietly breaks (2): it makes YAML.parse() SWALLOW REAL
 *    ERRORS and return a guessed structure. Verified — a config that fails with
 *    "Nested mappings are not allowed in compact mappings" parses "successfully"
 *    with silent set, into a shape nobody checked. Every downstream check would
 *    then run against a misread config and report findings about a firewall that
 *    does not exist.
 *
 * So: parseDocument, which never throws and never prints, and then read
 * `doc.errors` ourselves. Silence and correctness, rather than one bought with
 * the other.
 *
 * @returns {{ value: *, errors: number, warnings: number, firstError: string|null }}
 */
function parseYamlDoc(text) {
  const doc = YAML.parseDocument(text, {
    maxAliasCount: MAX_ALIAS_COUNT,
    logLevel: 'silent',
  });

  /*
   * An error's `message` embeds the source line, so it is NEVER carried out of
   * this function. Only the position and the reason survive — enough to tell a
   * client which line to look at in their own file, without this server ever
   * repeating its contents.
   */
  const describe = (e) => {
    const where = e && e.linePos && e.linePos[0]
      ? ' at line ' + e.linePos[0].line + ', column ' + e.linePos[0].col : '';
    return String(e.message).split(' at line')[0].split('\n')[0] + where;
  };

  let errors = (doc.errors || []).length;
  let firstError = errors ? describe(doc.errors[0]) : null;
  let value;

  if (!errors) {
    /*
     * toJS() CAN THROW EVEN WHEN parseDocument RECORDED NO ERRORS.
     *
     * An unresolved alias — which is what `- *.bat:` produces — is not detected
     * while parsing; it surfaces when the tree is converted. Without this catch
     * the raw library error escaped past the repair path and out of
     * parseConfig entirely, so a file the repair pass could have fixed came
     * back as an unhandled failure, and the message reaching the route was a
     * library internal rather than anything a user could act on.
     */
    try {
      value = doc.toJS({ maxAliasCount: MAX_ALIAS_COUNT });
    } catch (err) {
      errors = 1;
      firstError = describe(err);
      value = undefined;
    }
  }

  return {
    value,
    errors,
    warnings: (doc.warnings || []).length,
    firstError,
  };
}

/**
 * Repair the two malformed constructs FortiOS is known to emit.
 *
 * Line-based and deliberately narrow: it only ever adds quotes around a
 * mapping KEY that is already ambiguous, and only on lines that end in a colon.
 * It does not touch values, indentation, or structure — a "repair" that
 * reshapes a config would produce an audit of something the client does not
 * run.
 *
 * @returns {{ text: string, repairs: Array<{line:number, kind:string}> }}
 */
function repairFortiYaml(text) {
  const repairs = [];
  const lines = String(text).split('\n');

  const out = lines.map((line, i) => {
    // Only a key line: optional indent, optional "- ", then text, then a
    // trailing colon and nothing else. Anything with a value after the colon is
    // left alone.
    const m = /^(\s*(?:-\s+)?)(.*?):(\s*)$/.exec(line);
    if (!m) return line;

    const [, prefix, key, trail] = m;
    if (!key || /^["']/.test(key.trim())) return line;      // already quoted

    // `*` opens an alias, so a file-extension pattern like *.bat is read as one.
    const aliasLike = /^\*/.test(key.trim());
    // A key containing " : " reads as a mapping inside a compact mapping.
    const innerColon = /\s:\s|\s:$/.test(key) || key.indexOf(': ') >= 0;

    if (!aliasLike && !innerColon) return line;

    repairs.push({
      line: i + 1,
      kind: aliasLike ? 'alias-like-key' : 'colon-in-key',
    });
    // Double quotes, with any embedded double quote escaped. The key is data
    // from the config, so it is quoted rather than trusted.
    return prefix + '"' + key.trim().replace(/"/g, '\\"') + '":' + trail;
  });

  return { text: out.join('\n'), repairs };
}

/**
 * Text in, model out.
 *
 * Throws FortigateParseError for anything a caller should turn into a 400: too
 * large, empty, not a mapping, unparseable, or an alias bomb. Nothing here
 * should ever produce a 500 — the input is a file a client chose.
 */
function parseConfig(text, opts) {
  const o = opts || {};
  const raw = String(text == null ? '' : text);

  if (!raw.trim()) throw new FortigateParseError('The file is empty.');
  if (Buffer.byteLength(raw, 'utf8') > MAX_BYTES) {
    throw new FortigateParseError('The file is larger than 25 MB. That is not a FortiGate backup.');
  }

  /*
   * FortiOS writes YAML it cannot itself read back.
   *
   * Real exports carry unquoted scalars containing YAML-significant characters:
   * `- *.bat:` (a file-extension pattern, where `*` opens an alias) and
   * `- FAZ : 100.71.0.161:` (a name containing " : ", which reads as a mapping
   * nested inside a compact mapping). A strict parser is right to refuse both,
   * and the client is in no position to fix their firewall's exporter.
   *
   * So: parse strictly, and only on failure apply a narrow, named set of
   * repairs and try again. Never silently — `repaired` travels with the model
   * and the page reports it, because a repaired parse is a weaker claim than a
   * clean one and the reader is entitled to know which they are looking at.
   */
  let repairs = [];
  let ambiguities = 0;

  let doc = parseYamlDoc(raw);
  if (doc.errors) {
    const fixed = repairFortiYaml(raw);
    if (!fixed.repairs.length) {
      throw new FortigateParseError('Could not read the file as YAML or JSON: ' + doc.firstError);
    }
    const retry = parseYamlDoc(fixed.text);
    if (retry.errors) {
      throw new FortigateParseError(
        'Could not read the file, even after repairing ' + fixed.repairs.length +
        ' malformed line(s) of the kind FortiOS is known to emit. The remaining ' +
        'problem is: ' + retry.firstError);
    }
    doc = retry;
    repairs = fixed.repairs;
  }

  // Warnings are COUNTED, never carried: their text quotes the source line.
  ambiguities = doc.warnings;
  const root = doc.value;

  if (!root || typeof root !== 'object' || Array.isArray(root)) {
    throw new FortigateParseError(
      'The file parsed, but is not a FortiGate configuration — expected a mapping of sections.');
  }

  // Track what we consume so `unread` can name the rest honestly.
  const consumed = new Set();
  const take = (obj, key) => {
    const v = pick(obj, key);
    if (v !== undefined) consumed.add(key.toLowerCase());
    return v;
  };

  const system   = take(root, 'system')   || {};
  const firewall = take(root, 'firewall') || {};
  const logKey   = take(root, 'log')      || {};
  const vpnKey   = take(root, 'vpn')      || {};
  const configVersion = str(take(root, 'config-version') || take(root, 'configVersion'));

  const mask = detectMasking(root);

  const model = {
    device: {
      hostname:      str(pick(system.global || {}, 'hostname')),
      // FGT60F-7.6.0-FW-build2620-240611:opmode=0:vdom=0
      model:         configVersion ? (configVersion.split('-')[0] || null) : null,
      firmware:      configVersion ? (configVersion.split('-').slice(1, 2)[0] || null) : null,
      configVersion,
    },

    masked:        mask.masked,
    maskDetail:    mask,

    system: {
      global:       system.global || {},
      admins:       asEntries(pick(system, 'admin')),
      accprofiles:  asEntries(pick(system, 'accprofile')),
      interfaces:   asEntries(pick(system, 'interface')),
      snmpCommunity: asEntries(pick(system.snmp || {}, 'community')),
      snmpUser:      asEntries(pick(system.snmp || {}, 'user')),
      ntp:          (system.ntp || null),
      dns:          (system.dns || null),
      certificates: asEntries(pick(system, 'certificate')),
      passwordPolicy: pick(system, 'password-policy') || null,
    },

    policies: asEntries(pick(firewall, 'policy')).map(normalisePolicy),

    profiles: {
      antivirus:  asEntries(pick(root, 'antivirus')),
      ips:        asEntries(pick(root, 'ips')),
      webfilter:  asEntries(pick(root, 'webfilter')),
      dnsfilter:  asEntries(pick(root, 'dnsfilter')),
      application: asEntries(pick(root, 'application')),
    },

    vpn: {
      ipsecPhase1: asEntries(pick(vpnKey['ipsec'] || {}, 'phase1-interface', 'phase1')),
      ipsecPhase2: asEntries(pick(vpnKey['ipsec'] || {}, 'phase2-interface', 'phase2')),
      sslSettings: pick(vpnKey['ssl'] || {}, 'settings') || null,
    },

    logging: {
      disk:          pick(logKey['disk'] || {}, 'setting') || null,
      syslog:        asEntries(pick(logKey, 'syslogd', 'syslogd2', 'syslogd3')),
      fortianalyzer: pick(logKey['fortianalyzer'] || {}, 'setting') || null,
      memory:        pick(logKey['memory'] || {}, 'setting') || null,
    },
  };

  // Profile tables live at the top level; mark them consumed so they do not
  // show as unread.
  ['antivirus', 'ips', 'webfilter', 'dnsfilter', 'application']
    .forEach(k => { if (pick(root, k) !== undefined) consumed.add(k); });

  /*
   * WHAT WE DID NOT READ.
   *
   * Named rather than dropped. An audit that scored 92% on a config where half
   * the tree was unrecognised is not a 92% — it is an unknown wearing one, and
   * the only way anybody finds out is if the parser says so.
   */
  model.unread = Object.keys(root)
    .filter(k => !consumed.has(k.toLowerCase()))
    .sort();

  model.counts = {
    policies:   model.policies.length,
    admins:     model.system.admins.length,
    interfaces: model.system.interfaces.length,
    unread:     model.unread.length,
  };

  // A repaired parse is a weaker claim than a clean one, and the page says so.
  // `ambiguities` counts constructs the parser resolved one way when another
  // reading was possible — reported as a number only, because the library's
  // description of each one quotes the config line it came from.
  model.repaired = repairs;
  model.ambiguities = ambiguities;

  if (o.fileName) model.fileName = String(o.fileName);
  return model;
}

/** One firewall policy, with its reference fields flattened to name lists. */
function normalisePolicy(p) {
  const profiles = {
    av:        str(pick(p, 'av-profile')),
    ips:       str(pick(p, 'ips-sensor')),
    webfilter: str(pick(p, 'webfilter-profile')),
    dnsfilter: str(pick(p, 'dnsfilter-profile')),
    app:       str(pick(p, 'application-list')),
    ssl:       str(pick(p, 'ssl-ssh-profile')),
  };

  return {
    id:       str(pick(p, 'policyid')) || p._key,
    name:     str(pick(p, 'name')),
    srcintf:  names(pick(p, 'srcintf')),
    dstintf:  names(pick(p, 'dstintf')),
    srcaddr:  names(pick(p, 'srcaddr')),
    dstaddr:  names(pick(p, 'dstaddr')),
    service:  names(pick(p, 'service')),
    action:   (str(pick(p, 'action')) || '').toLowerCase() || null,
    // FortiOS omits `status` when a policy is enabled, so absent means enabled.
    // This is the one place a missing field legitimately has a default, and it
    // is a documented device behaviour rather than an assumption.
    status:   pick(p, 'status') === undefined ? 'enable' : (str(pick(p, 'status')) || 'enable'),
    logtraffic: (str(pick(p, 'logtraffic')) || '').toLowerCase() || null,
    nat:      flag(pick(p, 'nat')),
    schedule: names(pick(p, 'schedule')),
    comments: str(pick(p, 'comments')),
    profiles,
    // True when ANY security profile is applied.
    hasProfiles: Object.keys(profiles).some(k => k !== 'ssl' && profiles[k]),
  };
}

/** Does a name list mean "everything"? */
function isAny(list) {
  const l = (list || []).map(s => String(s).toLowerCase());
  return l.length > 0 && l.every(n => n === 'all' || n === 'any' || n === '*');
}

/** Does a service list mean "every port"? */
function isAnyService(list) {
  const l = (list || []).map(s => String(s).toUpperCase());
  return l.length > 0 && l.some(n => n === 'ALL' || n === 'ANY');
}

module.exports = {
  parseConfig,
  FortigateParseError,
  redact,
  repairFortiYaml,
  isSecretField,
  SECRET_FIELDS,
  MAX_BYTES,
  MAX_ALIAS_COUNT,
  // Exported for the checks, which must read the model the same way the parser
  // wrote it rather than re-deriving these rules.
  asEntries, names, flag, num, str, pick, isAny, isAnyService,
  detectMasking, normalisePolicy,
};
