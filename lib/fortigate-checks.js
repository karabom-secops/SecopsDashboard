'use strict';

/**
 * lib/fortigate-checks.js — what we assert about a FortiGate, and why.
 *
 * Each check is data plus a predicate:
 *
 *   { id, title, severity, cis, source, rationale, remediation,
 *     run(model) -> { status, detail, evidence } }
 *
 * THREE OUTCOMES, AND THE THIRD IS THE IMPORTANT ONE
 *
 *   pass             the control is in place
 *   fail             the control is absent or misconfigured
 *   not-assessable   the config did not tell us
 *
 * `not-assessable` exists because a section can be missing, a field can be
 * absent on this model or firmware, and "Password mask" can blank the very
 * value a check reads. Folding any of those into `fail` would produce findings
 * against a client for things we simply could not see — and a masked config,
 * which is the responsible way to send one, would score worse than an unmasked
 * one. It leaves the denominator entirely; see lib/fortigate-score.js.
 *
 * EVIDENCE IS IDENTIFIERS AND COUNTS, NEVER VALUES.
 *
 * A finding may say "policy 1 and policy 7"; it may not say what the pre-shared
 * key was. The config is discarded after the audit, and a check that copied a
 * secret into a finding would be the one thing that put it in the database
 * anyway. lib/fortigate-parser.js `redact()` is the net under this, but the
 * rule is that nothing needs catching in the first place.
 *
 * SOURCE
 *
 *   'cis'    — maps to a CIS FortiGate Benchmark control, referenced so a
 *              client can look it up and argue with it.
 *   'reflex' — our own, marked as ours rather than dressed up as a standard.
 */

const { flag, num, str, pick, isAny, isAnyService } = require('./fortigate-parser');
const policyLib = require('./fortigate-policy');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

/**
 * CATEGORIES — how findings are grouped in the report.
 *
 * The first five mirror the categories a client-facing firewall assessment
 * reports against, so our output can sit beside one and be compared line for
 * line. The last four are the device-hardening work those reports do not cover
 * and that we are not dropping to match a format.
 *
 * `order` drives presentation; `key` is stored on the finding.
 */
const CATEGORIES = [
  { key: 'risky-policy-conditions', order: 1,
    label: 'Risky Policy Conditions',
    blurb: 'How the action a policy takes compares with how permissive it is — ' +
           'an accept rule that is explicit about source, destination and service ' +
           'is a different thing from one that is not.' },
  { key: 'policy-attribute', order: 2,
    label: 'Policy Attribute',
    blurb: 'Hygiene across the rulebase: whether policies are named, commented, ' +
           'logged, and whether dead rules have been removed.' },
  { key: 'risky-inbound-blanket', order: 3,
    label: 'Risky Inbound Blanket',
    blurb: 'Inbound rules that combine a wildcard scope with a known-risky ' +
           'service — the FTP and RDP shaped exposures, open to anywhere.' },
  { key: 'risky-inbound-conditions', order: 4,
    label: 'Risky Inbound Conditions',
    blurb: 'Known risky or exploitable services reachable from the internet, ' +
           'by port and protocol, however narrowly the rule is scoped.' },
  { key: 'risky-outbound-conditions', order: 5,
    label: 'Risky Outbound Conditions',
    blurb: 'Egress that assists an attacker already inside: credential-leaking ' +
           'protocols, unmonitored file transfer and command-and-control paths.' },

  { key: 'administrative-access', order: 6, label: 'Administrative Access',
    blurb: 'How the device itself is managed and by whom.' },
  { key: 'threat-protection', order: 7, label: 'Threat Protection',
    blurb: 'Security profiles available to be applied to traffic.' },
  { key: 'remote-access', order: 8, label: 'Remote Access',
    blurb: 'IPsec and SSL-VPN configuration.' },
  { key: 'logging-and-platform', order: 9, label: 'Logging and Platform',
    blurb: 'Whether the device records what it did, and basic platform hygiene.' },
];

const CATEGORY_KEYS = CATEGORIES.map(c => c.key);

function categoryLabel(key) {
  const c = CATEGORIES.find(x => x.key === key);
  return c ? c.label : String(key);
}

/** Outcome helpers, so a check body reads as the judgement it is making. */
const pass = (detail, evidence) => ({ status: 'pass', detail: detail || null, evidence: evidence || null });
const fail = (detail, evidence) => ({ status: 'fail', detail: detail || null, evidence: evidence || null });
const unknown = (detail, evidence) =>
  ({ status: 'not-assessable', detail: detail || null, evidence: evidence || null });

/** Accept policies that are actually in force. Disabled rules are hygiene, not exposure. */
function livePolicies(model) {
  return (model.policies || []).filter(p => p.status !== 'disable' && p.action === 'accept');
}

/** Interfaces facing the internet, by declared role. */
function wanInterfaces(model) {
  return (model.system.interfaces || [])
    .filter(i => String(pick(i, 'role') || '').toLowerCase() === 'wan');
}

/**
 * Guard for every direction-scoped check.
 *
 * Returns a result to hand back, or null to carry on.
 *
 * ══ THE BLIND SPOT THIS EXISTS TO CLOSE ══
 *
 * A policy whose source and destination interfaces are both "any" touches the
 * WAN at both ends, so its direction cannot be determined — and it is very
 * often the most dangerous rule on the device. Without this guard it would
 * appear in neither the inbound nor the outbound set, and a device whose only
 * risky rule was that one would report "no inbound accept policies were found"
 * as a PASS.
 *
 * So "there are none facing this way" is only a pass when there are also no
 * live policies we could not place. Otherwise it is not-assessable, naming them.
 */
function directionGuard(ctx, direction) {
  if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
  if (!ctx.analysis.wanKnown) {
    return unknown('No interface declares role: wan, so inbound and outbound ' +
      'traffic cannot be told apart from the configuration alone. Confirm the ' +
      'interface roles on the device and re-run.');
  }

  if (ctx.analysis.facing(direction).length) return null;

  const unplaced = ctx.analysis.facing('unknown');
  if (unplaced.length) {
    return unknown('No ' + direction + ' accept policies could be identified, but ' +
      unplaced.length + ' enabled accept polic(y/ies) span both the internet and ' +
      'the internal network — their direction could not be determined, so they ' +
      'were not assessed either way.',
      { unplacedPolicies: unplaced.map(a => a.id).slice(0, 50) });
  }

  return pass('No enabled ' + direction + ' accept policies were found.');
}

/**
 * Shared body for the inbound-exposure checks, which differ only in WHICH risky
 * services they look for and therefore in the severity they carry.
 *
 * Written once because the failure mode of copying it four times is four
 * slightly different answers to the same question — and in particular four
 * chances to forget that an unknown WAN role means not-assessable rather than
 * a pass.
 *
 * @param {string[]} keys  keys from policyLib.RISKY_INBOUND
 */
function inboundRiskCheck(ctx, keys, label) {
  const guard = directionGuard(ctx, 'inbound');
  if (guard) return guard;

  const table = policyLib.RISKY_INBOUND.filter(r => keys.indexOf(r.key) >= 0);
  const inbound = ctx.analysis.facing('inbound');

  const hits = [];
  inbound.forEach((a) => {
    const risks = policyLib.risksOn(a, table);
    if (risks.length) hits.push({ policy: a.id, exposes: risks.map(r => r.key) });
  });

  if (!hits.length) {
    /*
     * A pass here is only as good as the service resolution behind it. Where a
     * policy's services could not be resolved, we did not look inside it — so
     * "we found nothing" would be a stronger claim than the evidence supports.
     */
    /*
     * Gated on SERVICE resolution specifically, not on `fullyResolved`.
     *
     * This helper answers "which risky services are exposed inbound", which
     * depends on service names resolving to ports and not at all on whether the
     * address objects resolved. Gating it on the combined flag made a config
     * with no address table report every service check as not-assessable —
     * conservative in the wrong place, and it buries a real exposure behind a
     * coverage caveat that does not apply to it.
     */
    const blind = inbound.filter(a => !a.servicesResolved);
    if (blind.length) {
      return unknown('No ' + label + ' were found on the inbound rules that could ' +
        'be read, but ' + blind.length + ' inbound rule(s) reference services that ' +
        'could not be resolved to ports and were not examined.',
        { unreadPolicies: blind.map(a => a.id).slice(0, 50) });
    }
    return pass('No ' + label + ' are reachable from the internet across ' +
      inbound.length + ' inbound policies.');
  }

  return fail(hits.length + ' inbound rules expose ' + label + '.',
    { findings: hits.slice(0, 25), total: hits.length });
}

const CHECKS = [
  /* ── Administrative access ─────────────────────────────────────────────── */
  {
    id: 'admin-telnet', title: 'Telnet administration is disabled',
    severity: 'high', source: 'cis', cis: '1.2',
    rationale: 'Telnet carries administrative credentials and session content in ' +
               'cleartext. Anyone positioned on the path can read them.',
    remediation: 'config system global / set admin-telnet disable',
    run(m) {
      const v = flag(pick(m.system.global, 'admin-telnet'));
      if (v === null) return unknown('admin-telnet is not present in this config.');
      return v ? fail('Telnet administration is enabled.') : pass();
    },
  },
  {
    id: 'admin-http', title: 'Plain HTTP administration is disabled',
    severity: 'high', source: 'cis', cis: '1.3',
    rationale: 'An HTTP management listener exposes the admin session to ' +
               'interception and downgrade.',
    remediation: 'config system global / set admin-https-redirect enable, and ' +
                 'restrict admin-port.',
    run(m) {
      const redirect = flag(pick(m.system.global, 'admin-https-redirect'));
      if (redirect === null) return unknown('admin-https-redirect is not present in this config.');
      return redirect ? pass() : fail('HTTP administration is not redirected to HTTPS.');
    },
  },
  {
    id: 'admin-idle-timeout', title: 'Administrative idle timeout is 5 minutes or less',
    severity: 'medium', source: 'cis', cis: '1.1',
    rationale: 'An unattended administrative session is a working console for ' +
               'anyone who reaches the keyboard.',
    remediation: 'config system global / set admintimeout 5',
    run(m) {
      const t = num(pick(m.system.global, 'admintimeout'));
      if (t === null) return unknown('admintimeout is not present in this config.');
      return t <= 5 ? pass('Idle timeout is ' + t + ' minutes.')
                    : fail('Idle timeout is ' + t + ' minutes.', { admintimeout: t });
    },
  },
  {
    id: 'admin-trusted-hosts', title: 'Every administrator is restricted by trusted host',
    severity: 'high', source: 'cis', cis: '2.1',
    rationale: 'Without a trusted host, an administrator account can be used ' +
               'from anywhere the management interface is reachable.',
    remediation: 'config system admin / edit <name> / set trusthost1 <subnet>',
    run(m) {
      const admins = m.system.admins || [];
      if (!admins.length) return unknown('No administrator accounts were found in this config.');
      const open = admins.filter((a) => {
        const hosts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
          .map(n => str(pick(a, 'trusthost' + n)))
          .filter(Boolean)
          // 0.0.0.0/0 is a trusted host entry that trusts everybody.
          .filter(h => !/^0\.0\.0\.0\s+0\.0\.0\.0$/.test(h));
        return hosts.length === 0;
      });
      if (!open.length) return pass('All ' + admins.length + ' administrators are restricted.');
      return fail(open.length + ' of ' + admins.length + ' administrators have no trusted host.',
        { admins: open.map(a => a._key) });
    },
  },
  {
    id: 'admin-default-account', title: 'The default "admin" account is not in use',
    severity: 'medium', source: 'reflex',
    rationale: 'A known username halves the work of a credential attack, and ' +
               '"admin" is the first one tried.',
    remediation: 'Create a named super_admin, verify access, then delete "admin".',
    run(m) {
      const admins = m.system.admins || [];
      if (!admins.length) return unknown('No administrator accounts were found in this config.');
      const has = admins.some(a => String(a._key).toLowerCase() === 'admin');
      return has ? fail('The default "admin" account exists.', { admins: ['admin'] })
                 : pass();
    },
  },
  {
    id: 'admin-password-policy', title: 'A password policy is enforced',
    severity: 'medium', source: 'cis', cis: '2.3',
    rationale: 'Without a policy, administrative passwords are whatever the ' +
               'person setting them felt like typing.',
    remediation: 'config system password-policy / set status enable',
    run(m) {
      const pol = m.system.passwordPolicy;
      if (!pol) return unknown('No password-policy section is present in this config.');
      const v = flag(pick(pol, 'status'));
      if (v === null) return unknown('password-policy status is not present.');
      return v ? pass() : fail('The password policy is disabled.');
    },
  },
  {
    id: 'admin-strong-crypto', title: 'Strong cryptography is enforced for management',
    severity: 'medium', source: 'cis', cis: '1.5',
    rationale: 'strong-crypto removes the weak ciphers and hashes the ' +
               'management services would otherwise accept.',
    remediation: 'config system global / set strong-crypto enable',
    run(m) {
      const v = flag(pick(m.system.global, 'strong-crypto'));
      if (v === null) return unknown('strong-crypto is not present in this config.');
      return v ? pass() : fail('strong-crypto is disabled.');
    },
  },
  {
    id: 'admin-banner', title: 'A pre-login banner is configured',
    severity: 'low', source: 'cis', cis: '1.4',
    rationale: 'A banner establishes that access is restricted, which matters ' +
               'when an incident becomes a legal matter.',
    remediation: 'config system global / set pre-login-banner enable',
    run(m) {
      const v = flag(pick(m.system.global, 'pre-login-banner'));
      if (v === null) return unknown('pre-login-banner is not present in this config.');
      return v ? pass() : fail('No pre-login banner is configured.');
    },
  },

  /* ── Management exposure ───────────────────────────────────────────────── */
  {
    id: 'wan-management', title: 'Management services are not exposed on WAN interfaces',
    severity: 'critical', source: 'cis', cis: '3.1',
    rationale: 'A management listener on an internet-facing interface is ' +
               'reachable by everyone, and is how firewalls are taken over.',
    remediation: 'config system interface / edit <wan> / unset allowaccess, or ' +
                 'restrict it to nothing.',
    run(m) {
      const wans = wanInterfaces(m);
      if (!wans.length) {
        return unknown('No interface is marked with the WAN role, so internet-facing ' +
                       'management could not be determined from this config.');
      }
      const bad = [];
      wans.forEach((i) => {
        const allow = String(pick(i, 'allowaccess') || '').toLowerCase().split(/\s+/);
        const mgmt = allow.filter(a => ['http', 'https', 'ssh', 'telnet', 'snmp'].indexOf(a) >= 0);
        if (mgmt.length) bad.push({ interface: str(pick(i, 'name')) || i._key, services: mgmt });
      });
      if (!bad.length) return pass('No management services on ' + wans.length + ' WAN interface(s).');
      return fail(bad.length + ' WAN interface(s) permit management access.', { interfaces: bad });
    },
  },

  /* ── SNMP ──────────────────────────────────────────────────────────────── */
  {
    id: 'snmp-v1v2c', title: 'SNMP v1/v2c communities are not in use',
    severity: 'high', source: 'cis', cis: '1.6',
    rationale: 'SNMP v1 and v2c authenticate with a community string sent in ' +
               'cleartext, and it is usually readable across the whole estate.',
    remediation: 'Remove SNMP communities and use SNMPv3 users with authPriv.',
    run(m) {
      const comms = (m.system.snmpCommunity || []).filter(c => flag(pick(c, 'status')) !== false);
      if (!comms.length) return pass('No SNMP v1/v2c communities are configured.');
      // The community NAME is the credential, so it is never echoed here.
      return fail(comms.length + ' SNMP v1/v2c community/communities are configured.',
        { communities: comms.length });
    },
  },
  {
    id: 'snmp-default-community', title: 'No default SNMP community name is used',
    severity: 'high', source: 'reflex',
    rationale: '"public" and "private" are the first two strings any scanner ' +
               'tries, and they are still found on production firewalls.',
    remediation: 'Remove the community, or move to SNMPv3.',
    run(m) {
      const comms = m.system.snmpCommunity || [];
      if (!comms.length) return pass('No SNMP communities are configured.');
      // THE ONE CHECK MASKING GENUINELY BLINDS. For v1/v2c the community name
      // IS the secret, so a masked export blanks it — and we would rather say
      // we could not tell than clear a firewall that is still on "public".
      const readable = comms.filter(c => str(pick(c, 'name')));
      if (!readable.length) {
        return unknown('Community names are masked in this export, so default names ' +
                       'could not be checked. Confirm on the device.');
      }
      const defaults = readable.filter(c =>
        ['public', 'private'].indexOf(String(pick(c, 'name')).toLowerCase()) >= 0);
      if (!defaults.length) return pass();
      return fail(defaults.length + ' SNMP community/communities use a default name.',
        { communities: defaults.length });
    },
  },

  /* ── Policy hygiene ────────────────────────────────────────────────────── */
  {
    id: 'policy-any-any', title: 'No policy permits any source to any destination on any service',
    // Risk, not hygiene — the prefix map would file every policy- check under
    // Policy Attribute, and this one belongs beside the other permissiveness
    // findings.
    category: 'risky-policy-conditions',
    severity: 'critical', source: 'cis', cis: '4.1',
    rationale: 'An any/any/ALL accept rule is the absence of a firewall on that ' +
               'path. Everything downstream of it is unfiltered.',
    remediation: 'Replace with rules scoped to the addresses and services the ' +
                 'traffic actually needs.',
    /*
     * Reads the ANALYSIS, not the raw policy fields.
     *
     * This used to call isAny() on srcaddr/dstaddr directly, which only ever
     * matched the literal strings 'all'/'any'/'*'. A rule whose source was an
     * address object containing 0.0.0.0/0 — or a group with one such member —
     * is an any/any rule in every sense that matters to the traffic, and this
     * check walked straight past it. ctx.analysis resolves the objects; see
     * analysePolicies() in lib/fortigate-policy.js.
     */
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const live = ctx.analysis.policies.filter(a => a.live);
      if (!live.length) return unknown('No enabled accept policies were found in this config.');
      const bad = live.filter(a => a.anySrc && a.anyDst && a.anyService);
      if (!bad.length) return pass('None of ' + live.length + ' enabled accept policies is any/any/ALL.');
      return fail(bad.length + ' policy/policies permit any source to any destination on all services.',
        (() => {
          /*
           * `via` is added ONLY where a named object opened the rule up. For a
           * literal `all` it would restate the finding ("source: all"), and
           * evidence that repeats the headline trains people to skip it.
           */
          const named = a => a && !/^all$/i.test(a);
          const via = bad.filter(a => named(a.anySrcVia) || named(a.anyDstVia))
            .slice(0, 20)
            .map((a) => {
              const parts = [];
              if (named(a.anySrcVia)) parts.push('source ' + a.anySrcVia);
              if (named(a.anyDstVia)) parts.push('destination ' + a.anyDstVia);
              return 'policy ' + a.id + ': ' + parts.join('; ');
            });
          return { policies: bad.map(a => a.id), ...(via.length ? { via } : {}) };
        })());
    },
  },
  {
    id: 'policy-logging', title: 'Every enabled accept policy logs',
    severity: 'high', source: 'cis', cis: '4.2',
    rationale: 'Traffic permitted by a rule that does not log is traffic that ' +
               'cannot be investigated afterwards. It is invisible to the SOC.',
    remediation: 'config firewall policy / edit <id> / set logtraffic all',
    run(m) {
      const live = livePolicies(m);
      if (!live.length) return unknown('No enabled accept policies were found in this config.');
      const unlogged = live.filter(p => p.logtraffic === 'disable' || p.logtraffic === null);
      if (!unlogged.length) return pass('All ' + live.length + ' enabled accept policies log.');
      return fail(unlogged.length + ' of ' + live.length + ' enabled accept policies do not log.',
        { policies: unlogged.map(p => p.id) });
    },
  },
  {
    id: 'policy-utm', title: 'Internet-bound policies apply security profiles',
    category: 'risky-policy-conditions',
    severity: 'high', source: 'reflex',
    rationale: 'A policy with no AV, IPS or web filtering is a router rule. The ' +
               'inspection the appliance was bought for is not being applied.',
    remediation: 'Apply an antivirus profile, IPS sensor and web filter to ' +
                 'policies that reach the internet.',
    run(m) {
      const wanNames = wanInterfaces(m).map(i => String(str(pick(i, 'name')) || i._key));
      const live = livePolicies(m);
      if (!live.length) return unknown('No enabled accept policies were found in this config.');
      if (!wanNames.length) {
        return unknown('No interface is marked with the WAN role, so internet-bound ' +
                       'policies could not be identified.');
      }
      const outbound = live.filter(p => p.dstintf.some(d => wanNames.indexOf(d) >= 0));
      if (!outbound.length) return pass('No enabled accept policy is bound for a WAN interface.');
      const bare = outbound.filter(p => !p.hasProfiles);
      if (!bare.length) return pass('All ' + outbound.length + ' internet-bound policies apply profiles.');
      return fail(bare.length + ' of ' + outbound.length + ' internet-bound policies apply no security profile.',
        { policies: bare.map(p => p.id) });
    },
  },
  {
    id: 'policy-service-all', title: 'No enabled policy permits every service',
    category: 'risky-policy-conditions',
    severity: 'medium', source: 'reflex',
    rationale: 'Service ALL grants every port and protocol, including the ones ' +
               'nobody intended to allow.',
    remediation: 'Replace ALL with the specific services required.',
    run(m) {
      const live = livePolicies(m);
      if (!live.length) return unknown('No enabled accept policies were found in this config.');
      const bad = live.filter(p => isAnyService(p.service));
      if (!bad.length) return pass();
      return fail(bad.length + ' enabled accept policy/policies permit all services.',
        { policies: bad.map(p => p.id) });
    },
  },
  {
    id: 'policy-disabled-present', title: 'Disabled policies have been removed',
    severity: 'low', source: 'reflex',
    rationale: 'Disabled rules accumulate, obscure the live ruleset, and are ' +
               'occasionally re-enabled by somebody who does not know why they ' +
               'were turned off.',
    remediation: 'Delete rules that are no longer needed; document any kept ' +
                 'deliberately in the comments field.',
    run(m) {
      const all = m.policies || [];
      if (!all.length) return unknown('No firewall policies were found in this config.');
      const off = all.filter(p => p.status === 'disable');
      if (!off.length) return pass();
      return fail(off.length + ' disabled policy/policies remain in the configuration.',
        { policies: off.map(p => p.id) });
    },
  },
  {
    id: 'policy-named', title: 'Every policy has a name',
    severity: 'low', source: 'reflex',
    rationale: 'An unnamed rule is one nobody can discuss, review or safely ' +
               'remove, because its purpose exists only in somebody\'s memory.',
    remediation: 'config firewall policy / edit <id> / set name "<purpose>"',
    run(m) {
      const all = m.policies || [];
      if (!all.length) return unknown('No firewall policies were found in this config.');
      const unnamed = all.filter(p => !p.name);
      if (!unnamed.length) return pass('All ' + all.length + ' policies are named.');
      return fail(unnamed.length + ' of ' + all.length + ' policies have no name.',
        { policies: unnamed.map(p => p.id) });
    },
  },

  /* ── Policy attribute ──────────────────────────────────────────────────── */
  {
    id: 'pa-comments', title: 'Every policy carries a comment',
    severity: 'low', source: 'reflex',
    rationale: 'A rule with no comment has no recorded reason to exist. That is ' +
               'why rulebases grow and never shrink: nobody can prove a rule is ' +
               'safe to delete, so nobody deletes it.',
    remediation: 'config firewall policy / edit <id> / set comments "<why, and who asked>"',
    run(m) {
      const all = m.policies || [];
      if (!all.length) return unknown('No firewall policies were found in this config.');
      const bare = all.filter(p => !p.comments);
      if (!bare.length) return pass('All ' + all.length + ' policies are commented.');
      return fail(bare.length + ' of ' + all.length + ' policies have no comment.',
        { policies: bare.map(p => p.id).slice(0, 50), total: bare.length });
    },
  },

  /* ── Risky policy conditions ───────────────────────────────────────────── */
  {
    id: 'rpc-any-source', title: 'No accept policy permits every source',
    severity: 'high', source: 'reflex',
    rationale: 'An accept rule whose source is "all" grants the same access to ' +
               'a known partner and to the whole internet. The action is ' +
               'permissive and the condition is unbounded, which is the ' +
               'combination worth finding.',
    remediation: 'Replace the "all" source with an address object or group ' +
                 'naming the hosts that actually need this.',
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const live = ctx.analysis.policies.filter(a => a.live);
      if (!live.length) return unknown('No enabled accept policies were found.');
      const bad = live.filter(a => a.anySrc);
      if (!bad.length) return pass('No enabled accept policy permits every source.');
      /*
       * `via` names the object chain that opened the rule up, because the
       * commonest form of this finding is no longer a literal "all": it is an
       * address object or group whose NAME reads as restrictive and whose
       * CONTENTS are 0.0.0.0/0. Reporting the policy id alone invites the reply
       * "no, that rule is scoped to Servers_Group" — which is true, and beside
       * the point, and takes a meeting to settle.
       */
      // Strings, not objects: the page joins an array with commas and
      // JSON.stringifies anything else, so an array of objects renders as raw
      // JSON in the middle of a client's report.
      const via = bad.filter(a => a.anySrcVia && !/^all$/i.test(a.anySrcVia))
                     .slice(0, 20).map(a => 'policy ' + a.id + ': ' + a.anySrcVia);
      return fail(bad.length + ' of ' + live.length + ' enabled accept policies ' +
        'permit every source.',
        { policies: bad.map(a => a.id).slice(0, 50), total: bad.length,
          ...(via.length ? { via } : {}) });
    },
  },
  {
    id: 'rpc-any-destination', title: 'No accept policy permits every destination',
    severity: 'medium', source: 'reflex',
    rationale: 'An unbounded destination means the rule grants more than whoever ' +
               'wrote it was asked for, and nobody can say how much more without ' +
               'reading the routing table.',
    remediation: 'Name the destinations this rule exists to reach.',
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const live = ctx.analysis.policies.filter(a => a.live);
      if (!live.length) return unknown('No enabled accept policies were found.');
      const bad = live.filter(a => a.anyDst);
      if (!bad.length) return pass('No enabled accept policy permits every destination.');
      const via = bad.filter(a => a.anyDstVia && !/^all$/i.test(a.anyDstVia))
                     .slice(0, 20).map(a => 'policy ' + a.id + ': ' + a.anyDstVia);
      return fail(bad.length + ' of ' + live.length + ' enabled accept policies ' +
        'permit every destination.',
        { policies: bad.map(a => a.id).slice(0, 50), total: bad.length,
          ...(via.length ? { via } : {}) });
    },
  },
  {
    id: 'rpc-broad-uninspected', title: 'Broad accept policies apply security profiles',
    severity: 'high', source: 'reflex',
    rationale: 'A rule can be permissive or uninspected and still be defensible. ' +
               'Being both means traffic nobody scoped is also traffic nobody ' +
               'scans, and the firewall is doing routing rather than security.',
    remediation: 'Either narrow the rule, or apply antivirus, IPS and web ' +
                 'filtering profiles to it.',
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const broad = ctx.analysis.policies.filter(
        a => a.live && (a.anySrc || a.anyDst || a.anyService));
      if (!broad.length) return pass('No enabled accept policy is broadly scoped.');
      const bad = broad.filter(a => !a.policy.hasProfiles);
      if (!bad.length) {
        return pass('All ' + broad.length + ' broadly scoped policies apply at ' +
          'least one security profile.');
      }
      return fail(bad.length + ' broadly scoped accept policies apply no security ' +
        'profile.', { policies: bad.map(a => a.id).slice(0, 50), total: bad.length });
    },
  },
  {
    id: 'rpc-deny-unlogged', title: 'Deny policies record what they blocked',
    severity: 'low', source: 'reflex',
    rationale: 'An unlogged deny stops the traffic and destroys the evidence. ' +
               'The rule that would have shown you the attack is the one that ' +
               'silently absorbed it.',
    remediation: 'config firewall policy / edit <id> / set logtraffic all',
    run(m) {
      const denies = (m.policies || []).filter(
        p => p.status !== 'disable' && p.action && p.action !== 'accept');
      if (!denies.length) return unknown('No enabled deny policies were found.');
      // NULL is not "disable": an absent logtraffic is a field we did not see.
      const off = denies.filter(p => p.logtraffic === 'disable');
      if (!off.length) return pass('No enabled deny policy has logging switched off.');
      return fail(off.length + ' of ' + denies.length + ' deny policies do not log.',
        { policies: off.map(p => p.id).slice(0, 50), total: off.length });
    },
  },
  {
    id: 'rpc-services-resolved', title: 'Every policy service could be resolved to ports',
    severity: 'medium', source: 'reflex',
    rationale: 'The inbound and outbound risk checks work on resolved ports. A ' +
               'service name that resolves to nothing is a rule whose contents ' +
               'were not examined — and a rulebase that was half read must not ' +
               'be reported as a rulebase that was found clean.',
    remediation: 'No device change is needed. This is a limit of the audit: send ' +
                 'the service definitions, or confirm these rules by hand.',
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const live = ctx.analysis.policies.filter(a => a.live);
      if (!live.length) return unknown('No enabled accept policies were found.');
      const unresolved = ctx.analysis.unresolvedPolicies();
      if (!unresolved.length) {
        return pass('All services on ' + live.length + ' enabled accept policies ' +
          'resolved to ports.');
      }
      /*
       * NOT-ASSESSABLE, not fail. Nothing is wrong with the device; the audit
       * could not see far enough. Grading it as a failure would penalise a
       * client for our coverage gap and hide the gap behind a finding they
       * cannot act on.
       */
      const svcNames = [];
      unresolved.forEach((a) => {
        a.resolved.unresolved.forEach(n => { if (svcNames.indexOf(n) < 0) svcNames.push(n); });
      });
      return unknown(unresolved.length + ' enabled accept policies reference ' +
        'services that could not be resolved to ports, so their contents were ' +
        'not assessed.',
        { policies: unresolved.map(a => a.id).slice(0, 50), services: svcNames.slice(0, 25) });
    },
  },
  {
    id: 'rpc-addresses-resolved', title: 'Every policy address could be resolved to networks',
    severity: 'medium', source: 'reflex',
    /*
     * The address twin of rpc-services-resolved, and the more important of the
     * two, because its failure mode is silent.
     *
     * An unresolvable SERVICE produces a policy nobody can classify, which is
     * visibly a gap. An unresolvable ADDRESS used to produce a policy that
     * looked precisely scoped: the scope test only asked whether the name was
     * the literal 'all', so any name it could not find read as "restricted".
     * A missing address table therefore turned into a clean report rather than
     * a gap, which is the worst outcome this audit can produce.
     */
    rationale: 'Whether a rule is scoped depends on what its address objects ' +
               'contain, not what they are called. A name that resolves to ' +
               'nothing is a rule whose real scope was never established — and ' +
               'an unresolved address must never be read as a narrow one.',
    remediation: 'No device change is needed. This is a limit of the audit: send ' +
                 'the address and group definitions, or confirm these rules by hand.',
    run(m, ctx) {
      if (!ctx || !ctx.analysis) return unknown('The rulebase could not be analysed.');
      const live = ctx.analysis.policies.filter(a => a.live);
      if (!live.length) return unknown('No enabled accept policies were found.');
      const unresolved = ctx.analysis.unresolvedAddressPolicies();
      if (!unresolved.length) {
        return pass('All source and destination addresses on ' + live.length +
          ' enabled accept policies resolved to networks.');
      }
      const addrNames = [];
      unresolved.forEach((a) => {
        a.addrUnresolved.forEach(n => { if (addrNames.indexOf(n) < 0) addrNames.push(n); });
      });
      // Not-assessable, not fail — the device is not at fault, our coverage is.
      return unknown(unresolved.length + ' enabled accept policies reference ' +
        'address objects that are not defined in this config, so their true ' +
        'scope was not assessed.',
        { policies: unresolved.map(a => a.id).slice(0, 50), addresses: addrNames.slice(0, 25) });
    },
  },

  /* ── Risky inbound blanket ─────────────────────────────────────────────── */
  {
    id: 'rib-any-service', title: 'No inbound policy permits every service',
    severity: 'critical', source: 'reflex',
    rationale: 'An inbound rule with service ALL publishes every port on the ' +
               'destination to whoever the source allows. Nothing behind it is ' +
               'protected by the firewall.',
    remediation: 'Replace ALL with the specific services the published host serves.',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'inbound');
      if (guard) return guard;
      const inbound = ctx.analysis.facing('inbound');
      const bad = inbound.filter(a => a.anyService);
      if (!bad.length) return pass('No inbound policy permits every service.');
      return fail(bad.length + ' of ' + inbound.length + ' inbound accept policies ' +
        'permit every service.', { policies: bad.map(a => a.id).slice(0, 50), total: bad.length });
    },
  },
  {
    id: 'rib-blanket-risky', title: 'No wide-open inbound rule exposes a risky service',
    severity: 'critical', source: 'reflex',
    rationale: 'This is the finding that gets organisations ransomed: RDP, SMB ' +
               'or a database port, reachable from any source on the internet. ' +
               'Scanning finds these within hours of them being created.',
    remediation: 'Restrict the source to named addresses, or move the service ' +
                 'behind the VPN. Publishing it to "all" is not a configuration ' +
                 'that can be made safe by other means.',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'inbound');
      if (guard) return guard;
      const inbound = ctx.analysis.facing('inbound');

      const hits = [];
      inbound.filter(a => a.anySrc).forEach((a) => {
        const risks = policyLib.risksOn(a, policyLib.RISKY_INBOUND);
        if (risks.length) hits.push({ policy: a.id, exposes: risks.map(r => r.key) });
      });
      if (!hits.length) {
        return pass('No inbound rule combines an "all" source with a risky service.');
      }
      return fail(hits.length + ' inbound rules expose a risky service to every ' +
        'source.', { findings: hits.slice(0, 25), total: hits.length });
    },
  },

  /* ── Risky inbound conditions ──────────────────────────────────────────── */
  {
    id: 'ric-critical-services', title: 'No critical service is reachable from the internet',
    severity: 'critical', source: 'reflex',
    rationale: 'Remote desktop, file sharing, database and remote-control ' +
               'protocols were designed for a trusted network. Exposed inbound ' +
               'they are the initial access vector in most ransomware cases we ' +
               'see, regardless of how narrowly the rule is scoped.',
    remediation: 'Move these behind the VPN. Where a rule must stay, restrict ' +
                 'the source and apply IPS.',
    run(m, ctx) {
      return inboundRiskCheck(ctx, ['rdp', 'smb', 'telnet', 'database', 'vnc'],
        'critical services');
    },
  },
  {
    id: 'ric-high-services', title: 'No high-risk service is reachable from the internet',
    severity: 'high', source: 'reflex',
    rationale: 'FTP, SNMP, LDAP, Windows RPC and the legacy remote-control ' +
               'protocols either carry credentials in clear text or disclose ' +
               'internal structure to anyone who asks.',
    remediation: 'Withdraw these from the internet, or replace them with an ' +
                 'authenticated, encrypted equivalent.',
    run(m, ctx) {
      return inboundRiskCheck(ctx, ['ftp', 'rpc', 'snmp', 'ldap', 'legacy'],
        'high-risk services');
    },
  },
  {
    id: 'ric-ssh-exposed', title: 'SSH is not published to the internet',
    severity: 'medium', source: 'reflex',
    rationale: 'SSH is defensible to expose and is still the most credential-' +
               'stuffed port on the internet. Worth knowing about deliberately ' +
               'rather than discovering in a log.',
    remediation: 'Restrict the source, enforce key-only authentication, or move ' +
                 'it behind the VPN.',
    run(m, ctx) {
      return inboundRiskCheck(ctx, ['ssh'], 'SSH');
    },
  },
  {
    id: 'ric-uninspected', title: 'Inbound policies apply security profiles',
    severity: 'high', source: 'reflex',
    rationale: 'Traffic arriving from the internet is the traffic most worth ' +
               'inspecting. A published service with no IPS in front of it is ' +
               'protected only by its own patch level.',
    remediation: 'Apply an IPS sensor and, for web services, a web application ' +
                 'or antivirus profile to every inbound policy.',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'inbound');
      if (guard) return guard;
      const inbound = ctx.analysis.facing('inbound');
      const bad = inbound.filter(a => !a.policy.hasProfiles);
      if (!bad.length) {
        return pass('All ' + inbound.length + ' inbound policies apply at least ' +
          'one security profile.');
      }
      return fail(bad.length + ' of ' + inbound.length + ' inbound policies apply ' +
        'no security profile.', { policies: bad.map(a => a.id).slice(0, 50), total: bad.length });
    },
  },

  /* ── Risky outbound conditions ─────────────────────────────────────────── */
  {
    id: 'roc-risky-egress', title: 'No risky protocol is permitted outbound',
    severity: 'high', source: 'reflex',
    rationale: 'Outbound rules decide what an attacker can do once they are ' +
               'already inside. SMB leaving the network leaks credentials to ' +
               'anything that answers; TFTP and FTP stage tooling and remove ' +
               'data; IRC and Tor are command-and-control.',
    remediation: 'Deny these protocols outbound and permit them only from the ' +
                 'named hosts that genuinely need them.',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'outbound');
      if (guard) return guard;
      const outbound = ctx.analysis.facing('outbound');

      const hits = [];
      outbound.forEach((a) => {
        const risks = policyLib.risksOn(a, policyLib.RISKY_OUTBOUND);
        if (risks.length) hits.push({ policy: a.id, permits: risks.map(r => r.key) });
      });
      if (!hits.length) return pass('No outbound rule permits a known-risky protocol.');
      return fail(hits.length + ' of ' + outbound.length + ' outbound rules permit ' +
        'a known-risky protocol.', { findings: hits.slice(0, 25), total: hits.length });
    },
  },
  {
    id: 'roc-any-service', title: 'No outbound policy permits every service',
    severity: 'medium', source: 'reflex',
    rationale: 'Unrestricted egress means any port an attacker chooses is a way ' +
               'out. It is also the single easiest control to tighten, because ' +
               'almost nothing legitimate needs it.',
    remediation: 'Replace ALL with the services the business actually uses ' +
                 'outbound, and log the rest.',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'outbound');
      if (guard) return guard;
      const outbound = ctx.analysis.facing('outbound');
      const bad = outbound.filter(a => a.anyService);
      if (!bad.length) return pass('No outbound policy permits every service.');
      return fail(bad.length + ' of ' + outbound.length + ' outbound policies permit ' +
        'every service.', { policies: bad.map(a => a.id).slice(0, 50), total: bad.length });
    },
  },
  {
    id: 'roc-unlogged', title: 'Outbound policies are logged',
    severity: 'medium', source: 'reflex',
    rationale: 'Outbound logs are how command-and-control and data movement are ' +
               'found after the fact. Without them an investigation has nothing ' +
               'to work from at exactly the point it matters.',
    remediation: 'config firewall policy / edit <id> / set logtraffic all',
    run(m, ctx) {
      const guard = directionGuard(ctx, 'outbound');
      if (guard) return guard;
      const outbound = ctx.analysis.facing('outbound');
      // logtraffic null means the field was absent — reported, never assumed.
      const off = outbound.filter(a => a.policy.logtraffic === 'disable');
      const silent = outbound.filter(a => a.policy.logtraffic === null);
      if (!off.length && !silent.length) {
        return pass('All ' + outbound.length + ' outbound policies log.');
      }
      if (!off.length) {
        return unknown(silent.length + ' outbound policies did not state a logging ' +
          'setting, so logging could not be confirmed.',
          { policies: silent.map(a => a.id).slice(0, 50) });
      }
      return fail(off.length + ' of ' + outbound.length + ' outbound policies have ' +
        'logging switched off.', { policies: off.map(a => a.id).slice(0, 50), total: off.length });
    },
  },

  /* ── Security profiles ─────────────────────────────────────────────────── */
  {
    id: 'profile-av', title: 'An antivirus profile is defined',
    severity: 'medium', source: 'cis', cis: '7.1',
    rationale: 'Without a profile there is nothing for a policy to reference, ' +
               'so no traffic is scanned regardless of licensing.',
    remediation: 'Define an antivirus profile and apply it to inbound and ' +
                 'outbound policies.',
    run(m) {
      const n = (m.profiles.antivirus || []).length;
      return n ? pass(n + ' antivirus profile(s) defined.')
               : fail('No antivirus profile is defined.');
    },
  },
  {
    id: 'profile-ips', title: 'An IPS sensor is defined',
    severity: 'high', source: 'cis', cis: '7.2',
    rationale: 'IPS is the control that catches exploitation of the services a ' +
               'policy legitimately allows through.',
    remediation: 'Define an IPS sensor and apply it to policies carrying ' +
                 'internet traffic.',
    run(m) {
      const n = (m.profiles.ips || []).length;
      return n ? pass(n + ' IPS sensor(s) defined.')
               : fail('No IPS sensor is defined.');
    },
  },

  /* ── VPN ───────────────────────────────────────────────────────────────── */
  {
    id: 'vpn-ipsec-proposal', title: 'IPsec proposals use current cryptography',
    severity: 'high', source: 'cis', cis: '8.1',
    rationale: 'DES, 3DES, MD5 and SHA-1 are broken or deprecated. A tunnel ' +
               'negotiated with them protects less than it appears to.',
    remediation: 'Use aes256-sha256 or better on every phase 1 and phase 2.',
    run(m) {
      const p1 = m.vpn.ipsecPhase1 || [];
      if (!p1.length) return unknown('No IPsec phase 1 interfaces are configured.');
      const weak = /(^|-)(des|3des|md5|sha1)(-|$)/i;
      const bad = p1.filter(v => weak.test(String(pick(v, 'proposal') || '')));
      if (!bad.length) return pass('All ' + p1.length + ' phase 1 proposals use current algorithms.');
      return fail(bad.length + ' of ' + p1.length + ' phase 1 proposals use deprecated algorithms.',
        { tunnels: bad.map(v => str(pick(v, 'name')) || v._key) });
    },
  },
  {
    id: 'vpn-ipsec-dhgrp', title: 'IPsec Diffie-Hellman groups are 14 or higher',
    severity: 'medium', source: 'cis', cis: '8.2',
    rationale: 'Groups 1, 2 and 5 are small enough to be attacked by a ' +
               'well-resourced adversary, retrospectively.',
    remediation: 'set dhgrp 14 (or higher) on every phase 1.',
    run(m) {
      const p1 = m.vpn.ipsecPhase1 || [];
      if (!p1.length) return unknown('No IPsec phase 1 interfaces are configured.');
      const bad = [];
      p1.forEach((v) => {
        const groups = String(pick(v, 'dhgrp') || '').trim().split(/\s+/).filter(Boolean).map(Number);
        if (!groups.length) return;
        if (groups.some(g => Number.isFinite(g) && g < 14)) {
          bad.push(str(pick(v, 'name')) || v._key);
        }
      });
      if (!bad.length) return pass();
      return fail(bad.length + ' tunnel(s) negotiate a Diffie-Hellman group below 14.',
        { tunnels: bad });
    },
  },
  {
    id: 'vpn-ssl-source-interface', title: 'SSL-VPN is restricted to specific interfaces',
    severity: 'medium', source: 'reflex',
    rationale: 'An SSL-VPN listening on every interface is reachable from ' +
               'inside as well as out, and is a standing target.',
    remediation: 'config vpn ssl settings / set source-interface <wan>',
    run(m) {
      const s = m.vpn.sslSettings;
      if (!s) return unknown('No SSL-VPN settings are present in this config.');
      const src = pick(s, 'source-interface');
      if (src === undefined) return fail('SSL-VPN is not restricted to a source interface.');
      return pass();
    },
  },

  /* ── Logging ───────────────────────────────────────────────────────────── */
  {
    id: 'log-destination', title: 'A logging destination is configured',
    severity: 'high', source: 'cis', cis: '9.1',
    rationale: 'A firewall that logs nowhere produces no evidence. Every ' +
               'incident involving it starts from nothing.',
    remediation: 'Enable disk logging, and forward to FortiAnalyzer or syslog.',
    run(m) {
      const disk = flag(pick(m.logging.disk || {}, 'status'));
      const faz  = flag(pick(m.logging.fortianalyzer || {}, 'status'));
      const sys  = (m.logging.syslog || []).some(s => flag(pick(s, 'status')) === true);
      if (disk === null && faz === null && !sys) {
        return unknown('No log settings are present in this config.');
      }
      if (disk || faz || sys) {
        return pass('Logging to ' + [disk && 'disk', faz && 'FortiAnalyzer', sys && 'syslog']
          .filter(Boolean).join(', ') + '.');
      }
      return fail('No logging destination is enabled.');
    },
  },
  {
    id: 'log-offbox', title: 'Logs are sent off the device',
    severity: 'medium', source: 'reflex',
    rationale: 'Local logs are lost when the device is wiped, replaced or ' +
               'compromised — which are the moments they matter most.',
    remediation: 'Forward to FortiAnalyzer or a syslog collector.',
    run(m) {
      const faz = flag(pick(m.logging.fortianalyzer || {}, 'status'));
      const sys = (m.logging.syslog || []).some(s => flag(pick(s, 'status')) === true);
      if (faz === null && !(m.logging.syslog || []).length) {
        return unknown('No off-box log settings are present in this config.');
      }
      return (faz || sys) ? pass() : fail('Logs are not forwarded off the device.');
    },
  },

  /* ── System ────────────────────────────────────────────────────────────── */
  {
    id: 'system-ntp', title: 'Time is synchronised',
    severity: 'low', source: 'cis', cis: '1.7',
    rationale: 'Logs from a device with the wrong clock cannot be correlated ' +
               'with anything else, which quietly ruins an investigation.',
    remediation: 'config system ntp / set ntpsync enable',
    run(m) {
      if (!m.system.ntp) return unknown('No NTP section is present in this config.');
      const v = flag(pick(m.system.ntp, 'ntpsync'));
      if (v === null) return unknown('ntpsync is not present in this config.');
      return v ? pass() : fail('NTP synchronisation is disabled.');
    },
  },
  {
    id: 'system-dns', title: 'DNS servers are configured',
    severity: 'low', source: 'reflex',
    rationale: 'Without DNS the device cannot resolve update servers, FQDN ' +
               'address objects or its own logging destinations.',
    remediation: 'config system dns / set primary <server>',
    run(m) {
      if (!m.system.dns) return unknown('No DNS section is present in this config.');
      return str(pick(m.system.dns, 'primary')) ? pass()
        : fail('No primary DNS server is configured.');
    },
  },
  {
    id: 'system-firmware', title: 'Firmware currency',
    severity: 'medium', source: 'reflex',
    rationale: 'FortiOS carries regularly exploited vulnerabilities, several of ' +
               'them in the SSL-VPN. Version currency is the single highest-value ' +
               'thing to check on a Fortinet device.',
    remediation: 'Compare the running version against Fortinet PSIRT advisories ' +
                 'and the recommended release for this model.',
    run(m) {
      const fw = m.device.firmware;
      if (!fw) return unknown('The firmware version could not be read from this config.');
      /*
       * REPORTED, NOT GRADED — and deliberately.
       *
       * Whether a version is current is a fact about Fortinet's advisories
       * today, not about this file. Hard-coding a cutoff here would produce a
       * check that is correct for a few months and then quietly starts passing
       * vulnerable devices, which is worse than one that says plainly that a
       * human has to look.
       */
      return unknown('Running FortiOS ' + fw + '. Check it against Fortinet PSIRT ' +
                     'advisories — this cannot be determined from the config alone.',
        { firmware: fw, model: m.device.model });
    },
  },
];

/*
 * Which category a check belongs to, by id prefix.
 *
 * A prefix map rather than a field on all forty checks, so a new check lands in
 * the right group by being named consistently. A check may still carry an
 * explicit `category`, which wins — three of the older `policy-` checks do,
 * because they are risk findings rather than hygiene ones and the prefix cannot
 * know that.
 *
 * FIRST MATCH WINS, so longer prefixes come first.
 */
const CATEGORY_BY_PREFIX = [
  ['rpc-',     'risky-policy-conditions'],
  ['pa-',      'policy-attribute'],
  ['rib-',     'risky-inbound-blanket'],
  ['ric-',     'risky-inbound-conditions'],
  ['roc-',     'risky-outbound-conditions'],
  ['policy-',  'policy-attribute'],
  ['admin-',   'administrative-access'],
  ['snmp-',    'administrative-access'],
  ['wan-',     'administrative-access'],
  ['profile-', 'threat-protection'],
  ['vpn-',     'remote-access'],
  ['log-',     'logging-and-platform'],
  ['system-',  'logging-and-platform'],
];

function categoryFor(check) {
  if (check.category) return check.category;
  const hit = CATEGORY_BY_PREFIX.find(([prefix]) => check.id.indexOf(prefix) === 0);
  /*
   * null, not a default bucket. A check whose id matches no prefix is a naming
   * mistake, and filing it under something plausible is how it stays invisible.
   * The test suite asserts every check resolves.
   */
  return hit ? hit[1] : null;
}

/** Run every check. Never throws — a broken check is not-assessable, not a 500. */
function runChecks(model) {
  /*
   * The rulebase analysis is built ONCE and shared. Twenty policy checks each
   * building their own service index would be wasteful, but the real reason is
   * agreement: every check must have the same answer to "what does policy 7
   * permit" and "which way does it face".
   *
   * If it throws, every policy check degrades to not-assessable rather than the
   * run failing — see the null ctx handling in each.
   */
  let analysis = null;
  try {
    analysis = policyLib.analysePolicies(model);
  } catch (err) {
    analysis = null;
  }
  const ctx = { analysis };

  return CHECKS.map((c) => {
    let r;
    try {
      r = c.run(model, ctx) || unknown('The check returned nothing.');
    } catch (err) {
      r = unknown('This check could not run against this configuration.');
    }
    return {
      id: c.id,
      title: c.title,
      severity: c.severity,
      category: categoryFor(c),
      source: c.source,
      cis: c.cis || null,
      rationale: c.rationale,
      remediation: c.remediation,
      status: r.status,
      detail: r.detail,
      evidence: r.evidence,
    };
  });
}

module.exports = {
  CHECKS, SEVERITIES, runChecks, livePolicies, wanInterfaces,
  CATEGORIES, CATEGORY_KEYS, categoryLabel, categoryFor,
};
