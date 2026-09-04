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

const SEVERITIES = ['critical', 'high', 'medium', 'low'];

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
    severity: 'critical', source: 'cis', cis: '4.1',
    rationale: 'An any/any/ALL accept rule is the absence of a firewall on that ' +
               'path. Everything downstream of it is unfiltered.',
    remediation: 'Replace with rules scoped to the addresses and services the ' +
                 'traffic actually needs.',
    run(m) {
      const live = livePolicies(m);
      if (!live.length) return unknown('No enabled accept policies were found in this config.');
      const bad = live.filter(p => isAny(p.srcaddr) && isAny(p.dstaddr) && isAnyService(p.service));
      if (!bad.length) return pass('None of ' + live.length + ' enabled accept policies is any/any/ALL.');
      return fail(bad.length + ' policy/policies permit any source to any destination on all services.',
        { policies: bad.map(p => p.id) });
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

/** Run every check. Never throws — a broken check is not-assessable, not a 500. */
function runChecks(model) {
  return CHECKS.map((c) => {
    let r;
    try {
      r = c.run(model) || unknown('The check returned nothing.');
    } catch (err) {
      r = unknown('This check could not run against this configuration.');
    }
    return {
      id: c.id,
      title: c.title,
      severity: c.severity,
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

module.exports = { CHECKS, SEVERITIES, runChecks, livePolicies, wanInterfaces };
