'use strict';

/**
 * lib/integrations/wazuh-fields.js
 *
 * Field descriptors and OpenSearch query builders for the Wazuh Indexer.
 *
 * Every Wazuh/FortiOS/Office365 field name used by the dashboard lives in this
 * file and nowhere else — they vary across FortiOS versions and Wazuh minor
 * releases, so expect to adjust them against a real deployment. The adapter
 * (wazuh-indexer.js) owns transport; this file owns "what to ask for".
 *
 * Mapping facts that decide whether an aggregation works at all:
 *   - Wazuh maps data.* strings as `keyword` DIRECTLY. There is no `.keyword`
 *     sub-field — use "data.action", never "data.action.keyword".
 *   - data.srcip / data.dstip are `ip` type. Terms aggs work, wildcards do not.
 *   - data.srcport / data.dstport are keyword (strings) — no numeric ranges.
 *   - Byte counters (data.sentbyte/rcvdbyte) land as keyword in most
 *     deployments, so a `sum` agg fails with "Expected numeric type". We do not
 *     build any bandwidth chart on them.
 */

// Pinned deliberately. `wazuh-archives-*` is disabled by default and 20-50x the
// volume; the bare `wazuh-alerts-*` alias can match 3.x indices whose mappings
// differ enough to break these aggregations.
const ALERTS_INDEX = 'wazuh-alerts-4.x-*';

const SOURCES = ['fortigate', 'office365', 'ms-graph'];

// Noise buckets that FortiOS emits for private/unroutable space.
const GEO_NOISE = ['Reserved', 'N/A', '-', ''];

// ── Source discriminators ──────────────────────────────────────────────────
// rule.groups is the reliable FortiGate signal — every stock rule carries it.
// decoder.name is the *deepest* matching decoder and varies by child decoder,
// which is why decoder.parent is in the `should` too. Stock FortiGate rule IDs
// sit around 81600-81699 but are never hardcoded here: custom rules break it.

function sourceFilter(source) {
  switch (source) {
    case 'fortigate':
      return { bool: { should: [
        { term: { 'rule.groups': 'fortigate' } },
        { term: { 'decoder.name': 'fortigate-firewall-v5' } },
        { term: { 'decoder.parent': 'fortigate-firewall-v5' } },
      ], minimum_should_match: 1 } };

    case 'office365':
      // data.integration is stamped by the wodle itself — the most precise signal.
      return { bool: { should: [
        { term: { 'data.integration': 'office365' } },
        { term: { 'rule.groups': 'office365' } },
      ], minimum_should_match: 1 } };

    case 'ms-graph':
      return { bool: { should: [
        { term: { 'data.integration': 'ms-graph' } },
        { prefix: { 'rule.groups': 'ms-graph' } },
      ], minimum_should_match: 1 } };

    default:
      throw new Error(`Unknown Wazuh source: ${source}`);
  }
}

/**
 * Mandatory per-tenant scope filters, built server-side from the integration
 * row. NEVER build these from a request parameter.
 *
 * @param {string} source
 * @param {object} scope   config_json.scope
 * @returns {Array} filter clauses (possibly empty)
 */
function scopeFilters(source, scope) {
  const s = scope || {};
  const out = [];
  const nonEmpty = a => Array.isArray(a) && a.length > 0;

  // Agent scoping applies to every source — a Wazuh serving several customers
  // separates them by agent group more often than by anything else.
  if (nonEmpty(s.agentGroups)) out.push({ terms: { 'agent.groups': s.agentGroups } });
  if (nonEmpty(s.agentIds))    out.push({ terms: { 'agent.id':     s.agentIds } });

  if (source === 'fortigate' && nonEmpty(s.fortigateDevnames)) {
    out.push({ bool: { should: [
      { terms: { 'data.devname': s.fortigateDevnames } },
      { terms: { 'data.devid':   s.fortigateDevnames } },
    ], minimum_should_match: 1 } });
  }
  if (source === 'office365' && nonEmpty(s.o365OrganizationIds)) {
    out.push({ terms: { 'data.office365.OrganizationId': s.o365OrganizationIds } });
  }
  if (source === 'ms-graph' && nonEmpty(s.graphTenantIds)) {
    out.push({ terms: { 'data.ms-graph.tenantId': s.graphTenantIds } });
  }

  return out;
}

/**
 * Base filter array for a search: time range + source + tenant scope.
 *
 * Throws when the integration is flagged multi-tenant but resolves to no scope
 * filters at all. A missing scope filter silently returns another customer's
 * data, which is the worst failure mode this integration has — fail loudly.
 */
function baseFilters(source, cfg, range) {
  const scoped = scopeFilters(source, cfg.scope);

  if (cfg.multiTenant === true && scoped.length === 0) {
    throw new Error(
      `Wazuh integration is marked multi-tenant but no scope filter resolved for "${source}". ` +
      'Refusing to query — set config_json.scope before enabling multiTenant.'
    );
  }

  return [
    // time_zone resolves bounds that carry no explicit offset (e.g. "2026-08-03"
    // or "now-30d/d") in the tenant's zone, so a live chart and a rollup chart
    // agree on where a day starts. It is ignored when the bound is Z-suffixed.
    { range: { [cfg.tsField]: {
      gte: range.from, lte: range.to,
      time_zone: cfg.timeZone,
      format: 'strict_date_optional_time',
    } } },
    sourceFilter(source),
    ...scoped,
  ];
}

// ── Aggregation helpers ────────────────────────────────────────────────────

/** terms agg with a shard_size wide enough to keep top-N honest. */
function terms(field, size, extra) {
  return Object.assign(
    { terms: { field, size, shard_size: Math.max(size * 5, 50), order: { _count: 'desc' } } },
    extra ? { aggs: extra } : {}
  );
}

/** date_histogram that zero-fills instead of gapping, in the tenant's zone. */
function daily(cfg, range, sub) {
  return Object.assign({
    date_histogram: {
      field: cfg.tsField,
      calendar_interval: '1d',
      time_zone: cfg.timeZone,
      min_doc_count: 0,
      extended_bounds: { min: range.from, max: range.to },
    },
  }, sub ? { aggs: sub } : {});
}

/** Newest event timestamp for the slice — drives the staleness banner. */
function lastEvent(cfg) {
  return { max: { field: cfg.tsField } };
}

// ── FortiGate action vocabularies ──────────────────────────────────────────
// data.action means OPPOSITE things across data.type. On traffic, "accept" is
// allowed-by-policy (normal). On IPS, "pass" means the attack was detected but
// let through (bad). assertTyped() below makes it structurally impossible to
// aggregate data.action without also filtering data.type.

const TRAFFIC_ALLOW = ['accept'];
const TRAFFIC_DENY  = ['deny', 'blocked', 'drop'];
const IPS_BLOCKED   = ['dropped', 'blocked', 'reset', 'clear_session'];
const IPS_ALLOWED   = ['detected', 'pass'];

function assertTyped(filters, what) {
  const typed = filters.some(f => f.term && f.term['data.type'] !== undefined);
  if (!typed) {
    throw new Error(`Refusing to aggregate data.action for "${what}" without a data.type filter — the vocabularies collide.`);
  }
}

// ── Managed NDR searches ───────────────────────────────────────────────────

/**
 * Traffic / policy decisions. Counts only accept and deny and labels the result
 * "policy decisions": start/close/timeout are session-lifecycle logs for the
 * SAME session and would double-count an allowed session three times over.
 */
function ndrTraffic(cfg, range) {
  const filters = [...baseFilters('fortigate', cfg, range), { term: { 'data.type': 'traffic' } }];
  assertTyped(filters, 'ndr.traffic');

  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: filters } },
    aggs: {
      over_time: daily(cfg, range, {
        decision: { filters: { other_bucket_key: 'other', filters: {
          allowed: { terms: { 'data.action': TRAFFIC_ALLOW } },
          denied:  { terms: { 'data.action': TRAFFIC_DENY } },
        } } },
        unique_sources: { cardinality: { field: 'data.srcip', precision_threshold: 3000 } },
      }),
      total_allowed: { filter: { terms: { 'data.action': TRAFFIC_ALLOW } } },
      total_denied:  { filter: { terms: { 'data.action': TRAFFIC_DENY } } },
      top_dst_port: terms('data.dstport', 10, { service: terms('data.service', 1) }),
      top_service:  terms('data.service', 10),
      top_policy:   terms('data.policyid', 10, { name: terms('data.policyname', 1) }),
      top_src: terms('data.srcip', 10, { country: terms('data.srccountry', 1) }),
      top_dst: terms('data.dstip', 10),
      last_event: lastEvent(cfg),
    },
  };
}

/** IPS / UTM threat activity, plus the sibling virus/webfilter/app-ctrl panels. */
function ndrThreats(cfg, range) {
  const filters = [...baseFilters('fortigate', cfg, range), { term: { 'data.type': 'utm' } }];
  assertTyped(filters, 'ndr.threats');

  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: filters } },
    aggs: {
      ips: {
        filter: { term: { 'data.subtype': 'ips' } },
        aggs: {
          top_attacks: terms('data.attack', 15, {
            severity: terms('data.severity', 5),
            blocked:  { filter: { terms: { 'data.action': IPS_BLOCKED } } },
            allowed:  { filter: { terms: { 'data.action': IPS_ALLOWED } } },
            targets:  { cardinality: { field: 'data.dstip' } },
          }),
          by_severity: terms('data.severity', 6),
          by_action:   terms('data.action', 8),
          top_sources: terms('data.srcip', 10, { country: terms('data.srccountry', 1) }),
          top_targets: terms('data.dstip', 10),
          blocked: { filter: { terms: { 'data.action': IPS_BLOCKED } } },
          allowed: { filter: { terms: { 'data.action': IPS_ALLOWED } } },
          unique_sources: { cardinality: { field: 'data.srcip', precision_threshold: 3000 } },
          trend: daily(cfg, range, {
            blocked: { filter: { terms: { 'data.action': IPS_BLOCKED } } },
          }),
        },
      },
      virus: {
        filter: { term: { 'data.subtype': 'virus' } },
        aggs: { top: terms('data.virus', 10) },
      },
      webfilter: {
        filter: { term: { 'data.subtype': 'webfilter' } },
        aggs: { top_category: terms('data.catdesc', 10) },
      },
      appctrl: {
        filter: { term: { 'data.subtype': 'app-ctrl' } },
        aggs: { top_app: terms('data.app', 10, { category: terms('data.appcat', 1) }) },
      },
      last_event: lastEvent(cfg),
    },
  };
}

/**
 * Geo of external threats. FortiOS emits data.srccountry itself when its geo-IP
 * database is loaded — full country names, zero dependency on indexer config.
 * The GeoLocation.* processor is disabled by default in Wazuh 4.x, so it is
 * only a fallback (and only ever populates src, never dst).
 */
function ndrGeo(cfg, range) {
  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: baseFilters('fortigate', cfg, range) } },
    aggs: {
      by_country: {
        filter: { bool: { must_not: [{ terms: { 'data.srccountry': GEO_NOISE } }] } },
        aggs: {
          countries: terms('data.srccountry', 20, {
            unique_sources: { cardinality: { field: 'data.srcip', precision_threshold: 3000 } },
            denied: { filter: { terms: { 'data.action': [...TRAFFIC_DENY, ...IPS_BLOCKED] } } },
          }),
        },
      },
      // Fallback used only when the primary agg comes back with zero buckets.
      by_geoip: terms('GeoLocation.country_name', 20),
    },
  };
}

/**
 * VPN and firewall-admin access. Uses runtime_mappings to coalesce the user
 * field across FortiOS versions (data.user / xauthuser / srcuser). Runtime
 * fields are evaluated at query time — fine over this filtered slice (VPN and
 * system events only), never over a month of raw traffic.
 */
function ndrVpnAdmin(cfg, range) {
  const filters = [
    ...baseFilters('fortigate', cfg, range),
    { term: { 'data.type': 'event' } },
    { terms: { 'data.subtype': ['vpn', 'system'] } },
  ];

  const vpnFailed = { bool: { should: [
    { term: { 'data.status': 'failure' } },
    { term: { 'data.action': 'ssl-login-fail' } },
    { term: { 'data.logid': '0101039426' } },
  ], minimum_should_match: 1 } };

  const vpnSuccess = { bool: { should: [
    { term: { 'data.status': 'success' } },
    { terms: { 'data.action': ['tunnel-up', 'ssl-login', 'login'] } },
  ], minimum_should_match: 1 } };

  const configChange = { bool: { should: [
    { term: { 'data.logid': '0100032003' } },
    { exists: { field: 'data.cfgpath' } },
  ], minimum_should_match: 1 } };

  /* FortiOS names the VPN user differently across versions and tunnel types
     (data.user on SSL-VPN, data.xauthuser on IPsec XAuth, data.srcuser
     elsewhere). A search-time runtime field would coalesce them in one agg, but
     the Wazuh Indexer rejects `runtime_mappings` outright:
       400 Unknown key for a START_OBJECT in [runtime_mappings]
     — it is an Elasticsearch 7.11+ feature that this OpenSearch fork does not
     parse. So we bucket each field separately and merge the tallies in JS
     (see mergeTallies in wazuh-indexer.js). Cheaper than a script anyway. */
  const VPN_USER_FIELDS = ['data.user', 'data.xauthuser', 'data.srcuser', 'data.unauthuser'];

  const userAggs = {};
  VPN_USER_FIELDS.forEach(f => {
    userAggs['by_' + f.replace('data.', '')] = terms(f, 10, {
      // Same story for the remote address: SSL-VPN event logs use data.remip,
      // not data.srcip. Count both and take the larger estimate.
      by_remip: { cardinality: { field: 'data.remip' } },
      by_srcip: { cardinality: { field: 'data.srcip' } },
      reason:   terms('data.reason', 1),
    });
  });

  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: filters } },
    aggs: {
      vpn: {
        filter: { term: { 'data.subtype': 'vpn' } },
        aggs: {
          outcome: { filters: { filters: { failed: vpnFailed, success: vpnSuccess } } },
          failed_users: { filter: vpnFailed, aggs: userAggs },
          trend: daily(cfg, range, { failed: { filter: vpnFailed } }),
          last_event: lastEvent(cfg),
        },
      },
      admin: {
        filter: { term: { 'data.subtype': 'system' } },
        aggs: {
          logins: {
            filter: { term: { 'data.action': 'login' } },
            aggs: {
              by_user: terms('data.user', 10, { via: terms('data.ui', 1) }),
              failed:  { filter: { term: { 'data.status': 'failed' } } },
            },
          },
          config_changes: {
            filter: configChange,
            aggs: {
              by_path:  terms('data.cfgpath', 15),
              by_admin: terms('data.user', 10),
            },
          },
          last_event: lastEvent(cfg),
        },
      },
    },
  };
}

// ── Managed Identity searches ────────────────────────────────────────────

const O365_ADMIN_OPS = [
  'Add member to role.', 'Remove member from role.', 'Add user.', 'Delete user.',
  'Update user.', 'Reset user password.', 'Change user password.',
  'Add service principal.', 'Consent to application.', 'Add owner to application.',
  'Disable Strong Authentication.',
];

const O365_MAILBOX_OPS = [
  'New-InboxRule', 'Set-InboxRule', 'UpdateInboxRules', 'Remove-InboxRule',
  'New-TransportRule', 'Set-TransportRule', 'Set-Mailbox',
  'Add-MailboxPermission', 'Add-RecipientPermission',
];

const O365_SHARING_OPS = [
  'AnonymousLinkCreated', 'AnonymousLinkUsed', 'SharingInvitationCreated',
  'AddedToSecureLink', 'SecureLinkCreated', 'CompanyLinkCreated', 'SharingSet',
];

function o365Main(cfg, range) {
  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: baseFilters('office365', cfg, range) } },
    aggs: {
      signins: {
        filter: { terms: { 'data.office365.Operation': ['UserLoggedIn', 'UserLoginFailed'] } },
        aggs: {
          over_time: daily(cfg, range, {
            failed:  { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } } },
            success: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } } },
            users:   { cardinality: { field: 'data.office365.UserId' } },
          }),
          total_failed:  { filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } } },
          total_success: { filter: { term: { 'data.office365.Operation': 'UserLoggedIn' } } },
          unique_users:  { cardinality: { field: 'data.office365.UserId' } },
        },
      },
      failed_logins: {
        filter: { term: { 'data.office365.Operation': 'UserLoginFailed' } },
        aggs: {
          // LogonError is the single best "why are logins failing" field.
          by_reason: terms('data.office365.LogonError', 12),
          by_user:   terms('data.office365.UserId', 15, {
            distinct_ips: { cardinality: { field: 'data.office365.ClientIP' } },
          }),
          // size is intentionally generous: ClientIP arrives with and without a
          // :port suffix, and the adapter re-merges those buckets afterwards.
          by_ip: terms('data.office365.ClientIP', 40, {
            targeted_users: { cardinality: { field: 'data.office365.UserId' } },
          }),
        },
      },
      admin_changes: {
        filter: { bool: {
          filter: [{ term: { 'data.office365.RecordType': '8' } }],
          should: O365_ADMIN_OPS.map(op => ({ prefix: { 'data.office365.Operation': op.replace(/\.$/, '') } })),
          minimum_should_match: 1,
        } },
        aggs: {
          by_operation: terms('data.office365.Operation', 15),
          by_actor:     terms('data.office365.UserId', 10),
          recent: { top_hits: {
            size: 10,
            sort: [{ [cfg.tsField]: 'desc' }],
            _source: { includes: [
              cfg.tsField, 'data.office365.Operation', 'data.office365.UserId',
              'data.office365.TargetUserOrGroupName', 'data.office365.ClientIP',
              'data.office365.ResultStatus',
            ] },
          } },
        },
      },
      mailbox_rules: {
        filter: { bool: {
          filter: [{ terms: { 'data.office365.Operation': O365_MAILBOX_OPS } }],
          // ExternalAccess:true means Microsoft/partner ran it — big noise filter.
          must_not: [{ term: { 'data.office365.ExternalAccess': 'true' } }],
        } },
        aggs: {
          by_operation: terms('data.office365.Operation', 10),
          by_mailbox:   terms('data.office365.MailboxOwnerUPN', 10),
          recent: { top_hits: {
            size: 10,
            sort: [{ [cfg.tsField]: 'desc' }],
            _source: { includes: [
              cfg.tsField, 'data.office365.Operation', 'data.office365.MailboxOwnerUPN',
              'data.office365.UserId', 'data.office365.ClientIPAddress',
            ] },
          } },
        },
      },
      external_sharing: {
        filter: { bool: { should: [
          { terms: { 'data.office365.Operation': O365_SHARING_OPS } },
          { term:  { 'data.office365.TargetUserOrGroupType': 'Guest' } },
        ], minimum_should_match: 1 } },
        aggs: {
          by_operation: terms('data.office365.Operation', 10),
          by_site:      terms('data.office365.SiteUrl', 10),
          by_user:      terms('data.office365.UserId', 10),
        },
      },
      dlp: {
        filter: { term: { 'data.office365.Operation': 'DlpRuleMatch' } },
        aggs: {
          by_policy:    terms('data.office365.PolicyDetails.PolicyName', 10),
          by_info_type: terms('data.office365.SensitiveInfoTypeData.SensitiveInfoTypeName', 10),
          trend:        daily(cfg, range),
        },
      },
      by_workload: terms('data.office365.Workload', 10),
      last_event: lastEvent(cfg),
    },
  };
}

function o365Graph(cfg, range) {
  // status.errorCode may be mapped long or keyword depending on the first value
  // the index saw — match both forms.
  const signinOk = { terms: { 'data.ms-graph.status.errorCode': [0, '0'] } };

  return {
    size: 0,
    timeout: '20s',
    query: { bool: { filter: baseFilters('ms-graph', cfg, range) } },
    aggs: {
      alerts: {
        filter: { term: { 'data.ms-graph.relationship': 'alerts_v2' } },
        aggs: {
          by_severity:  terms('data.ms-graph.severity', 5),
          by_status:    terms('data.ms-graph.status', 5),
          by_source:    terms('data.ms-graph.serviceSource', 8),
          by_technique: terms('data.ms-graph.mitreTechniques', 12),
          high:         { filter: { terms: { 'data.ms-graph.severity': ['high', 'medium'] } } },
          trend: daily(cfg, range, {
            high: { filter: { terms: { 'data.ms-graph.severity': ['high', 'medium'] } } },
          }),
          recent: { top_hits: {
            size: 10,
            sort: [{ [cfg.tsField]: 'desc' }],
            _source: { includes: [
              cfg.tsField, 'data.ms-graph.title', 'data.ms-graph.severity',
              'data.ms-graph.status', 'data.ms-graph.serviceSource', 'data.ms-graph.category',
            ] },
          } },
        },
      },
      // riskyUsers is a STATE resource, not an event stream: Wazuh re-emits the
      // same users on every poll, so a date_histogram of it is meaningless.
      // De-dupe to the latest document per user instead.
      risky_users: {
        filter: { term: { 'data.ms-graph.relationship': 'riskyUsers' } },
        aggs: {
          users: terms('data.ms-graph.userPrincipalName', 25, {
            latest: { top_hits: {
              size: 1,
              sort: [{ [cfg.tsField]: 'desc' }],
              _source: { includes: [
                'data.ms-graph.riskLevel', 'data.ms-graph.riskState',
                'data.ms-graph.riskDetail', 'data.ms-graph.riskLastUpdatedDateTime',
              ] },
            } },
          }),
          distinct: { cardinality: { field: 'data.ms-graph.userPrincipalName' } },
        },
      },
      risk_detections: {
        filter: { term: { 'data.ms-graph.relationship': 'riskDetections' } },
        aggs: {
          by_type:    terms('data.ms-graph.riskEventType', 15),
          by_country: terms('data.ms-graph.location.countryOrRegion', 20),
        },
      },
      signins: {
        filter: { term: { 'data.ms-graph.relationship': 'signIns' } },
        aggs: {
          // ISO-2 codes here, unlike FortiGate's full country names.
          by_country: terms('data.ms-graph.location.countryOrRegion', 25, {
            failed: { filter: { bool: { must_not: [signinOk] } } },
            users:  { cardinality: { field: 'data.ms-graph.userPrincipalName' } },
          }),
          legacy_auth: {
            filter: { terms: { 'data.ms-graph.clientAppUsed': [
              'IMAP4', 'POP3', 'SMTP', 'Authenticated SMTP', 'Exchange ActiveSync', 'Other clients',
            ] } },
            aggs: { by_user: terms('data.ms-graph.userPrincipalName', 10) },
          },
          ca_failures: { filter: { term: { 'data.ms-graph.conditionalAccessStatus': 'failure' } } },
        },
      },
      last_event: lastEvent(cfg),
    },
  };
}

// ── Capability probe ───────────────────────────────────────────────────────

/**
 * Cheap "is anything arriving?" counts, one per source. Run on integration save
 * and hourly — never on page load.
 */
function probeSearch(source, cfg, range) {
  const body = {
    size: 0,
    timeout: '10s',
    // Must be `true`, not a number. Every search we send carries
    // rest_total_hits_as_int, and the indexer rejects that combination when the
    // hit count is capped rather than exact:
    //   400 [rest_total_hits_as_int] cannot be used if the tracking of total
    //       hits is not accurate, got 1
    // The probe is a size:0 count over 7 days, so exact tracking is cheap.
    track_total_hits: true,
    query: { bool: { filter: baseFilters(source, cfg, range) } },
    aggs: { last_event: lastEvent(cfg) },
  };
  if (source === 'ms-graph') {
    body.aggs.relationships = terms('data.ms-graph.relationship', 10);
  }
  return body;
}

// ── Response normalisation helpers ─────────────────────────────────────────

/**
 * O365 ClientIP arrives as "1.2.3.4", "1.2.3.4:51234" and "[2001:db8::1]:443"
 * interchangeably, which splits one host across several terms buckets and
 * inflates any "unique source IPs" figure. Strip the port and re-merge.
 */
function normaliseClientIp(raw) {
  let v = String(raw == null ? '' : raw).trim();
  if (!v) return '';
  const bracket = v.match(/^\[(.+)\](?::\d+)?$/);      // [v6]:port
  if (bracket) return bracket[1];
  if ((v.match(/:/g) || []).length === 1) v = v.split(':')[0]; // v4:port
  return v;
}

/** Merge terms buckets whose keys collapse to the same value under `keyFn`. */
function mergeBuckets(buckets, keyFn) {
  const out = new Map();
  (buckets || []).forEach(b => {
    const key = keyFn(b.key);
    if (!key) return;
    const prev = out.get(key);
    if (prev) {
      prev.doc_count += b.doc_count;
      // Sub-agg values are approximate anyway; take the larger of the two.
      Object.keys(b).forEach(k => {
        if (b[k] && typeof b[k] === 'object' && typeof b[k].value === 'number') {
          if (!prev[k] || prev[k].value < b[k].value) prev[k] = b[k];
        }
      });
    } else {
      out.set(key, Object.assign({}, b, { key }));
    }
  });
  return [...out.values()].sort((a, b) => b.doc_count - a.doc_count);
}

/**
 * ResultStatus is inconsistent by workload: Success/Failed on Azure AD,
 * Succeeded/PartiallySucceeded/Failed on Exchange, sometimes True/False, and
 * sometimes absent entirely. Normalise in JS rather than filtering on it.
 */
function resultOk(status) {
  const s = String(status == null ? '' : status).toLowerCase();
  if (!s) return null;
  return s === 'success' || s === 'succeeded' || s === 'true' || s === 'partiallysucceeded';
}

module.exports = {
  ALERTS_INDEX,
  SOURCES,
  GEO_NOISE,
  sourceFilter,
  scopeFilters,
  baseFilters,
  ndrTraffic,
  ndrThreats,
  ndrGeo,
  ndrVpnAdmin,
  o365Main,
  o365Graph,
  probeSearch,
  normaliseClientIp,
  mergeBuckets,
  resultOk,
  TRAFFIC_ALLOW,
  TRAFFIC_DENY,
  IPS_BLOCKED,
  IPS_ALLOWED,
};
