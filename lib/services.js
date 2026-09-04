'use strict';

/**
 * lib/services.js — what a client actually buys from us.
 *
 * WHY THIS EXISTS
 *
 * Every client gets the same fifteen-section board report, and an analyst
 * hand-ticks the sections that apply. A client who only buys awareness training
 * had "Vulnerability Dashboard — no data" ticked by default, which reads to a
 * board as a failing control rather than a service they never bought. Turning
 * sections off by hand works until someone forgets, and nobody notices a
 * MISSING section the way they notice a wrong one.
 *
 * So the client's service mix is recorded once, and the report defaults from
 * it. The analyst can still tick anything — this sets the starting point, it
 * does not lock the deck.
 *
 * NULL vs EMPTY, which is the distinction that matters:
 *
 *   tenants.services IS NULL   nobody has said yet. Every section is offered,
 *                              exactly as before this feature existed.
 *   tenants.services = '{}'    somebody said "none". Only the always-on
 *                              sections are offered.
 *
 * Defaulting an unconfigured client to "buys nothing" would silently gut every
 * existing client's report the moment this shipped.
 */

/**
 * The catalogue. `key` is stored; everything else is presentation.
 *
 * Order is the order the checkboxes render in: the four core services first,
 * then the managed-service add-ons, then the wrapper offerings.
 */
const SERVICES = [
  { key: 'mdr',       label: 'Managed Detection & Response',
    hint: 'MDR tickets, incident response, detection KPIs' },
  { key: 'vuln',      label: 'Vulnerability Management',
    hint: 'External scanning, remediation SLAs' },
  { key: 'awareness', label: 'Security Awareness Training',
    hint: 'Training completion, phishing simulations' },
  { key: 'edr',       label: 'Managed EDR',
    hint: 'Endpoint detection and response — included in MDR' },
  { key: 'ndr',       label: 'Managed NDR',
    hint: 'Network detection and response — included in MDR' },
  { key: 'identity',  label: 'Managed Identity',
    hint: 'Microsoft 365 identity and access — included in MDR' },
  { key: 'pentest',   label: 'Penetration Testing',
    hint: 'Engagements, findings and red team' },
  { key: 'firewall',  label: 'Firewall Configuration Review',
    hint: 'FortiGate config audit against CIS and our own checks' },
  { key: 'viso',      label: 'vISO',
    hint: 'Governance, risk, compliance, third-party risk and the managed-service reporting that goes with it' },
];

const SERVICE_KEYS = SERVICES.map(s => s.key);

/**
 * Services that are DELIVERED AS PART OF another service.
 *
 * MDR includes endpoint, network and identity detection — a client on MDR is
 * not asked to buy Managed EDR, NDR or Identity separately, and must not be
 * reported as lacking them. Before this, an MDR client showed three coverage
 * gaps for capabilities they were already paying for, and the report withheld
 * the endpoint dashboards their MDR service produces.
 *
 * The IMPLIED services are deliberately not written into the stored record.
 * `tenants.services` stays a statement of what was sold; this is a statement of
 * what that entitles them to, and the two are different things that change for
 * different reasons. Expansion happens on read, through effectiveServices().
 */
const SERVICE_INCLUDES = {
  mdr: ['edr', 'ndr', 'identity'],
};

/**
 * What a client is actually covered for, given what they bought.
 *
 * Returns null for null — "not recorded" survives expansion, because an
 * unrecorded client has not been given MDR by implication either.
 *
 * Single-pass: nothing in SERVICE_INCLUDES currently implies something that
 * itself implies more, and a transitive closure here would invite a cycle that
 * is not needed. If that changes, this is the one place to make it recursive.
 */
function effectiveServices(services) {
  if (!Array.isArray(services)) return null;

  const out = {};
  services.forEach((k) => {
    const key = String(k || '').trim().toLowerCase();
    if (SERVICE_KEYS.indexOf(key) < 0) return;
    out[key] = true;
    (SERVICE_INCLUDES[key] || []).forEach((implied) => { out[implied] = true; });
  });

  return SERVICE_KEYS.filter(k => out[k]);
}

/** True when this service is only present because another one includes it. */
function isImplied(services, key) {
  if (!Array.isArray(services)) return false;
  if (services.indexOf(key) >= 0) return false;
  return (effectiveServices(services) || []).indexOf(key) >= 0;
}

/**
 * Keys that used to mean something else.
 *
 * vCISO was renamed to vISO. The rename landed before anyone ran
 * db/migrate-tenant-services.sql, so in practice no row holds the old key —
 * but a stored value outliving a rename is exactly the kind of thing that is
 * cheap to handle now and expensive to diagnose later.
 */
const LEGACY_KEYS = { vciso: 'viso' };

/**
 * Which Secure Score component each service is responsible for.
 *
 * This is what separates "scored badly" from "never bought". A client who buys
 * only awareness training scored 0 for vulnerability management and 0 for
 * incident response, dragging their composite to roughly a third of their
 * actual awareness result — a number that reads as failure and is really a
 * statement about our order book.
 *
 * The vulnerability component has two yardsticks (lib/estate.js), and they are
 * supplied by different services: an infrastructure scan comes from
 * Vulnerability Management, endpoint patch currency comes from Managed EDR.
 * Which one covers it therefore depends on which basis was actually used —
 * see coversComponent().
 *
 * vISO deliberately covers NOTHING here. It is governance, oversight and
 * board reporting; it does not scan a host, patch an endpoint or work a
 * ticket. A client who buys only vISO has real value delivered and near-zero
 * technical coverage, and the score should say so rather than flatter it.
 * If Reflex bundles a technical service into the vISO package, add it here —
 * it is one line, and it is the only place that decides this.
 */
const COMPONENT_KEYS = ['vulnerabilities', 'awareness', 'incidentResponse'];

/*
 * COVERAGE IS THE THREE CORE SERVICES. Nothing else moves it.
 *
 *   Managed Detection & Response   -> incident response
 *   Vulnerability Management       -> vulnerabilities
 *   Security Awareness Training    -> awareness
 *
 * Managed EDR used to cover the vulnerabilities component, on the grounds that
 * the engine scores an endpoint-only estate on patch currency rather than on a
 * scan. That was defensible arithmetic and the wrong answer commercially: it
 * credited an MDR client with vulnerability coverage they had not bought, and
 * put "Endpoint Patch Currency" in a board report for an engagement that never
 * included it. Vulnerability coverage now means the Vulnerability Management
 * service and nothing else.
 *
 * NDR, Identity, pentest and vISO deliver real value and cover none of the
 * three scored components; that is a statement about this score, not about the
 * services.
 */
const SERVICE_COVERS = {
  mdr:       ['incidentResponse'],
  vuln:      ['vulnerabilities'],
  awareness: ['awareness'],
  edr:       [],
  ndr:       [],
  identity:  [],
  pentest:   [],
  viso:      [],
  // Covers nothing, on purpose. A firewall review is real work with its own
  // score, but the Secure Score's coverage is MDR + Vulnerability Management +
  // Security Awareness and adding a fourth here would silently re-weight every
  // existing client's coverage figure. It gates its report section and nothing
  // else.
  firewall:  [],
};

/**
 * Is this component covered by something the client buys?
 *
 * @param {Array<string>|null} services
 * @param {string} component       one of COMPONENT_KEYS
 * @param {string} [vulnBasis]     'infrastructure' | 'endpoint' | 'unknown'
 * @returns {boolean|null}  null when services were never recorded, because
 *          "we have not asked" is not an answer and must not be read as "no".
 */
function coversComponent(services, component, vulnBasis) {   // eslint-disable-line no-unused-vars
  // Expanded first, so a client on MDR is credited with what MDR includes.
  const eff = effectiveServices(services);
  if (!eff) return null;

  // `vulnBasis` is accepted and ignored. It used to branch here — endpoint
  // basis credited Managed EDR with vulnerability coverage — and that branch
  // is what let an MDR client's coverage include a service they had not
  // bought. The parameter stays so callers need no change and so this comment
  // has somewhere to live.
  return SERVICE_KEYS.some(k =>
    eff.indexOf(k) >= 0 && (SERVICE_COVERS[k] || []).indexOf(component) >= 0);
}

/** The services that would cover this component, for "what's missing" copy. */
function servicesCovering(component) {
  return SERVICE_KEYS.filter(k => (SERVICE_COVERS[k] || []).indexOf(component) >= 0);
}

/** Presentation label for a key, or the key itself if we do not know it. */
function serviceLabel(key) {
  const s = SERVICES.find(x => x.key === key);
  return s ? s.label : String(key);
}

/**
 * Clean a caller-supplied list into something safe to store.
 *
 * Returns null for null/undefined — meaning "not configured", which is NOT the
 * same as an empty array and must survive the round trip. Anything else becomes
 * a de-duplicated array of known keys in catalogue order, so an unknown key
 * from a stale client cannot be persisted and the stored order never depends on
 * the order checkboxes happened to be clicked.
 */
function normaliseServices(input) {
  if (input === null || input === undefined) return null;
  if (!Array.isArray(input)) return null;

  const seen = {};
  input.forEach((k) => {
    let key = String(k || '').trim().toLowerCase();
    if (LEGACY_KEYS[key]) key = LEGACY_KEYS[key];
    if (SERVICE_KEYS.indexOf(key) >= 0) seen[key] = true;
  });
  return SERVICE_KEYS.filter(k => seen[k]);
}

/** True when the tenant is known to buy this service. Unconfigured => false. */
function hasService(services, key) {
  return Array.isArray(services) && services.indexOf(key) >= 0;
}

module.exports = {
  SERVICE_INCLUDES,
  LEGACY_KEYS,
  effectiveServices,
  isImplied,
  SERVICES,
  SERVICE_KEYS,
  COMPONENT_KEYS,
  SERVICE_COVERS,
  serviceLabel,
  normaliseServices,
  hasService,
  coversComponent,
  servicesCovering,
};
