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
    hint: 'Endpoint detection and response' },
  { key: 'ndr',       label: 'Managed NDR',
    hint: 'Network detection and response' },
  { key: 'identity',  label: 'Managed Identity',
    hint: 'Microsoft 365 identity and access' },
  { key: 'pentest',   label: 'Penetration Testing',
    hint: 'Engagements, findings and red team' },
  { key: 'vciso',     label: 'vCISO',
    hint: 'Governance, risk, compliance, third-party risk and the managed-service reporting that goes with it' },
];

const SERVICE_KEYS = SERVICES.map(s => s.key);

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
 * vCISO deliberately covers NOTHING here. It is governance, oversight and
 * board reporting; it does not scan a host, patch an endpoint or work a
 * ticket. A client who buys only vCISO has real value delivered and near-zero
 * technical coverage, and the score should say so rather than flatter it.
 * If Reflex bundles a technical service into the vCISO package, add it here —
 * it is one line, and it is the only place that decides this.
 */
const COMPONENT_KEYS = ['vulnerabilities', 'awareness', 'incidentResponse'];

const SERVICE_COVERS = {
  vuln:      ['vulnerabilities'],     // infrastructure basis
  edr:       ['vulnerabilities'],     // endpoint basis
  awareness: ['awareness'],
  mdr:       ['incidentResponse'],
  ndr:       [],
  identity:  [],
  pentest:   [],
  vciso:     [],
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
function coversComponent(services, component, vulnBasis) {
  if (!Array.isArray(services)) return null;

  if (component === 'vulnerabilities') {
    // Charge it to the service that supplies the yardstick actually applied.
    // Crediting Managed EDR for an infrastructure scan it cannot see would
    // report coverage the client does not have.
    if (vulnBasis === 'endpoint')       return services.indexOf('edr') >= 0;
    if (vulnBasis === 'infrastructure') return services.indexOf('vuln') >= 0;
    return services.indexOf('vuln') >= 0 || services.indexOf('edr') >= 0;
  }

  return SERVICE_KEYS.some(k =>
    services.indexOf(k) >= 0 && (SERVICE_COVERS[k] || []).indexOf(component) >= 0);
}

/** The services that would cover this component, for "what's missing" copy. */
function servicesCovering(component, vulnBasis) {
  if (component === 'vulnerabilities') {
    if (vulnBasis === 'endpoint')       return ['edr'];
    if (vulnBasis === 'infrastructure') return ['vuln'];
    return ['vuln', 'edr'];
  }
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
    const key = String(k || '').trim().toLowerCase();
    if (SERVICE_KEYS.indexOf(key) >= 0) seen[key] = true;
  });
  return SERVICE_KEYS.filter(k => seen[k]);
}

/** True when the tenant is known to buy this service. Unconfigured => false. */
function hasService(services, key) {
  return Array.isArray(services) && services.indexOf(key) >= 0;
}

module.exports = {
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
