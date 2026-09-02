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
  serviceLabel,
  normaliseServices,
  hasService,
};
