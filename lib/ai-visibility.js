'use strict';

/**
 * lib/ai-visibility.js — the sanctioned-app register, and how an AI tool's
 * status is decided.
 *
 * A client's DNS traffic says WHICH AI tools are in use. Whether that use is a
 * problem depends on a decision only the client can make with us: is the tool
 * sanctioned? This file holds that rule, in one place, so the tab, the summary
 * route and the board report cannot disagree about it.
 *
 *   sanctioned     approved for use
 *   unsanctioned   not approved — allowed traffic to it is SHADOW AI
 *   under_review   a decision is being made
 *   unreviewed     nobody has decided. NOT sanctioned: "not recorded is not
 *                  none", and a tool nobody looked at is not an approved one
 */

const STATUSES = ['sanctioned', 'unsanctioned', 'under_review'];
const NOTE_MAX = 1000;
const NAME_MAX = 200;

/** The keys lib/integrations/dnsfilter.js produces: app:<id> or domain:<host>. */
const APP_KEY_RE = /^(app|domain):[a-z0-9._-]{1,120}$/;

function validAppKey(key) {
  return typeof key === 'string' && APP_KEY_RE.test(key);
}

/**
 * Validate a decision from the tab.
 * @returns {{ ok: true, value } | { ok: false, error }}
 */
function validateDecision(body) {
  const b = body || {};
  if (STATUSES.indexOf(b.status) < 0) {
    return { ok: false, error: `status must be one of: ${STATUSES.join(', ')}.` };
  }
  const note = b.note == null ? '' : String(b.note).trim();
  if (note.length > NOTE_MAX) return { ok: false, error: `note must be ${NOTE_MAX} characters or fewer.` };
  const appName = b.appName == null ? '' : String(b.appName).trim().slice(0, NAME_MAX);
  return { ok: true, value: { status: b.status, note: note || null, appName: appName || null } };
}

/** The status of one app, given the register (a Map or object keyed by app key). */
function statusOf(appKey, decisions) {
  const d = decisions instanceof Map ? decisions.get(appKey) : (decisions || {})[appKey];
  return d && STATUSES.indexOf(d.status) >= 0 ? d.status : 'unreviewed';
}

/** Shadow AI: traffic reached a tool the client has said is not approved. */
function isShadow(app, status) {
  return status === 'unsanctioned' && (Number(app && app.allowed) || 0) > 0;
}

/**
 * Apps annotated with their status, plus the counts the tab and report headline.
 * Blocked-only traffic to an unsanctioned tool is the policy working, so it is
 * not counted as shadow AI.
 */
function annotateApps(apps, decisions) {
  const rows = (apps || []).map((a) => {
    const status = statusOf(a.key, decisions);
    const d = decisions instanceof Map ? decisions.get(a.key) : (decisions || {})[a.key];
    return Object.assign({}, a, {
      status,
      shadow: isShadow(a, status),
      note: d && d.note ? d.note : null,
    });
  });
  return {
    rows,
    shadowCount:     rows.filter(r => r.shadow).length,
    unreviewedCount: rows.filter(r => r.status === 'unreviewed').length,
    sanctionedCount: rows.filter(r => r.status === 'sanctioned').length,
  };
}

module.exports = {
  STATUSES,
  NOTE_MAX,
  APP_KEY_RE,
  validAppKey,
  validateDecision,
  statusOf,
  isShadow,
  annotateApps,
};
