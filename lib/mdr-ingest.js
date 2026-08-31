'use strict';

/**
 * lib/mdr-ingest.js — writing a sync's worth of MDR tickets.
 *
 * Extracted from server.js for the same reason lib/report-pptx-route.js was:
 * this is the riskiest code in the MDR path — it runs on a live ingest several
 * times a day and every tenant's Secure Score depends on what it writes — and
 * inside server.js it could not be tested at all without a database.
 *
 * Everything here takes an explicit `client` (a pg client or transaction), so a
 * test can pass a recorder and assert the exact statement sequence.
 *
 * ── WHAT CHANGED, AND WHY IT IS SAFE ──────────────────────────────────────
 *
 * This used to `DELETE FROM mdr_uploads WHERE tenant_id = $1` and re-insert
 * every ticket. mdr_tickets.upload_id cascaded, so each ticket row was
 * destroyed and recreated several times a day: no stable identity, no history,
 * nothing for a client to track. See db/migrate-mdr-history.sql.
 *
 * The invariant that keeps every existing query correct is that each ticket the
 * feed still returns has its `upload_id` RE-POINTED at the new snapshot. So
 * "tickets on the latest upload_id" still means "tickets in the last sync", and
 * GET /api/mdr, /api/mdr/trends, loadIncidentRate() and /api/reports/metrics
 * need no changes at all. Tickets the feed has dropped keep a stale upload_id,
 * fall out of those queries exactly as before, and survive for the portal.
 */

/** Fields whose movement is worth a history row. */
const MDR_TRACKED_FIELDS = ['status', 'severity', 'assigned_to', 'resolved_at'];

/** How long superseded snapshot rows are kept before pruning. */
const MDR_SNAPSHOT_KEEP_DAYS = 180;

/**
 * Snapshot statistics, computed from the INCOMING FEED rather than the table.
 *
 * That distinction is what makes ticket persistence safe: mdr_uploads still
 * describes one sync, so calculateMdrScore sees the same numbers it always did
 * even though the ticket rows now outlive the snapshot.
 */
function calcMdrStats(tickets) {
  // Non-objects are dropped before anything reads .status. The previous version
  // did `tickets.filter(t => t.status === ...)` directly, so a single null or
  // malformed row in a vendor payload threw and aborted the whole tenant's
  // sync — losing the good tickets along with the bad one.
  const list = (Array.isArray(tickets) ? tickets : []).filter(t => t && typeof t === 'object');

  const resolved = list.filter(t => t.status === 'solved' || t.status === 'closed');
  const pending  = list.filter(t => t.status === 'pending' || t.status === 'open');

  let totalHours = 0, countedRes = 0;
  resolved.forEach((t) => {
    if (t.createdAt && t.resolvedAt) {
      const hrs = (new Date(t.resolvedAt) - new Date(t.createdAt)) / 3600000;
      if (hrs >= 0) { totalHours += hrs; countedRes++; }
    }
  });

  return {
    total:                list.length,
    resolved_count:       resolved.length,
    pending_count:        pending.length,
    avg_resolution_hours: countedRes > 0 ? parseFloat((totalHours / countedRes).toFixed(2)) : null,
  };
}

/**
 * Compare a stored ticket against the incoming one.
 *
 * Normalisation matters more than it looks. Severity casing varies by feed, and
 * a timestamp re-parsed from the same instant must not read as a change — a
 * spurious diff writes history claiming something happened when nothing did,
 * which is worse than recording nothing.
 *
 * @returns {Array<{field, oldValue, newValue}>} empty when nothing moved
 */
function diffTicketFields(prior, incoming) {
  const p = prior || {};
  const t = incoming || {};

  const norm = (field, v) => {
    if (v === null || v === undefined || v === '') return null;
    if (field === 'resolved_at') {
      const ms = new Date(v).getTime();
      return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
    }
    return String(v).trim().toLowerCase();
  };

  const next = {
    status:      t.status,
    severity:    t.severity,
    assigned_to: t.assignedTo,
    resolved_at: t.resolvedAt,
  };

  const out = [];
  for (const field of MDR_TRACKED_FIELDS) {
    const before = norm(field, p[field]);
    const after  = norm(field, next[field]);
    if (before !== after) {
      out.push({
        field,
        oldValue: p[field] == null ? null : String(p[field]),
        newValue: next[field] == null ? null : String(next[field]),
      });
    }
  }
  return out;
}

/** Append change rows. One statement, and nothing at all when nothing moved. */
async function recordTicketEvents(client, ticketId, tenantId, diffs, eventType) {
  if (!diffs || !diffs.length) return 0;

  const values = [];
  const params = [];
  diffs.forEach((d, i) => {
    const b = i * 6;
    values.push(`($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6})`);
    params.push(ticketId, tenantId, eventType || 'changed', d.field, d.oldValue, d.newValue);
  });

  await client.query(
    `INSERT INTO mdr_ticket_events (ticket_id, tenant_id, event_type, field, old_value, new_value)
     VALUES ${values.join(',')}`,
    params
  );
  return diffs.length;
}

/**
 * Ingest a sync's worth of tickets. Signature unchanged from the server.js
 * version so the single call site is untouched.
 *
 * @param {Object} client       pg client inside the caller's transaction
 * @param {number} tenantId
 * @param {Array}  tickets      parsed feed rows
 * @param {number} uploadedBy   user id, or null for a scheduled sync
 * @returns {Object} the snapshot stats, as before
 */
async function writeMdrTickets(client, tenantId, tickets, uploadedBy) {
  const stats = calcMdrStats(tickets);

  // New snapshot FIRST; old ones are pruned at the very end. A crash mid-sync
  // then leaves the previous snapshot intact rather than leaving none.
  const uploadRes = await client.query(
    `INSERT INTO mdr_uploads (tenant_id, uploaded_at, uploaded_by, total_tickets, resolved_count, pending_count, avg_resolution_hours)
     VALUES ($1, NOW(), $2, $3, $4, $5, $6) RETURNING id`,
    [tenantId, uploadedBy, stats.total, stats.resolved_count, stats.pending_count, stats.avg_resolution_hours]
  );
  const uploadId = uploadRes.rows[0].id;

  // One payload can carry the same ticket twice. Left alone the second copy
  // would diff against the first and record a move that never happened. Last
  // occurrence wins, matching the old insert order.
  const byNumber = new Map();
  for (const t of (Array.isArray(tickets) ? tickets : [])) {
    if (t && t.ticketNumber !== null && t.ticketNumber !== undefined) {
      byNumber.set(String(t.ticketNumber), t);
    }
  }

  let inserted = 0, updated = 0, events = 0;

  for (const t of byNumber.values()) {
    const ticketNumber = String(t.ticketNumber);

    const priorRes = await client.query(
      `SELECT id, status, severity, assigned_to, resolved_at
         FROM mdr_tickets
        WHERE tenant_id = $1 AND ticket_number = $2
        FOR UPDATE`,
      [tenantId, ticketNumber]
    );
    const prior = priorRes.rows[0];

    if (!prior) {
      const ins = await client.query(
        `INSERT INTO mdr_tickets
           (upload_id, tenant_id, ticket_number, subject, status, ticket_type, severity,
            created_at, resolved_at, updated_at, assigned_to,
            first_seen_at, last_seen_at, status_changed_at, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11, NOW(), NOW(), NOW(), $12)
         RETURNING id`,
        [uploadId, tenantId, ticketNumber, t.subject, t.status, t.ticketType, t.severity,
         t.createdAt || null, t.resolvedAt || null, t.updatedAt || null, t.assignedTo || null,
         t.source || 'arctic_wolf']
      );
      inserted++;
      events += await recordTicketEvents(client, ins.rows[0].id, tenantId,
        [{ field: 'status', oldValue: null, newValue: t.status == null ? null : String(t.status) }],
        'created');
      continue;
    }

    const diffs = diffTicketFields(prior, t);
    const statusMoved = diffs.some(d => d.field === 'status');

    await client.query(
      `UPDATE mdr_tickets SET
         upload_id   = $1,
         subject     = $2,
         status      = $3,
         ticket_type = $4,
         severity    = $5,
         created_at  = COALESCE($6, created_at),
         resolved_at = $7,
         updated_at  = $8,
         assigned_to = $9,
         last_seen_at = NOW(),
         status_changed_at = CASE WHEN $10 THEN NOW() ELSE status_changed_at END
       WHERE id = $11`,
      [uploadId, t.subject, t.status, t.ticketType, t.severity,
       t.createdAt || null, t.resolvedAt || null, t.updatedAt || null, t.assignedTo || null,
       statusMoved, prior.id]
    );
    updated++;

    // first_seen_at is never rewritten: it is when WE first saw the ticket,
    // and that cannot change.
    events += await recordTicketEvents(client, prior.id, tenantId, diffs, 'changed');
  }

  // Prune superseded snapshots. Surviving tickets already point at the new
  // upload, so anything still referencing a pruned row is one the feed no
  // longer returns — SET NULL detaches it and keeps it.
  await client.query(
    `DELETE FROM mdr_uploads
      WHERE tenant_id = $1 AND id <> $2
        AND uploaded_at < NOW() - ($3 || ' days')::interval`,
    [tenantId, uploadId, String(MDR_SNAPSHOT_KEEP_DAYS)]
  );

  return Object.assign({}, stats, { uploadId, inserted, updated, events });
}

module.exports = {
  MDR_TRACKED_FIELDS,
  MDR_SNAPSHOT_KEEP_DAYS,
  calcMdrStats,
  diffTicketFields,
  recordTicketEvents,
  writeMdrTickets,
};
