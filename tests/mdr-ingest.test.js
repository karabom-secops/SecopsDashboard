'use strict';

/**
 * MDR ticket ingest — identity, history, and the invariant that keeps every
 * existing query correct.
 *
 * THE DEFECT
 *
 * writeMdrTickets used to DELETE the tenant's uploads and re-insert every
 * ticket. upload_id cascaded, so each row was destroyed and recreated several
 * times a day: no stable identity, no status history, nothing a client could
 * track. A ticket someone was watching would vanish and come back with a new id.
 *
 * THE THING MOST LIKELY TO BREAK
 *
 * Not the portal — the INTERNAL views. GET /api/mdr, /api/mdr/trends,
 * loadIncidentRate() and /api/reports/metrics all mean "tickets on the latest
 * upload_id". They keep working only because the upsert re-points upload_id at
 * the new snapshot for every ticket the feed returned. If that ever stops, the
 * internal panel silently empties. Several checks below exist solely to pin it.
 *
 * Driven with a RECORDING CLIENT rather than a database: every statement is
 * captured, so the tests can assert the sequence and the parameters directly.
 *
 *   node tests/mdr-ingest.test.js <repoRoot>
 */

const path = require('path');
const ROOT = process.argv[2] || path.join(__dirname, '..');
const M = require(path.join(ROOT, 'lib', 'mdr-ingest.js'));
const { createChecker } = require('./helpers/check');

const { check, section, done } = createChecker('mdr-ingest');

/**
 * A pg client that records instead of connecting.
 *
 * `existing` maps ticket_number -> stored row, standing in for what is already
 * in the table, so an "unchanged second sync" can be simulated exactly.
 */
function recorder(existing) {
  const store = new Map(Object.entries(existing || {}));
  let nextId = 1000;
  const calls = [];

  return {
    calls,
    async query(sql, params) {
      calls.push({ sql: String(sql).replace(/\s+/g, ' ').trim(), params: params || [] });

      if (/INSERT INTO mdr_uploads/i.test(sql)) return { rows: [{ id: 777 }] };

      if (/FROM mdr_tickets\s+WHERE tenant_id/i.test(sql)) {
        const row = store.get(String(params[1]));
        return { rows: row ? [row] : [] };
      }

      if (/INSERT INTO mdr_tickets/i.test(sql)) {
        const id = ++nextId;
        store.set(String(params[2]), { id, status: params[4], severity: params[6],
                                       assigned_to: params[10], resolved_at: params[8] });
        return { rows: [{ id }] };
      }

      return { rows: [] };
    },
    /** Statements matching a pattern. */
    matching(re) { return calls.filter(c => re.test(c.sql)); },
  };
}

const ticket = (over) => Object.assign({
  ticketNumber: 'AW-1', subject: 'Suspicious sign-in', status: 'open',
  ticketType: 'incident', severity: 'HIGH',
  createdAt: '2026-08-01T09:00:00Z', resolvedAt: null,
  updatedAt: '2026-08-01T09:00:00Z', assignedTo: 'analyst-a',
}, over || {});

(async function main() {

  // ── The deletion is gone ───────────────────────────────────────────────
  section('a sync no longer destroys the tenant\'s tickets');
  {
    const c = recorder();
    await M.writeMdrTickets(c, 5, [ticket()], 1);

    check('no DELETE of mdr_tickets anywhere',
      c.matching(/DELETE FROM mdr_tickets/i).length === 0);
    // The exact statement that caused the data loss.
    const wipes = c.matching(/DELETE FROM mdr_uploads WHERE tenant_id = \$1$/i);
    check('no unconditional wipe of mdr_uploads', wipes.length === 0,
      wipes.map(w => w.sql).join(' | '));
    const prunes = c.matching(/DELETE FROM mdr_uploads/i);
    check('the only upload delete is the age-bounded prune',
      prunes.length === 1 && /uploaded_at < NOW\(\)/.test(prunes[0].sql));
    check('and it excludes the snapshot just written',
      /id <> \$2/.test(prunes[0].sql));
  }

  // ── Ordering: snapshot first, prune last ───────────────────────────────
  section('a crash mid-sync leaves the previous snapshot, not none');
  {
    const c = recorder();
    await M.writeMdrTickets(c, 5, [ticket()], 1);
    const insertAt = c.calls.findIndex(x => /INSERT INTO mdr_uploads/i.test(x.sql));
    const pruneAt  = c.calls.findIndex(x => /DELETE FROM mdr_uploads/i.test(x.sql));
    check('the new snapshot is written first', insertAt === 0, insertAt);
    check('the prune runs last', pruneAt === c.calls.length - 1, pruneAt + '/' + c.calls.length);
  }

  // ── THE invariant ──────────────────────────────────────────────────────
  section('upload_id is re-pointed, so internal views keep working');
  {
    const c = recorder({ 'AW-1': { id: 1, status: 'open', severity: 'HIGH',
                                   assigned_to: 'analyst-a', resolved_at: null } });
    await M.writeMdrTickets(c, 5, [ticket()], 1);

    const upd = c.matching(/UPDATE mdr_tickets SET/i)[0];
    check('an existing ticket is updated, not re-inserted',
      !!upd && c.matching(/INSERT INTO mdr_tickets/i).length === 0);
    check('the update sets upload_id first', /UPDATE mdr_tickets SET upload_id = \$1/.test(upd.sql));
    check('to the NEW snapshot id', upd.params[0] === 777, upd.params[0]);
    check('and refreshes last_seen_at', /last_seen_at = NOW\(\)/.test(upd.sql));
  }

  // ── Idempotence ────────────────────────────────────────────────────────
  section('re-running the same feed changes nothing');
  {
    const c = recorder({ 'AW-1': { id: 1, status: 'open', severity: 'HIGH',
                                   assigned_to: 'analyst-a', resolved_at: null } });
    const r = await M.writeMdrTickets(c, 5, [ticket()], 1);

    check('no ticket inserted', r.inserted === 0, r.inserted);
    check('one updated', r.updated === 1, r.updated);
    // The cost argument for the events table: an unchanged sync must be free.
    check('ZERO history rows written for an unchanged ticket', r.events === 0, r.events);
    check('and no event INSERT statement at all',
      c.matching(/INSERT INTO mdr_ticket_events/i).length === 0);
    check('status_changed_at is left alone when status did not move',
      /status_changed_at = CASE WHEN \$10 THEN NOW\(\) ELSE status_changed_at END/
        .test(c.matching(/UPDATE mdr_tickets SET/i)[0].sql));
    check('and the flag passed is false', c.matching(/UPDATE mdr_tickets SET/i)[0].params[9] === false);
  }

  // ── Change detection ───────────────────────────────────────────────────
  section('a real change is recorded, once');
  {
    const c = recorder({ 'AW-1': { id: 1, status: 'open', severity: 'HIGH',
                                   assigned_to: 'analyst-a', resolved_at: null } });
    const r = await M.writeMdrTickets(c, 5,
      [ticket({ status: 'solved', resolvedAt: '2026-08-02T10:00:00Z' })], 1);

    check('two fields moved: status and resolved_at', r.events === 2, r.events);
    const ev = c.matching(/INSERT INTO mdr_ticket_events/i);
    check('written in one statement, not one per field', ev.length === 1, ev.length);
    check('the old value is preserved', ev[0].params.includes('open'));
    check('and the new one', ev[0].params.includes('solved'));
    check('status_changed_at moves', c.matching(/UPDATE mdr_tickets SET/i)[0].params[9] === true);
  }

  section('a new ticket gets an opening event');
  {
    const c = recorder();
    const r = await M.writeMdrTickets(c, 5, [ticket()], 1);
    check('one ticket inserted', r.inserted === 1, r.inserted);
    // Both halves, deliberately. Checking the parameter alone passed even when
    // the VALUES clause had been changed to a literal NULL — the argument was
    // still being passed, it had just stopped being used.
    const ins = c.matching(/INSERT INTO mdr_tickets/i)[0];
    check('tenant_id is in the column list, before ticket_number',
      /\(upload_id, tenant_id, ticket_number,/.test(ins.sql), ins.sql.slice(0, 70));
    check('and the VALUES clause actually binds it',
      /VALUES \(\$1,\$2,\$3,/.test(ins.sql), (ins.sql.match(/VALUES \([^)]*\)/) || [''])[0]);
    check('to this tenant, not via the upload_id hop', ins.params[1] === 5, ins.params[1]);
    check('and first_seen_at stamped', /first_seen_at/.test(c.matching(/INSERT INTO mdr_tickets/i)[0].sql));
    const ev = c.matching(/INSERT INTO mdr_ticket_events/i)[0];
    check('an opening event is recorded', !!ev);
    check('typed as created, not changed', ev && ev.params.includes('created'));
  }

  section('first_seen_at is never rewritten');
  {
    const c = recorder({ 'AW-1': { id: 1, status: 'open', severity: 'HIGH',
                                   assigned_to: 'analyst-a', resolved_at: null } });
    await M.writeMdrTickets(c, 5, [ticket({ status: 'solved' })], 1);
    check('the UPDATE does not touch first_seen_at',
      !/first_seen_at/.test(c.matching(/UPDATE mdr_tickets SET/i)[0].sql));
  }

  // ── diffTicketFields ───────────────────────────────────────────────────
  section('diffing does not invent changes');
  const D = M.diffTicketFields;
  const base = { status: 'open', severity: 'HIGH', assigned_to: 'a', resolved_at: null };

  check('identical is empty',
    D(base, { status: 'open', severity: 'HIGH', assignedTo: 'a', resolvedAt: null }).length === 0);
  check('severity CASE alone is not a change',
    D(base, { status: 'open', severity: 'high', assignedTo: 'a', resolvedAt: null }).length === 0);
  check('surrounding whitespace is not a change',
    D(base, { status: ' open ', severity: 'HIGH', assignedTo: 'a', resolvedAt: null }).length === 0);
  // The same instant in a different notation must not read as a move.
  check('a re-formatted timestamp is not a change',
    D({ ...base, resolved_at: '2026-08-02T10:00:00Z' },
      { status: 'open', severity: 'HIGH', assignedTo: 'a', resolvedAt: '2026-08-02T10:00:00.000Z' }
    ).length === 0);
  check('null and empty string are the same absence',
    D({ ...base, assigned_to: null },
      { status: 'open', severity: 'HIGH', assignedTo: '', resolvedAt: null }).length === 0);
  check('a real status move is caught',
    D(base, { status: 'solved', severity: 'HIGH', assignedTo: 'a', resolvedAt: null })
      .map(d => d.field).join(',') === 'status');
  check('a reopen is representable — resolved_at clearing is a change',
    D({ ...base, status: 'solved', resolved_at: '2026-08-02T10:00:00Z' },
      { status: 'open', severity: 'HIGH', assignedTo: 'a', resolvedAt: null })
      .map(d => d.field).sort().join(',') === 'resolved_at,status');
  check('subject is deliberately NOT tracked — vendors reword them',
    M.MDR_TRACKED_FIELDS.indexOf('subject') === -1);
  check('null inputs are safe', D(null, null).length === 0);

  // ── Duplicates within one payload ──────────────────────────────────────
  section('a duplicate inside one payload does not fake a change');
  {
    const c = recorder();
    const r = await M.writeMdrTickets(c, 5, [
      ticket({ status: 'open' }),
      ticket({ status: 'solved' }),   // same ticketNumber, later in the feed
    ], 1);
    check('written once, not twice', r.inserted === 1, r.inserted);
    check('last occurrence wins',
      c.matching(/INSERT INTO mdr_tickets/i)[0].params[4] === 'solved');
    check('and no spurious change event', r.events === 1, r.events);
  }

  section('malformed feed rows are skipped, not written as nulls');
  {
    const c = recorder();
    const r = await M.writeMdrTickets(c, 5,
      [null, undefined, { subject: 'no number' }, ticket()], 1);
    check('only the usable ticket is written', r.inserted === 1, r.inserted);
  }

  // ── Stats stay feed-derived ────────────────────────────────────────────
  section('snapshot stats are unchanged by ticket persistence');
  const S = M.calcMdrStats;
  check('total counts the feed', S([ticket(), ticket({ ticketNumber: 'AW-2' })]).total === 2);
  check('resolved counts solved and closed',
    S([ticket({ status: 'solved' }), ticket({ status: 'closed' }), ticket({ status: 'open' })])
      .resolved_count === 2);
  check('pending counts pending and open',
    S([ticket({ status: 'pending' }), ticket({ status: 'open' })]).pending_count === 2);
  check('average resolution hours',
    S([ticket({ status: 'solved', createdAt: '2026-08-01T00:00:00Z',
                resolvedAt: '2026-08-01T06:00:00Z' })]).avg_resolution_hours === 6);
  check('a negative span is excluded rather than dragging the mean down',
    S([ticket({ status: 'solved', createdAt: '2026-08-02T00:00:00Z',
                resolvedAt: '2026-08-01T00:00:00Z' })]).avg_resolution_hours === null);
  check('no resolved tickets yields null, not zero',
    S([ticket({ status: 'open' })]).avg_resolution_hours === null);
  check('an empty feed is safe', S([]).total === 0 && S(null).total === 0);
  // The stats the snapshot records must describe the FEED, or persisting
  // tickets would inflate every tenant's MDR score.
  {
    const c = recorder({ 'AW-9': { id: 9, status: 'open', severity: 'LOW',
                                   assigned_to: null, resolved_at: null } });
    const r = await M.writeMdrTickets(c, 5, [ticket()], 1);
    check('a tenant with retained history still reports the feed size',
      r.total === 1, r.total);
  }

  done();
})();
