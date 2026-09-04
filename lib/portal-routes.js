'use strict';

/**
 * lib/portal-routes.js — everything the client portal can read.
 *
 * THREE RULES, APPLIED WITHOUT EXCEPTION
 *
 * 1. Tenant comes from resolvePortalTenant(req) — the session, never a
 *    parameter. No handler in this file may call any other resolve*Tenant
 *    helper; they all have a superadmin branch that trusts a query string.
 *
 * 2. Ownership lives in the WHERE clause, never in a post-fetch `if`. A wrong
 *    id and another tenant's id then look identical: both return nothing, both
 *    404. There is no shape of response that distinguishes them.
 *
 * 3. Columns are an explicit allowlist. Never SELECT *, never the internal
 *    payload. Two things in particular never cross: analyst names
 *    (mdr_tickets.assigned_to, ir_incidents.assigned_to) and the Secure Score's
 *    weighting internals, which are written for a colleague and read very
 *    differently to the customer being weighted.
 *
 * Everything here is read-only. requirePortalSession already refuses writes;
 * the absence of any mutating handler is the second lock.
 */

const estateLib = require('./estate');
const secureScore = require('./secure-score');
const reportArchive = require('./report-archive');
// publicFinding() is the allowlist that keeps `evidence` off the client-facing
// projection. Imported rather than reimplemented here, so the rule lives in one
// place and the portal cannot drift from the report.
const fortigateScore = require('./fortigate-score');
const { resolvePortalTenant } = require('./portal-gate');

/** Severity ordering used for sorting and for the client-facing labels. */
const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

/** Statuses that mean "this is finished". */
const CLOSED_STATUSES = ['solved', 'closed', 'resolved'];

function titleCase(s) {
  const v = String(s == null ? '' : s).trim();
  if (!v) return '';
  return v.charAt(0).toUpperCase() + v.slice(1).toLowerCase();
}

function isClosed(status) {
  return CLOSED_STATUSES.indexOf(String(status || '').toLowerCase()) >= 0;
}

/**
 * Register every portal route on the app.
 *
 * @param {Object} app     express app
 * @param {Object} deps    { pool, requireAuth, portalSession, onError }
 */
function register(app, deps) {
  const { pool, requireAuth, portalSession, onError } = deps;
  const fail = onError || ((res, err) => res.status(500).json({ error: err.message }));

  /** Wrap a handler so tenant resolution and error handling are never forgotten. */
  function portal(handler) {
    return async function (req, res) {
      try {
        const tenantId = resolvePortalTenant(req);
        if (!tenantId) {
          return res.status(403).json({
            error: 'This account is not linked to a client. Contact your administrator.',
          });
        }
        return await handler(req, res, tenantId);
      } catch (err) {
        // ALWAYS log. This branch used to swallow 42P01/42703 silently and tell
        // the client "not available yet", which reads as a missing migration —
        // so a genuine SQL bug of ours (an output alias used inside an ORDER BY
        // expression) presented for all the world as an un-run migration, with
        // nothing in the log to say otherwise.
        if (err.code === '42P01' || err.code === '42703') {
          console.error('[portal] ' + req.method + ' ' + req.originalUrl +
            ' failed with ' + err.code + ': ' + err.message +
            (err.code === '42703'
              ? ' — an undefined COLUMN usually means a bug in this query, not a missing migration.'
              : ' — an undefined TABLE usually means a migration has not been run.'));

          // Staff previewing get the real reason; a client gets the plain one.
          var detail = (req.session && req.session.role !== 'client')
            ? ' (' + err.code + ': ' + err.message + ')' : '';
          return res.status(503).json({
            error: 'This section is not available yet.' + detail,
          });
        }
        return fail(res, err);
      }
    };
  }

  const gate = [requireAuth, portalSession];

  // ── Who am I ────────────────────────────────────────────────────────────
  app.get('/api/portal/me', gate, portal(async (req, res, tenantId) => {
    const t = await pool.query('SELECT name FROM tenants WHERE id = $1', [tenantId]);
    return res.json({
      username:   req.session.username,
      role:       req.session.role,
      clientName: t.rows.length ? t.rows[0].name : '',
      // Staff previewing see the portal exactly as a client does, but should
      // know they are doing so.
      preview:    req.session.role !== 'client',
    });
  }));

  // ── Incidents ───────────────────────────────────────────────────────────
  /**
   * The merged list.
   *
   * MDR tickets and IR incidents share no key, so a linked pair would appear
   * twice. ir_incidents.mdr_ticket_number is the operator-set link (see
   * db/migrate-ir-mdr-link.sql); where it is set, the IR record wins because it
   * is the richer one, and the ticket is suppressed.
   *
   * Until staff link them, an escalated event DOES appear twice. That is
   * visible and explainable. Matching on subject and timestamp instead would
   * silently merge unrelated events, which is worse for being invisible.
   */
  app.get('/api/portal/incidents', gate, portal(async (req, res, tenantId) => {
    const limit  = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const ir = await pool.query(
      `SELECT id, title, description, severity, status, phase, incident_type,
              opened_at, closed_at, mdr_ticket_number
         FROM ir_incidents
        WHERE tenant_id = $1
        ORDER BY opened_at DESC`,
      [tenantId]
    );

    const linked = new Set(
      ir.rows.map(r => r.mdr_ticket_number).filter(Boolean).map(String)
    );

    const mdr = await pool.query(
      `SELECT ticket_number, subject, status, severity, ticket_type,
              created_at, resolved_at, status_changed_at, first_seen_at
         FROM mdr_tickets
        WHERE tenant_id = $1 AND portal_visible
        ORDER BY created_at DESC NULLS LAST`,
      [tenantId]
    );

    const items = [];

    ir.rows.forEach((r) => {
      items.push({
        key:        'ir-' + r.id,
        source:     'incident-response',
        reference:  r.mdr_ticket_number || null,
        title:      r.title,
        summary:    r.description || '',
        severity:   String(r.severity || '').toLowerCase(),
        status:     titleCase(r.status),
        closed:     isClosed(r.status),
        phase:      titleCase(String(r.phase || '').replace(/-/g, ' ')),
        category:   titleCase(String(r.incident_type || '').replace(/_/g, ' ')),
        openedAt:   r.opened_at,
        closedAt:   r.closed_at,
      });
    });

    mdr.rows.forEach((r) => {
      if (linked.has(String(r.ticket_number))) return;   // shown as its IR record
      items.push({
        key:        'mdr-' + r.ticket_number,
        source:     'mdr',
        reference:  r.ticket_number,
        title:      r.subject,
        summary:    '',
        severity:   String(r.severity || '').toLowerCase(),
        status:     titleCase(r.status),
        closed:     isClosed(r.status),
        phase:      null,
        category:   titleCase(r.ticket_type),
        openedAt:   r.created_at || r.first_seen_at,
        closedAt:   r.resolved_at,
      });
    });

    // Open first, then most severe, then most recent — the order someone
    // scanning for "what still needs me" actually wants.
    items.sort((a, b) => {
      if (a.closed !== b.closed) return a.closed ? 1 : -1;
      const s = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
      if (s) return s;
      return new Date(b.openedAt || 0) - new Date(a.openedAt || 0);
    });

    const open = items.filter(i => !i.closed);
    return res.json({
      total: items.length,
      openCount: open.length,
      // The duplicate warning is surfaced rather than hidden: a client counting
      // rows deserves to know why two look alike.
      linkedCount: linked.size,
      items: items.slice(offset, offset + limit),
    });
  }));

  /** One incident, with its history. */
  app.get('/api/portal/incidents/:key', gate, portal(async (req, res, tenantId) => {
    const key = String(req.params.key || '');

    if (key.startsWith('ir-')) {
      const id = parseInt(key.slice(3), 10);
      const r = await pool.query(
        `SELECT id, title, description, severity, status, phase, incident_type,
                opened_at, closed_at, mdr_ticket_number
           FROM ir_incidents WHERE id = $1 AND tenant_id = $2`,
        [id, tenantId]
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Incident not found.' });
      const row = r.rows[0];

      // Playbook steps are internal working notes; only the fact that a phase
      // completed is client-facing.
      const acts = await pool.query(
        `SELECT phase, status, completed_at FROM ir_activities
          WHERE incident_id = $1 ORDER BY sort_order, id`,
        [row.id]
      );
      const byPhase = {};
      acts.rows.forEach((a) => {
        const p = String(a.phase || 'identification');
        byPhase[p] = byPhase[p] || { phase: titleCase(p.replace(/-/g, ' ')), done: 0, total: 0, completedAt: null };
        byPhase[p].total++;
        if (a.status === 'done') {
          byPhase[p].done++;
          if (a.completed_at && (!byPhase[p].completedAt || a.completed_at > byPhase[p].completedAt)) {
            byPhase[p].completedAt = a.completed_at;
          }
        }
      });

      /*
       * When the incident entered each phase.
       *
       * ir_incidents.phase is overwritten in place, so this is the only record
       * of how the response actually ran. Append-only and NOT assumed linear:
       * eradication commonly bounces back to containment, and the trail shows
       * that rather than smoothing it into a tidy five-step march.
       */
      let phases = [];
      try {
        const ph = await pool.query(
          `SELECT phase, entered_at FROM ir_phase_events
            WHERE incident_id = $1 AND tenant_id = $2
            ORDER BY entered_at, id`,
          [row.id, tenantId]
        );
        phases = ph.rows.map((p, i, all) => {
          // Left when the NEXT phase was entered; the last one is still open,
          // so its end is the incident's close or nothing at all.
          const next = all[i + 1];
          const until = next ? next.entered_at : (row.closed_at || null);
          return {
            phase: titleCase(String(p.phase || '').replace(/-/g, ' ')),
            enteredAt: p.entered_at,
            leftAt: until,
            current: !next && !isClosed(row.status),
            durationHours: until
              ? Math.max(0, Math.round(
                  (new Date(until) - new Date(p.entered_at)) / 36e5 * 10) / 10)
              : null,
          };
        });
      } catch (err) {
        // History table not migrated yet — the incident still renders, just
        // without its timings.
        if (err.code !== '42P01') throw err;
      }

      return res.json({
        key, source: 'incident-response',
        reference: row.mdr_ticket_number || null,
        title: row.title, summary: row.description || '',
        severity: String(row.severity || '').toLowerCase(),
        status: titleCase(row.status), closed: isClosed(row.status),
        phase: titleCase(String(row.phase || '').replace(/-/g, ' ')),
        category: titleCase(String(row.incident_type || '').replace(/_/g, ' ')),
        openedAt: row.opened_at, closedAt: row.closed_at,
        progress: Object.values(byPhase),
        phases,
        timeline: [],
      });
    }

    if (key.startsWith('mdr-')) {
      const number = key.slice(4);
      const r = await pool.query(
        `SELECT id, ticket_number, subject, status, severity, ticket_type,
                created_at, resolved_at, first_seen_at, status_changed_at
           FROM mdr_tickets
          WHERE tenant_id = $1 AND ticket_number = $2 AND portal_visible`,
        [tenantId, number]
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Incident not found.' });
      const row = r.rows[0];

      // The trail this whole refactor existed to make possible.
      const ev = await pool.query(
        `SELECT event_at, event_type, field, old_value, new_value
           FROM mdr_ticket_events
          WHERE ticket_id = $1 AND tenant_id = $2
          ORDER BY event_at, id`,
        [row.id, tenantId]
      );

      return res.json({
        key, source: 'mdr', reference: row.ticket_number,
        title: row.subject, summary: '',
        severity: String(row.severity || '').toLowerCase(),
        status: titleCase(row.status), closed: isClosed(row.status),
        phase: null, category: titleCase(row.ticket_type),
        openedAt: row.created_at || row.first_seen_at,
        closedAt: row.resolved_at,
        progress: [],
        timeline: ev.rows.map(e => ({
          at: e.event_at,
          type: e.event_type,
          field: e.field,
          from: e.field === 'status' ? titleCase(e.old_value) : e.old_value,
          to:   e.field === 'status' ? titleCase(e.new_value) : e.new_value,
        })),
      });
    }

    return res.status(404).json({ error: 'Incident not found.' });
  }));

  // ── Reports ─────────────────────────────────────────────────────────────
  app.get('/api/portal/reports', gate, portal(async (req, res, tenantId) => {
    const rows = await reportArchive.listPublications(pool, { tenantId, publishedOnly: true });
    return res.json({
      reports: rows.map(r => ({
        id: r.id, period: r.period, periodLabel: r.period_label || r.period,
        title: r.title, version: r.version, isLatest: r.isLatest,
        publishedAt: r.published_at, coverNote: r.cover_note,
        pptxBytes: r.pptx_bytes, slideCount: r.slide_count,
        canDownload: !r.purged_at, canView: !!r.has_html,
      })),
    });
  }));

  app.get('/api/portal/reports/:id/download.pptx', gate, portal(async (req, res, tenantId) => {
    const row = await reportArchive.getPublication(pool, parseInt(req.params.id, 10),
      tenantId, { publishedOnly: true });
    if (!row) return res.status(404).json({ error: 'Report not found.' });
    res.on('finish', () => reportArchive.noteDownload(pool, row.id));
    return reportArchive.sendPublicationPptx(res, row);
  }));

  app.get('/api/portal/reports/:id/view', gate, portal(async (req, res, tenantId) => {
    const row = await reportArchive.getPublication(pool, parseInt(req.params.id, 10),
      tenantId, { publishedOnly: true, withHtml: true });
    if (!row) return res.status(404).json({ error: 'Report not found.' });
    return reportArchive.sendPublicationHtml(res, row);
  }));

  // ── Secure Score ────────────────────────────────────────────────────────
  /**
   * The score, stripped of its workings.
   *
   * The internal payload carries the weighting model — exposure points, patch
   * relief, "weighted at half pending evidence", the recommendation list aimed
   * at an analyst. Those explain a number to a colleague; to the customer being
   * weighted they read as a negotiation. The client gets the score, the
   * components, the trend and the rating, and nothing that invites an argument
   * about the arithmetic instead of the posture.
   */
  app.get('/api/portal/secure-score', gate, portal(async (req, res, tenantId) => {
    const hist = await pool.query(
      `SELECT score_date, composite_score, vuln_score, awareness_score, mdr_score
         FROM secure_scores
        WHERE tenant_id = $1
        ORDER BY score_date DESC
        LIMIT 24`,
      [tenantId]
    );
    if (!hist.rows.length) {
      return res.json({ available: false, reason: 'No score has been calculated yet.' });
    }

    const latest = hist.rows[0];
    const score = Number(latest.composite_score) || 0;
    const rating = score >= 80 ? 'Excellent' : score >= 70 ? 'Good'
                 : score >= 50 ? 'Fair' : 'Poor';

    return res.json({
      available: true,
      score, rating, asOf: latest.score_date,
      components: [
        { label: 'Vulnerability management', score: Number(latest.vuln_score) || 0 },
        { label: 'Security awareness',       score: Number(latest.awareness_score) || 0 },
        { label: 'Incident response',        score: Number(latest.mdr_score) || 0 },
      ],
      trend: hist.rows.slice().reverse()
        .map(r => ({ date: r.score_date, score: Number(r.composite_score) || 0 })),
    });
  }));

  // ── Vulnerabilities ─────────────────────────────────────────────────────
  /**
   * Counts, trend and SLA state. NO FINDING LIST.
   *
   * Host, port, CVE and solution for open findings is a working map of the
   * client's unpatched internet-facing services. It is their data and they may
   * have it — but through a report their team has reviewed, not standing behind
   * a portal password. The counts tell them where they stand; the detail is a
   * deliberate omission, not an oversight.
   */
  /**
   * GET /api/portal/firewall — the client's latest FortiGate review.
   *
   * WHAT IS WITHHELD, AND WHY IT IS THE SAME REASONING AS /vulns ABOVE.
   *
   * `evidence` — the policy ids, interface names and tunnel names behind each
   * finding — is not sent. Together those are a working map of where this
   * client's firewall is weakest, standing behind a portal password.
   *
   * They get the finding, its severity, why it matters and how to fix it: enough
   * to act on and to hold us to. The rule-level detail goes to their team
   * through a review their analyst walks them through, not as a downloadable
   * list. Built with publicFinding(), an allowlist, so a field added to a
   * finding later is withheld by default rather than published because nobody
   * updated a blocklist.
   */
  app.get('/api/portal/firewall', gate, portal(async (req, res, tenantId) => {
    const a = await pool.query(
      `SELECT id, uploaded_at, device_name, model, firmware, score, coverage,
              total_checks, assessed, passed, failed, not_assessable
         FROM firewall_audits
        WHERE tenant_id = $1
        ORDER BY uploaded_at DESC LIMIT 1`, [tenantId]);

    if (!a.rows.length) return res.json({ available: true, audit: null });
    const row = a.rows[0];

    const f = await pool.query(
      `SELECT check_id, severity, status, title, rationale, remediation,
              cis_ref, source
         FROM firewall_findings
        WHERE audit_id = $1 AND tenant_id = $2
        ORDER BY id`, [row.id, tenantId]);

    return res.json({
      available: true,
      audit: {
        reviewedAt: row.uploaded_at,
        device: { model: row.model, firmware: row.firmware },
        score: row.score,
        band: fortigateScore.band(row.score),
        coverage: row.coverage,
        totalChecks: row.total_checks,
        assessed: row.assessed,
        passed: row.passed,
        failed: row.failed,
        notAssessable: row.not_assessable,
        // The device HOSTNAME is deliberately absent too: it is an internal
        // naming convention, and it identifies the box in a document that
        // travels.
        findings: f.rows.map(r => fortigateScore.publicFinding({
          id: r.check_id, title: r.title, severity: r.severity, status: r.status,
          cis: r.cis_ref, source: r.source,
          rationale: r.rationale, remediation: r.remediation,
        })),
      },
      note: 'Findings from a review of the firewall configuration supplied. The ' +
            'configuration file itself is not retained.',
    });
  }));

  app.get('/api/portal/vulns', gate, portal(async (req, res, tenantId) => {
    const scans = await pool.query(
      `SELECT id, month_key, summary, scanned_hosts
         FROM vuln_scans WHERE tenant_id = $1
        ORDER BY month_key DESC LIMIT 12`,
      [tenantId]
    );
    if (!scans.rows.length) {
      return res.json({ available: false, reason: 'No vulnerability scan has been uploaded yet.' });
    }

    const latest = scans.rows[0];
    const sum = latest.summary || {};
    const num = v => Number(v) || 0;

    // Past the remediation SLA. due_date is set at parse time per severity.
    const overdue = await pool.query(
      `SELECT COUNT(*)::int AS n FROM vuln_findings
        WHERE scan_id = $1 AND status = 'open'
          AND due_date IS NOT NULL AND due_date < NOW()`,
      [latest.id]
    );

    const estate = estateLib.resolveEstate(null, { scannedHosts: latest.scanned_hosts });
    return res.json({
      available: true,
      monthKey: latest.month_key,
      counts: {
        critical: num(sum.critical), high: num(sum.high),
        medium:   num(sum.medium),   low:  num(sum.low),
      },
      pastSla: overdue.rows[0].n,
      scannedHosts: latest.scanned_hosts,
      trend: scans.rows.slice().reverse().map(s => ({
        monthKey: s.month_key,
        critical: num((s.summary || {}).critical),
        high:     num((s.summary || {}).high),
      })),
      note: 'Covers external-facing assets. Internal servers and workstations ' +
            'are not in scope for this scan.',
      scanDenominator: estateLib.scanDenominator(estate),
    });
  }));

  // ── Remediation tracker ─────────────────────────────────────────────────
  /**
   * Everything outstanding, from all four sources, in one list.
   *
   * WHAT IS DELIBERATELY LEFT OUT
   *
   * Host, port, CVE, plugin id, the remediation write-up, and every internal
   * note and owner. The /api/portal/vulns view withholds the finding list on
   * the grounds that it is a working map of the client's unpatched perimeter,
   * and shipping the same detail here through a different door would undo that
   * decision without anyone deciding it.
   *
   * What IS included is the actionable layer: what the item is, how serious,
   * when it is due, and whether it is late. A client can act on that and
   * cannot use it as a target list.
   *
   * The four sources share no key and no status vocabulary, so each is
   * normalised to one shape rather than the client being asked to hold four
   * models in their head.
   */
  const REMEDIATION_OPEN = ['open', 'in-progress', 'identified', 'assessing',
                            'mitigating', 'monitoring', 'contained', 'remediating'];

  function isOpenItem(status) {
    return REMEDIATION_OPEN.indexOf(String(status || '').toLowerCase()) >= 0;
  }

  app.get('/api/portal/remediation', gate, portal(async (req, res, tenantId) => {
    const items = [];
    const soft = async (fn) => {
      // One un-migrated table must not blank the whole tracker.
      try { return await fn(); } catch (err) {
        if (err.code === '42P01' || err.code === '42703') return null;
        throw err;
      }
    };

    // Vulnerabilities, from the latest scan only — older scans are superseded.
    await soft(async () => {
      const scan = await pool.query(
        `SELECT id FROM vuln_scans WHERE tenant_id = $1
          ORDER BY month_key DESC LIMIT 1`, [tenantId]);
      if (!scan.rows.length) return;
      const f = await pool.query(
        `SELECT name, risk, status, due_date, first_seen_at
           FROM vuln_findings
          WHERE scan_id = $1 AND status IN ('open', 'in-progress')
          ORDER BY due_date NULLS LAST LIMIT 500`,
        [scan.rows[0].id]
      );
      f.rows.forEach((r) => items.push({
        source: 'Vulnerability',
        title: r.name,
        severity: String(r.risk || '').toLowerCase(),
        status: titleCase(r.status),
        dueDate: r.due_date,
        raisedAt: r.first_seen_at,
      }));
    });

    await soft(async () => {
      const r = await pool.query(
        `SELECT title, risk_score, stage, due_date, start_date
           FROM risks WHERE tenant_id = $1 AND stage <> 'closed'
          ORDER BY risk_score DESC LIMIT 200`, [tenantId]);
      r.rows.forEach((x) => items.push({
        source: 'Risk',
        title: x.title,
        // The register scores 1-25; mapped to the same four words everything
        // else uses, so one list does not carry two severity scales.
        severity: x.risk_score >= 20 ? 'critical' : x.risk_score >= 12 ? 'high'
                : x.risk_score >= 6 ? 'medium' : 'low',
        status: titleCase(x.stage),
        dueDate: x.due_date,
        raisedAt: x.start_date,
      }));
    });

    await soft(async () => {
      const r = await pool.query(
        `SELECT title, severity, status, due_date, created_at
           FROM pentest_findings
          WHERE tenant_id = $1 AND status IN ('open', 'in-progress')
          ORDER BY created_at DESC LIMIT 200`, [tenantId]);
      r.rows.forEach((x) => items.push({
        source: 'Penetration test',
        title: x.title,
        severity: String(x.severity || '').toLowerCase(),
        status: titleCase(x.status),
        dueDate: x.due_date,
        raisedAt: x.created_at,
      }));
    });

    await soft(async () => {
      const r = await pool.query(
        `SELECT title, severity, status, opened_at
           FROM ir_incidents
          WHERE tenant_id = $1 AND status NOT IN ('resolved', 'closed')
          ORDER BY opened_at DESC LIMIT 200`, [tenantId]);
      r.rows.forEach((x) => items.push({
        source: 'Incident',
        title: x.title,
        severity: String(x.severity || '').toLowerCase(),
        status: titleCase(x.status),
        dueDate: null,
        raisedAt: x.opened_at,
      }));
    });

    const now = Date.now();
    items.forEach((i) => {
      i.overdue = !!(i.dueDate && new Date(i.dueDate).getTime() < now);
      i.open = isOpenItem(i.status);
    });

    // Overdue first, then most severe, then soonest due. What a client opening
    // this page is looking for is "what is late", so that leads.
    items.sort((a, b) => {
      if (a.overdue !== b.overdue) return a.overdue ? -1 : 1;
      const s = (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0);
      if (s) return s;
      if (a.dueDate && b.dueDate) return new Date(a.dueDate) - new Date(b.dueDate);
      return a.dueDate ? -1 : b.dueDate ? 1 : 0;
    });

    return res.json({
      total: items.length,
      overdue: items.filter(i => i.overdue).length,
      bySeverity: ['critical', 'high', 'medium', 'low'].reduce((acc, k) => {
        acc[k] = items.filter(i => i.severity === k).length;
        return acc;
      }, {}),
      items,
      note: 'Open items only. Vulnerability entries name the issue but not the ' +
            'affected systems — those are in your board report, with our ' +
            'assessment alongside them.',
    });
  }));

  // ── Awareness ───────────────────────────────────────────────────────────
  /**
   * Aggregate plus named per-employee completion.
   *
   * Names are included deliberately: it is the client's own staff, their own
   * training obligation, and the existing manager report already shows exactly
   * this. Worth knowing that it makes the portal a place where one employee can
   * see another's training record.
   */
  app.get('/api/portal/awareness', gate, portal(async (req, res, tenantId) => {
    const up = await pool.query(
      `SELECT id, uploaded_at, total_users, total_incomplete, upload_type
         FROM awareness_uploads WHERE tenant_id = $1
        ORDER BY uploaded_at DESC LIMIT 1`,
      [tenantId]
    );
    if (!up.rows.length) {
      return res.json({ available: false, reason: 'No training records have been uploaded yet.' });
    }

    const row = up.rows[0];
    const staff = parseInt(row.total_users, 10) || 0;

    /*
     * total_users and total_incomplete DO NOT SHARE A UNIT on a history upload.
     *
     * writeAwarenessHistory stores total_users = unique PEOPLE and
     * total_incomplete = not-started SESSIONS. Subtracting one from the other
     * is meaningless — for a real client it gave 242 − 994, which clamped to
     * zero and reported every one of their staff as having completed nothing
     * while the Awareness tab showed 78%.
     *
     * So the totals come from the sessions themselves, exactly as
     * /api/secure-score already does for the same reason.
     */
    let completed = 0;
    let outstanding = 0;
    let unit = 'people';

    if (row.upload_type === 'history') {
      const t = await pool.query(
        `SELECT COUNT(*) FILTER (WHERE LOWER(status) LIKE '%complet%')::int AS completed,
                COUNT(*)::int AS total
           FROM awareness_sessions
          WHERE upload_id = $1
            AND (session_type IS NULL OR LOWER(session_type) NOT LIKE '%phishing simulation%')`,
        [row.id]
      );
      const totalSessions = t.rows[0].total || 0;
      completed   = t.rows[0].completed || 0;
      outstanding = Math.max(0, totalSessions - completed);
      unit = 'sessions';
    } else {
      // Summary and manual uploads count PEOPLE in both columns, so the
      // subtraction is meaningful there.
      const incomplete = parseInt(row.total_incomplete, 10) || 0;
      completed   = Math.max(0, staff - incomplete);
      outstanding = incomplete;
    }

    let people = [];
    if (row.upload_type === 'history') {
      const r = await pool.query(
        `SELECT user_first_name, user_last_name, user_email,
                COUNT(*) FILTER (WHERE LOWER(status) LIKE '%complet%')::int AS completed,
                COUNT(*)::int AS assigned
           FROM awareness_sessions
          WHERE upload_id = $1
            AND (session_type IS NULL OR LOWER(session_type) NOT LIKE '%phishing simulation%')
          GROUP BY user_first_name, user_last_name, user_email
          -- The aggregate is REPEATED rather than referring to the "completed"
          -- output alias. Postgres accepts a bare alias in ORDER BY but not one
          -- inside an expression: dividing it sends the planner looking for a
          -- real column of that name, and it raises 42703 undefined_column.
          -- Least-covered staff first, so the people who need chasing lead.
          ORDER BY (COUNT(*) FILTER (WHERE LOWER(status) LIKE '%complet%'))::float
                   / NULLIF(COUNT(*), 0) ASC NULLS LAST
          LIMIT 500`,
        [row.id]
      );
      people = r.rows.map(p => ({
        name: [p.user_first_name, p.user_last_name].filter(Boolean).join(' ').trim() || p.user_email,
        email: p.user_email,
        completed: p.completed, assigned: p.assigned,
        pct: p.assigned ? Math.round((p.completed / p.assigned) * 100) : 0,
      }));
    } else if (row.upload_type !== 'manual') {
      const r = await pool.query(
        `SELECT user_first_name, user_last_name, user_email, incomplete_sessions
           FROM awareness_users WHERE upload_id = $1
          ORDER BY incomplete_sessions DESC LIMIT 500`,
        [row.id]
      );
      people = r.rows.map(p => ({
        name: [p.user_first_name, p.user_last_name].filter(Boolean).join(' ').trim() || p.user_email,
        email: p.user_email,
        outstanding: parseInt(p.incomplete_sessions, 10) || 0,
      }));
    }

    const assessed = completed + outstanding;

    return res.json({
      available: true,
      asOf: row.uploaded_at,
      totalStaff: staff,
      completed,
      outstanding,
      // The percentage is over whatever `unit` counts — sessions on a history
      // upload, people otherwise. The client is told which, so "78%" is never
      // silently a different measure from one month to the next.
      completionPct: assessed ? Math.round((completed / assessed) * 100) : 0,
      unit,
      assessed,
      // Manual figures are client-supplied and must not be presented as though
      // we verified them.
      selfReported: row.upload_type === 'manual',
      people,
    });
  }));
}

module.exports = {
  register,
  SEVERITY_RANK,
  CLOSED_STATUSES,
  titleCase,
  isClosed,
};
