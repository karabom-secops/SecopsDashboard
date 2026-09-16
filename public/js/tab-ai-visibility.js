/* tab-ai-visibility.js — AI Visibility: generative AI use seen in DNSFilter.

   Four independent panels (usage, tools, users, policy), each rendering or
   explaining itself, on the same envelope contract as Managed NDR and Identity.

   The tools table is also where the sanctioned-app register is kept. A tool
   nobody has decided on is UNREVIEWED — never shown as sanctioned — and allowed
   traffic to a tool marked unsanctioned is flagged as shadow AI.

   Staff only. This tab names users; nothing here has a portal route. */
const AiVisibilityTab = (() => {
  'use strict';

  const U = window.WazuhUI;
  const charts = {};
  let bound   = false;
  let summary = null;

  const STATUS = {
    unreviewed:   { label: 'Unreviewed',   badge: 'badge-muted' },
    sanctioned:   { label: 'Sanctioned',   badge: 'badge-green' },
    unsanctioned: { label: 'Unsanctioned', badge: 'badge-red' },
    under_review: { label: 'Under review', badge: 'badge-amber' },
  };

  function selectedDays() {
    const sel = document.getElementById('ai-range');
    return sel ? sel.value : '30';
  }

  function canDecide(s) {
    return !!(s && s.decisionsAvailable) &&
      typeof window.canWrite === 'function' && window.canWrite('ai-visibility');
  }

  // ── Stats ────────────────────────────────────────────────────────────────

  function renderStats(s) {
    const u = U.isReady(s.usage) ? s.usage.data : null;
    const a = U.isReady(s.apps)  ? s.apps.data  : null;
    const dash = '—';
    const total = u ? u.allowed + u.blocked : null;
    const blockedPct = u ? U.pct(u.blocked, total) : null;

    U.renderStats('ai-stats', [
      { label: `AI Lookups (${s.windowDays}d)`, value: u ? U.fmtNum(total) : dash, accent: 'blue' },
      { label: 'Blocked',          value: blockedPct === null ? dash : blockedPct + '%', accent: 'green' },
      // Null when the all-traffic denominator is missing for any day — a share
      // over part of the period is not the share.
      { label: 'Share of All DNS', value: u && u.sharePct != null ? u.sharePct + '%' : dash, accent: 'amber' },
      { label: 'AI Tools Seen',    value: a ? U.fmtNum(a.rows.length) : dash, accent: 'blue' },
      { label: 'Shadow AI Tools',  value: a ? U.fmtNum(a.shadowCount) : dash, accent: a && a.shadowCount > 0 ? 'red' : 'green' },
      { label: 'Unreviewed Tools', value: a ? U.fmtNum(a.unreviewedCount) : dash, accent: a && a.unreviewedCount > 0 ? 'amber' : 'green' },
    ]);
  }

  // ── Panels ───────────────────────────────────────────────────────────────

  function renderTrend(s) {
    U.panel('ai-trend-panel', s.usage, (d) => {
      U.lineChart(charts, 'trend', 'ai-trend-chart', d.trend, [
        { label: 'Allowed', field: 'allowed', color: U.COLORS.amber, fill: true, fillColor: 'rgba(245,158,11,.12)' },
        { label: 'Blocked', field: 'blocked', color: U.COLORS.green },
      ]);
    });
  }

  function statusCell(r, editable) {
    const st = STATUS[r.status] || STATUS.unreviewed;
    if (!editable) {
      return `<span class="badge ${st.badge}" title="${U.esc(r.note || '')}">${U.esc(st.label)}</span>`;
    }
    const opts = Object.keys(STATUS).map(k =>
      `<option value="${k}" ${k === r.status ? 'selected' : ''}>${U.esc(STATUS[k].label)}</option>`).join('');
    return `<select class="form-input ai-decision" style="min-width:9rem"
              data-key="${U.esc(r.key)}" data-name="${U.esc(r.name)}"
              aria-label="Decision for ${U.esc(r.name)}">${opts}</select>`;
  }

  function renderApps(s) {
    const editable = canDecide(s);
    U.panel('ai-apps-panel', s.apps, (d) => {
      U.fillTable('ai-apps-table', d.rows, 5, r => `
        <tr>
          <td>${U.esc(r.name)}${r.mapped ? '' : ' <span class="edr-muted">(domain)</span>'}${r.shadow ? ' <span class="badge badge-red">Shadow AI</span>' : ''}</td>
          <td>${statusCell(r, editable)}</td>
          <td>${U.fmtNum(r.allowed + r.blocked)}</td>
          <td class="${r.shadow ? 'edr-tone-red' : ''}">${U.fmtNum(r.allowed)}</td>
          <td class="edr-tone-green">${U.fmtNum(r.blocked)}</td>
        </tr>`);
    });
  }

  function renderUsers(s) {
    U.panel('ai-users-panel', s.users, (d) => {
      U.fillTable('ai-users-table', d.rows, 3, r => `
        <tr>
          <td>${U.esc(r.user)}</td>
          <td>${U.fmtNum(r.count)}</td>
          <td>${U.esc((r.apps || []).map(a => a.name).join(', ') || '—')}</td>
        </tr>`);
    });
  }

  function renderPolicy(s) {
    U.panel('ai-policy-panel', s.policy, (d) => {
      U.fillTable('ai-policy-table', d.rows, 3, (r) => {
        const state = r.aiBlocked === null
          ? '<span class="badge badge-muted">Unknown</span>'
          : r.aiBlocked ? '<span class="badge badge-green">Blocked</span>'
                        : '<span class="badge badge-amber">Allowed</span>';
        return `<tr><td>${U.esc(r.name)}</td><td>${state}</td><td>${r.allowListOnly ? 'Allow-list only' : '—'}</td></tr>`;
      });
    });
  }

  function renderNotes(s) {
    U.renderSourceNote('ai-source-note', s);
    const note = document.getElementById('ai-source-note');
    if (!note) return;
    const extra = [];
    const u = U.isReady(s.usage) ? s.usage.data : null;
    if (u && u.sharePct == null && u.totalReason) {
      extra.push('The share of all DNS is not shown: the all-traffic total was not read for every day in the period.');
    }
    if (U.isReady(s.apps) && s.apps.data.sampled) extra.push('On busy days only the top AI domains were read.');
    if (U.isReady(s.users) && s.users.data.sampled) extra.push('Users are limited to the 50 most active per day.');
    ['usage', 'apps', 'users', 'policy'].forEach((k) => {
      const d = U.isReady(s[k]) ? s[k].data : null;
      if (d && d.unavailableOnSomeDays) {
        // The detail is the DNSFilter error itself. It is what turns "some days
        // could not be read" into something an operator can act on.
        extra.push(`Some days' ${k} could not be read (${U.reasonText(d.unavailableOnSomeDays)})` +
          (d.unavailableDetail ? ` ${d.unavailableDetail}` : ''));
      }
    });
    if (U.isReady(s.policy) && s.policy.data.asOf) extra.push(`Policy as read on ${s.policy.data.asOf}.`);
    if (!s.decisionsAvailable) extra.push('The sanctioned-app register is not set up yet (db/migrate-ai-visibility.sql).');
    if (extra.length) note.textContent += ' ' + extra.join(' ');
  }

  // ── Decisions ────────────────────────────────────────────────────────────

  async function saveDecision(sel) {
    const meta = document.getElementById('ai-sync-meta');
    const url = 'api/ai-visibility/decisions/' + encodeURIComponent(sel.dataset.key);
    sel.disabled = true;
    try {
      const res = sel.value === 'unreviewed'
        ? await fetch(url + U.tenantQS(), { method: 'DELETE', credentials: 'same-origin' })
        : await fetch(url, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(Object.assign({ status: sel.value, appName: sel.dataset.name }, U.tenantBody())),
        });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${U.esc(d.error || 'Could not save the decision.')}`;
        sel.disabled = false;
        return;
      }
    } catch (err) {
      if (meta) meta.innerHTML = `<span class="edr-tone-red">✗</span> ${U.esc(err.message)}`;
      sel.disabled = false;
      return;
    }
    await loadAndRender();
  }

  // ── Load ─────────────────────────────────────────────────────────────────

  async function loadAndRender() {
    let s = null;
    try {
      const res = await fetch('api/ai-visibility/summary' + U.tenantQS({ days: selectedDays() }), { credentials: 'same-origin' });
      s = res.ok ? await res.json() : null;
    } catch (err) {
      console.error('AI Visibility load failed:', err);
      s = null;
    }

    const empty   = document.getElementById('ai-empty');
    const content = document.getElementById('ai-content');

    if (!s || !s.configured) {
      U.renderEmptyState('ai-empty', s, 'the client\'s DNSFilter organisation id is set and verified with Test Connection');
      if (empty)   empty.hidden = false;
      if (content) content.hidden = true;
      U.renderSyncMeta('ai-sync-meta', s && s.sync);
      summary = null;
      return;
    }

    if (empty)   empty.hidden = true;
    if (content) content.hidden = false;

    summary = s;
    renderStats(s);
    renderTrend(s);
    renderApps(s);
    renderUsers(s);
    renderPolicy(s);
    U.renderSyncMeta('ai-sync-meta', s.sync);
    renderNotes(s);
  }

  function bind() {
    if (bound) return;
    bound = true;

    const range = document.getElementById('ai-range');
    if (range) range.addEventListener('change', () => loadAndRender());

    const refresh = document.getElementById('ai-refresh-btn');
    if (refresh) refresh.addEventListener('click', () => loadAndRender());

    const sync = document.getElementById('ai-sync-btn');
    if (sync) sync.addEventListener('click', () => U.syncNow('ai-sync-btn', 'ai-sync-meta', loadAndRender, 'dnsfilter'));

    // Delegated: the table body is re-rendered on every load.
    const apps = document.getElementById('ai-apps-panel');
    if (apps) {
      apps.addEventListener('change', (e) => {
        const sel = e.target && e.target.closest && e.target.closest('select.ai-decision');
        if (sel) saveDecision(sel);
      });
    }
  }

  return {
    loadAndRender: async () => { bind(); await loadAndRender(); },
    getSummary:    () => summary,
    STATUS,
  };
})();

window.AiVisibilityTab = AiVisibilityTab;
