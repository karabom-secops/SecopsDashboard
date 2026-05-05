/* tab-orgs.js — renders the Organisations tab */

(function () {
  'use strict';

  let _orgs = [];
  let _sortKey = 'orgName';
  let _sortAsc  = true;

  // ── Public render function ─────────────────────────────────────────────────
  window.renderOrgs = function renderOrgs(weekData) {
    const orgs = weekData.orgs || [];

    // Enrich with escalationPct for sorting/display
    _orgs = orgs.map(o => ({
      ...o,
      escalationPct: o.alerts > 0 ? Math.round((o.escalated / o.alerts) * 100) : 0,
    }));

    renderStatCards(_orgs);
    renderTable();
    attachSortHandlers();
  };

  // ── Stat cards ─────────────────────────────────────────────────────────────
  function renderStatCards(orgs) {
    const totalOrgs     = orgs.length;
    const totalAlerts   = orgs.reduce((s, o) => s + (o.alerts || 0), 0);
    const totalEscalated = orgs.reduce((s, o) => s + (o.escalated || 0), 0);
    const noIRPlan      = orgs.filter(o => !o.irPlan).length;

    const container = document.getElementById('orgs-stat-cards');
    container.innerHTML = [
      statCard('Organisations', totalOrgs,     'accent-blue'),
      statCard('Total Alerts',  totalAlerts,   'accent-red'),
      statCard('Escalated',     totalEscalated,'accent-amber'),
      statCard('No IR Plan',    noIRPlan,      noIRPlan > 0 ? 'accent-red' : 'accent-green'),
    ].join('');
  }

  // ── Table rendering ────────────────────────────────────────────────────────
  function renderTable() {
    const sorted = sortOrgs(_orgs, _sortKey, _sortAsc);
    const tbody  = document.getElementById('orgs-tbody');
    tbody.innerHTML = '';

    if (sorted.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="6" style="text-align:center;color:var(--muted);padding:1.5rem">No org data available.</td>';
      tbody.appendChild(tr);
      return;
    }

    sorted.forEach(org => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escHtml(org.orgName)}</td>
        <td>${org.alerts}</td>
        <td class="${escalationClass(org.escalationPct)}">${org.escalated}</td>
        <td class="${escalationClass(org.escalationPct)}">${org.escalationPct}%</td>
        <td>${coverageCell(org.coverageScore)}</td>
        <td>${irBadge(org.irPlan)}</td>
      `;
      tbody.appendChild(tr);
    });

    updateSortArrows();
  }

  // ── Sort ──────────────────────────────────────────────────────────────────
  function attachSortHandlers() {
    const ths = document.querySelectorAll('#orgs-table th[data-sort]');
    ths.forEach(th => {
      // Remove old listeners by cloning
      const fresh = th.cloneNode(true);
      th.parentNode.replaceChild(fresh, th);
      fresh.addEventListener('click', () => {
        const key = fresh.dataset.sort;
        if (_sortKey === key) {
          _sortAsc = !_sortAsc;
        } else {
          _sortKey = key;
          _sortAsc = true;
        }
        renderTable();
        attachSortHandlers(); // re-bind since we replaced nodes
      });
    });
  }

  function sortOrgs(orgs, key, asc) {
    return [...orgs].sort((a, b) => {
      let va = a[key], vb = b[key];
      if (va === null || va === undefined) va = asc ? Infinity : -Infinity;
      if (vb === null || vb === undefined) vb = asc ? Infinity : -Infinity;
      if (typeof va === 'string') return asc ? va.localeCompare(vb) : vb.localeCompare(va);
      return asc ? va - vb : vb - va;
    });
  }

  function updateSortArrows() {
    document.querySelectorAll('#orgs-table th[data-sort]').forEach(th => {
      const arrow = th.querySelector('.sort-arrow');
      if (!arrow) return;
      if (th.dataset.sort === _sortKey) {
        arrow.textContent = _sortAsc ? ' ▲' : ' ▼';
      } else {
        arrow.textContent = '';
      }
    });
  }

  // ── Cell helpers ──────────────────────────────────────────────────────────
  function escalationClass(pct) {
    if (pct > 20) return 'esc-bad';
    if (pct > 10) return 'esc-warn';
    return '';
  }

  function coverageCell(score) {
    if (score === null || score === undefined) {
      return '<span style="color:var(--muted)">—</span>';
    }
    const cls = score < 75 ? 'cov-bad' : score < 90 ? 'cov-warn' : 'cov-good';
    const pct = Math.min(100, Math.max(0, score));
    return `
      <div class="coverage-cell">
        <div class="coverage-bar-bg">
          <div class="coverage-bar-fill ${cls}" style="width:${pct}%"></div>
        </div>
        <span class="${cls}">${score}%</span>
      </div>`;
  }

  function irBadge(hasIR) {
    return hasIR
      ? '<span class="ir-badge yes">Yes</span>'
      : '<span class="ir-badge no">No</span>';
  }

  // ── Generic stat card ─────────────────────────────────────────────────────
  function statCard(label, value, accent) {
    return `<div class="stat-card ${accent}">
      <span class="stat-label">${label}</span>
      <span class="stat-value">${value}</span>
    </div>`;
  }

  function escHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

})();
