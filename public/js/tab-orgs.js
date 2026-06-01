/* tab-orgs.js — renders the Organisations tab */

(function () {
  'use strict';

  let _orgs = [];
  let _sortKey = 'orgName';
  let _sortAsc  = true;
  let _vulnSummary = null; // latest vuln summary per tenant (superadmin only)

  // ── Public render function ─────────────────────────────────────────────────
  window.renderOrgs = async function renderOrgs(weekData, section = '') {
    const orgs = weekData.orgs || [];

    // Enrich with escalationPct for sorting/display
    _orgs = orgs.map(o => ({
      ...o,
      escalationPct: o.alerts > 0 ? Math.round((o.escalated / o.alerts) * 100) : 0,
    }));

    // Superadmin: fetch latest vuln summary per tenant and show columns
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    _vulnSummary = null;
    if (isSA) {
      try {
        const res = await fetch('api/vulns/latest-summary');
        if (res.ok) {
          _vulnSummary = await res.json();
          // Merge vuln critical/high counts into orgs by normalising names
          _vulnSummary.forEach(vs => {
            if (!vs.summary) return;
            const tName = (vs.tenantName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
            const match = _orgs.find(o => {
              const oName = (o.orgName || '').toLowerCase().replace(/[^a-z0-9]/g, '');
              return oName === tName || oName.startsWith(tName) || tName.startsWith(oName);
            });
            if (match) {
              match.vulnCritical = vs.summary.critical || 0;
              match.vulnHigh     = vs.summary.high || 0;
            }
          });
        }
      } catch { /* non-fatal */ }
    }

    // Show/hide vuln columns header
    ['orgVulnCriticalTh', 'orgVulnHighTh'].forEach(id => {
      const el = document.getElementById(`${section ? section + '-' : ''}${id}`);
      if (el) el.hidden = !isSA;
    });

    renderStatCards(_orgs, section);
    renderCarousel(section);
    // Sorting still works in carousel rendering, but we don't attach handlers to hidden table
  };

  // ── Carousel rendering ─────────────────────────────────────────────────────
  function renderCarousel(section = '') {
    const prefix = section ? `${section}-` : '';
    const slidesContainer = document.getElementById(`${prefix}orgs-carousel-slides`);
    const controlsContainer = document.getElementById(`${prefix}orgs-carousel-controls`);
    
    if (!slidesContainer || !controlsContainer) return;

    const sorted = sortOrgs(_orgs, _sortKey, _sortAsc);
    slidesContainer.innerHTML = '';
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';

    if (sorted.length === 0) {
      const slide = document.createElement('div');
      slide.className = 'carousel-slide';
      slide.innerHTML = '<p style="color:var(--muted);font-size:.87rem;padding:1rem">No org data available.</p>';
      slidesContainer.appendChild(slide);
    } else {
      sorted.forEach(org => {
        const slide = document.createElement('div');
        slide.className = 'carousel-slide';
        const vulnHtml = isSA ? `
          <div>
            <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Crit Vulns</div>
            <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.vulnCritical != null ? org.vulnCritical : '—'}</div>
          </div>
          <div>
            <div style="color:var(--muted);font-size:0.8rem;font-weight:600">High Vulns</div>
            <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.vulnHigh != null ? org.vulnHigh : '—'}</div>
          </div>
        ` : '';
        slide.innerHTML = `
          <div style="display:grid;grid-template-columns:repeat(${isSA ? 4 : 3},1fr);gap:1rem;font-size:0.9rem">
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Org Name</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500;max-width:150px;word-wrap:break-word">${escHtml(org.orgName)}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Alerts</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.alerts}</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Escalated</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.escalated} (${org.escalationPct}%)</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">Coverage</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.coverageScore}%</div>
            </div>
            <div>
              <div style="color:var(--muted);font-size:0.8rem;font-weight:600">IR Plan</div>
              <div style="margin-top:0.25rem;color:var(--text);font-weight:500">${org.irPlan ? 'Yes' : 'No'}</div>
            </div>
            ${vulnHtml}
          </div>
        `;
        slidesContainer.appendChild(slide);
      });
    }

    // Initialize or reinitialize carousel
    if (window._orgsCarousel) {
      window._orgsCarousel.destroy();
    }
    window._orgsCarousel = window.initCarousel(`#${prefix}orgs-carousel`);
    updateSortArrows(section);

  // ── Stat cards ─────────────────────────────────────────────────────────────
  function renderStatCards(orgs, section = '') {
    const totalOrgs      = orgs.length;
    const totalAlerts    = orgs.reduce((s, o) => s + (o.alerts || 0), 0);
    const totalEscalated = orgs.reduce((s, o) => s + (o.escalated || 0), 0);
    const noIRPlan       = orgs.filter(o => !o.irPlan).length;

    const container = document.getElementById(`${section ? section + '-' : ''}orgs-stat-cards`);
    if (!container) return;
    container.innerHTML = [
      statCard('Organisations', totalOrgs,     'accent-blue'),
      statCard('Total Alerts',  totalAlerts,   'accent-red'),
      statCard('Escalated',     totalEscalated,'accent-amber'),
      statCard('No IR Plan',    noIRPlan,      noIRPlan > 0 ? 'accent-red' : 'accent-green'),
    ].join('');
  }

  // ── Table rendering ────────────────────────────────────────────────────────
  function renderTable(section = '') {
    const sorted = sortOrgs(_orgs, _sortKey, _sortAsc);
    const tbody  = document.getElementById(`${section ? section + '-' : ''}orgs-tbody`);
    if (!tbody) return;
    tbody.innerHTML = '';
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';

    if (sorted.length === 0) {
      const tr = document.createElement('tr');
      tr.innerHTML = `<td colspan="${isSA ? 8 : 6}" style="text-align:center;color:var(--muted);padding:1.5rem">No org data available.</td>`;
      tbody.appendChild(tr);
      return;
    }

    sorted.forEach(org => {
      const tr = document.createElement('tr');
      const vulnCols = isSA ? `
        <td class="${(org.vulnCritical || 0) > 0 ? 'esc-bad' : ''}">${org.vulnCritical != null ? org.vulnCritical : '<span style="color:var(--muted)">—</span>'}</td>
        <td class="${(org.vulnHigh || 0) > 0 ? 'esc-warn' : ''}">${org.vulnHigh != null ? org.vulnHigh : '<span style="color:var(--muted)">—</span>'}</td>
      ` : '';
      tr.innerHTML = `
        <td>${escHtml(org.orgName)}</td>
        <td>${org.alerts}</td>
        <td class="${escalationClass(org.escalationPct)}">${org.escalated}</td>
        <td class="${escalationClass(org.escalationPct)}">${org.escalationPct}%</td>
        <td>${coverageCell(org.coverageScore)}</td>
        <td>${irBadge(org.irPlan)}</td>
        ${vulnCols}
      `;
      tbody.appendChild(tr);
    });

    updateSortArrows(section);
  }

  // ── Sort ──────────────────────────────────────────────────────────────────
  function attachSortHandlers(section = '') {
    const ths = document.querySelectorAll(`#${section ? section + '-' : ''}orgs-table th[data-sort]`);
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
        renderTable(section);
        attachSortHandlers(section); // re-bind since we replaced nodes
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

  function updateSortArrows(section = '') {
    document.querySelectorAll(`#${section ? section + '-' : ''}orgs-table th[data-sort]`).forEach(th => {
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
