/* app.js — core orchestration: week loading, tab switching, week selector */

(function () {
  'use strict';

  // Shared state
  window.currentWeekKey = null;
  window._summaryData = [];

  const weekSelect    = document.getElementById('weekSelect');
  const dashboard     = document.getElementById('dashboard');
  const tabPanels     = {
    priorities: document.getElementById('tab-priorities'),
    orgs:       document.getElementById('tab-orgs'),
    metrics:    document.getElementById('tab-metrics'),
    vulns:      document.getElementById('tab-vulns'),
    incidents:  document.getElementById('tab-incidents'),
    awareness:  document.getElementById('tab-awareness'),
    admin:      document.getElementById('tab-admin'),
  };

  // ── Sidebar navigation ────────────────────────────────────────────────────
  const sideNavItems = document.querySelectorAll('.side-nav-item');

  const TAB_LABELS = {
    priorities: 'Priorities',
    orgs:       'Arctic Wolf Health',
    metrics:    'Metrics & Trends',
    vulns:      'Vulnerabilities',
    awareness:  'Awareness',
    admin:      'Admin',
  };

  // ── Tab switching ──────────────────────────────────────────────────────────
  function switchTab(target) {
    // Update side nav active state
    sideNavItems.forEach(item => {
      item.classList.toggle('active', item.dataset.tab === target);
    });

    // Show/hide panels
    Object.entries(tabPanels).forEach(([key, panel]) => {
      if (panel) panel.hidden = key !== target;
    });

    // Lazy-render tabs that need it
    if (target === 'metrics' && window._summaryData.length && window.currentWeekKey) {
      const weekData = window._lastWeekData;
      if (weekData) renderMetrics(weekData, window._summaryData);
    }
    if (target === 'vulns') {
      renderVulns();
    }
    if (target === 'incidents' && typeof window.renderIncidents === 'function') {
      window.renderIncidents();
    }
    if (target === 'awareness' && typeof window.renderAwareness === 'function') {
      window.renderAwareness();
    }
    if (target === 'admin' && typeof window.renderAdmin === 'function') {
      window.renderAdmin();
    }
  }

  // Side nav items drive tab switching directly
  sideNavItems.forEach(item => {
    item.addEventListener('click', () => {
      switchTab(item.dataset.tab);
    });
  });

  // Expose so other modules can switch tabs programmatically
  window.switchTab = switchTab;

  // ── Week selector ──────────────────────────────────────────────────────────
  weekSelect.addEventListener('change', () => {
    const key = weekSelect.value;
    if (key) loadWeek(key);
  });

  // ── Populate week dropdown ─────────────────────────────────────────────────
  async function populateWeeks() {
    try {
      const res = await fetch('api/weeks');
      const weeks = await res.json();
      weekSelect.innerHTML = '<option value="">— Select week —</option>';
      weeks.forEach(w => {
        const opt = document.createElement('option');
        opt.value = w.key;
        opt.textContent = w.weekCommencing || w.key;
        weekSelect.appendChild(opt);
      });
      return weeks;
    } catch (_) {
      return [];
    }
  }

  // ── Load a week and render all tabs ───────────────────────────────────────
  window.loadWeek = async function loadWeek(weekKey) {
    window.currentWeekKey = weekKey;

    // Update selector to reflect the loaded week
    if (weekSelect.value !== weekKey) weekSelect.value = weekKey;

    // Fetch week data and metrics summary in parallel
    let weekData, summaryData;
    try {
      [weekData, summaryData] = await Promise.all([
        fetch(`api/week/${weekKey}`).then(r => r.json()),
        fetch('api/metrics/summary').then(r => r.json()),
      ]);
    } catch (err) {
      console.error('Failed to load week data:', err);
      return;
    }

    if (weekData.error) { console.error(weekData.error); return; }

    window._lastWeekData = weekData;
    window._summaryData  = summaryData;

    // Dynamic page title
    const wLabel = weekData.weekCommencing || weekKey;
    document.title = `SecOps — Week ${wLabel}`;

    // Ensure dashboard is visible
    dashboard.hidden = false;

    // Render all three tabs (metrics only if panel is visible to avoid 0-size canvas)
    renderPriorities(weekData);
    renderOrgs(weekData);

    const metricsPanel = tabPanels.metrics;
    if (!metricsPanel.hidden) {
      renderMetrics(weekData, summaryData);
    }

    const vulnsPanel = tabPanels.vulns;
    if (!vulnsPanel.hidden) {
      renderVulns();
    }

    const incidentsPanel = tabPanels.incidents;
    if (!incidentsPanel.hidden && typeof window.renderIncidents === 'function') {
      window.renderIncidents();
    }
  };

  // ── Refresh current week after a status PATCH ─────────────────────────────
  window.refreshCurrentWeek = async function refreshCurrentWeek() {
    if (!window.currentWeekKey) return;
    try {
      const [weekData, summaryData] = await Promise.all([
        fetch(`api/week/${window.currentWeekKey}`).then(r => r.json()),
        fetch('api/metrics/summary').then(r => r.json()),
      ]);
      window._lastWeekData = weekData;
      window._summaryData  = summaryData;
      renderPriorities(weekData);
      renderOrgs(weekData);
      if (!tabPanels.metrics.hidden) renderMetrics(weekData, summaryData);
      if (!tabPanels.vulns.hidden) renderVulns();
    } catch (err) {
      console.error('Refresh failed:', err);
    }
  };

  // ── Init ───────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', async () => {
    const weeks = await populateWeeks();

    // Check if redirected from upload page with a specific week/tab
    const params       = new URLSearchParams(location.search);
    const preselectKey = params.get('week');
    const tabParam     = params.get('tab');
    const monthParam   = params.get('month');

    // Clean the URL without reloading
    if (preselectKey || tabParam || monthParam) {
      history.replaceState(null, '', '/secops/');
    }

    if (preselectKey) {
      await loadWeek(preselectKey);

      // Switch to a specific tab if redirected from upload
      if (tabParam && tabPanels[tabParam]) {
        const targetBtn = document.querySelector(`.side-nav-item[data-tab="${tabParam}"]`);
        if (targetBtn) targetBtn.click();
      }
    } else if (tabParam === 'vulns') {
      // Redirect from Nessus upload — switch straight to vulns tab
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="vulns"]');
      if (targetBtn) targetBtn.click();
      if (monthParam) renderVulns(monthParam);
    } else if (tabParam === 'awareness') {
      // Redirect from awareness upload
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="awareness"]');
      if (targetBtn) targetBtn.click();
    } else if (tabParam === 'incidents') {
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="incidents"]');
      if (targetBtn) targetBtn.click();
    } else if (weeks.length > 0) {
      // Auto-load the most recent week (first in the list — sorted desc)
      await loadWeek(weeks[0].key);
    }
  });

})();
