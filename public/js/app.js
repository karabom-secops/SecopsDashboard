/* app.js — core orchestration: week loading, tab switching, week selector */

(function () {
  'use strict';

  // Shared state
  window.currentWeekKey = null;
  window._summaryData = [];

  const weekSelect    = document.getElementById('weekSelect');
  const dashboard     = document.getElementById('dashboard');
  const tabPanels     = {
    operations:   document.getElementById('tab-operations'),
    metrics:      document.getElementById('tab-metrics'),
    vulns:        document.getElementById('tab-vulns'),
    awareness:    document.getElementById('tab-awareness'),
    'secure-score': document.getElementById('tab-secure-score'),
    grc:          document.getElementById('tab-grc'),
    admin:        document.getElementById('tab-admin'),
  };

  // ── Sidebar navigation ────────────────────────────────────────────────────
  const sideNavItems = document.querySelectorAll('.side-nav-item');

  const TAB_LABELS = {
    operations: 'Operations',
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
    if (target === 'operations') {
      if (window._lastWeekData) {
        renderPriorities(window._lastWeekData, 'operations');
        renderOrgs(window._lastWeekData, 'operations');
      }
      if (typeof window.renderIncidents === 'function') {
        window.renderIncidents('operations').catch(() => {});
      }
      if (window.initCarousel) {
        if (window._operationsCarousel) {
          window._operationsCarousel.destroy();
          window._operationsCarousel = null;
        }
        setTimeout(() => {
          window._operationsCarousel = window.initCarousel('#operations-carousel');
        }, 50);
      }
    }
    if (target === 'awareness' && typeof window.renderAwareness === 'function') {
      window.renderAwareness();
    }
    if (target === 'secure-score' && typeof window.SecureScoreTab !== 'undefined') {
      window.SecureScoreTab.loadAndRender();
    }
    if (target === 'grc' && typeof window.GrcTab !== 'undefined') {
      window.GrcTab.loadAndRender();
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

    // Render the operations section and other visible tabs (metrics only if panel is visible to avoid 0-size canvas)
    const metricsPanel = tabPanels.metrics;
    if (!metricsPanel.hidden) {
      renderMetrics(weekData, summaryData);
    }

    const vulnsPanel = tabPanels.vulns;
    if (!vulnsPanel.hidden) {
      renderVulns();
    }

    const operationsPanel = tabPanels.operations;
    if (!operationsPanel.hidden) {
      renderPriorities(weekData, 'operations');
      renderOrgs(weekData, 'operations');
      if (typeof window.renderIncidents === 'function') {
        window.renderIncidents('operations').catch(() => {});
      }
      // Init carousel for default operations tab (switchTab is never called for the default tab)
      if (window.initCarousel && !window._operationsCarousel) {
        window._operationsCarousel = window.initCarousel('#operations-carousel');
      }
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
      if (!tabPanels.metrics.hidden) renderMetrics(weekData, summaryData);
      if (!tabPanels.vulns.hidden) renderVulns();
      if (!tabPanels.operations.hidden) {
             // Reinitialize carousel after data refresh
             if (!tabPanels.operations.hidden && window._operationsCarousel) {
               window._operationsCarousel.destroy();
               window._operationsCarousel = null;
             }
             if (!tabPanels.operations.hidden && window.initCarousel) {
               setTimeout(() => {
                 window._operationsCarousel = window.initCarousel('#operations-carousel');
               }, 100);
             }
        renderPriorities(weekData, 'operations');
        renderOrgs(weekData, 'operations');
        if (typeof window.renderIncidents === 'function') {
          window.renderIncidents('operations').catch(() => {});
        }
      }
    } catch (err) {
      console.error('Refresh failed:', err);
    }
  };

  // ── Init ───────────────────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', async () => {
    const weeks = await populateWeeks();

    // Check if redirected from upload page with a specific week/tab
    const params           = new URLSearchParams(location.search);
    const preselectKey     = params.get('week');
    const tabParam         = params.get('tab');
    const monthParam       = params.get('month');
    const autoClosedParam  = params.get('autoClosed');

    // Clean the URL without reloading
    if (preselectKey || tabParam || monthParam || autoClosedParam) {
      history.replaceState(null, '', '/secops/');
    }

    if (preselectKey) {
      await loadWeek(preselectKey);

      // Switch to a specific tab if redirected from upload
      if (tabParam && tabPanels[tabParam]) {
        const targetBtn = document.querySelector(`.side-nav-item[data-tab="${tabParam}"]`);
        if (targetBtn) targetBtn.click();
        if (autoClosedParam && tabParam === 'vulns') {
          const n = parseInt(autoClosedParam, 10);
          if (!isNaN(n) && n > 0 && typeof window.showVulnAutoClosedNotice === 'function') {
            window.showVulnAutoClosedNotice(`${n} previously identified finding${n !== 1 ? 's were' : ' was'} automatically marked fixed because they no longer appear in the uploaded scan.`);
          }
        }
      }
    } else if (tabParam === 'vulns') {
      // Redirect from Nessus upload — switch straight to vulns tab
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="vulns"]');
      if (targetBtn) targetBtn.click();
      if (monthParam) {
        renderVulns(monthParam);
        const n = parseInt(autoClosedParam || '0', 10);
        if (!isNaN(n) && n > 0 && typeof window.showVulnAutoClosedNotice === 'function') {
          window.showVulnAutoClosedNotice(`${n} previously identified finding${n !== 1 ? 's were' : ' was'} automatically marked fixed because they no longer appear in the uploaded scan.`);
        }
      }
    } else if (tabParam === 'awareness') {
      // Redirect from awareness upload
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="awareness"]');
      if (targetBtn) targetBtn.click();
    } else if (tabParam === 'operations') {
      if (weeks.length > 0) await loadWeek(weeks[0].key);
      const targetBtn = document.querySelector('.side-nav-item[data-tab="operations"]');
      if (targetBtn) targetBtn.click();
    } else if (weeks.length > 0) {
      // Auto-load the most recent week (first in the list — sorted desc)
      await loadWeek(weeks[0].key);
    }
  });

})();
