/* app.js — core orchestration: week loading, tab switching, week selector */

(function () {
  'use strict';

  // Shared state
  window.currentWeekKey = null;

  const dashboard     = document.getElementById('dashboard');
  const tabPanels     = {
    operations:   document.getElementById('tab-operations'),
    redteam:      document.getElementById('tab-redteam'),
    vulns:        document.getElementById('tab-vulns'),
    awareness:    document.getElementById('tab-awareness'),
    'incident-response': document.getElementById('tab-incident-response'),
    grc:          document.getElementById('tab-grc'),
    'risk-register': document.getElementById('tab-risk-register'),
    'third-party-risk': document.getElementById('tab-third-party-risk'),
    'remediation-tracker': document.getElementById('tab-remediation-tracker'),
    'secure-score': document.getElementById('tab-secure-score'),
    edr:          document.getElementById('tab-edr'),
    ndr:          document.getElementById('tab-ndr'),
    o365:         document.getElementById('tab-o365'),
    'mdr-pricing': document.getElementById('tab-mdr-pricing'),
    reports:      document.getElementById('tab-reports'),
    'client-profile': document.getElementById('tab-client-profile'),
    admin:        document.getElementById('tab-admin'),
  };

  // ── Sidebar navigation ────────────────────────────────────────────────────
  // Nav clicks, the active-item marking and the category accordion all live in
  // sidenav.js, which delegates on `document` — so it reaches the cloned items
  // inside a rail flyout as well as the real ones. Caching a NodeList here
  // would snapshot the DOM at parse time and miss those clones entirely.

  const TAB_LABELS = {
    operations: 'Operations',
    redteam:    'Red Team',
    vulns:      'Vulnerabilities',
    awareness:  'Awareness',
    'incident-response': 'Incident Response',
    grc:        'GRC',
    'risk-register': 'Risk Register',
    'third-party-risk': 'Third-Party Risk',
    'remediation-tracker': 'Remediation Tracker',
    'secure-score': 'Secure Score',
    edr:        'Managed EDR',
    ndr:        'Managed NDR',
    o365:       'Managed Identity',
    'mdr-pricing': 'MDR Pricing',
    reports:    'Reports',
    'client-profile': 'Client Profile',
    admin:      'Admin',
  };

  // ── Tab switching ──────────────────────────────────────────────────────────
  function switchTab(target) {
    // Access check first — switchTab is exposed on window, so this is the only
    // thing stopping someone navigating to a tab they have no access to.
    if (typeof window.canView === 'function' && !window.canView(target)) {
      return;
    }

    // Mark the active item (real + flyout clones) and open its category.
    if (window.SideNav) window.SideNav.syncActive(target);

    // Show/hide panels
    Object.entries(tabPanels).forEach(([key, panel]) => {
      if (panel) panel.hidden = key !== target;
    });

    // The sidebar is the usual "where am I", but it shrinks to icons or
    // disappears entirely — so the header carries the name in those modes.
    const label = document.getElementById('currentTabLabel');
    if (label) label.textContent = TAB_LABELS[target] || '';
    document.title = (TAB_LABELS[target] ? TAB_LABELS[target] + ' · ' : '') + 'SecOps Dashboard';

    window.currentTab = target;
    renderTab(target);
  }

  /**
   * Run a tab's renderer. Split out of switchTab so the same dispatch serves
   * both "the user opened this tab" and "the data underneath it changed" —
   * notably a superadmin switching organisation, which must not leave one
   * tenant's numbers on screen labelled as another's.
   */
  function renderTab(target) {
    // Lazy-render tabs that need it
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
    // Re-reads on every switch, including a superadmin changing organisation —
    // a profile left on screen labelled as the wrong client would be worse here
    // than anywhere else on the dashboard, because it is editable.
    if (target === 'client-profile' && typeof window.ClientProfileTab !== 'undefined') {
      window.ClientProfileTab.loadAndRender();
    }
    if (target === 'grc' && typeof window.GrcTab !== 'undefined') {
      window.GrcTab.loadAndRender();
    }
    if (target === 'redteam' && typeof window.RedteamTab !== 'undefined') {
      window.RedteamTab.loadAndRender();
    }
    if (target === 'incident-response' && typeof window.IrTab !== 'undefined') {
      window.IrTab.loadAndRender();
    }
    if (target === 'risk-register' && typeof window.RiskRegisterTab !== 'undefined') {
      window.RiskRegisterTab.loadAndRender();
    }
    if (target === 'third-party-risk' && typeof window.ThirdPartyRiskTab !== 'undefined') {
      window.ThirdPartyRiskTab.loadAndRender();
    }
    if (target === 'remediation-tracker' && typeof window.RemediationTrackerTab !== 'undefined') {
      window.RemediationTrackerTab.loadAndRender();
    }
    if (target === 'edr' && typeof window.EdrTab !== 'undefined') {
      window.EdrTab.loadAndRender();
    }
    if (target === 'ndr' && typeof window.NdrTab !== 'undefined') {
      window.NdrTab.loadAndRender();
    }
    if (target === 'o365' && typeof window.O365Tab !== 'undefined') {
      window.O365Tab.loadAndRender();
    }
    if (target === 'mdr-pricing' && typeof window.MdrPricingTab !== 'undefined') {
      window.MdrPricingTab.loadAndRender();
    }
    if (target === 'reports' && typeof window.ReportsTab !== 'undefined') {
      window.ReportsTab.loadAndRender();
    }
    if (target === 'admin' && typeof window.renderAdmin === 'function') {
      window.renderAdmin();
    }
  }

  /* A superadmin changed the Organisation selector. Re-render whatever is on
     screen: almost every tab is tenant-scoped, and showing one customer's
     figures under another customer's name is worse than showing nothing.
     Routing through renderTab means a tab added later is covered automatically
     — the previous version named two tabs explicitly and silently went stale
     for the other fourteen. */
  document.addEventListener('tenant:changed', () => {
    if (window.currentTab) renderTab(window.currentTab);
  });

  // ── Manager Dashboard button ─────────────────────────────────────────────
  const managerDashboardBtn = document.getElementById('managerDashboardBtn');
  if (managerDashboardBtn) {
    managerDashboardBtn.addEventListener('click', () => {
      if (!window.canView('manager')) {
        alert('You do not have permission to access the Manager Dashboard.');
        return;
      }
      location.href = 'manager.html';
    });
  }

  // Expose so other modules can switch tabs programmatically. sidenav.js calls
  // through this too — its delegated click handler is what drives the nav.
  window.switchTab = switchTab;

  // ── Fetch the list of available weeks ────────────────────────────────────
  async function populateWeeks() {
    try {
      const res = await fetch('api/weeks');
      return await res.json();
    } catch (_) {
      return [];
    }
  }

  // ── Load a week and render all tabs ───────────────────────────────────────
  window.loadWeek = async function loadWeek(weekKey) {
    window.currentWeekKey = weekKey;

    let weekData;
    try {
      weekData = await fetch(`api/week/${weekKey}`).then(r => r.json());
    } catch (err) {
      console.error('Failed to load week data:', err);
      return;
    }

    if (weekData.error) { console.error(weekData.error); return; }

    window._lastWeekData = weekData;

    // Dynamic page title
    const wLabel = weekData.weekCommencing || weekKey;
    document.title = `SecOps — Week ${wLabel}`;

    // Ensure dashboard is visible
    dashboard.hidden = false;

    // Render the operations section and any other visible tab.
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
      const weekData = await fetch(`api/week/${window.currentWeekKey}`).then(r => r.json());
      window._lastWeekData = weekData;
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

  // auth.js resolves GET /api/auth/me asynchronously; nothing here may run
  // until window.canView is answering from the real access map.
  function whenAuthReady() {
    if (window.currentUser) return Promise.resolve();
    return new Promise(resolve => {
      document.addEventListener('authReady', () => resolve(), { once: true });
    });
  }

  // Operations is the default landing tab. If the user has no access to it,
  // fall back to the first tab the side nav is actually showing them —
  // SideNav.firstVisibleTab() walks the categories in order and then the
  // pinned footer, so an admin-only user still lands somewhere.
  function selectDefaultTab() {
    if (window.canView('operations')) {
      switchTab('operations');
      return 'operations';
    }

    const firstAllowed = window.SideNav
      ? window.SideNav.firstVisibleTab()
      : Array.from(document.querySelectorAll('.side-nav-item[data-tab]'))
          .map(item => item.dataset.tab)
          .find(key => key && window.canView(key));

    Object.values(tabPanels).forEach(panel => { if (panel) panel.hidden = true; });

    if (firstAllowed) switchTab(firstAllowed);
    return firstAllowed || null;
  }

  document.addEventListener('DOMContentLoaded', async () => {
    await whenAuthReady();
    selectDefaultTab();

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
