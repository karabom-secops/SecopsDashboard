/* tab-pricing.js — the Pricing page shell: a sub-tab bar over two calculators.
   MDR (tab-mdr-pricing.js) and vISO (tab-viso-pricing.js) each own their pane;
   this file only decides which one is showing. */
const PricingTab = (() => {
  'use strict';

  /*
   * The page key is still `mdr-pricing` (lib/pages.js), because per-user page
   * grants are stored against it — renaming the key would silently revoke the
   * Pricing page from everyone who has it. Only the label changed.
   */
  const SUBTABS = [
    { key: 'mdr',  label: 'MDR' },
    { key: 'viso', label: 'vISO' },
  ];
  const STORAGE_KEY = 'pricingSubtab';

  let active = null;
  let built = false;

  function remembered() {
    try {
      const v = localStorage.getItem(STORAGE_KEY);
      return SUBTABS.some(t => t.key === v) ? v : null;
    } catch (_) { return null; }
  }

  function build() {
    const bar = document.getElementById('pricingSubtabs');
    if (!bar || built) return;

    // Same markup and classes as the Admin sub-tab bar (tab-admin.js), so the
    // two read as one pattern.
    bar.innerHTML = SUBTABS.map(t =>
      `<button type="button" class="pricing-subtab" role="tab" id="pricingSubtab-${t.key}"` +
      ` data-subtab="${t.key}" aria-controls="pricingPane-${t.key}" aria-selected="false"` +
      ` tabindex="-1">${t.label}</button>`
    ).join('');

    bar.addEventListener('click', (e) => {
      const b = e.target.closest('[data-subtab]');
      if (b) show(b.dataset.subtab);
    });

    // Arrow keys move between sub-tabs, as a tablist is expected to.
    bar.addEventListener('keydown', (e) => {
      if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
      const i = SUBTABS.findIndex(t => t.key === active);
      const next = SUBTABS[(i + (e.key === 'ArrowRight' ? 1 : SUBTABS.length - 1)) % SUBTABS.length];
      show(next.key);
      const btn = document.getElementById('pricingSubtab-' + next.key);
      if (btn) btn.focus();
      e.preventDefault();
    });

    built = true;
  }

  function show(key) {
    active = SUBTABS.some(t => t.key === key) ? key : SUBTABS[0].key;
    try { localStorage.setItem(STORAGE_KEY, active); } catch (_) { /* non-critical */ }

    SUBTABS.forEach((t) => {
      const on = t.key === active;
      const pane = document.getElementById('pricingPane-' + t.key);
      if (pane) pane.hidden = !on;
      const btn = document.getElementById('pricingSubtab-' + t.key);
      if (btn) {
        btn.classList.toggle('is-on', on);
        btn.setAttribute('aria-selected', String(on));
        btn.setAttribute('tabindex', on ? '0' : '-1');
      }
    });

    // Render on open. Each calculator binds once and recalculates after that.
    if (active === 'mdr' && window.MdrPricingTab) window.MdrPricingTab.loadAndRender();
    if (active === 'viso' && window.VisoPricingTab) window.VisoPricingTab.loadAndRender();
  }

  function loadAndRender() {
    build();
    show(active || remembered() || SUBTABS[0].key);
  }

  return { loadAndRender, SUBTABS };
})();

window.PricingTab = PricingTab;
