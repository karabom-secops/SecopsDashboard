/* tab-mdr-pricing.js — MDR Pricing calculator */
const MdrPricingTab = (() => {
  'use strict';

  // Per-unit monthly rates (USD) — adjust to match current price book.
  const RATES = {
    perUser:   8,
    perServer: 25,
    perSite:   50,
    perSensor: 15,
    dataExplorer: 200, // flat add-on fee
  };

  const fields = {};
  let summaryEl = null;
  let bound = false;

  function fmt(n) {
    return '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function calculate() {
    const users   = Number(fields.users.value) || 0;
    const servers = Number(fields.servers.value) || 0;
    const sites   = Number(fields.sites.value) || 0;
    const sensors = Number(fields.sensors.value) || 0;
    const dataExplorer = fields.dataExplorer.checked;

    const usersCost   = users * RATES.perUser;
    const serversCost = servers * RATES.perServer;
    const sitesCost   = sites * RATES.perSite;
    const sensorsCost = sensors * RATES.perSensor;
    const dataExplorerCost = dataExplorer ? RATES.dataExplorer : 0;

    const total = usersCost + serversCost + sitesCost + sensorsCost + dataExplorerCost;

    summaryEl.innerHTML = `
      <div class="stat-card">
        <div class="stat-label">Users (${users} × ${fmt(RATES.perUser)})</div>
        <div class="stat-value">${fmt(usersCost)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Servers (${servers} × ${fmt(RATES.perServer)})</div>
        <div class="stat-value">${fmt(serversCost)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Sites (${sites} × ${fmt(RATES.perSite)})</div>
        <div class="stat-value">${fmt(sitesCost)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Sensors (${sensors} × ${fmt(RATES.perSensor)})</div>
        <div class="stat-value">${fmt(sensorsCost)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Data Explorer</div>
        <div class="stat-value">${dataExplorer ? fmt(dataExplorerCost) : '—'}</div>
      </div>
      <div class="stat-card accent-blue">
        <div class="stat-label">Estimated Monthly Total</div>
        <div class="stat-value">${fmt(total)}</div>
      </div>
    `;
  }

  function bindEvents() {
    if (bound) return;
    ['users', 'servers', 'sites', 'sensors'].forEach((key) => {
      fields[key].addEventListener('input', calculate);
    });
    fields.dataExplorer.addEventListener('change', calculate);
    bound = true;
  }

  function loadAndRender() {
    fields.users        = document.getElementById('mdrp-users');
    fields.servers      = document.getElementById('mdrp-servers');
    fields.sites         = document.getElementById('mdrp-sites');
    fields.sensors       = document.getElementById('mdrp-sensors');
    fields.dataExplorer  = document.getElementById('mdrp-data-explorer');
    summaryEl = document.getElementById('mdrp-summary');

    bindEvents();
    calculate();
  }

  return { loadAndRender };
})();

window.MdrPricingTab = MdrPricingTab;
