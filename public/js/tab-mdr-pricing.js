/* tab-mdr-pricing.js — MDR Pricing calculator */
const MdrPricingTab = (() => {
  'use strict';

  const STORAGE_KEY = 'mdrPricingRates';

  // Default annual unit cost ($) per line item — used until the user overrides them.
  const DEFAULT_RATES = {
    mdrUser:      61.44,
    mdrServer:    61.44,
    o365:         22.56,
    incident:     670.00,
    dataExplorer: 13.68,
    platform:     15.00,
    logRetention: 0.00,
    sensor:       712.52,
    physicalSensor: 2171.00,
    awareness:    20.38,
  };

  // Line item definitions: qty(state) resolves how many units are billed.
  const LINE_ITEMS = [
    { key: 'mdrUser',      label: 'MDR Connect User',                qty: (s) => s.users },
    { key: 'mdrServer',    label: 'MDR Connect Server',               qty: (s) => s.servers },
    { key: 'o365',         label: 'O365',                             qty: (s) => s.users },
    { key: 'incident',     label: 'Incident Response',                qty: (s) => (s.incidentResponse ? 1 : 0) },
    { key: 'dataExplorer', label: 'Data Explorer',                    qty: (s) => (s.dataExplorer ? s.users + s.servers : 0) },
    { key: 'platform',     label: 'Platform',                         qty: (s) => s.users + s.servers },
    { key: 'logRetention', label: '90 Day Log Retention',             qty: (s) => s.users + s.servers },
    { key: 'sensor',       label: 'Virtual 100 Series Sensor (Optional)', qty: (s) => (s.sensor ? s.sensors : 0) },
    { key: 'physicalSensor', label: 'Physical Sensor (Optional)',     qty: (s) => (s.physicalSensor ? s.sensors : 0) },
    { key: 'awareness',    label: 'Managed Security Awareness Plus',  qty: (s) => (s.awareness ? s.users : 0) },
  ];

  const fields = {};
  const rateInputs = {};
  let tableBody = null;
  let summaryEl = null;
  let resetBtn = null;
  let bound = false;

  function fmtUsd(n) {
    return '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }

  function fmtZar(n) {
    return 'R' + n.toLocaleString('en-US', { minimumFractionDigits: 0, maximumFractionDigits: 0 });
  }

  function loadRates() {
    try {
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (stored && typeof stored === 'object') {
        return Object.assign({}, DEFAULT_RATES, stored);
      }
    } catch (_) { /* ignore malformed storage */ }
    return Object.assign({}, DEFAULT_RATES);
  }

  function saveRates(rates) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(rates));
    } catch (_) { /* storage unavailable — non-critical */ }
  }

  function getState() {
    return {
      users:            Number(fields.users.value) || 0,
      servers:          Number(fields.servers.value) || 0,
      sites:            Number(fields.sites.value) || 0,
      sensors:          Number(fields.sensors.value) || 0,
      dataExplorer:     fields.dataExplorer.checked,
      incidentResponse: fields.incidentResponse.checked,
      sensor:           fields.sensor.checked,
      physicalSensor:   fields.physicalSensor.checked,
      awareness:        fields.awareness.checked,
    };
  }

  function renderTable() {
    tableBody.innerHTML = LINE_ITEMS.map((item) => `
      <tr>
        <td>${item.label}</td>
        <td data-qty-for="${item.key}">0</td>
        <td>
          <input class="form-input mdrp-rate-input" data-rate-key="${item.key}"
                 type="number" min="0" step="0.01" style="max-width:120px;">
        </td>
        <td data-annual-for="${item.key}">$0.00</td>
      </tr>
    `).join('');

    LINE_ITEMS.forEach((item) => {
      rateInputs[item.key] = tableBody.querySelector(`[data-rate-key="${item.key}"]`);
    });
  }

  function applyRatesToInputs(rates) {
    LINE_ITEMS.forEach((item) => {
      rateInputs[item.key].value = rates[item.key];
    });
  }

  function getRatesFromInputs() {
    const rates = {};
    LINE_ITEMS.forEach((item) => {
      rates[item.key] = Number(rateInputs[item.key].value) || 0;
    });
    return rates;
  }

  function calculate() {
    const rates = getRatesFromInputs();
    saveRates(rates);

    const state = getState();
    let totalCost = 0;

    LINE_ITEMS.forEach((item) => {
      const qty = item.qty(state);
      const annual = qty * rates[item.key];
      totalCost += annual;
      tableBody.querySelector(`[data-qty-for="${item.key}"]`).textContent = qty;
      tableBody.querySelector(`[data-annual-for="${item.key}"]`).textContent = fmtUsd(annual);
    });

    const margin = Number(fields.margin.value) || 0;
    const discount = Number(fields.discount.value) || 0;
    const roe = Number(fields.roe.value) || 0;

    const sellPrice = totalCost * (1 + margin / 100);
    const discountAmount = sellPrice * (discount / 100);
    const finalTotalUsd = sellPrice - discountAmount;
    const finalTotalZar = finalTotalUsd * roe;
    const finalMonthlyUsd = finalTotalUsd / 12;
    const finalMonthlyZar = finalTotalZar / 12;

    summaryEl.innerHTML = `
      <div class="stat-card">
        <div class="stat-label">Total Cost (Annual)</div>
        <div class="stat-value">${fmtUsd(totalCost)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Sell Price (+${margin}% margin)</div>
        <div class="stat-value">${fmtUsd(sellPrice)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Discount (${discount}%)</div>
        <div class="stat-value">-${fmtUsd(discountAmount)}</div>
      </div>
      <div class="stat-card accent-blue">
        <div class="stat-label">Final Annual Total (USD)</div>
        <div class="stat-value">${fmtUsd(finalTotalUsd)}</div>
      </div>
      <div class="stat-card accent-blue">
        <div class="stat-label">Final Annual Total (ZAR)</div>
        <div class="stat-value">${fmtZar(finalTotalZar)}</div>
      </div>
      <div class="stat-card accent-green">
        <div class="stat-label">Final Monthly Total (USD)</div>
        <div class="stat-value">${fmtUsd(finalMonthlyUsd)}</div>
      </div>
      <div class="stat-card accent-green">
        <div class="stat-label">Final Monthly Total (ZAR)</div>
        <div class="stat-value">${fmtZar(finalMonthlyZar)}</div>
      </div>
    `;
  }

  function bindEvents() {
    if (bound) return;
    ['users', 'servers', 'sites', 'sensors', 'margin', 'discount', 'roe'].forEach((key) => {
      fields[key].addEventListener('input', calculate);
    });
    ['dataExplorer', 'incidentResponse', 'sensor', 'physicalSensor', 'awareness'].forEach((key) => {
      fields[key].addEventListener('change', calculate);
    });

    tableBody.addEventListener('input', (e) => {
      if (e.target.matches('[data-rate-key]')) calculate();
    });

    resetBtn.addEventListener('click', () => {
      applyRatesToInputs(DEFAULT_RATES);
      calculate();
    });

    bound = true;
  }

  function loadAndRender() {
    fields.users        = document.getElementById('mdrp-users');
    fields.servers      = document.getElementById('mdrp-servers');
    fields.sites         = document.getElementById('mdrp-sites');
    fields.sensors       = document.getElementById('mdrp-sensors');
    fields.dataExplorer      = document.getElementById('mdrp-data-explorer');
    fields.incidentResponse  = document.getElementById('mdrp-incident-response');
    fields.sensor             = document.getElementById('mdrp-sensor');
    fields.physicalSensor     = document.getElementById('mdrp-physical-sensor');
    fields.awareness          = document.getElementById('mdrp-awareness');
    fields.margin        = document.getElementById('mdrp-margin');
    fields.discount       = document.getElementById('mdrp-discount');
    fields.roe            = document.getElementById('mdrp-roe');

    tableBody = document.getElementById('mdrp-table-body');
    summaryEl = document.getElementById('mdrp-summary');
    resetBtn  = document.getElementById('mdrp-reset-rates');

    if (!bound) {
      renderTable();
      applyRatesToInputs(loadRates());
    }
    bindEvents();
    calculate();
  }

  return { loadAndRender };
})();

window.MdrPricingTab = MdrPricingTab;
