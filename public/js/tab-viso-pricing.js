/* tab-viso-pricing.js — vISO (virtual Information Security Officer) pricing calculator.
   The vISO sub-tab of the Pricing page; tab-pricing.js owns the sub-tab bar. */
const VisoPricingTab = (() => {
  'use strict';

  /*
   * ══ WHAT THIS PRICES, AND WHERE THE NUMBERS CAME FROM ══
   *
   * vISO is sold as a retainer, not as units — so unlike the MDR calculator
   * beside it, there is no quantity table. The price is a tier, and the
   * decisions on a quote are: which tier, how many managed services come with
   * it, and how much discount the margin can take.
   *
   * The defaults are the rate card proposed when vISO pricing was first worked
   * out: three tiers anchored against the cost of an in-house Information
   * Security Officer, with the platform split out as a visible line so it can
   * be waived on attach. They are DEFAULTS — every figure is editable, saved in
   * this browser, and resettable. Nothing here is a price anyone has approved.
   *
   * ══ WHY MARGIN IS COMPUTED, NOT STATED ══
   *
   * The original proposal quoted "60–66% gross margin". That figure depends
   * entirely on the consultant day cost, which ranges R5,500–R7,500 loaded, and
   * on what the platform costs to run per client. A calculator that printed a
   * margin percentage from a brochure would be right for exactly one set of
   * inputs. This one derives it from the inputs on screen, and warns when a
   * discount — or a waived platform fee — takes it under the floor.
   *
   * All figures are ZAR. vISO is delivered in-house and priced in rand; the
   * MDR calculator works in USD because its costs are vendor list prices.
   */

  const STORAGE_KEY = 'visoPricingCard';

  const TIERS = [
    {
      key: 'essential', label: 'vISO Essential', fits: 'Under 150 users, single site',
      includes: [
        'SecOps platform and client portal',
        'Quarterly board pack',
        'Annual GRC self-assessment',
        'Risk register maintained',
        'Remediation tracker',
      ],
    },
    {
      key: 'standard', label: 'vISO Standard', fits: '150–750 users',
      includes: [
        'Everything in Essential',
        'Monthly board pack and monthly review call',
        'Third-party risk register',
        'Vulnerability SLA governance',
        'Policy review cycle',
      ],
    },
    {
      key: 'executive', label: 'vISO Executive', fits: '750+ users, regulated, certification track',
      includes: [
        'Everything in Standard',
        'Board and exco attendance',
        'ISO 27001 and POPIA certification readiness',
        'Penetration test and firewall audit oversight',
        'Incident post-mortems and vendor assurance programme',
      ],
    },
  ];

  /*
   * Advisory + platform = the list price per month:
   *   Essential  R9,000  + R3,500  = R12,500
   *   Standard   R21,500 + R6,500  = R28,000
   *   Executive  R54,000 + R11,000 = R65,000
   *
   * Platform running cost defaults to R0 because it is not known here, and
   * inventing one would be worse than leaving it visibly unset. The margin card
   * says so until somebody fills it in.
   */
  const DEFAULT_CARD = {
    rates: {
      essential: { advisory: 9000,  platform: 3500,  days: 0.5 },
      standard:  { advisory: 21500, platform: 6500,  days: 1.5 },
      executive: { advisory: 54000, platform: 11000, days: 3.5 },
    },
    dayCost: 6500,           // loaded consultant cost per day, midpoint of R5,500–R7,500
    platformCost: 0,         // platform running cost per client per month — not known
    gmFloor: 50,             // gross margin below this raises a warning
    fteAnnual: 1500000,      // an in-house ISO, fully loaded, per year (R1.2m–R1.9m)
    waiverThreshold: 3,      // platform fee waived at this many managed services
  };

  /*
   * The managed services that can be attached. Keys and labels MATCH
   * lib/services.js, which is server-side and cannot be loaded here; the test
   * suite compares the two so they cannot drift apart silently.
   *
   * `includedIn` mirrors SERVICE_INCLUDES: MDR delivers Managed EDR, NDR and
   * Identity, so an MDR client is not buying three extra services and must not
   * be counted as having four towards the platform waiver.
   */
  const SERVICES = [
    { key: 'mdr',       label: 'Managed Detection & Response' },
    { key: 'vuln',      label: 'Vulnerability Management' },
    { key: 'awareness', label: 'Security Awareness Training' },
    { key: 'edr',       label: 'Managed EDR',      includedIn: 'mdr' },
    { key: 'ndr',       label: 'Managed NDR',      includedIn: 'mdr' },
    { key: 'identity',  label: 'Managed Identity', includedIn: 'mdr' },
    { key: 'email',     label: 'Managed Email Security' },
    { key: 'pentest',   label: 'Penetration Testing' },
    { key: 'firewall',  label: 'Firewall Configuration Review' },
  ];
  const SERVICE_KEYS = SERVICES.map(s => s.key);

  // ── Pure arithmetic ────────────────────────────────────────────────────────

  /** A non-negative finite number, or 0. Form fields arrive as strings. */
  function num(v) {
    const n = Number(v);
    return Number.isFinite(n) ? Math.max(0, n) : 0;
  }

  /**
   * The services that count towards the waiver: known keys only, each once,
   * and not a service the client already has inside MDR.
   */
  function attachedServices(selected) {
    const set = new Set((Array.isArray(selected) ? selected : [])
      .filter(k => SERVICE_KEYS.indexOf(k) >= 0));
    return SERVICES
      .filter(s => set.has(s.key) && !(s.includedIn && set.has(s.includedIn)))
      .map(s => s.key);
  }

  /**
   * Price one vISO quote.
   *
   * @param {Object} i
   *   rate            { advisory, platform, days } for the chosen tier
   *   services        attached managed service keys
   *   discountPct     0–100, clamped
   *   termMonths      contract length, at least 1
   *   dayCost         loaded consultant cost per day
   *   platformCost    platform running cost per month
   *   gmFloorPct      margin below which the quote is flagged
   *   fteAnnual       in-house ISO fully loaded cost per year
   *   waiverThreshold managed services needed to waive the platform fee
   */
  function calculate(i) {
    const input = i || {};
    const rate = input.rate || {};

    const advisory = num(rate.advisory);
    const platform = num(rate.platform);
    const days     = num(rate.days);

    const attached = attachedServices(input.services);
    // An empty or zero threshold must not quietly waive the fee for everyone.
    const waiverThreshold = Math.max(1, Math.round(num(input.waiverThreshold)) || DEFAULT_CARD.waiverThreshold);

    /*
     * THE WAIVER IS THE COMMERCIAL LEVER, AND IT IS NOT FREE.
     *
     * vISO's job is to make the managed services underneath it sticky, so the
     * platform fee is given away when enough of them are attached. But the
     * platform still costs the same to run — only the revenue goes — so the
     * margin below is computed after the waiver, and a waived fee plus a
     * discount is exactly the combination that trips the floor.
     */
    const platformWaived  = platform > 0 && attached.length >= waiverThreshold;
    const platformCharged = platformWaived ? 0 : platform;

    const listMonthly     = advisory + platform;
    const beforeDiscount  = advisory + platformCharged;
    const discountPct     = Math.min(100, num(input.discountPct));
    const discountMonthly = beforeDiscount * discountPct / 100;
    const finalMonthly    = beforeDiscount - discountMonthly;

    const termMonths    = Math.max(1, Math.round(num(input.termMonths)) || 12);
    const annualValue   = finalMonthly * 12;
    const contractValue = finalMonthly * termMonths;

    const labourMonthly = days * num(input.dayCost);
    const platformCost  = num(input.platformCost);
    const costMonthly   = labourMonthly + platformCost;

    /*
     * null, not 0 or -Infinity, when there is no revenue to take a margin of.
     * A 100% discount is still flagged — selling delivery for nothing is below
     * any floor — but it is not given a percentage that means nothing.
     */
    const grossMarginPct = finalMonthly > 0
      ? ((finalMonthly - costMonthly) / finalMonthly) * 100
      : null;
    const gmFloorPct = num(input.gmFloorPct);
    const belowFloor = grossMarginPct === null
      ? costMonthly > 0
      : grossMarginPct < gmFloorPct;

    const fteAnnual = num(input.fteAnnual);

    return {
      advisoryMonthly: advisory,
      platformMonthly: platform,
      platformCharged, platformWaived,
      attached, attachedCount: attached.length, waiverThreshold,
      listMonthly, beforeDiscount,
      discountPct, discountMonthly, finalMonthly,
      termMonths, annualValue, contractValue,
      days, labourMonthly, costMonthly,
      // Margin is overstated while the platform's running cost is unset, and
      // the summary has to be able to say so.
      platformCostKnown: platformCost > 0,
      grossMarginPct, gmFloorPct, belowFloor,
      fteAnnual,
      fteSharePct: fteAnnual > 0 ? (annualValue / fteAnnual) * 100 : null,
    };
  }

  // ── Formatting ─────────────────────────────────────────────────────────────

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // en-US grouping to match the MDR calculator beside it ("R28,000").
  function fmtZar(n) {
    return 'R' + Math.round(Number(n) || 0).toLocaleString('en-US');
  }

  function fmtPct(n) {
    return n === null || n === undefined ? '—' : (Math.round(n * 10) / 10).toFixed(1) + '%';
  }

  /** The summary cards for a calculated quote. Pure, so it can be tested. */
  function summaryHtml(r, tier) {
    const card = (label, value, sub, cls) => `
      <div class="stat-card${cls ? ' ' + cls : ''}">
        <div class="stat-label">${esc(label)}</div>
        <div class="stat-value">${esc(value)}</div>
        ${sub ? `<div class="visop-sub">${esc(sub)}</div>` : ''}
      </div>`;

    const platformSub = r.platformMonthly <= 0
      ? 'No platform fee on this tier'
      : r.platformWaived
        ? `${fmtZar(r.platformMonthly)} waived — ${r.attachedCount} managed services attached`
        : `Waived at ${r.waiverThreshold}+ managed services (${r.attachedCount} attached)`;

    const marginSub = `Delivery cost ${fmtZar(r.costMonthly)}/month · floor ${r.gmFloorPct}%` +
      (r.platformCostKnown ? '' : ' · excludes platform running cost');

    let html =
      card('List price / month', fmtZar(r.listMonthly),
           `${tier ? tier.label + ': ' : ''}advisory ${fmtZar(r.advisoryMonthly)} + platform ${fmtZar(r.platformMonthly)}`) +
      card('Platform fee', r.platformWaived ? 'Waived' : fmtZar(r.platformCharged), platformSub) +
      card(`Discount (${r.discountPct}%)`, '-' + fmtZar(r.discountMonthly)) +
      card('Final monthly (ZAR)', fmtZar(r.finalMonthly), null, 'accent-blue') +
      card('Annual value (ZAR)', fmtZar(r.annualValue), null, 'accent-blue') +
      card(`Contract value (${r.termMonths} months)`, fmtZar(r.contractValue), null, 'accent-green') +
      card('Gross margin', fmtPct(r.grossMarginPct), marginSub, r.belowFloor ? 'visop-warn' : 'accent-green') +
      card('Share of an in-house ISO', fmtPct(r.fteSharePct),
           r.fteAnnual > 0
             ? `${fmtZar(r.annualValue)} a year against ${fmtZar(r.fteAnnual)} fully loaded`
             : 'Set the in-house ISO cost below');

    if (r.belowFloor) {
      // Name the levers that are actually available on THIS quote, rather than
      // a generic "margin is low" that leaves the salesperson guessing.
      const levers = [];
      if (r.discountPct > 0) levers.push('reduce the discount');
      if (r.platformWaived) levers.push('charge the platform fee');
      if (!tier || tier.key !== 'executive') levers.push('quote the next tier up');
      const head = r.grossMarginPct === null
        ? `This quote brings in no revenue against ${fmtZar(r.costMonthly)} a month of delivery cost.`
        : `Gross margin of ${fmtPct(r.grossMarginPct)} is below the ${r.gmFloorPct}% floor.`;
      html += `<div class="visop-alert" role="alert">${esc(head)}` +
        (levers.length ? ` ${esc(levers.join(', or ').replace(/^./, c => c.toUpperCase()))}.` : '') +
        '</div>';
    }
    return html;
  }

  // ── Rate card persistence ──────────────────────────────────────────────────

  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  /** Stored values over the defaults, field by field — a card saved before a
   *  field existed still loads, and a malformed value falls back rather than
   *  poisoning the calculation. */
  function mergeCard(stored) {
    const c = clone(DEFAULT_CARD);
    const s = stored || {};
    ['dayCost', 'platformCost', 'gmFloor', 'fteAnnual', 'waiverThreshold'].forEach((k) => {
      if (s[k] !== undefined && s[k] !== '' && Number.isFinite(Number(s[k]))) c[k] = Number(s[k]);
    });
    TIERS.forEach((t) => {
      const r = (s.rates || {})[t.key] || {};
      ['advisory', 'platform', 'days'].forEach((f) => {
        if (r[f] !== undefined && r[f] !== '' && Number.isFinite(Number(r[f]))) c.rates[t.key][f] = Number(r[f]);
      });
    });
    return c;
  }

  function loadCard() {
    try {
      const stored = JSON.parse(localStorage.getItem(STORAGE_KEY));
      if (stored && typeof stored === 'object') return mergeCard(stored);
    } catch (_) { /* unavailable or malformed — defaults */ }
    return clone(DEFAULT_CARD);
  }

  function saveCard(card) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(card)); } catch (_) { /* non-critical */ }
  }

  // ── The pane ───────────────────────────────────────────────────────────────

  let root = null;
  let bound = false;

  function q(sel) { return root.querySelector(sel); }

  function numberField(id, label, attrs) {
    return `
      <div class="form-group" style="flex:1 1 180px;">
        <label class="form-label" for="${id}">${esc(label)}</label>
        <input class="form-input" id="${id}" type="number" ${attrs}>
      </div>`;
  }

  function shellHtml() {
    return `
      <div class="pricing-pane-actions">
        <p class="section-subtitle" style="margin:0">Virtual Information Security Officer — annual commitment, billed monthly, all figures in ZAR. The rate card is saved in this browser.</p>
        <button class="btn btn-secondary" id="visop-reset" type="button">Reset Rate Card to Defaults</button>
      </div>

      <div class="visop-tiers" role="radiogroup" aria-label="vISO tier">
        ${TIERS.map(t => `
          <label class="visop-tier">
            <input type="radio" name="visop-tier" value="${t.key}"${t.key === 'standard' ? ' checked' : ''}>
            <span class="visop-tier-name">${esc(t.label)}</span>
            <span class="visop-tier-fits">${esc(t.fits)}</span>
            <span class="visop-tier-price" data-list-for="${t.key}"></span>
          </label>`).join('')}
      </div>
      <div id="visop-includes" class="visop-includes"></div>

      <div style="display:flex; gap:1.5rem; flex-wrap:wrap; align-items:flex-start; margin-bottom:1.5rem;">
        <div style="flex:1 1 260px; min-width:240px;">
          <fieldset class="visop-services">
            <legend class="form-label">Managed services attached</legend>
            ${SERVICES.map(s => `
              <label class="visop-service">
                <input type="checkbox" data-service="${s.key}">
                <span>${esc(s.label)}</span>
                <span class="visop-included" data-included-for="${s.key}" hidden>included in MDR</span>
              </label>`).join('')}
            <p class="visop-sub">vISO reporting is fed by these integrations. Quoted without a supported stack, the reporting is keyed by hand and the margin shown here will not hold.</p>
          </fieldset>
          <div class="form-group">
            <label class="form-label" for="visop-discount">Discount (%)</label>
            <input class="form-input" id="visop-discount" type="number" min="0" max="100" step="0.5" value="0">
          </div>
          <div class="form-group">
            <label class="form-label" for="visop-term">Contract term (months)</label>
            <input class="form-input" id="visop-term" type="number" min="1" step="1" value="12">
          </div>
        </div>
        <div id="visop-summary" class="stat-grid" style="flex:2 1 400px; min-width:300px;"></div>
      </div>

      <h3 class="visop-h">Rate card</h3>
      <div class="table-wrapper" style="margin-bottom:1.5rem;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Tier</th><th>Fits</th>
              <th>Advisory fee (R/month)</th><th>Platform fee (R/month)</th>
              <th>Analyst days / month</th><th>List price (R/month)</th>
            </tr>
          </thead>
          <tbody>
            ${TIERS.map(t => `
              <tr>
                <td>${esc(t.label)}</td>
                <td>${esc(t.fits)}</td>
                <td><input class="form-input visop-rate" data-tier="${t.key}" data-field="advisory" type="number" min="0" step="100" style="max-width:130px;"></td>
                <td><input class="form-input visop-rate" data-tier="${t.key}" data-field="platform" type="number" min="0" step="100" style="max-width:130px;"></td>
                <td><input class="form-input visop-rate" data-tier="${t.key}" data-field="days" type="number" min="0" step="0.5" style="max-width:100px;"></td>
                <td data-card-list-for="${t.key}"></td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>

      <h3 class="visop-h">Delivery cost and guardrails</h3>
      <div style="display:flex; gap:1.5rem; flex-wrap:wrap; margin-bottom:1.5rem;">
        ${numberField('visop-day-cost', 'Consultant day cost, loaded (R)', 'min="0" step="100"')}
        ${numberField('visop-platform-cost', 'Platform running cost per client (R/month)', 'min="0" step="100"')}
        ${numberField('visop-gm-floor', 'Gross margin floor (%)', 'min="0" max="100" step="1"')}
        ${numberField('visop-fte', 'In-house ISO, fully loaded (R/year)', 'min="0" step="50000"')}
        ${numberField('visop-waiver', 'Waive platform fee at (managed services)', 'min="1" step="1"')}
      </div>`;
  }

  const CARD_FIELDS = [
    ['visop-day-cost', 'dayCost'],
    ['visop-platform-cost', 'platformCost'],
    ['visop-gm-floor', 'gmFloor'],
    ['visop-fte', 'fteAnnual'],
    ['visop-waiver', 'waiverThreshold'],
  ];

  function writeCard(card) {
    TIERS.forEach(t => ['advisory', 'platform', 'days'].forEach((f) => {
      const el = q(`.visop-rate[data-tier="${t.key}"][data-field="${f}"]`);
      if (el) el.value = card.rates[t.key][f];
    }));
    CARD_FIELDS.forEach(([id, k]) => { const el = q('#' + id); if (el) el.value = card[k]; });
  }

  function readCard() {
    const raw = { rates: {} };
    TIERS.forEach((t) => {
      raw.rates[t.key] = {};
      ['advisory', 'platform', 'days'].forEach((f) => {
        const el = q(`.visop-rate[data-tier="${t.key}"][data-field="${f}"]`);
        raw.rates[t.key][f] = el ? el.value : undefined;
      });
    });
    CARD_FIELDS.forEach(([id, k]) => { const el = q('#' + id); raw[k] = el ? el.value : undefined; });
    // Through mergeCard, so a cleared field falls back to its default rather
    // than becoming a zero that silently reprices the quote.
    return mergeCard(raw);
  }

  function update() {
    const card = readCard();
    saveCard(card);

    const checkedTier = q('input[name="visop-tier"]:checked');
    const tier = TIERS.find(t => t.key === (checkedTier && checkedTier.value)) || TIERS[1];

    const boxes = Array.from(root.querySelectorAll('[data-service]'));
    const mdrOn = boxes.some(b => b.dataset.service === 'mdr' && b.checked);
    boxes.forEach((b) => {
      const svc = SERVICES.find(s => s.key === b.dataset.service);
      const implied = !!(svc && svc.includedIn && mdrOn);
      // Disabled rather than unticked, so turning MDR off again restores what
      // was chosen. calculate() ignores implied services either way.
      b.disabled = implied;
      const tag = q(`[data-included-for="${b.dataset.service}"]`);
      if (tag) tag.hidden = !implied;
    });

    const r = calculate({
      rate: card.rates[tier.key],
      services: boxes.filter(b => b.checked).map(b => b.dataset.service),
      discountPct: q('#visop-discount').value,
      termMonths: q('#visop-term').value,
      dayCost: card.dayCost,
      platformCost: card.platformCost,
      gmFloorPct: card.gmFloor,
      fteAnnual: card.fteAnnual,
      waiverThreshold: card.waiverThreshold,
    });

    q('#visop-summary').innerHTML = summaryHtml(r, tier);
    q('#visop-includes').innerHTML =
      `<div class="form-label">${esc(tier.label)} includes</div>` +
      `<ul>${tier.includes.map(x => `<li>${esc(x)}</li>`).join('')}</ul>`;

    TIERS.forEach((t) => {
      const list = card.rates[t.key].advisory + card.rates[t.key].platform;
      const tile = q(`[data-list-for="${t.key}"]`);
      if (tile) tile.textContent = fmtZar(list) + ' / month';
      const cell = q(`[data-card-list-for="${t.key}"]`);
      if (cell) cell.textContent = fmtZar(list);
    });
  }

  function loadAndRender() {
    root = document.getElementById('pricingPane-viso');
    if (!root) return;
    if (!bound) {
      root.innerHTML = shellHtml();
      writeCard(loadCard());
      root.addEventListener('input', update);
      root.addEventListener('change', update);
      q('#visop-reset').addEventListener('click', () => {
        writeCard(clone(DEFAULT_CARD));
        update();
      });
      bound = true;
    }
    update();
  }

  return {
    loadAndRender,
    // Exposed for tests: the arithmetic and the summary are pure.
    calculate, attachedServices, summaryHtml, mergeCard,
    TIERS, SERVICES, DEFAULT_CARD,
  };
})();

window.VisoPricingTab = VisoPricingTab;
