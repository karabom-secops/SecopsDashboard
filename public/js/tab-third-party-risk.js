/* tab-third-party-risk.js — Per-tenant vendor inventory and inherent risk */

const ThirdPartyRiskTab = (() => {
  'use strict';

  let _vendors = [];
  let _filter  = 'all';

  /**
   * Scoring constants, mirrored from lib/vendor-score.js.
   *
   * The server is authoritative — it recomputes on every write and every score
   * shown in the table and the board report comes from the stored value. This
   * copy exists only to drive the live readout in the modal, which scores form
   * state that has never reached the server. Same arrangement, and the same
   * reason, as calcSectionScore in tab-grc.js.
   *
   * If lib/vendor-score.js changes, change these too.
   */
  const IMPACT_POINTS    = { critical: 5, high: 4, medium: 3, low: 1 };
  const EXPOSURE_POINTS  = { regulated: 5, pii: 4, confidential: 3, internal: 2, none: 1 };
  const ASSURANCE_FACTOR = { both: 0.6, soc2: 0.6, iso27001: 0.6, questionnaire: 0.8, none: 1.0 };

  const CRITICALITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  const DATA_LABEL = {
    regulated: 'Regulated', pii: 'PII', confidential: 'Confidential',
    internal: 'Internal', none: 'None',
  };
  const ASSURANCE_LABEL = {
    both: 'SOC 2 + ISO 27001', soc2: 'SOC 2', iso27001: 'ISO 27001',
    questionnaire: 'Questionnaire', none: 'None',
  };
  const STATUS_LABEL = {
    onboarding: 'Onboarding', active: 'Active', under_review: 'Under review',
    offboarding: 'Offboarding', terminated: 'Terminated',
  };

  // Assurance values that count as independent evidence. A questionnaire is
  // the vendor's own word, so it is not one. Must match VENDOR_EVIDENCE in
  // server.js and the SQL in GET /api/vendors/stats.
  const EVIDENCE = ['soc2', 'iso27001', 'both'];

  function esc(s) {
    return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function fmt(dateStr) {
    if (!dateStr) return '—';
    return String(dateStr).slice(0, 10);
  }

  function canWrite() {
    return window.canWrite('third-party-risk');
  }

  function tenantParam(sep) {
    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  /** Today as YYYY-MM-DD, so every date comparison is calendar-day based. */
  function todayKey() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate());
  }

  // Same 1-25 scale as the Risk Register, so scoreBadge means the same thing
  // on both tabs.
  function scoreBadge(score) {
    if (score >= 15) return 'badge-red';
    if (score >= 8)  return 'badge-amber';
    return 'badge-green';
  }

  function tierBadge(criticality) {
    if (criticality === 'critical') return 'badge-red';
    if (criticality === 'high')     return 'badge-amber';
    if (criticality === 'medium')   return 'badge-blue';
    return 'badge-muted';
  }

  /**
   * Has the recorded assurance passed its expiry date?
   *
   * Kept separate from hasEvidence: a questionnaire is never independent
   * evidence, but that does not make it expired. Conflating the two labels a
   * perfectly current questionnaire "Expired".
   */
  function assuranceExpired(v) {
    if (v.assurance === 'none') return false;
    const exp = fmt(v.assurance_expires);
    if (exp === '—') return false;
    return exp < todayKey();
  }

  /** Independent, unexpired third-party evidence on file? */
  function hasEvidence(v) {
    return EVIDENCE.indexOf(v.assurance) !== -1 && !assuranceExpired(v);
  }

  function isReviewOverdue(v) {
    if (v.status === 'terminated') return false;
    const due = fmt(v.next_review_date);
    if (due === '—') return false;
    return due < todayKey();
  }

  // ── Stats ──────────────────────────────────────────────────────────────────

  async function renderStats() {
    const el = document.getElementById('tpr-stats');
    if (!el) return;
    try {
      const res  = await fetch('api/vendors/stats' + tenantParam('?'), { credentials: 'same-origin' });
      const data = await res.json();
      el.innerHTML = `
        <div class="stat-card accent-blue">
          <div class="stat-label">Vendors Under Management</div>
          <div class="stat-value">${data.total}</div>
        </div>
        <div class="stat-card accent-red">
          <div class="stat-label">Critical &amp; High Tier</div>
          <div class="stat-value">${data.highTier}</div>
        </div>
        <div class="stat-card ${data.reviewsOverdue ? 'accent-red' : 'accent-green'}">
          <div class="stat-label">Reviews Overdue</div>
          <div class="stat-value">${data.reviewsOverdue}</div>
        </div>
        <div class="stat-card ${data.noEvidence ? 'accent-amber' : 'accent-green'}">
          <div class="stat-label">No Assurance Evidence</div>
          <div class="stat-value">${data.noEvidence}</div>
        </div>
        <div class="stat-card ${data.expiringSoon ? 'accent-amber' : ''}">
          <div class="stat-label">Evidence Expiring (90d)</div>
          <div class="stat-value">${data.expiringSoon}</div>
        </div>`;
    } catch (_) {
      el.innerHTML = '<p class="empty-state">Failed to load stats.</p>';
    }
  }

  // ── Table rendering ────────────────────────────────────────────────────────

  function visibleVendors() {
    if (_filter === 'all')         return _vendors;
    if (_filter === 'overdue')     return _vendors.filter(isReviewOverdue);
    if (_filter === 'no-evidence') return _vendors.filter(v => !hasEvidence(v) && v.status !== 'terminated');
    return _vendors.filter(v => v.criticality === _filter);
  }

  function emptyState() {
    if (_vendors.length === 0) {
      return `
        <div class="empty-state-container">
          <div class="empty-state-title">No vendors recorded</div>
          <div class="empty-state-description">
            Add the suppliers who hold your data, run your systems, or would disrupt
            the business if they failed. Their criticality, data access and assurance
            evidence produce a risk score and feed the board report.
          </div>
          ${canWrite() ? '<button class="btn btn-primary empty-state-cta" id="tpr-empty-cta">+ Add the first vendor</button>' : ''}
        </div>`;
    }
    return '<p class="empty-state">No vendors match this filter.</p>';
  }

  function render() {
    const el = document.getElementById('tpr-list');
    if (!el) return;

    const items = visibleVendors();
    if (items.length === 0) {
      el.innerHTML = emptyState();
      const cta = document.getElementById('tpr-empty-cta');
      if (cta) cta.addEventListener('click', () => openModal(null));
      return;
    }

    el.innerHTML = `
      <div class="table-wrapper">
        <table class="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Service</th>
              <th>Owner</th>
              <th>Tier</th>
              <th>Data</th>
              <th>Assurance</th>
              <th>Inherent</th>
              <th>Residual</th>
              <th>Next Review</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(v => {
              const overdue  = isReviewOverdue(v);
              const evidence = hasEvidence(v);
              const expired  = assuranceExpired(v);
              return `
              <tr class="tpr-row" data-id="${v.id}" style="cursor:pointer">
                <td><strong>${esc(v.name)}</strong></td>
                <td>${esc(v.service) || '—'}</td>
                <td>${esc(v.owner) || '—'}</td>
                <td><span class="badge ${tierBadge(v.criticality)}">${CRITICALITY_LABEL[v.criticality] || esc(v.criticality)}</span></td>
                <td>${DATA_LABEL[v.data_access] || esc(v.data_access)}${v.network_access ? ' <span class="badge badge-muted">Network</span>' : ''}</td>
                <td>
                  <span class="badge ${evidence ? 'badge-green' : 'badge-amber'}">${ASSURANCE_LABEL[v.assurance] || esc(v.assurance)}</span>
                  ${expired ? '<span class="badge badge-red">Expired</span>' : ''}
                </td>
                <td>${v.inherent_score}</td>
                <td><span class="badge ${scoreBadge(v.residual_score)}">${v.residual_score}</span></td>
                <td>${overdue ? `<span class="badge badge-red">${fmt(v.next_review_date)}</span>` : fmt(v.next_review_date)}</td>
                <td>${STATUS_LABEL[v.status] || esc(v.status)}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;

    el.querySelectorAll('.tpr-row').forEach(row => {
      row.addEventListener('click', () => openModal(parseInt(row.dataset.id, 10)));
    });
  }

  // ── Data loading ───────────────────────────────────────────────────────────

  async function load() {
    const res = await fetch('api/vendors' + tenantParam('?'), { credentials: 'same-origin' });
    const data = await res.json();
    _vendors = data.vendors || [];
  }

  // ── Modal ──────────────────────────────────────────────────────────────────

  const val = (id) => document.getElementById(id).value;

  /**
   * Live score readout. Mirrors scoreVendor() in lib/vendor-score.js — see the
   * note on the constants above.
   */
  function updateScoreDisplay() {
    const criticality = val('tpr-criticality');
    const dataAccess  = val('tpr-data-access');
    const assurance   = val('tpr-assurance');
    const expires     = val('tpr-assurance-expires');
    const network     = document.getElementById('tpr-network-access').checked;

    const impact = IMPACT_POINTS[criticality] || 3;
    let exposure = EXPOSURE_POINTS[dataAccess] || 1;
    if (network) exposure += 1;
    if (exposure > 5) exposure = 5;
    const inherent = impact * exposure;

    const current = !expires || expires >= todayKey();
    const factor  = current ? (ASSURANCE_FACTOR[assurance] != null ? ASSURANCE_FACTOR[assurance] : 1.0) : 1.0;
    const residual = Math.max(1, Math.round(inherent * factor));

    document.getElementById('tpr-score-display').textContent = residual;

    let explain = 'Inherent ' + inherent + ' (criticality ' + impact + ' × exposure ' + exposure + ')';
    if (residual < inherent) {
      explain += ', reduced to ' + residual + ' by the assurance evidence held.';
    } else if (!current && assurance !== 'none') {
      explain += '. The assurance evidence has expired, so it earns no reduction.';
    } else {
      explain += '. No assurance evidence held, so nothing reduces it.';
    }
    document.getElementById('tpr-score-explain').textContent = explain;
  }

  function openModal(id) {
    const v = id ? _vendors.find(x => x.id === id) : null;
    const readOnly = !canWrite();

    // Move the modal to be a direct child of <body> so its fixed positioning
    // and stacking order can never be affected by an ancestor (e.g. .tab-panel).
    const modalEl = document.getElementById('vendor-modal');
    if (modalEl.parentElement !== document.body) document.body.appendChild(modalEl);

    document.getElementById('tpr-modal-title').textContent = v ? 'Edit Vendor' : 'New Vendor';
    document.getElementById('tpr-id').value               = v ? v.id : '';
    document.getElementById('tpr-name').value             = v ? v.name : '';
    document.getElementById('tpr-service').value          = v ? v.service : '';
    document.getElementById('tpr-owner').value            = v ? v.owner : '';
    document.getElementById('tpr-criticality').value      = v ? v.criticality : 'medium';
    document.getElementById('tpr-data-access').value      = v ? v.data_access : 'none';
    document.getElementById('tpr-network-access').checked = v ? !!v.network_access : false;
    document.getElementById('tpr-assurance').value        = v ? v.assurance : 'none';
    document.getElementById('tpr-status').value           = v ? v.status : 'active';
    ['assurance-expires:assurance_expires', 'contract-start:contract_start',
     'contract-end:contract_end', 'last-review:last_review_date',
     'next-review:next_review_date'].forEach(pair => {
      const parts = pair.split(':');
      const el = document.getElementById('tpr-' + parts[0]);
      const raw = v ? v[parts[1]] : null;
      // fmt() returns an em dash for empty, which a date input rejects.
      el.value = raw ? fmt(raw) : '';
    });
    document.getElementById('tpr-notes').value = v ? v.notes : '';
    updateScoreDisplay();

    document.getElementById('tpr-modal-delete').hidden = !(v && canWrite());

    document.getElementById('tpr-form').querySelectorAll('input, select, textarea').forEach(el => {
      el.disabled = readOnly;
    });
    document.getElementById('tpr-modal-save').hidden = readOnly;

    modalEl.hidden = false;
    document.body.classList.add('modal-open');
  }

  function closeModal() {
    document.getElementById('vendor-modal').hidden = true;
    document.body.classList.remove('modal-open');
  }

  async function saveVendor() {
    const id = val('tpr-id');
    const body = {
      name:              val('tpr-name').trim(),
      service:           val('tpr-service').trim(),
      owner:             val('tpr-owner').trim(),
      criticality:       val('tpr-criticality'),
      data_access:       val('tpr-data-access'),
      network_access:    document.getElementById('tpr-network-access').checked,
      assurance:         val('tpr-assurance'),
      assurance_expires: val('tpr-assurance-expires') || null,
      contract_start:    val('tpr-contract-start')    || null,
      contract_end:      val('tpr-contract-end')      || null,
      last_review_date:  val('tpr-last-review')       || null,
      next_review_date:  val('tpr-next-review')       || null,
      status:            val('tpr-status'),
      notes:             val('tpr-notes').trim(),
    };
    if (!body.name) { alert('Vendor name is required.'); return; }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    const res = await fetch(id ? `api/vendors/${id}` : 'api/vendors', {
      method: id ? 'PUT' : 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      alert('Could not save the vendor: ' + (err.error || res.status));
      return;
    }

    closeModal();
    await load();
    render();
    renderStats();
  }

  async function deleteVendor() {
    const id = val('tpr-id');
    if (!id) return;
    if (!confirm('Delete this vendor? Any risks linked to it stay on the register with the link cleared.')) return;
    await fetch(`api/vendors/${id}` + tenantParam('?'), { method: 'DELETE', credentials: 'same-origin' });
    closeModal();
    await load();
    render();
    renderStats();
  }

  // ── Wiring ─────────────────────────────────────────────────────────────────

  function wireOnce() {
    if (ThirdPartyRiskTab._wired) return;
    ThirdPartyRiskTab._wired = true;

    document.getElementById('tpr-new-btn').addEventListener('click', () => openModal(null));
    document.getElementById('tpr-new-btn').hidden = !canWrite();
    document.getElementById('tpr-modal-close').addEventListener('click', closeModal);
    document.getElementById('tpr-modal-close-2').addEventListener('click', closeModal);
    document.getElementById('tpr-modal-save').addEventListener('click', saveVendor);
    document.getElementById('tpr-modal-delete').addEventListener('click', deleteVendor);

    ['tpr-criticality', 'tpr-data-access', 'tpr-assurance', 'tpr-assurance-expires'].forEach(id => {
      document.getElementById(id).addEventListener('change', updateScoreDisplay);
    });
    document.getElementById('tpr-network-access').addEventListener('change', updateScoreDisplay);

    document.getElementById('tpr-filters').addEventListener('click', (e) => {
      const chip = e.target.closest('.chip');
      if (!chip) return;
      _filter = chip.dataset.filter;
      document.querySelectorAll('#tpr-filters .chip').forEach(c => {
        c.classList.toggle('active', c === chip);
      });
      render();
    });
  }

  // ── Main entry ─────────────────────────────────────────────────────────────

  async function loadAndRender() {
    wireOnce();
    await renderStats();
    await load();
    render();
  }

  return { loadAndRender };
})();

window.ThirdPartyRiskTab = ThirdPartyRiskTab;
