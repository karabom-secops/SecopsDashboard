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

  /** YYYY-MM-DD. This feeds <input type="date">, so the shape is fixed. */
  function fmt(dateStr) {
    if (!dateStr) return '—';
    return String(dateStr).slice(0, 10);
  }

  /**
   * '1 Nov 2026' for display. Separate from fmt() on purpose — date inputs
   * only accept ISO, and a column of ISO dates is slower to read than one a
   * person would write. Parsed as UTC so a DATE never shifts a day.
   */
  function fmtDisplay(dateStr) {
    if (!dateStr) return '—';
    const key = String(dateStr).slice(0, 10);
    const d = new Date(key + 'T00:00:00Z');
    if (isNaN(d.getTime())) return key;
    return d.toLocaleDateString('en-GB',
      { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
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

  /**
   * Build one tile.
   *
   * Colour is reserved for a state somebody has to act on. Inventory counts
   * carry no accent no matter how large they are — "12 vendors" and "4 of them
   * critical" are facts about the estate, not failures, and colouring them red
   * spends the reader's attention on something they cannot do anything about.
   * A tile that has nothing to report reads the same as its neighbours rather
   * than turning green to congratulate itself.
   */
  function statTile(label, value, accent) {
    return `
      <div class="stat-card${accent ? ' accent-' + accent : ''}">
        <div class="stat-label">${label}</div>
        <div class="stat-value">${value}</div>
      </div>`;
  }

  async function renderStats() {
    const el = document.getElementById('tpr-stats');
    if (!el) return;
    try {
      const res  = await fetch('api/vendors/stats' + tenantParam('?'), { credentials: 'same-origin' });
      if (!res.ok) throw new Error('stats ' + res.status);
      const d = await res.json();
      el.innerHTML =
        statTile('Vendors Under Management', d.total,          null) +
        statTile('Critical &amp; High Tier',     d.highTier,       null) +
        statTile('Reviews Overdue',          d.reviewsOverdue, d.reviewsOverdue ? 'red'   : null) +
        statTile('No Assurance Evidence',    d.noEvidence,     d.noEvidence     ? 'amber' : null) +
        statTile('Evidence Expiring (90d)',  d.expiringSoon,   d.expiringSoon   ? 'amber' : null);
    } catch (_) {
      // Not a grid item: a failure message stretched into a stat-card slot
      // reads as a broken tile rather than as an error.
      el.innerHTML = '<p class="tpr-load-error">Could not load vendor statistics.</p>';
    }
  }

  // ── Table rendering ────────────────────────────────────────────────────────

  /**
   * Rows for the current filter.
   *
   * "All" means all vendors under management, which excludes terminated
   * relationships — the same population /api/vendors/stats counts. They used to
   * be listed here while being excluded from the tiles, so the header read
   * "4 vendors under management" above a table of five. Terminated vendors are
   * still reachable, through their own filter.
   */
  function underManagement(v) { return v.status !== 'terminated'; }

  function visibleVendors() {
    if (_filter === 'all')         return _vendors.filter(underManagement);
    if (_filter === 'terminated')  return _vendors.filter(v => v.status === 'terminated');
    if (_filter === 'overdue')     return _vendors.filter(v => underManagement(v) && isReviewOverdue(v));
    if (_filter === 'no-evidence') return _vendors.filter(v => underManagement(v) && !hasEvidence(v));
    return _vendors.filter(v => underManagement(v) && v.criticality === _filter);
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

  /**
   * The secondary line under a vendor's name: what they do, who owns the
   * relationship, and — only when it is not the ordinary case — their status.
   * Keeping status silent for active vendors means the eye goes to the three
   * that are offboarding rather than reading "Active" forty times.
   */
  function vendorSubLine(v) {
    const parts = [];
    if (v.service) parts.push(esc(truncate(v.service, 44)));
    if (v.owner)   parts.push(esc(v.owner));
    if (v.status && v.status !== 'active') {
      parts.push('<span class="tpr-status">' + (STATUS_LABEL[v.status] || esc(v.status)) + '</span>');
    }
    return parts.length ? '<div class="tpr-sub">' + parts.join(' &middot; ') + '</div>' : '';
  }

  function truncate(s, n) {
    const str = String(s == null ? '' : s);
    return str.length > n ? str.slice(0, n).replace(/\s+\S*$/, '') + '…' : str;
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

    // Six columns, not ten. Owner, data classification, status and the
    // inherent score moved into the row's secondary line or the detail modal:
    // ten columns forced a horizontal scrollbar on a laptop, which costs more
    // than the columns were worth. Inherent and residual in particular sat
    // adjacent on the same 1-25 scale, one a bare number and one a badge —
    // residual is the number anyone acts on, and the modal explains how it was
    // derived from the inherent one.
    el.innerHTML = `
      <div class="table-wrapper">
        <table class="data-table tpr-table">
          <thead>
            <tr>
              <th scope="col">Vendor</th>
              <th scope="col">Tier</th>
              <th scope="col">Data access</th>
              <th scope="col">Assurance</th>
              <th scope="col" class="num">Risk</th>
              <th scope="col">Next review</th>
            </tr>
          </thead>
          <tbody>
            ${items.map(v => {
              const overdue  = isReviewOverdue(v);
              const evidence = hasEvidence(v);
              const expired  = assuranceExpired(v);
              const label    = CRITICALITY_LABEL[v.criticality] || esc(v.criticality);
              return `
              <tr class="tpr-row" data-id="${v.id}">
                <td>
                  <button type="button" class="tpr-name-btn" data-id="${v.id}">${esc(v.name)}</button>
                  ${vendorSubLine(v)}
                </td>
                <td><span class="badge ${tierBadge(v.criticality)}">${label}</span></td>
                <td>
                  ${DATA_LABEL[v.data_access] || esc(v.data_access)}
                  ${v.network_access ? '<span class="badge badge-muted">Network</span>' : ''}
                </td>
                <td>
                  <span class="badge ${evidence ? 'badge-green' : 'badge-muted'}">${ASSURANCE_LABEL[v.assurance] || esc(v.assurance)}</span>
                  ${expired ? '<span class="badge badge-amber">Expired</span>' : ''}
                </td>
                <td class="num"><span class="badge ${scoreBadge(v.residual_score)}">${v.residual_score}</span></td>
                <td class="num">
                  ${fmtDisplay(v.next_review_date)}
                  ${overdue ? '<span class="badge badge-red">Overdue</span>' : ''}
                </td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;

    // A real <button>, so the row is reachable by Tab, activates on Enter and
    // Space, is announced as a control, and picks up the shared focus ring.
    // It used to be a click handler on a <tr> with cursor:pointer and no
    // tabindex — opening a vendor was mouse-only.
    el.querySelectorAll('.tpr-name-btn').forEach(btn => {
      btn.addEventListener('click', () => openModal(parseInt(btn.dataset.id, 10)));
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

    // Same thresholds as scoreBadge(), so the readout and the table badge for
    // the same vendor can never disagree about what colour the number is.
    const out = document.getElementById('tpr-score-display');
    out.textContent = residual;
    out.className = 'tpr-score ' +
      (residual >= 15 ? 'is-high' : residual >= 8 ? 'is-medium' : 'is-low');

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
    setModalMessage('');

    modalEl.hidden = false;
    document.body.classList.add('modal-open');

    // Dialog semantics, Esc, backdrop dismissal, focus trap and focus restore.
    // Visibility stays this module's business; the helper only layers on the
    // accessible behaviour and calls back here to hide.
    if (window.ModalA11y) {
      window.ModalA11y.open(modalEl, {
        labelledBy: 'tpr-modal-title',
        onClose: hideModal,
      });
    }
  }

  /** Message line in the modal footer, replacing alert(). */
  function setModalMessage(text) {
    const el = document.getElementById('tpr-modal-msg');
    if (el) el.textContent = text || '';
  }

  /** Hides the modal. Called by ModalA11y once it has released the trap. */
  function hideModal() {
    document.getElementById('vendor-modal').hidden = true;
    document.body.classList.remove('modal-open');
  }

  /**
   * Close route for the tab's own controls (Cancel, the header ×, a successful
   * save). Routes through ModalA11y so focus is restored to whatever opened
   * the dialog; falls back to hiding directly if the helper is absent.
   */
  function closeModal() {
    if (window.ModalA11y) window.ModalA11y.close(document.getElementById('vendor-modal'));
    else hideModal();
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
    // Inline, next to the button that failed — an alert() steals focus, cannot
    // be styled, and drops the user back with no idea which field was wrong.
    if (!body.name) {
      setModalMessage('Vendor name is required.');
      document.getElementById('tpr-name').focus();
      return;
    }

    const isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) body.tenantId = window.globalTenantId;

    const saveBtn = document.getElementById('tpr-modal-save');
    saveBtn.disabled = true;
    setModalMessage('');
    try {
      const res = await fetch(id ? `api/vendors/${id}` : 'api/vendors', {
        method: id ? 'PUT' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setModalMessage(err.error || ('Could not save the vendor (' + res.status + ').'));
        return;
      }
    } catch (_) {
      setModalMessage('Could not reach the server. Check your connection and try again.');
      return;
    } finally {
      saveBtn.disabled = false;
    }

    closeModal();
    await load();
    render();
    renderStats();
  }

  async function deleteVendor() {
    const id = val('tpr-id');
    if (!id) return;
    // Kept as confirm(): this is destructive and irreversible, and the native
    // dialog's blocking behaviour is the right shape for that. Only the
    // non-blocking error paths moved inline.
    if (!confirm('Delete this vendor? Any risks linked to it stay on the register with the link cleared.')) return;
    try {
      const res = await fetch(`api/vendors/${id}` + tenantParam('?'),
        { method: 'DELETE', credentials: 'same-origin' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setModalMessage(err.error || ('Could not delete the vendor (' + res.status + ').'));
        return;
      }
    } catch (_) {
      setModalMessage('Could not reach the server. Check your connection and try again.');
      return;
    }
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
