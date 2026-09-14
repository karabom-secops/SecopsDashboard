/* portal-remediation.js — everything outstanding, and formally accepting a risk.
 *
 * Vulnerability rows name the issue but never the affected host, port or CVE:
 * the Vulnerabilities view withholds the finding list deliberately, and this
 * must not undo that decision through a different door. See lib/portal-routes.js.
 *
 * RISK ACCEPTANCE is the portal's only write. A client names who is accepting,
 * why, and until when; the request is recorded as pending, and the item stays
 * open — and keeps counting — until our team approves it. The page says so at
 * every step, because a client who thinks clicking "Accept" closed a finding
 * will be surprised to see it in next month's report.
 */
(function () {
  'use strict';

  var P = window.Portal;

  var _items = [];
  var _data = null;
  var _acceptances = [];
  var _acceptMeta = { available: false, maxTermDays: 365, defaultTermDays: 90 };
  var _filter = { scope: 'open', source: '', q: '' };
  var _accepting = null;     // the item whose acceptance form is open
  var _flash = null;         // { tone, text } shown once above the list
  var _wired = false;

  var STATUS_LABEL = {
    pending:   'Pending review',
    approved:  'Accepted',
    rejected:  'Not accepted',
    withdrawn: 'Withdrawn',
    expired:   'Expired',
  };
  var STATUS_BADGE = {
    pending: 'badge-amber', approved: 'badge-green', rejected: 'badge-red',
    withdrawn: 'badge-muted', expired: 'badge-muted',
  };

  function todayUtc() { return new Date().toISOString().slice(0, 10); }
  function addDays(dateStr, days) {
    var d = new Date(dateStr + 'T00:00:00Z');
    d.setUTCDate(d.getUTCDate() + days);
    return d.toISOString().slice(0, 10);
  }

  /** Staff previewing cannot act (the server refuses it), so they are not offered to. */
  function canAct() {
    return _acceptMeta.available && !window.__portalPreview;
  }

  function matches(i) {
    if (_filter.scope === 'overdue' && !i.overdue) return false;
    if (_filter.source && i.source !== _filter.source) return false;
    if (_filter.q) {
      var q = _filter.q.trim().toLowerCase();
      if (q && (i.title || '').toLowerCase().indexOf(q) < 0 &&
               (i.source || '').toLowerCase().indexOf(q) < 0) return false;
    }
    return true;
  }

  function chip(value, label, active) {
    return '<button type="button" class="chip' + (active ? ' active' : '') +
      '" data-scope="' + P.esc(value) + '">' + P.esc(label) + '</button>';
  }

  function controls(data, sources) {
    return '<div class="filter-bar">' +
      '<div class="chip-row" role="group" aria-label="Filter">' +
        chip('open',    'All open (' + (data.total || 0) + ')', _filter.scope === 'open') +
        chip('overdue', 'Overdue (' + (data.overdue || 0) + ')', _filter.scope === 'overdue') +
      '</div>' +
      '<select id="remSource" class="form-select" aria-label="Filter by source">' +
        '<option value="">All sources</option>' +
        sources.map(function (s) {
          return '<option value="' + P.esc(s) + '"' +
            (_filter.source === s ? ' selected' : '') + '>' + P.esc(s) + '</option>';
        }).join('') +
      '</select>' +
      '<input id="remSearch" class="form-input table-search-input" type="search"' +
        ' placeholder="Search remediation items" aria-label="Search remediation items"' +
        ' aria-controls="remList" value="' + P.esc(_filter.q) + '" />' +
      '<span id="remCount" class="portal-count" role="status" aria-live="polite"></span>' +
    '</div>';
  }

  function due(i) {
    if (!i.dueDate) return '<span class="portal-muted">—</span>';
    var txt = P.esc(P.fmtDate(i.dueDate));
    // Late is the only thing on this page anyone needs to spot at a glance.
    return i.overdue
      ? '<span class="badge badge-red">' + txt + '</span>'
      : txt;
  }

  /** The acceptance column: pending, an action, or nothing for items that cannot be accepted. */
  function acceptCell(i) {
    if (!i.ref) return '<span class="portal-muted">—</span>';
    if (i.acceptance && i.acceptance.status === 'pending') {
      return '<span class="badge badge-amber">Pending review</span>';
    }
    if (!canAct()) return '<span class="portal-muted">—</span>';
    return '<button type="button" class="btn btn-secondary btn-sm" data-accept-ref="' +
      P.esc(i.ref) + '">Accept risk</button>';
  }

  function list() {
    var rows = _items.filter(matches);

    var countEl = document.getElementById('remCount');
    if (countEl) {
      countEl.textContent = rows.length === _items.length
        ? _items.length + ' items'
        : rows.length + ' of ' + _items.length + ' items';
    }

    var cols = [
      { label: 'Item', raw: function (i) {
          return P.esc(i.title || 'Untitled') +
            '<div class="cell-sub"><span>' + P.esc(i.source) + '</span></div>';
        } },
      { label: 'Severity', cls: 'col-narrow', raw: function (i) { return P.sevPill(i.severity); } },
      { label: 'Status',   cls: 'col-narrow', raw: function (i) { return P.esc(i.status || '—'); } },
      { label: 'Raised',   cls: 'col-narrow', raw: function (i) { return P.esc(P.fmtDate(i.raisedAt)); } },
      { label: 'Target',   cls: 'col-narrow', raw: due },
    ];
    if (_acceptMeta.available) {
      cols.push({ label: 'Risk acceptance', cls: 'col-narrow', raw: acceptCell });
    }

    return P.table(cols, rows, {
      emptyTitle: _filter.scope === 'overdue' && !_filter.source && !_filter.q
        ? 'Nothing is overdue'
        : 'Nothing matches these filters',
      emptyDetail: _filter.scope === 'overdue' && !_filter.source && !_filter.q
        ? 'Every open item is still inside its target date.' : '',
    });
  }

  /* ── The acceptance form ─────────────────────────────────────────────── */

  function formHtml(item) {
    var today = todayUtc();
    var min = addDays(today, 1);
    var max = addDays(today, _acceptMeta.maxTermDays || 365);
    var def = addDays(today, _acceptMeta.defaultTermDays || 90);
    var client = window.__clientName || 'your organisation';

    return '<form id="remAcceptFormEl" class="portal-card portal-accept" novalidate>' +
      '<h3 class="portal-card-title">Accept this risk</h3>' +
      '<p class="portal-card-lead"><strong>' + P.esc(item.title || 'Untitled') + '</strong> · ' +
        P.esc(item.source) + ' · ' + P.sevPill(item.severity) + '</p>' +
      '<p class="portal-note portal-accept-explain">Accepting a risk records that ' + P.esc(client) +
        ' has decided not to remediate this item for now. Our team reviews every request; ' +
        'until it is approved the item stays open and continues to count in your score. ' +
        'An acceptance lasts until its review date, when the item reopens and needs a new decision.</p>' +
      '<div class="portal-accept-grid">' +
        '<div class="portal-accept-field">' +
          '<label class="form-label" for="raApproverName">Accepted by</label>' +
          '<input id="raApproverName" class="form-input" maxlength="120" required autocomplete="name" />' +
        '</div>' +
        '<div class="portal-accept-field">' +
          '<label class="form-label" for="raApproverRole">Their role</label>' +
          '<input id="raApproverRole" class="form-input" maxlength="120" required placeholder="e.g. Chief Information Officer" />' +
        '</div>' +
        '<div class="portal-accept-field portal-accept-wide">' +
          '<label class="form-label" for="raJustification">Why is this risk being accepted?</label>' +
          '<textarea id="raJustification" class="form-input" rows="4" minlength="20" maxlength="2000" required ' +
            'placeholder="The business reason, and any compensating controls in place."></textarea>' +
        '</div>' +
        '<div class="portal-accept-field">' +
          '<label class="form-label" for="raExpiresOn">Review date</label>' +
          '<input id="raExpiresOn" class="form-input" type="date" min="' + min + '" max="' + max +
            '" value="' + def + '" required />' +
          '<span class="portal-accept-hint">At most ' + P.esc(_acceptMeta.maxTermDays || 365) + ' days from today.</span>' +
        '</div>' +
        '<div class="portal-accept-field portal-accept-wide">' +
          '<label class="portal-accept-confirm">' +
            '<input id="raConfirmed" type="checkbox" required /> ' +
            'I confirm the person named above is authorised to accept this risk on behalf of ' +
            P.esc(client) + '.' +
          '</label>' +
        '</div>' +
      '</div>' +
      '<div class="portal-accept-error" role="alert" hidden></div>' +
      '<div class="portal-card-actions">' +
        '<button type="submit" class="btn btn-primary btn-sm">Submit for review</button> ' +
        '<button type="button" class="btn btn-secondary btn-sm" data-accept-cancel>Cancel</button>' +
      '</div>' +
    '</form>';
  }

  function openForm(ref) {
    var item = _items.filter(function (i) { return i.ref === ref; })[0];
    if (!item) return;
    _accepting = item;
    _flash = null;
    var host = document.getElementById('remAcceptForm');
    if (!host) return;
    host.innerHTML = formHtml(item);
    renderFlash();
    try { host.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) { host.scrollIntoView(); }
    var first = document.getElementById('raApproverName');
    if (first) first.focus();
  }

  function closeForm() {
    _accepting = null;
    var host = document.getElementById('remAcceptForm');
    if (host) host.innerHTML = '';
  }

  async function submitForm(form) {
    var errEl = form.querySelector('.portal-accept-error');
    var btn = form.querySelector('button[type="submit"]');
    var val = function (id) { var el = document.getElementById(id); return el ? el.value : ''; };

    errEl.hidden = true;
    btn.disabled = true;
    try {
      await P.post('risk-acceptances', {
        ref: _accepting.ref,
        approverName: val('raApproverName'),
        approverRole: val('raApproverRole'),
        justification: val('raJustification'),
        expiresOn: val('raExpiresOn'),
        confirmed: !!(document.getElementById('raConfirmed') || {}).checked,
      });
      var title = _accepting.title;
      closeForm();
      _flash = { tone: 'ok', text: 'Submitted for review: ' + title + '. It stays open until our team approves it.' };
      await reload();
    } catch (err) {
      // The server's message is written for the client — say it as it is.
      errEl.textContent = err.message;
      errEl.hidden = false;
      btn.disabled = false;
    }
  }

  async function withdraw(id) {
    if (!window.confirm('Withdraw this acceptance request? The item stays open.')) return;
    try {
      await P.post('risk-acceptances/' + encodeURIComponent(id) + '/withdraw', {});
      _flash = { tone: 'ok', text: 'Request withdrawn.' };
    } catch (err) {
      _flash = { tone: 'error', text: err.message };
    }
    await reload();
  }

  /* ── The register ────────────────────────────────────────────────────── */

  function registerHtml() {
    if (!_acceptMeta.available) return '';
    var head = '<h3 class="portal-card-title">Risk acceptances</h3>';
    if (!_acceptances.length) {
      return '<div class="portal-card">' + head +
        '<p class="portal-card-lead">No risks have been accepted. Use <strong>Accept risk</strong> ' +
        'on an open vulnerability or penetration test finding to record a decision not to remediate it for now.</p>' +
      '</div>';
    }
    return '<div class="portal-card">' + head +
      P.table([
        { label: 'Item', raw: function (a) {
            return P.esc(a.title || 'Untitled') +
              '<div class="cell-sub"><span>' + P.esc(a.source || '') + '</span></div>';
          } },
        { label: 'Status', cls: 'col-narrow', raw: function (a) {
            return '<span class="badge ' + (STATUS_BADGE[a.status] || 'badge-muted') + '">' +
              P.esc(STATUS_LABEL[a.status] || a.status) + '</span>';
          } },
        { label: 'Accepted by', raw: function (a) {
            return P.esc(a.approverName) + '<div class="cell-sub"><span>' + P.esc(a.approverRole) + '</span></div>';
          } },
        { label: 'Review date', cls: 'col-narrow', raw: function (a) { return P.esc(P.fmtDate(a.expiresOn)); } },
        { label: 'Our note', raw: function (a) {
            return a.reviewNote ? P.esc(a.reviewNote) : '<span class="portal-muted">—</span>';
          } },
        { label: '', cls: 'col-narrow', raw: function (a) {
            return a.status === 'pending' && canAct()
              ? '<button type="button" class="btn btn-secondary btn-sm" data-withdraw-id="' +
                P.esc(a.id) + '">Withdraw</button>'
              : '';
          } },
      ], _acceptances) +
    '</div>';
  }

  /* ── Page ────────────────────────────────────────────────────────────── */

  function renderFlash() {
    var el = document.getElementById('remFlash');
    if (!el) return;
    if (!_flash) { el.innerHTML = ''; return; }
    el.innerHTML = '<p class="portal-flash portal-flash-' + P.esc(_flash.tone) + '" role="status">' +
      P.esc(_flash.text) + '</p>';
  }

  function render() {
    var data = _data || {};
    _items = data.items || [];

    var el = document.getElementById('tab-remediation');
    var head = P.viewHead('Remediation',
      'Everything currently open across vulnerabilities, risks, penetration ' +
      'test findings and incidents.');

    if (!_items.length && !_acceptances.length) {
      el.innerHTML = head + '<div id="remFlash"></div>' + P.emptyState('Nothing outstanding',
        'There are no open remediation items for your environment.');
      renderFlash();
      return;
    }

    var sev = data.bySeverity || {};
    var cards = [
      { label: 'Open items', value: data.total || 0 },
      { label: 'Overdue', value: data.overdue || 0,
        accent: (data.overdue || 0) > 0 ? 'red' : 'green',
        sub: 'Past the agreed target date' },
      { label: 'Critical & high', value: (sev.critical || 0) + (sev.high || 0),
        accent: ((sev.critical || 0) + (sev.high || 0)) > 0 ? 'amber' : 'green' },
    ];
    var pendingCount = _acceptances.filter(function (a) { return a.status === 'pending'; }).length;
    if (_acceptMeta.available && pendingCount) {
      cards.push({ label: 'Acceptances pending', value: pendingCount, accent: 'amber',
        sub: 'Awaiting review by our team' });
    }

    var sources = _items.map(function (i) { return i.source; })
      .filter(function (v, idx, a) { return a.indexOf(v) === idx; }).sort();

    el.innerHTML = head + P.statCards(cards) +
      '<div id="remFlash"></div>' +
      '<div id="remAcceptForm"></div>' +
      controls(data, sources) +
      '<div id="remList">' + list() + '</div>' +
      '<p class="portal-note">' + P.esc(data.note || '') + '</p>' +
      (window.__portalPreview && _acceptMeta.available
        ? '<p class="portal-note"><strong>Preview.</strong> Risk acceptance is only available to client accounts.</p>'
        : '') +
      '<div id="remRegister">' + registerHtml() + '</div>';

    renderFlash();
    if (_accepting) openForm(_accepting.ref);
    wire(el);
    list();   // populate the count on first paint
  }

  /**
   * Delegated, and wired ONCE. The earlier version added a click listener on
   * every render, so each reload stacked another and a chip click ran N times.
   */
  function wire(el) {
    if (_wired) return;
    _wired = true;

    el.addEventListener('click', function (ev) {
      var c = ev.target.closest('.chip[data-scope]');
      if (c) {
        _filter.scope = c.dataset.scope;
        Array.prototype.forEach.call(
          el.querySelectorAll('.chip[data-scope]'),
          function (b) { b.classList.toggle('active', b === c); });
        refresh();
        return;
      }
      var acc = ev.target.closest('[data-accept-ref]');
      if (acc) { openForm(acc.getAttribute('data-accept-ref')); return; }
      if (ev.target.closest('[data-accept-cancel]')) { closeForm(); return; }
      var wd = ev.target.closest('[data-withdraw-id]');
      if (wd) { withdraw(wd.getAttribute('data-withdraw-id')); }
    });

    el.addEventListener('change', function (ev) {
      if (ev.target && ev.target.id === 'remSource') { _filter.source = ev.target.value; refresh(); }
    });
    // Only #remList is re-rendered, so the search box keeps focus and caret.
    el.addEventListener('input', function (ev) {
      if (ev.target && ev.target.id === 'remSearch') { _filter.q = ev.target.value; refresh(); }
    });
    el.addEventListener('submit', function (ev) {
      if (ev.target && ev.target.id === 'remAcceptFormEl') {
        ev.preventDefault();
        submitForm(ev.target);
      }
    });
  }

  function refresh() {
    var host = document.getElementById('remList');
    if (host) host.innerHTML = list();
  }

  /**
   * Both requests, settled independently: an un-migrated acceptances table
   * must not blank the remediation list, and vice versa.
   */
  async function reload() {
    var r = await Promise.allSettled([P.get('remediation'), P.get('risk-acceptances')]);
    if (r[0].status !== 'fulfilled') throw r[0].reason;
    _data = r[0].value;
    var acc = r[1].status === 'fulfilled' ? r[1].value : null;
    _acceptMeta = {
      available: !!(acc && acc.available),
      maxTermDays: (acc && acc.maxTermDays) || 365,
      defaultTermDays: (acc && acc.defaultTermDays) || 90,
    };
    _acceptances = (acc && acc.acceptances) || [];
    render();
  }

  window.PortalRemediation = {
    async load() {
      var el = document.getElementById('tab-remediation');
      try {
        await reload();
      } catch (err) {
        el.innerHTML = P.viewHead('Remediation') + P.errorState(err.message);
      }
    },
  };
})();
