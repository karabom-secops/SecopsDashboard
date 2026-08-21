'use strict';

/**
 * Reports tab — assembles the branded 16:9 client deck.
 *
 * Owns the selectors, the section toggles, the Overview tile overrides and the
 * Observations narrative. Slide rendering lives in report-sections.js, page
 * chrome in report-deck.js.
 */
window.ReportsTab = (function () {

  var S = window.ReportShell;
  var D = window.ReportDeck;

  var STORAGE_PREFIX = 'secops.reports.v1.';

  // The tiles on the Overview slide, in slide order.
  var TILES = [
    { id: 'secureScore',       label: 'Secure Score',       hint: '0–100' },
    { id: 'openTickets',       label: 'Open Tickets',       hint: 'count' },
    { id: 'ticketedIncidents', label: 'Ticketed Incidents', hint: 'count' },
  ];

  var SOURCE_LABELS = {
    'mdr-tickets':  'MDR tickets',
    'arctic-wolf':  'Arctic Wolf',
    'secure-score': 'Secure Score tab',
    'unavailable':  'no source',
  };

  // The only place that knows which endpoint backs which `requires` key.
  var DATA_SOURCES = {
    metrics: function (ctx) {
      return 'api/reports/metrics?period=' + encodeURIComponent(ctx.period) + tenantParam('&');
    },
    secureScore:      function () { return 'api/secure-score' + tenantParam('?'); },
    // Prior-month component scores, for the trend and maturity sections.
    secureScoreHistory: function () { return 'api/secure-score/history' + tenantParam('?'); },
    // Managed EDR / Managed Identity back the Cyber Defence Coverage slide.
    // Both take a trailing day window rather than a calendar month, so ask for
    // enough days to span the reporting period (see edrWindowDays).
    edr:  function (ctx) { return 'api/edr/summary?days='  + edrWindowDays(ctx) + tenantParam('&'); },
    o365: function (ctx) { return 'api/o365/summary?days=' + edrWindowDays(ctx) + tenantParam('&'); },
    // Same endpoint the Awareness tab uses, so the deck cannot drift from it.
    awareness:        function () { return 'api/awareness' + tenantParam('?'); },
    mdr:              function () { return 'api/mdr' + tenantParam('?'); },
    vulnSummary:      function () { return 'api/vulns/latest-summary' + tenantParam('?'); },
    vulnFindings:     function () { return 'api/remediation-tracker' + tenantParam('?'); },
    // 12 months of severity counts, for the Vulnerability Dashboard trend.
    vulnTrends:       function () { return 'api/vulns/trends' + tenantParam('?'); },
    // Vendor inventory, for the Third-Party Risk Dashboard. Scores are derived
    // server-side, so the deck reads the same numbers as the tab.
    vendors:          function () { return 'api/vendors' + tenantParam('?'); },
    // GRC self-assessment: total, framework and per-section scores + answers.
    grcAssessment:    function () { return 'api/grc/assessment' + tenantParam('?'); },
    // The question bank is global — no tenant parameter.
    grcQuestions:     function () { return 'api/grc/questions'; },
  };

  /**
   * Fold the live Secure Score into the metrics payload's tile triple. The
   * scoring engine stays in one place (/api/secure-score, same as the Secure
   * Score tab); this only supplies the tile's `derived` half.
   */
  function mergeSecureScore(metrics, secureScore) {
    if (!metrics || !metrics.tiles) return metrics;
    var t = metrics.tiles.secureScore;
    if (!t) return metrics;
    var s = secureScore && secureScore.score != null ? Math.round(secureScore.score) : null;
    if (s == null) return metrics;
    t.derived = s;
    t.source  = 'secure-score';
    if (secureScore.rating) t.rating = secureScore.rating;
    return metrics;
  }

  var _tenants   = [];
  var _metrics   = null;   // last /api/reports/metrics payload
  var _rendered  = false;

  // ── Helpers ───────────────────────────────────────────────────────────────

  function isSuperAdmin() {
    return !!(window.currentUser && window.currentUser.role === 'superadmin');
  }

  /** Whether this user may write report_metrics / trigger an Arctic Wolf sync. */
  function canPersist() {
    return window.canWrite('reports');
  }

  function tenantParam(sep) {
    if (!isSuperAdmin()) return '';
    var el = document.getElementById('rpt-client');
    var id = el && el.value ? el.value : window.globalTenantId;
    return id ? sep + 'tenantId=' + encodeURIComponent(id) : '';
  }

  function selectedTenantId() {
    var el = document.getElementById('rpt-client');
    if (el && el.value) return el.value;
    return (window.currentUser && window.currentUser.tenantId) || window.globalTenantId || null;
  }

  function storageKey() {
    return STORAGE_PREFIX + (selectedTenantId() || 'self');
  }

  function loadPrefs() {
    try {
      var raw = JSON.parse(localStorage.getItem(storageKey()));
      if (raw && typeof raw === 'object') return raw;
    } catch (_) { /* ignore malformed storage */ }
    return {};
  }

  function savePrefs(prefs) {
    try { localStorage.setItem(storageKey(), JSON.stringify(prefs)); }
    catch (_) { /* storage unavailable — non-critical */ }
  }

  function currentPrefs() {
    var sections = {};
    window.ReportSections.forEach(function (s) {
      var cb = document.getElementById('rpt-sec-' + s.id);
      sections[s.id] = cb ? cb.checked : true;
    });
    var overrides = {};
    allOverrideIds().forEach(function (id) {
      var el = document.getElementById('rpt-ov-' + id);
      if (el && el.value.trim()) overrides[id] = el.value.trim();
    });
    return {
      sections:  sections,
      overrides: overrides,
      narrative: (document.getElementById('rpt-narrative') || {}).value || '',
      assurance: (document.getElementById('rpt-assurance') || {}).value || '',
      execSummary: (document.getElementById('rpt-exec-summary') || {}).value || '',
      comments:  readComments(),
      author:    (document.getElementById('rpt-author')    || {}).value || '',
      period:    (document.getElementById('rpt-period')    || {}).value || '',
    };
  }

  /**
   * Commentary is registry-driven: a section opts in with `commentable: true`.
   *
   * Boxes are only rendered for sections currently switched on, so `_comments`
   * holds the authoritative text. Reading straight from the DOM would silently
   * discard a note the moment its section was toggled off.
   */
  var _comments = {};

  function commentableSections() {
    return window.ReportSections.filter(function (s) {
      if (!s.commentable) return false;
      var cb = document.getElementById('rpt-sec-' + s.id);
      return !cb || cb.checked;
    });
  }

  function readComments() {
    // Live DOM values win; anything not on screen keeps its stored text.
    commentableSections().forEach(function (s) {
      var el = document.getElementById('rpt-comment-' + s.id);
      if (el) _comments[s.id] = el.value;
    });

    var out = {};
    Object.keys(_comments).forEach(function (id) {
      if (String(_comments[id] || '').trim()) out[id] = _comments[id];
    });
    return out;
  }

  function renderCommentBoxes(prefs) {
    var host = document.getElementById('rpt-comments');
    if (!host) return;

    if (prefs && prefs.comments) {
      Object.keys(prefs.comments).forEach(function (id) {
        if (_comments[id] === undefined) _comments[id] = prefs.comments[id];
      });
    }

    var list = commentableSections();
    if (!list.length) { host.innerHTML = ''; return; }

    host.innerHTML = list.map(function (s) {
      return '<label class="rpt-cfield">' +
          '<span class="rpt-clabel">' + s.n + '. ' + S.esc(s.label) + '</span>' +
          '<textarea id="rpt-comment-' + s.id + '" rows="3" ' +
                    'placeholder="Optional commentary shown beneath this section…">' +
            S.esc(_comments[s.id] || '') +
          '</textarea>' +
        '</label>';
    }).join('');

    // Keep the store in step as the user types, so a later re-render (a section
    // toggled, a client switched) never loses in-progress text.
    list.forEach(function (s) {
      var el = document.getElementById('rpt-comment-' + s.id);
      if (el) el.oninput = function () { _comments[s.id] = el.value; };
    });
  }

  /**
   * Days of telemetry to request so the window covers the reporting period.
   * The EDR and O365 endpoints only accept a trailing window, so a report on an
   * older month needs a longer one. Clamped to what those routes allow.
   */
  function edrWindowDays(ctx) {
    var m = /^(\d{4})-(\d{2})$/.exec((ctx && ctx.period) || '');
    if (!m) return 30;
    var start = Date.UTC(Number(m[1]), Number(m[2]) - 1, 1);
    var days  = Math.ceil((Date.now() - start) / 86400000);
    return Math.max(30, Math.min(365, days));
  }

  /** Overview tiles plus every attested metric, which share the override store. */
  function allOverrideIds() {
    var ids = TILES.map(function (t) { return t.id; });
    (window.ReportSections.MANUAL_METRICS || []).forEach(function (g) {
      g.items.forEach(function (it) { ids.push(it.id); });
    });
    return ids;
  }

  function periodLabel(period) {
    var parts = String(period || '').split('-');
    if (parts.length !== 2) return String(period || '');
    var d = new Date(Date.UTC(Number(parts[0]), Number(parts[1]) - 1, 1));
    if (isNaN(d.getTime())) return String(period);
    return d.toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
  }

  // The session only carries `username`; the cover usually wants a real name, so
  // this is a starting point the user is expected to edit (and it is remembered).
  function defaultAuthor() {
    return (window.currentUser || {}).username || '';
  }

  function notice(msg, isError) {
    var el = document.getElementById('rpt-warnings');
    if (!el) return;
    if (!msg) { el.hidden = true; el.textContent = ''; return; }
    el.hidden = false;
    el.textContent = msg;
    el.className = isError ? 'rpt-notice error' : 'rpt-notice';
  }

  // ── Rendering the tab ─────────────────────────────────────────────────────

  function renderSectionToggles(prefs) {
    var host = document.getElementById('rpt-sections');
    if (!host) return;

    var groups = [];
    var byGroup = {};
    window.ReportSections.forEach(function (s) {
      if (!byGroup[s.group]) { byGroup[s.group] = []; groups.push(s.group); }
      byGroup[s.group].push(s);
    });

    host.innerHTML = groups.map(function (g) {
      return '<div class="rpt-group">' +
          '<div class="rpt-group-label">' + S.esc(g) + '</div>' +
          byGroup[g].map(function (s) {
            var on = prefs.sections && prefs.sections[s.id] !== undefined
              ? prefs.sections[s.id] : true;
            return '<label class="rpt-section-row">' +
                '<span class="integration-toggle">' +
                  '<input type="checkbox" id="rpt-sec-' + s.id + '"' + (on ? ' checked' : '') + '>' +
                  '<span class="int-toggle-slider"></span>' +
                '</span>' +
                '<span class="rpt-section-name">' + s.n + '. ' + S.esc(s.label) + '</span>' +
              '</label>';
          }).join('') +
        '</div>';
    }).join('');
  }

  function renderTiles(prefs) {
    var host = document.getElementById('rpt-tiles');
    if (!host) return;
    var tiles = (_metrics && _metrics.tiles) || {};

    host.innerHTML = TILES.map(function (t) {
      var info    = tiles[t.id] || { derived: null, source: 'unavailable' };
      var derived = info.derived == null || info.derived === '' ? null : String(info.derived);
      var src     = SOURCE_LABELS[info.source] || info.source || 'no source';
      var stored  = prefs.overrides && prefs.overrides[t.id];
      var value   = stored != null ? stored
                  : (info.override != null ? info.override : (derived || ''));

      return '<div class="rpt-tile">' +
          '<div class="rpt-tile-head">' +
            '<span class="rpt-tile-label">' + S.esc(t.label) + '</span>' +
            '<span class="rpt-source-badge' + (derived == null ? ' warn' : '') + '">' + S.esc(src) + '</span>' +
          '</div>' +
          '<div class="rpt-tile-derived">Derived: <b>' + S.esc(derived == null ? 'no data' : derived) + '</b></div>' +
          '<input type="text" class="rpt-tile-override" id="rpt-ov-' + t.id + '" ' +
                 'value="' + S.esc(value) + '" placeholder="' + S.esc(t.hint) + '">' +
        '</div>';
    }).join('');
  }


  async function populateClients(prefs) {
    var sel = document.getElementById('rpt-client');
    if (!sel) return;

    try {
      var res = await fetch('api/tenants', { credentials: 'same-origin' });
      _tenants = res.ok ? await res.json() : [];
    } catch (_) { _tenants = []; }

    var ownId = (window.currentUser && window.currentUser.tenantId) || null;
    var preselect = isSuperAdmin() ? (window.globalTenantId || '') : ownId;

    sel.innerHTML = _tenants.map(function (t) {
      return '<option value="' + t.id + '"' + (String(t.id) === String(preselect) ? ' selected' : '') + '>' +
        S.esc(t.name) + '</option>';
    }).join('');

    // Non-superadmins report on their own client only; the name is still needed
    // for the cover title, so the select stays visible but locked.
    sel.disabled = !isSuperAdmin();
    if (!isSuperAdmin() && !sel.value && _tenants.length) sel.value = _tenants[0].id;
  }

  function clientName() {
    var sel = document.getElementById('rpt-client');
    if (sel && sel.selectedIndex >= 0 && sel.options[sel.selectedIndex]) {
      return sel.options[sel.selectedIndex].textContent;
    }
    return (_metrics && _metrics.tenantName) || 'Client';
  }

  // ── Data ──────────────────────────────────────────────────────────────────

  /**
   * Data sources that failed to load on the last fetch, as
   * { key, url, status, message }. Reset at the start of each fetch round.
   *
   * The deck renders a missing source as "No data", which is right — it must
   * never invent a figure. But it made a 403, a 404, a 500 and a genuinely
   * empty table completely indistinguishable, so "why is my vulnerability
   * count blank?" had no answer anywhere in the UI. These are surfaced above
   * the section list after a generate.
   */
  var _fetchProblems = [];

  async function fetchJson(url, key) {
    try {
      var res = await fetch(url, { credentials: 'same-origin' });
      if (!res.ok) {
        var detail = '';
        try {
          var body = await res.json();
          if (body && body.error) detail = body.error;
        } catch (_) { /* not JSON — the status is all we have */ }
        _fetchProblems.push({ key: key || url, url: url, status: res.status, message: detail });
        return null;
      }
      return await res.json();
    } catch (err) {
      _fetchProblems.push({
        key: key || url, url: url, status: 0,
        message: 'could not reach the server',
      });
      return null;
    }
  }

  /** Human-readable account of what failed, or '' if everything loaded. */
  function fetchProblemSummary() {
    if (!_fetchProblems.length) return '';
    var parts = _fetchProblems.map(function (p) {
      var why = p.status === 403 ? 'no permission for this data'
        : p.status === 404 ? 'endpoint not found'
        : p.status === 400 ? (p.message || 'bad request')
        : p.status === 0   ? 'server unreachable'
        : p.status >= 500  ? (p.message || 'server error')
        : (p.message || 'HTTP ' + p.status);
      return p.key + ' (' + why + ')';
    });
    return 'Some data could not be loaded, so those figures show "No data": ' +
      parts.join('; ') + '.';
  }

  /** Fetch only the endpoints the selected sections actually need. */
  async function fetchNeeded(selectedIds, ctx) {
    var keys = [];
    window.ReportSections.forEach(function (s) {
      if (selectedIds.indexOf(s.id) === -1) return;
      // `optional` is fetched but does not gate: a section listing it renders
      // with whatever subset arrived, rather than disabling itself outright.
      s.requires.concat(s.optional || []).forEach(function (k) {
        if (keys.indexOf(k) === -1) keys.push(k);
      });
    });
    // The Observations draft, the Overview tiles and the awareness gauge all read
    // metrics, so pull it (and the Secure Score that feeds it) whenever anything
    // is selected. Neither is in `requires`: a missing Secure Score must not
    // disable the whole Overview slide, it just leaves one tile empty.
    if (selectedIds.length) {
      ['metrics', 'secureScore'].forEach(function (k) {
        if (keys.indexOf(k) === -1) keys.push(k);
      });
    }

    // Fresh slate each round, so a warning never persists from a prior client.
    _fetchProblems = [];

    var pairs = await Promise.all(keys.map(async function (k) {
      return [k, await fetchJson(DATA_SOURCES[k](ctx), k)];
    }));

    var out = {};
    pairs.forEach(function (p) { out[p[0]] = p[1]; });
    out.metrics = mergeSecureScore(out.metrics, out.secureScore);
    return out;
  }

  /** Refresh the derived tile values for the currently selected client/period. */
  async function refreshMetrics() {
    var period = (document.getElementById('rpt-period') || {}).value || '';
    var pair = await Promise.all([
      fetchJson(DATA_SOURCES.metrics({ period: period })),
      fetchJson(DATA_SOURCES.secureScore()),
    ]);
    _metrics = mergeSecureScore(pair[0], pair[1]);
    var p = loadPrefs();
    renderTiles(p);

    var warns = (_metrics && _metrics.warnings) || [];
    if (!pair[1] || pair[1].score == null) {
      warns = warns.concat('No Secure Score available yet — it needs vulnerability, awareness or MDR data.');
    }
    notice(warns.length ? warns.join(' ') : '');
  }

  /** Persist manual overrides. Best-effort — localStorage already has them. */
  async function saveOverrides(period, overrides) {
    if (!canPersist()) return;

    var payload = { period: period, overrides: {} };
    if (isSuperAdmin()) payload.tenantId = selectedTenantId();
    allOverrideIds().forEach(function (id) {
      payload.overrides[id] = overrides[id] != null ? overrides[id] : null;
    });

    try {
      await fetch('api/reports/metrics', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
    } catch (_) { /* the deck does not depend on this succeeding */ }
  }

  /**
   * Pull the Arctic Wolf tiles live and cache them server-side, then re-read.
   * Kept off the generate path: each report can take up to two minutes to build
   * on Arctic Wolf's side.
   */
  async function syncArcticWolf() {
    var btn = document.getElementById('rpt-awsync-btn');
    var period = (document.getElementById('rpt-period') || {}).value || '';
    if (btn) { btn.disabled = true; btn.textContent = 'Refreshing…'; }
    notice('Requesting MONTHLY_EXECUTIVE_TICKET_SUMMARY from Arctic Wolf…');

    try {
      var payload = { period: period };
      if (isSuperAdmin()) payload.tenantId = selectedTenantId();

      var res = await fetch('api/reports/metrics/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      var body = await res.json().catch(function () { return null; });

      if (!res.ok) {
        notice((body && body.error) || 'Arctic Wolf refresh failed.', true);
        return;
      }

      var msgs = [];
      msgs.push('Arctic Wolf: updated ' + (body.written || 0) + ' value' +
                (body.written === 1 ? '' : 's') + '.');
      (body.warnings || []).forEach(function (w) { msgs.push(w); });
      notice(msgs.join(' '), !body.written);

      await refreshMetrics();
    } catch (err) {
      notice('Arctic Wolf refresh failed: ' + err.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Refresh from Arctic Wolf'; }
    }
  }

  // ── Generate ──────────────────────────────────────────────────────────────

  async function generate() {
    var btn = document.getElementById('rpt-generate-btn');
    // Reserved before the data fetch: every source is awaited below, and a
    // window opened after an await loses user activation and is blocked.
    var deckWindow = S.reserveReportWindow({
      width: 1280, height: 820, title: 'Client Report Deck',
    });
    if (!deckWindow) return;
    if (btn) { btn.disabled = true; btn.textContent = 'Building…'; }

    try {
      var prefs = currentPrefs();
      savePrefs(prefs);

      if (isSuperAdmin() && !selectedTenantId()) {
        notice('Select a client before generating a report.', true);
        return;
      }

      var period = prefs.period || new Date().toISOString().slice(0, 7);
      var selected = window.ReportSections
        .filter(function (s) { return prefs.sections[s.id]; })
        .map(function (s) { return s.id; });

      if (!selected.length) {
        notice('Select at least one section to include.', true);
        return;
      }

      var ctx = { period: period, tenantId: selectedTenantId() };
      var data = await fetchNeeded(selected, ctx);
      if (data.metrics) _metrics = data.metrics;

      // Overrides typed in the tab win over anything the server returned.
      if (data.metrics && data.metrics.tiles) {
        Object.keys(prefs.overrides).forEach(function (id) {
          if (data.metrics.tiles[id]) data.metrics.tiles[id].override = prefs.overrides[id];
          else data.metrics.tiles[id] = { derived: null, source: 'manual', override: prefs.overrides[id] };
        });
      }

      var now = new Date();
      var full = {
        clientName:  clientName(),
        period:      period,
        periodLabel: periodLabel(period),
        author:      prefs.author || defaultAuthor(),
        dateStr:     now.toISOString().slice(0, 10).replace(/-/g, '/'),
        year:        now.getFullYear(),
        tenantId:    selectedTenantId(),
        narrative:   prefs.narrative,
        assurance:   prefs.assurance,
        execSummary: prefs.execSummary,
        comments:    prefs.comments || {},
        overrides:   prefs.overrides,
        data:        data,
        logoDataUri: await S.logoToDataUri(),
        P:           S.PALETTE,
      };

      var slides  = [D.coverSlide(full)];
      var skipped = [];

      window.ReportSections.forEach(function (s) {
        if (selected.indexOf(s.id) === -1) return;

        var missing = s.requires.some(function (k) { return full.data[k] == null; });
        if (missing) { skipped.push(s.label); return; }

        var body = null;
        try { body = s.render(full); }
        catch (err) { body = null; }

        if (!body) { skipped.push(s.label); return; }

        // A section may return one body, or an array of bodies when its content
        // does not fit a single fixed-height slide (slides never scroll — see
        // .slide overflow:hidden in report-deck.js). Each body becomes a page.
        var bodies = Array.isArray(body) ? body.filter(Boolean) : [body];
        if (!bodies.length) { skipped.push(s.label); return; }

        bodies.forEach(function (b) {
          slides.push(D.slide({ title: s.label, body: b, pageNo: slides.length + 1, ctx: full }));
        });
      });

      var msgs = [];
      // Load failures first: they explain the blanks the other messages report,
      // and are the difference between "this client has no scan" and "the
      // request was refused".
      var problems = fetchProblemSummary();
      if (problems) msgs.push(problems);
      if (skipped.length) msgs.push('Skipped: ' + skipped.join(', ') + ' (no data).');
      (_metrics && _metrics.warnings || []).forEach(function (w) { msgs.push(w); });
      notice(msgs.join(' '), !!problems);

      deckWindow.write(D.renderDeck(slides, full));

      saveOverrides(period, prefs.overrides);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Generate Deck'; }
    }
  }

  async function redraftNarrative() {
    var period = (document.getElementById('rpt-period') || {}).value || '';
    var ctx = { period: period, tenantId: selectedTenantId() };
    var data = await fetchNeeded(
      ['execSummary', 'humanRisk', 'threatLandscape', 'vulnDashboard'], ctx);
    var el = document.getElementById('rpt-narrative');
    if (!el) return;
    el.value = window.ReportSections.draftObservations({
      clientName:  clientName(),
      periodLabel: periodLabel(period),
      tenantId:    selectedTenantId(),
      data:        data,
    });
  }

  async function redraftAssurance() {
    var period = (document.getElementById('rpt-period') || {}).value || '';
    var ctx = { period: period, tenantId: selectedTenantId() };
    var data = await fetchNeeded(
      ['execRisk', 'businessImpact', 'assuranceDashboard'], ctx);
    var el = document.getElementById('rpt-assurance');
    if (!el) return;

    // The attested figures live in the form, not the server response, so fold
    // the typed overrides in before drafting.
    var prefs = currentPrefs();
    if (data.metrics && data.metrics.tiles) {
      Object.keys(prefs.overrides).forEach(function (id) {
        if (data.metrics.tiles[id]) data.metrics.tiles[id].override = prefs.overrides[id];
        else data.metrics.tiles[id] = { derived: null, source: 'manual', override: prefs.overrides[id] };
      });
    }

    el.value = window.ReportSections.draftAssurance({
      clientName:  clientName(),
      periodLabel: periodLabel(period),
      period:      period,
      tenantId:    selectedTenantId(),
      data:        data,
    });
  }

  async function redraftExecSummary() {
    var period = (document.getElementById('rpt-period') || {}).value || '';
    var ctx = { period: period, tenantId: selectedTenantId() };
    var data = await fetchNeeded(
      ['execSummary', 'assuranceDashboard', 'businessImpact', 'humanRisk'], ctx);
    var el = document.getElementById('rpt-exec-summary');
    if (!el) return;
    el.value = window.ReportSections.draftExecSummary({
      clientName:  clientName(),
      period:      period,
      periodLabel: periodLabel(period),
      tenantId:    selectedTenantId(),
      data:        data,
    });
  }

  function reset() {
    try { localStorage.removeItem(storageKey()); } catch (_) {}
    _rendered = false;
    loadAndRender();
  }

  // ── Entry point ───────────────────────────────────────────────────────────

  async function loadAndRender() {
    var prefs = loadPrefs();

    if (!_rendered) {
      var periodEl = document.getElementById('rpt-period');
      if (periodEl) periodEl.value = prefs.period || new Date().toISOString().slice(0, 7);

      var authorEl = document.getElementById('rpt-author');
      if (authorEl) authorEl.value = prefs.author || defaultAuthor();

      var narrEl = document.getElementById('rpt-narrative');
      if (narrEl) narrEl.value = prefs.narrative || '';

      var assurEl = document.getElementById('rpt-assurance');
      if (assurEl) assurEl.value = prefs.assurance || '';

      var execEl = document.getElementById('rpt-exec-summary');
      if (execEl) execEl.value = prefs.execSummary || '';

      renderCommentBoxes(prefs);

      renderSectionToggles(prefs);

      await populateClients(prefs);

      var gen = document.getElementById('rpt-generate-btn');
      if (gen) gen.onclick = generate;

      var rst = document.getElementById('rpt-reset-btn');
      if (rst) rst.onclick = reset;

      // The sync + override-persistence routes are requireAdmin; data-admin-only
      // hides for readonly alone, so gate the rest of the roles explicitly.
      var awsync = document.getElementById('rpt-awsync-btn');
      if (awsync) {
        if (canPersist()) awsync.onclick = syncArcticWolf;
        else {
          var wrap = awsync.closest ? awsync.closest('.rpt-tile-actions') : null;
          (wrap || awsync).hidden = true;
        }
      }

      var draft = document.getElementById('rpt-redraft-btn');
      if (draft) draft.onclick = function () {
        draft.disabled = true;
        redraftNarrative().finally(function () { draft.disabled = false; });
      };

      var draftE = document.getElementById('rpt-redraft-exec-btn');
      if (draftE) draftE.onclick = function () {
        draftE.disabled = true;
        redraftExecSummary().finally(function () { draftE.disabled = false; });
      };

      var draftA = document.getElementById('rpt-redraft-assurance-btn');
      if (draftA) draftA.onclick = function () {
        draftA.disabled = true;
        redraftAssurance().finally(function () { draftA.disabled = false; });
      };

      // Switching client switches the localStorage bucket too, so re-apply that
      // client's saved toggles and narrative alongside the new metrics.
      var clientEl = document.getElementById('rpt-client');
      if (clientEl) clientEl.onchange = function () {
        var p = loadPrefs();
        renderSectionToggles(p);
        var n = document.getElementById('rpt-narrative');
        if (n) n.value = p.narrative || '';
        var a = document.getElementById('rpt-assurance');
        if (a) a.value = p.assurance || '';
        var e = document.getElementById('rpt-exec-summary');
        if (e) e.value = p.execSummary || '';
        _comments = {};
        renderCommentBoxes(p);
        refreshMetrics();
      };

      if (periodEl) periodEl.onchange = refreshMetrics;

      _rendered = true;
    }

    await refreshMetrics();
  }

  return { loadAndRender: loadAndRender };
})();
