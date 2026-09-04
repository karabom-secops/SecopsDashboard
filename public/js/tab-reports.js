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
    // Latest FortiGate configuration audit. The config itself was never stored;
    // this is the findings.
    firewall:         function () { return 'api/firewall/audits/latest' + tenantParam('?'); },
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

    /*
     * THE IN-SCOPE SCORE, NOT THE OVERALL.
     *
     * This read `secureScore.score` — the overall composite, which counts
     * controls the client never bought as zero. The Executive Summary of the
     * same deck reports the in-scope score, so the two disagreed: 55 here and
     * 47 there, from one payload, with nothing on either to say why. An
     * analyst's only recourse was to type the right number into the override
     * box, which is a fix that lasts until the next person forgets.
     *
     * ReportSections.headlineScore owns the rule. Deriving it again here is
     * how they drifted apart in the first place.
     */
    var R = window.ReportSections;
    var head = R && R.headlineScore
      ? R.headlineScore(secureScore)
      : null;
    if (!head || head.score == null) return metrics;

    t.derived = head.score;
    t.source  = 'secure-score';
    t.scoped  = head.scoped;
    if (head.rating) t.rating = head.rating;
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

  /**
   * The services this client consumes, or null when nobody has recorded them.
   *
   * Comes from GET /api/tenants, which is already fetched for the client
   * dropdown, so pre-selecting the deck costs no extra request.
   */
  var _tenantServices = null;
  var _servicesKnown  = false;
  var _withheldSources = [];

  function readTenantServices() {
    var id = selectedTenantId();
    var t = (_tenants || []).filter(function (x) { return String(x.id) === String(id); })[0];
    // Array vs null is the whole distinction: null means "not recorded", and
    // an empty array means "recorded as none". They must not collapse.
    _servicesKnown  = !!(t && Array.isArray(t.services));
    // The EFFECTIVE set decides which sections are offered: MDR includes
    // endpoint, network and identity detection, so an MDR client should be
    // offered those sections without having ticked those boxes. The server
    // expands it — the rule lives in lib/services.js and only there.
    _tenantServices = _servicesKnown
      ? (Array.isArray(t.effectiveServices) ? t.effectiveServices : t.services)
      : null;
  }

  function renderSectionToggles(prefs) {
    var host = document.getElementById('rpt-sections');
    if (!host) return;
    readTenantServices();

    var groups = [];
    var byGroup = {};
    window.ReportSections.forEach(function (s) {
      if (!byGroup[s.group]) { byGroup[s.group] = []; groups.push(s.group); }
      byGroup[s.group].push(s);
    });

    /*
     * What this client buys decides the STARTING tick-state.
     *
     * A client who only buys awareness training got "Vulnerability Dashboard"
     * ticked by default and a slide reading "no data" — which a board reads as
     * a failing control rather than a service they never purchased.
     *
     * Precedence, and the order matters:
     *   1. an explicit saved choice for this client wins, always;
     *   2. otherwise the recorded service mix decides;
     *   3. and where no service mix has been recorded, everything is offered,
     *      exactly as before this existed.
     * So this never silently overrides an analyst who has already chosen.
     */
    var byService = window.ReportSections.defaultSectionsFor
      ? window.ReportSections.defaultSectionsFor(_tenantServices)
      : null;

    var auto = 0;
    host.innerHTML = groups.map(function (g) {
      return '<div class="rpt-group">' +
          '<div class="rpt-group-label">' + S.esc(g) + '</div>' +
          byGroup[g].map(function (s) {
            var saved = prefs.sections && prefs.sections[s.id] !== undefined
              ? prefs.sections[s.id] : null;
            var suggested = byService && byService[s.id] !== undefined ? byService[s.id] : true;
            var on = saved !== null ? saved : suggested;

            // Flag only where the service mix turned something OFF that would
            // otherwise be on — that is the change worth explaining.
            var offByService = _servicesKnown && !suggested;
            if (offByService && saved === null) auto++;

            // Disabled, not merely tagged. assembleDeck() refuses to build a
            // section for a service the client does not consume, so a tickable
            // box here would be a control that silently does nothing — which
            // is worse than no control at all.
            return '<label class="rpt-section-row' + (offByService ? ' rpt-section-na' : '') + '">' +
                '<span class="integration-toggle">' +
                  '<input type="checkbox" id="rpt-sec-' + s.id + '"' +
                    (on && !offByService ? ' checked' : '') +
                    (offByService ? ' disabled' : '') + '>' +
                  '<span class="int-toggle-slider"></span>' +
                '</span>' +
                '<span class="rpt-section-name">' + s.n + '. ' + S.esc(s.label) + '</span>' +
                (offByService
                  ? '<span class="rpt-section-tag" title="This client does not consume the service this section reports on. Record the service on the Admin tab to include it.">not subscribed</span>'
                  : '') +
              '</label>';
          }).join('') +
        '</div>';
    }).join('');

    var note = document.getElementById('rpt-sections-note');
    if (note) {
      if (!_servicesKnown) {
        note.textContent = 'No services recorded for this client, so every section is offered. ' +
          'Record them on the Admin tab and the deck will pre-select itself.';
        note.hidden = false;
      } else if (auto) {
        note.textContent = auto + ' section' + (auto === 1 ? '' : 's') +
          ' switched off automatically — this client does not subscribe to those services. ' +
          'Tick any of them to include it anyway.';
        note.hidden = false;
      } else {
        note.hidden = true;
      }
    }
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
          // Which score this is, when it is the scoped one. Without it, a
          // Secure Score tile reading 47 beside a Secure Score tab reading 55
          // looks like a bug, and the analyst "corrects" it by hand.
          '<div class="rpt-tile-derived">Derived: <b>' +
            S.esc(derived == null ? 'no data' : derived) + '</b>' +
            (info.scoped ? '<span class="rpt-tile-qual"> &middot; services in scope</span>' : '') +
          '</div>' +
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

  /**
   * Which service each data source belongs to.
   *
   * THE ENFORCEMENT POINT FOR THE WHOLE DECK.
   *
   * Gating sections was not enough, because sections draw across service
   * boundaries: the Cyber Risk Heat Map is a vISO deliverable built from
   * VULNERABILITY findings, Threat Landscape mixes vulnerability and MDR data,
   * Risk Appetite pulls EDR, identity and vulnerability data. A client on vISO
   * alone would have received a heat map and a business-impact analysis built
   * entirely from scan data they do not buy.
   *
   * So the data is withheld at the source rather than filtered at each of a
   * dozen render functions. The existing machinery then does the rest: a
   * section whose `requires` are missing self-disables, and one whose
   * `optional` extras are missing renders without them. Both behaviours are
   * already in place and already tested — nothing here needs a new rule.
   *
   * `null` means the source is not tied to any service and is always fetched.
   */
  var SOURCE_SERVICE = {
    vulnFindings:       'vuln',
    vulnSummary:        'vuln',
    vulnTrends:         'vuln',
    mdr:                'mdr',
    edr:                'edr',
    o365:               'identity',
    awareness:          'awareness',
    vendors:            'viso',
    grcAssessment:      'viso',
    grcQuestions:       'viso',
    firewall:           'firewall',
    secureScore:        null,
    secureScoreHistory: null,
    metrics:            null,
  };

  /**
   * True when the client consumes the service behind this data source.
   *
   * `services`/`known` default to the module's state but can be passed in, so
   * the rule is a pure function a test can drive directly. Without that seam a
   * suite can only assert the code EXISTS — which is what an earlier version of
   * the deck audit did, reimplementing this logic itself and therefore passing
   * happily with the real withholding disabled.
   */
  function sourceInScope(key, services, known) {
    var isKnown = known === undefined ? _servicesKnown : known;
    var list    = services === undefined ? _tenantServices : services;
    if (!isKnown) return true;                 // unrecorded => unchanged
    var svc = SOURCE_SERVICE[key];
    if (svc === null || svc === undefined) return true;
    return (list || []).indexOf(svc) >= 0;
  }

  /** Fetch only the endpoints the selected sections actually need. */
  async function fetchNeeded(selectedIds, ctx) {
    var keys = [];
    var withheld = [];
    window.ReportSections.forEach(function (s) {
      if (selectedIds.indexOf(s.id) === -1) return;
      // `optional` is fetched but does not gate: a section listing it renders
      // with whatever subset arrived, rather than disabling itself outright.
      s.requires.concat(s.optional || []).forEach(function (k) {
        if (!sourceInScope(k)) {
          if (withheld.indexOf(k) === -1) withheld.push(k);
          return;
        }
        if (keys.indexOf(k) === -1) keys.push(k);
      });
    });
    _withheldSources = withheld;
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

  /**
   * Gather the data, apply the overrides and render every selected section to
   * HTML. Shared by the on-screen deck and the PowerPoint download so the two
   * can never be built from different data, different overrides, or a different
   * idea of which sections were skipped.
   *
   * Returns null when the user has to fix something first; the reason is already
   * on screen via notice().
   */
  async function assembleDeck() {
    var prefs = currentPrefs();
    savePrefs(prefs);

    if (isSuperAdmin() && !selectedTenantId()) {
      notice('Select a client before generating a report.', true);
      return null;
    }

    var period = prefs.period || new Date().toISOString().slice(0, 7);

    // Re-read before anything is fetched: the client may have changed since
    // the toggles were last rendered, and every gate below depends on it.
    readTenantServices();

    /*
     * A section for a service the client does not buy is not built, whatever
     * the toggle says.
     *
     * This used to be a default the analyst could override. It is now a rule:
     * the instruction is that the deck shows only what the client consumes,
     * and a starting point that can be silently overridden is not that. The
     * toggle for such a section is disabled in the UI, so nothing is
     * mysteriously ignored.
     */
    var notSubscribed = [];
    var selected = window.ReportSections
      .filter(function (s) {
        if (!prefs.sections[s.id]) return false;
        if (!_servicesKnown || !s.services) return true;
        var covered = s.services.some(function (k) {
          return (_tenantServices || []).indexOf(k) >= 0;
        });
        if (!covered) notSubscribed.push(s.label);
        return covered;
      })
      .map(function (s) { return s.id; });

    if (!selected.length) {
      notice(notSubscribed.length
        ? 'Every selected section belongs to a service this client does not consume.'
        : 'Select at least one section to include.', true);
      return null;
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

    var rendered = [];
    var skipped  = [];

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

      rendered.push({ label: s.label, bodies: bodies });
    });

    var msgs = [];
    // Load failures first: they explain the blanks the other messages report,
    // and are the difference between "this client has no scan" and "the
    // request was refused".
    var problems = fetchProblemSummary();
    if (problems) msgs.push(problems);
    if (skipped.length) msgs.push('Skipped: ' + skipped.join(', ') + ' (no data).');
    // Named separately from 'no data': an analyst chasing a missing upload for
    // a service the client never bought is chasing something that will never
    // arrive.
    if (notSubscribed.length) {
      msgs.push('Not included: ' + notSubscribed.join(', ') +
        ' (service not consumed by this client).');
    }
    (_metrics && _metrics.warnings || []).forEach(function (w) { msgs.push(w); });

    saveOverrides(period, prefs.overrides);

    return { full: full, rendered: rendered, msgs: msgs, problems: !!problems };
  }

  /**
   * The deck as an array of slide HTML strings, cover first.
   *
   * Shared by Generate and Publish so the archived document is byte-identical
   * to the one staff previewed. It also stops the two paths disagreeing about
   * the SHAPE of a slide list: renderDeck() takes rendered HTML, not the
   * {label, bodies} records assembleDeck() returns, and passing the latter
   * silently stringifies to "[object Object]" and produces a blank deck.
   */
  function buildSlides(model) {
    var slides = [D.coverSlide(model.full)];
    model.rendered.forEach(function (sec) {
      sec.bodies.forEach(function (b) {
        slides.push(D.slide({
          title: sec.label, body: b, pageNo: slides.length + 1, ctx: model.full,
        }));
      });
    });
    return slides;
  }

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
      var model = await assembleDeck();
      if (!model) { deckWindow.fail('Nothing to render.'); return; }

      notice(model.msgs.join(' '), model.problems);

      deckWindow.write(D.renderDeck(buildSlides(model), model.full));
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Generate Deck'; }
    }
  }

  /**
   * The same deck as an editable PowerPoint file.
   *
   * The section HTML is rendered here and POSTed; lib/report-pptx.js on the
   * server translates it into native slides. Nothing about the deck's content is
   * recomputed there, so the .pptx and the on-screen deck cannot disagree.
   *
   * No window is reserved: this is a download, not a popup, so it is immune to
   * the popup-blocker problem that shapes generate().
   */
  async function downloadPptx() {
    var btn = document.getElementById('rpt-pptx-btn');
    var label = btn ? btn.textContent : '';
    if (btn) { btn.disabled = true; btn.textContent = 'Building…'; }

    try {
      var model = await assembleDeck();
      if (!model) return;

      if (!model.rendered.length) {
        notice('No section produced any content to export.', true);
        return;
      }

      var res = await fetch('api/reports/pptx', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ctx: {
            clientName:  model.full.clientName,
            period:      model.full.period,
            periodLabel: model.full.periodLabel,
            author:      model.full.author,
            dateStr:     model.full.dateStr,
          },
          sections: model.rendered,
        }),
      });

      if (!res.ok) {
        // The error body is JSON on a handled failure and HTML on a crash —
        // never assume, or the user gets "[object Object]" as the reason.
        var reason = 'HTTP ' + res.status;
        try {
          var j = await res.json();
          if (j && j.error) reason = j.error;
        } catch (e) { /* keep the status */ }
        notice('PowerPoint export failed: ' + reason, true);
        return;
      }

      var blob = await res.blob();
      var name = filenameFrom(res.headers.get('Content-Disposition')) ||
        ((model.full.clientName || 'Client').replace(/[^A-Za-z0-9._-]+/g, '-') +
         '-Cybersecurity-Board-Report-' + (model.full.period || '') + '.pptx');

      S.downloadFile(name, blob,
        'application/vnd.openxmlformats-officedocument.presentationml.presentation');

      var slides = res.headers.get('X-Pptx-Slides');
      notice(model.msgs.concat(
        ['PowerPoint downloaded' + (slides ? ' (' + slides + ' slides)' : '') + '.']
      ).join(' '), model.problems);
    } catch (err) {
      notice('PowerPoint export failed: ' + err.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = label || 'Download PowerPoint'; }
    }
  }

  /* ── Publishing to the client portal ────────────────────────────────────
     Publish and download both go through the SAME assembleDeck() call. That is
     the guarantee the archived artefact is exactly the deck that was previewed:
     re-fetching at publish time would let the stored report differ from the one
     someone approved, and nobody would ever know. */

  async function publishReport() {
    var btn = document.getElementById('rpt-publish-btn');
    var label = btn ? btn.textContent : '';

    var note = window.prompt(
      'Publish this report to the client portal?\n\n' +
      'They will be able to download it immediately. Add a short note to show ' +
      'alongside it (optional):', '');
    if (note === null) return;   // cancelled

    if (btn) { btn.disabled = true; btn.textContent = 'Publishing…'; }
    try {
      var model = await assembleDeck();
      if (!model) return;
      if (!model.rendered.length) {
        notice('No section produced any content to publish.', true);
        return;
      }

      var body = {
        period: model.full.period,
        title: model.full.periodLabel || model.full.period,
        coverNote: note,
        ctx: {
          clientName:  model.full.clientName,
          period:      model.full.period,
          periodLabel: model.full.periodLabel,
          author:      model.full.author,
          dateStr:     model.full.dateStr,
        },
        sections: model.rendered,
      };

      // The viewable artefact, so a client without PowerPoint can still read
      // it — and so there is a record of what was published, which a pptx
      // regenerated later from `sections` would not be.
      //
      // buildSlides() is the same call Generate makes. Passing model.rendered
      // straight to renderDeck() is what shipped first, and it archived a deck
      // whose only visible content was "[object Object]" — so the document is
      // checked here rather than trusted.
      var deckHtml = D.renderDeck(buildSlides(model), model.full);
      if (deckHtml.indexOf('[object Object]') > -1) {
        notice('Publish aborted: the deck did not render. Nothing was published.', true);
        return;
      }
      if (deckHtml.indexOf('</head>') === -1) {
        notice('Publish aborted: the deck is not a complete document.', true);
        return;
      }
      body.deckHtml = deckHtml;

      var res = await fetch('api/reports/publish' + tenantParam('?'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(Object.assign(body, tenantBodyFields())),
      });

      var data = null;
      try { data = await res.json(); } catch (e) { data = null; }
      if (!res.ok) {
        notice('Publish failed: ' + ((data && data.error) || 'HTTP ' + res.status), true);
        return;
      }

      var pub = data.publication || {};
      notice('Published to the client portal as ' +
        (pub.period || '') + ' v' + (pub.version || 1) + '.', false);
      renderPublications();
    } catch (err) {
      notice('Publish failed: ' + err.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = label || 'Publish to client'; }
    }
  }

  /** Superadmin must name the tenant in the body; everyone else is pinned. */
  function tenantBodyFields() {
    if (!isSuperAdmin()) return {};
    var el = document.getElementById('rpt-client');
    var id = el && el.value ? el.value : window.globalTenantId;
    return id ? { tenantId: id } : {};
  }

  /** The archive for the selected client: what the portal is showing them. */
  async function renderPublications() {
    var host = document.getElementById('rpt-publications');
    if (!host) return;

    try {
      var res = await fetch('api/reports/publications' + tenantParam('?'),
        { credentials: 'same-origin' });
      if (!res.ok) {
        var j = await res.json().catch(function () { return {}; });
        host.innerHTML = '<p class="rpt-pub-empty">' +
          S.esc(j.error || 'Could not load published reports.') + '</p>';
        return;
      }
      var data = await res.json();
      var rows = data.publications || [];

      if (!rows.length) {
        host.innerHTML = '<p class="rpt-pub-empty">Nothing published to this client yet.</p>';
        return;
      }

      host.innerHTML =
        '<table class="data-table rpt-pub-table"><thead><tr>' +
          '<th scope="col">Period</th><th scope="col">Version</th>' +
          '<th scope="col">Published</th><th scope="col">Status</th>' +
          '<th scope="col">Downloads</th><th scope="col"></th>' +
        '</tr></thead><tbody>' +
        rows.map(function (r) {
          var qs = tenantParam('?');
          var base = 'api/reports/publications/' + encodeURIComponent(r.id);
          return '<tr' + (r.status === 'withdrawn' ? ' class="rpt-pub-withdrawn"' : '') + '>' +
            '<td>' + S.esc(r.period_label || r.period) +
              (r.isLatest ? '' : ' <span class="rpt-pub-tag">superseded</span>') + '</td>' +
            '<td>v' + S.esc(r.version) + '</td>' +
            '<td>' + S.esc(new Date(r.published_at).toLocaleDateString('en-ZA')) + '</td>' +
            '<td>' + S.esc(r.status === 'withdrawn' ? 'Withdrawn' : 'Published') + '</td>' +
            '<td>' + S.esc(r.download_count || 0) + '</td>' +
            '<td class="rpt-pub-actions">' +
              '<a class="btn btn-secondary btn-sm" href="' + base + '/pptx' + qs + '">Download</a> ' +
              (r.has_html
                ? '<a class="btn btn-secondary btn-sm" target="_blank" rel="noopener" href="' +
                  base + '/view' + qs + '">View</a> ' : '') +
              (r.status === 'published'
                ? '<button type="button" class="btn btn-danger btn-sm rpt-withdraw" data-id="' +
                  S.esc(r.id) + '">Withdraw</button>' : '') +
            '</td></tr>';
        }).join('') +
        '</tbody></table>';

      host.querySelectorAll('.rpt-withdraw').forEach(function (b) {
        b.addEventListener('click', function () { withdraw(b.dataset.id); });
      });
    } catch (err) {
      host.innerHTML = '<p class="rpt-pub-empty">' + S.esc(err.message) + '</p>';
    }
  }

  async function withdraw(id) {
    var reason = window.prompt(
      'Withdraw this report?\n\nThe client will no longer see it. ' +
      'Why is it being withdrawn?', '');
    if (reason === null) return;
    if (!reason.trim()) { notice('A reason is required to withdraw a report.', true); return; }

    try {
      var res = await fetch('api/reports/publications/' + encodeURIComponent(id) + '/withdraw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(Object.assign({ reason: reason }, tenantBodyFields())),
      });
      var j = await res.json().catch(function () { return {}; });
      if (!res.ok) { notice('Withdraw failed: ' + (j.error || res.status), true); return; }
      notice('Report withdrawn. The client can no longer see it.', false);
      renderPublications();
    } catch (err) {
      notice('Withdraw failed: ' + err.message, true);
    }
  }

  /** Pull the filename out of a Content-Disposition header, if it has one. */
  function filenameFrom(header) {
    var m = /filename="?([^";]+)"?/.exec(header || '');
    return m ? m[1] : null;
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

      // Clients first: the section toggles pre-select from the selected
      // client's recorded services, and populateClients is what loads them.
      // Rendering the toggles first left _tenants empty, so every client
      // looked unconfigured on the first paint and nothing was pre-selected.
      await populateClients(prefs);

      renderSectionToggles(prefs);

      var gen = document.getElementById('rpt-generate-btn');
      if (gen) gen.onclick = generate;

      var pptx = document.getElementById('rpt-pptx-btn');
      if (pptx) pptx.onclick = downloadPptx;

      // Publishing writes to the archive the client portal reads, so it needs
      // write on the reports page — the same gate the server enforces.
      // The button ships hidden in the markup so it never flashes for a reader
      // who cannot use it — which means the writable branch has to REVEAL it.
      // Setting only the handler leaves it hidden for everyone, which is how it
      // stayed invisible until now.
      var pub = document.getElementById('rpt-publish-btn');
      if (pub) {
        pub.hidden = !canPersist();
        if (canPersist()) pub.onclick = publishReport;
      }

      // Without this, a readonly user sits on a permanent "Loading…" for an
      // archive that is never fetched.
      var pubWrap = document.getElementById('rpt-published-wrap');
      if (pubWrap) pubWrap.hidden = !canPersist();
      if (canPersist()) renderPublications();

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
        // The archive is per-tenant. Leaving the previous client's table on
        // screen would not just mislead — its Withdraw buttons carry that
        // client's publication ids, so a click would retract the wrong report.
        if (canPersist()) renderPublications();
        refreshMetrics();
      };

      if (periodEl) periodEl.onchange = refreshMetrics;

      _rendered = true;
    }

    await refreshMetrics();
  }

  return {
    loadAndRender: loadAndRender,
    // Test seam: the withholding rule the whole deck depends on, exposed so a
    // suite can drive the real function instead of restating it.
    sourceInScope: sourceInScope,
    SOURCE_SERVICE: SOURCE_SERVICE,
  };
})();
