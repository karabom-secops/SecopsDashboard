/* tab-firewall.js — FortiGate configuration audit.
 *
 * Upload a backup, get a scored posture review. The analyst view: full detail,
 * including the evidence the client-facing report and portal withhold.
 *
 * THE FILE IS NOT STORED ANYWHERE. It is posted, parsed in memory on the
 * server, audited and dropped. This page says so, because an analyst about to
 * ask a client for their firewall config needs to be able to answer "where does
 * it go" with something better than "I think it's fine".
 */

window.FirewallTab = (function () {
  'use strict';

  var BASE = (function () {
    var base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) { return BASE + 'api/' + path; }

  var SEV_ORDER = ['critical', 'high', 'medium', 'low'];

  var _audit = null;
  var _history = [];
  var _msg = null;
  var _view = 'current';
  var _parseNote = null;

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function canUpload() {
    return typeof window.canWrite === 'function' ? window.canWrite('firewall') : false;
  }

  function tenantParam(sep) {
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  async function get(path) {
    var res = await fetch(apiUrl(path), { credentials: 'same-origin' });
    var j = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(j.error || ('HTTP ' + res.status));
    return j;
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  function scoreBlock(a) {
    // NULL IS NOT ZERO. A config where nothing could be assessed has no score;
    // printing 0 would say the firewall failed everything.
    var score = a.score == null
      ? '<span class="fw-nd">Not assessed</span>'
      : esc(a.score) + '<span class="fw-of">/100</span>';

    var d = a.device || {};
    return '<div class="fw-head">' +
        '<div class="fw-score fw-' + esc((a.band && a.band.key) || 'unknown') + '">' +
          '<div class="fw-score-v">' + score + '</div>' +
          '<div class="fw-score-l">' + esc((a.band && a.band.label) || '') + '</div>' +
        '</div>' +
        '<div class="fw-meta">' +
          '<div class="fw-device">' + esc(d.name || 'Unnamed device') +
            (d.model ? ' &middot; ' + esc(d.model) : '') +
            (d.firmware ? ' &middot; FortiOS ' + esc(d.firmware) : '') + '</div>' +
          '<div class="fw-sub">' +
            esc(a.failed) + ' finding' + (a.failed === 1 ? '' : 's') + ' &middot; ' +
            esc(a.passed) + ' passed &middot; ' +
            esc(a.notAssessable) + ' not assessable' +
          '</div>' +
          '<div class="fw-sub">Scored against ' + esc(a.assessed) + ' of ' +
            esc(a.totalChecks) + ' checks (' + esc(a.coverage) + '% coverage) &middot; ' +
            'uploaded ' + esc(a.uploadedAt ? new Date(a.uploadedAt).toLocaleString() : '') +
            (a.uploadedBy ? ' by ' + esc(a.uploadedBy) : '') + '</div>' +
        '</div>' +
      '</div>' +
      maskNotice(a) +
      parseNotice() +
      unreadNotice(a);
  }

  /**
   * Whether the config appeared password-masked. TRI-STATE, and it says which.
   *
   * A guess presented as a fact here either sends someone rotating credentials
   * needlessly, or tells them a file was safe when nobody actually knows.
   */
  function maskNotice(a) {
    if (a.appearedMasked === true) {
      return '<div class="fw-note fw-good">This configuration appeared to be ' +
        'password-masked. It was not stored either way.</div>';
    }
    if (a.appearedMasked === false) {
      return '<div class="fw-note fw-bad"><strong>This configuration appeared NOT ' +
        'to be password-masked.</strong> It has not been stored — only these ' +
        'findings were — but it passed through a browser and this server. Have the ' +
        'client rotate the credentials it contained, and ask them to tick ' +
        '&ldquo;Password mask&rdquo; on the backup screen next time.</div>';
    }
    return '<div class="fw-note">Whether this configuration was password-masked ' +
      'could not be determined.</div>';
  }

  /* Where the export was not valid YAML and had to be repaired to be read. */
  function parseNotice() {
    if (!_parseNote) return '';
    return '<div class="fw-note">' + esc(_parseNote) + '</div>';
  }

  function unreadNotice(a) {
    var u = a.unreadSections || [];
    if (!u.length) return '';
    return '<div class="fw-note">' + esc(u.length) + ' configuration section(s) ' +
      'were present but are outside what this audit reads: <code>' +
      u.map(esc).join('</code>, <code>') + '</code>. Findings cover the rest — ' +
      'the score is not a statement about these.</div>';
  }

  function findingRow(f) {
    var badge = f.status === 'fail' ? 'fw-fail'
              : f.status === 'pass' ? 'fw-pass' : 'fw-na';
    var label = f.status === 'fail' ? 'Finding'
              : f.status === 'pass' ? 'Pass' : 'Not assessable';

    // Evidence: identifiers and counts. The server redacts anything that looks
    // like a secret before it is stored, and the checks are written not to put
    // one here in the first place.
    var ev = '';
    if (f.evidence && typeof f.evidence === 'object') {
      var bits = Object.keys(f.evidence).map(function (k) {
        var v = f.evidence[k];
        return esc(k) + ': ' + esc(Array.isArray(v) ? v.join(', ') : JSON.stringify(v));
      });
      if (bits.length) ev = '<div class="fw-ev">' + bits.join(' &middot; ') + '</div>';
    }

    return '<div class="fw-f fw-sev-' + esc(f.severity) + '">' +
        '<div class="fw-f-top">' +
          '<span class="fw-badge ' + badge + '">' + esc(label) + '</span>' +
          '<span class="fw-sev">' + esc(f.severity) + '</span>' +
          '<span class="fw-f-t">' + esc(f.title) + '</span>' +
          (f.cis ? '<span class="fw-ref">CIS ' + esc(f.cis) + '</span>'
                 : '<span class="fw-ref fw-own">Reflex</span>') +
        '</div>' +
        (f.detail ? '<div class="fw-f-d">' + esc(f.detail) + '</div>' : '') +
        ev +
        '<div class="fw-f-r"><strong>Why:</strong> ' + esc(f.rationale) + '</div>' +
        (f.status === 'pass' ? '' :
          '<div class="fw-f-r"><strong>Fix:</strong> ' + esc(f.remediation) + '</div>') +
      '</div>';
  }

  function findingsBlock(a) {
    var all = a.findings || [];
    var fails = all.filter(function (f) { return f.status === 'fail'; });
    var na    = all.filter(function (f) { return f.status === 'not-assessable'; });
    var pass  = all.filter(function (f) { return f.status === 'pass'; });

    fails.sort(function (x, y) {
      return SEV_ORDER.indexOf(x.severity) - SEV_ORDER.indexOf(y.severity);
    });

    return '<h3 class="fw-h">Findings (' + esc(fails.length) + ')</h3>' +
      (fails.length ? fails.map(findingRow).join('')
        : '<div class="fw-note fw-good">Every check that could be evaluated passed.</div>') +

      /*
       * Not-assessable gets its own section rather than being mixed into the
       * findings or hidden away. It is the honest boundary of the audit: these
       * are the things nobody has checked, and a reader who does not see them
       * will assume they passed.
       */
      (na.length ? '<h3 class="fw-h">Could not be assessed (' + esc(na.length) + ')</h3>' +
        '<p class="fw-note">Excluded from the score rather than counted against it. ' +
        'Confirm these on the device.</p>' +
        na.map(findingRow).join('') : '') +

      (pass.length ? '<h3 class="fw-h">Passed (' + esc(pass.length) + ')</h3>' +
        pass.map(findingRow).join('') : '');
  }

  function uploadBlock() {
    if (!canUpload()) return '';
    return '<div class="admin-card fw-upload">' +
        '<h3 class="admin-card-title">Upload a configuration</h3>' +
        '<p class="admin-card-hint">On the FortiGate: click the admin name ' +
          'top-right &rarr; <strong>Configuration &rarr; Backup</strong> &rarr; ' +
          'Backup to <strong>Local PC</strong> &rarr; File format ' +
          '<strong>YAML</strong> &rarr; tick <strong>Password mask</strong> &rarr; OK.</p>' +
        // Stated on the page, not just in a policy document somewhere.
        '<p class="fw-note fw-good"><strong>The file is not stored.</strong> It is ' +
          'parsed in memory, audited, and discarded when the upload finishes. Only ' +
          'the findings below are kept.</p>' +
        '<div class="admin-form-row">' +
          '<div class="form-group" style="grid-column: span 2">' +
            '<label class="modal-label" for="fw-file">Configuration file (.yaml, .yml, .json)</label>' +
            '<input id="fw-file" type="file" accept=".yaml,.yml,.json,.conf,text/yaml,application/json">' +
          '</div>' +
          '<div class="form-group admin-form-submit">' +
            '<label class="modal-label">&nbsp;</label>' +
            '<button id="fw-upload" type="button" class="btn btn-primary">Audit configuration</button>' +
          '</div>' +
        '</div>' +
        (_msg ? '<p class="fw-note ' + (_msg.bad ? 'fw-bad' : 'fw-good') + '">' +
          esc(_msg.text) + '</p>' : '') +
      '</div>';
  }

  function historyBlock() {
    if (!_history.length) return '<p class="fw-note">No previous audits.</p>';
    return '<div class="fw-hist">' + _history.map(function (a) {
      return '<button type="button" class="fw-h-row" data-audit="' + esc(a.id) + '">' +
          '<span class="fw-h-when">' +
            esc(a.uploadedAt ? new Date(a.uploadedAt).toLocaleDateString() : '') + '</span>' +
          '<span class="fw-h-dev">' + esc((a.device && a.device.name) || 'Unnamed') + '</span>' +
          '<span class="fw-h-score">' +
            (a.score == null ? 'n/a' : esc(a.score)) + '</span>' +
          '<span class="fw-h-sub">' + esc(a.failed) + ' findings &middot; ' +
            esc(a.coverage) + '% coverage</span>' +
        '</button>';
    }).join('') + '</div>';
  }

  function render() {
    var host = document.getElementById('tab-firewall');
    if (!host) return;

    var body;
    if (_view === 'history') {
      body = historyBlock();
    } else if (_audit) {
      body = scoreBlock(_audit) + findingsBlock(_audit);
    } else {
      body = '<div class="fw-note">No configuration has been audited for this ' +
        'client yet.' + (canUpload() ? ' Upload one above.' : '') + '</div>';
    }

    host.innerHTML =
      '<div class="page-head"><h2>Firewall Configuration Review</h2>' +
        '<p class="page-sub">A FortiGate backup audited against the CIS FortiGate ' +
        'Benchmark and Reflex\'s own checks.</p></div>' +
      uploadBlock() +
      '<div class="fw-tabs">' +
        '<button type="button" class="fw-tab' + (_view === 'current' ? ' is-on' : '') +
          '" data-view="current">Latest audit</button>' +
        '<button type="button" class="fw-tab' + (_view === 'history' ? ' is-on' : '') +
          '" data-view="history">History</button>' +
      '</div>' +
      '<div class="fw-body">' + body + '</div>';

    wire();
  }

  function wire() {
    document.querySelectorAll('#tab-firewall .fw-tab').forEach(function (b) {
      b.onclick = function () { _view = b.dataset.view; render(); };
    });
    document.querySelectorAll('#tab-firewall .fw-h-row').forEach(function (b) {
      b.onclick = function () { openAudit(b.dataset.audit); };
    });
    var up = document.getElementById('fw-upload');
    if (up) up.onclick = doUpload;
  }

  async function openAudit(id) {
    try {
      var j = await get('firewall/audits/' + encodeURIComponent(id) + tenantParam('?'));
      _audit = j.audit;
      _view = 'current';
      render();
    } catch (err) {
      _msg = { text: 'Could not load that audit: ' + err.message, bad: true };
      render();
    }
  }

  async function doUpload() {
    var input = document.getElementById('fw-file');
    var file = input && input.files && input.files[0];
    if (!file) { _msg = { text: 'Choose a configuration file first.', bad: true }; render(); return; }

    var btn = document.getElementById('fw-upload');
    if (btn) { btn.disabled = true; btn.textContent = 'Auditing…'; }

    var fd = new FormData();
    fd.append('configFile', file);
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (isSA && window.globalTenantId) fd.append('tenantId', window.globalTenantId);

    try {
      var res = await fetch(apiUrl('firewall/audits'), {
        method: 'POST', credentials: 'same-origin', body: fd,
      });
      var j = await res.json().catch(function () { return {}; });
      if (!res.ok) { _msg = { text: j.error || ('Upload failed (HTTP ' + res.status + ').'), bad: true }; return; }

      _audit = j.audit;
      _view = 'current';
      // The mask warning is the server's, shown verbatim — it is advice about a
      // file that has already left the client's hands, and softening it here
      // would be the wrong kind of tidy. It outranks the parse note: rotating
      // exposed credentials matters more than a quoting quirk.
      _msg = j.maskWarning ? { text: j.maskWarning, bad: true }
           : j.parseNote   ? { text: j.parseNote, bad: false }
           : { text: 'Configuration audited. The file was not stored.', bad: false };
      _parseNote = j.parseNote || null;
      loadHistory();
    } catch (err) {
      _msg = { text: 'Upload failed: ' + err.message, bad: true };
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Audit configuration'; }
      render();
    }
  }

  async function loadHistory() {
    try { _history = (await get('firewall/audits' + tenantParam('?'))).audits || []; }
    catch (err) { _history = []; }
  }

  async function loadAndRender() {
    var host = document.getElementById('tab-firewall');
    if (!host) return;
    try {
      var j = await get('firewall/audits/latest' + tenantParam('?'));
      _audit = j.audit;
      await loadHistory();
      render();
    } catch (err) {
      host.innerHTML = '<div class="fw-note fw-bad">Could not load firewall audits: ' +
        esc(err.message) + '</div>';
    }
  }

  return {
    loadAndRender: loadAndRender,
    // Seams for the test harness.
    _render: render,
    _apiUrl: apiUrl,
    _findingRow: findingRow,
    _maskNotice: maskNotice,
    _setAudit: function (a) { _audit = a; },
  };
})();
