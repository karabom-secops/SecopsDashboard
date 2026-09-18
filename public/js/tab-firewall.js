/* tab-firewall.js — FortiGate configuration audit.
 *
 * Upload a backup, get a scored posture review. The analyst view: full detail,
 * including the evidence the client-facing report and portal withhold.
 *
 * THE FILE IS NOT STORED ANYWHERE. It is posted, parsed in memory on the
 * server, audited and dropped. This page says so, because an analyst about to
 * ask a client for their firewall config needs to be able to answer "where does
 * it go" with something better than "I think it's fine".
 *
 * WHY THIS PAGE IS BUILT THE WAY IT IS
 *
 * A single config produces somewhere near sixty check results, and a rulebase
 * with a few hundred policies pushes the per-policy ones higher. Rendered as one
 * flat, fully-expanded column — findings, then not-assessable, then every pass —
 * the page was technically complete and practically unusable: the two criticals
 * an analyst came for sat somewhere inside several screens of prose they had to
 * scroll past.
 *
 * So the list is filtered rather than merely printed: one status at a time,
 * narrowable by severity, category and free text, with each result's rationale
 * and fix behind a disclosure. The rules that hiding must obey:
 *
 *   - Nothing is hidden silently. Every count is on screen even when its list is
 *     not, and a filtered list says how much it is hiding and offers one click
 *     back to everything.
 *   - "Could not be assessed" keeps equal billing with findings. It is the
 *     honest boundary of the audit, and a reader who cannot see it will assume
 *     those checks passed.
 *   - Null is not zero, in the headline score and in every category.
 */

window.FirewallTab = (function () {
  'use strict';

  var BASE = (function () {
    var base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) { return BASE + 'api/' + path; }

  var SEV_ORDER = ['critical', 'high', 'medium', 'low'];

  /*
   * The three outcomes, as tabs over one list rather than three stacked lists.
   * Order is deliberate: what to fix, then what nobody checked, then what is
   * fine. "Could not be assessed" sits second so it is passed over on the way to
   * the passes, not buried under them.
   */
  var STATUSES = [
    { key: 'fail',           label: 'Findings' },
    { key: 'not-assessable', label: 'Could not be assessed' },
    { key: 'pass',           label: 'Passed' },
  ];

  var _audit = null;
  var _history = [];
  var _msg = null;
  var _view = 'current';
  var _parseNote = null;
  var _loading = false;

  // Filter state. Empty severity list means every severity — an explicit "all"
  // sentinel would be one more value to keep in step with the chips.
  var _q = '';
  var _sev = [];
  var _cat = null;
  var _status = 'fail';
  var _expand = 'auto';   // auto | all | none

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function plural(n, word) { return esc(n) + ' ' + word + (n === 1 ? '' : 's'); }

  function canUpload() {
    return typeof window.canWrite === 'function' ? window.canWrite('firewall') : false;
  }

  /*
   * Deletion is superadmin-only on the server (requireSuperAdmin), so the button
   * is superadmin-only here. Hiding a control the server would refuse is not the
   * security boundary — the route is — but showing one it would refuse teaches
   * analysts that this page lies to them.
   *
   * Deliberately NOT canWrite('firewall'): analysts have write on this page so
   * they can run audits. Being able to produce a record is not the same right as
   * being able to erase one.
   */
  function canDelete() {
    return !!(window.currentUser && window.currentUser.role === 'superadmin');
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

  // ── Filtering ─────────────────────────────────────────────────────────────

  /** One finding's searchable text, evidence included. */
  function haystack(f) {
    var bits = [f.title, f.detail, f.rationale, f.remediation,
                f.cis, f.checkId, f.severity, f.category, categoryLabel(f.category)];
    if (f.evidence && typeof f.evidence === 'object') {
      Object.keys(f.evidence).forEach(function (k) {
        bits.push(k);
        bits.push(evidenceValue(f.evidence[k]));
      });
    }
    return bits.filter(Boolean).join(' ').toLowerCase();
  }

  /**
   * The one place a finding is decided in or out of the list.
   *
   * A filter left undefined means "do not narrow on this", never "match
   * nothing" — a typo in the state should show too much, which is visible, not
   * too little, which is not.
   */
  function applyFilters(list, st) {
    var s = st || {};
    var q = String(s.q || '').trim().toLowerCase();
    var sev = s.sev || [];
    return (list || []).filter(function (f) {
      if (s.status && f.status !== s.status) return false;
      if (s.cat && (f.category || null) !== s.cat) return false;
      if (sev.length && sev.indexOf(f.severity) < 0) return false;
      if (q && haystack(f).indexOf(q) < 0) return false;
      return true;
    });
  }

  function filterState(over) {
    var st = { q: _q, sev: _sev, cat: _cat, status: _status };
    if (over) Object.keys(over).forEach(function (k) { st[k] = over[k]; });
    return st;
  }

  function anyFilter() {
    return !!(String(_q).trim() || _sev.length || _cat);
  }

  function bySeverity(x, y) {
    return SEV_ORDER.indexOf(x.severity) - SEV_ORDER.indexOf(y.severity);
  }

  function categoryLabel(key) {
    if (!key) return 'Not categorised';
    var cats = (_audit && _audit.byCategory) || [];
    for (var i = 0; i < cats.length; i++) if (cats[i].key === key) return cats[i].label;
    return key;
  }

  // ── Rendering: header ─────────────────────────────────────────────────────

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
            plural(a.failed, 'finding') + ' &middot; ' +
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

  // ── Rendering: one finding ────────────────────────────────────────────────

  /**
   * Evidence values, read as English rather than as JSON.
   *
   * JSON.stringify put quotes around every string and braces around every
   * object, so `interfaces: ["port1","port2"]` reached the analyst as
   * `interfaces: ["port1","port2"]` when what they needed was port1, port2.
   * A null stays visible as "not recorded" — an evidence key present with no
   * value is not the same as a count of zero.
   */
  function evidenceValue(v) {
    if (Array.isArray(v)) return v.map(evidenceValue).join(', ');
    if (v === null || v === undefined) return 'not recorded';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  function evidenceLabel(k) {
    var s = String(k).replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2');
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  /** Whether this row starts open, given the expand-all/none override. */
  function startsOpen(f) {
    if (_expand === 'all') return true;
    if (_expand === 'none') return false;
    // Auto: the ones somebody has to act on today.
    return f.status === 'fail' && (f.severity === 'critical' || f.severity === 'high');
  }

  function findingRow(f, open) {
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
        return '<span class="fw-ev-i"><span class="fw-ev-k">' + esc(evidenceLabel(k)) +
          '</span> ' + esc(evidenceValue(f.evidence[k])) + '</span>';
      });
      if (bits.length) ev = '<div class="fw-ev">' + bits.join('') + '</div>';
    }

    var isOpen = open === undefined ? startsOpen(f) : !!open;

    return '<details class="fw-f fw-sev-' + esc(f.severity) + '"' + (isOpen ? ' open' : '') +
        ' data-check="' + esc(f.checkId || '') + '">' +
        '<summary class="fw-f-top">' +
          '<span class="fw-badge ' + badge + '">' + esc(label) + '</span>' +
          '<span class="fw-sev">' + esc(f.severity) + '</span>' +
          '<span class="fw-f-t">' + esc(f.title) + '</span>' +
          (f.cis ? '<span class="fw-ref">CIS ' + esc(f.cis) + '</span>'
                 : '<span class="fw-ref fw-own">Reflex</span>') +
        '</summary>' +
        '<div class="fw-f-body">' +
          (f.detail ? '<div class="fw-f-d">' + esc(f.detail) + '</div>' : '') +
          ev +
          '<div class="fw-f-r"><strong>Why:</strong> ' + esc(f.rationale) + '</div>' +
          (f.status === 'pass' ? '' :
            '<div class="fw-f-r"><strong>Fix:</strong> ' + esc(f.remediation) + '</div>') +
        '</div>' +
      '</details>';
  }

  /**
   * Per-category scorecards.
   *
   * The categories mirror how a client-facing firewall assessment reports, so
   * this page can sit beside one. A category with nothing assessable shows
   * "n/a", NOT 0 — the difference between "we looked and the rulebase is bad"
   * and "we could not look" is the whole point of the not-assessable outcome,
   * and a zero here would erase it.
   *
   * Each card is also the filter for its own findings: the question a scorecard
   * provokes is "which ones", and the answer was previously several screens
   * away.
   */
  function categoryBlock(a) {
    var cats = a.byCategory || [];
    if (!cats.length) return '';

    return '<h3 class="fw-h">By category</h3>' +
      '<div class="fw-cats">' + cats.map(function (c) {
        var score = c.score == null
          ? '<span class="fw-nd">n/a</span>'
          : esc(c.score) + '<span class="fw-of">/100</span>';
        var on = _cat === c.key;
        return '<button type="button" class="fw-cat fw-' +
            esc((c.band && c.band.key) || 'unknown') + (on ? ' is-on' : '') +
            '" data-cat="' + esc(c.key) + '" aria-pressed="' + (on ? 'true' : 'false') +
            '" title="Show only this category">' +
            '<span class="fw-cat-top">' +
              '<span class="fw-cat-l">' + esc(c.label) + '</span>' +
              '<span class="fw-cat-v">' + score + '</span>' +
            '</span>' +
            '<span class="fw-cat-sub">' +
              plural(c.failed, 'finding') + ' &middot; ' +
              esc(c.passed) + ' passed' +
              (c.notAssessable
                ? ' &middot; ' + esc(c.notAssessable) + ' not assessable' : '') +
            '</span>' +
            (c.blurb ? '<span class="fw-cat-b">' + esc(c.blurb) + '</span>' : '') +
          '</button>';
      }).join('') + '</div>';
  }

  /* Findings grouped under their category heading, in report order. */
  function groupByCategory(list, cats) {
    var order = (cats || []).map(function (c) { return c.key; });
    var labels = {};
    (cats || []).forEach(function (c) { labels[c.key] = c.label; });

    var groups = [];
    function bucket(key) {
      var hit = groups.filter(function (g) { return g.key === key; })[0];
      if (!hit) {
        hit = { key: key, label: labels[key] || 'Not categorised', rows: [] };
        groups.push(hit);
      }
      return hit;
    }
    list.forEach(function (f) { bucket(f.category || null).rows.push(f); });

    // Uncategorised last, and named as such rather than folded into a real
    // group — a finding from before categorisation is not a finding about
    // nothing.
    return groups.sort(function (x, y) {
      var xi = x.key === null ? 999 : order.indexOf(x.key);
      var yi = y.key === null ? 999 : order.indexOf(y.key);
      return (xi < 0 ? 998 : xi) - (yi < 0 ? 998 : yi);
    });
  }

  // ── Rendering: the controls over the list ─────────────────────────────────

  /**
   * The status tabs, counted.
   *
   * The counts are of what the OTHER filters leave, so switching tab never
   * lands on an empty list whose control promised rows. They are always
   * rendered, including at zero: an outcome that vanishes when it is empty is
   * an outcome nobody can confirm was looked at.
   */
  function segBlock(all) {
    return STATUSES.map(function (s) {
      var n = applyFilters(all, filterState({ status: s.key, sev: [] })).length;
      var on = _status === s.key;
      return '<button type="button" class="fw-st' + (on ? ' is-on' : '') +
        '" data-status="' + esc(s.key) + '" role="tab" aria-selected="' +
        (on ? 'true' : 'false') + '">' + esc(s.label) +
        ' <span class="fw-st-n">' + esc(n) + '</span></button>';
    }).join('');
  }

  /* Severity chips, counted within the status tab and the other filters. */
  function chipsBlock(all) {
    var inTab = applyFilters(all, filterState({ sev: [] }));
    var counts = {};
    inTab.forEach(function (f) { counts[f.severity] = (counts[f.severity] || 0) + 1; });

    var chips = SEV_ORDER.filter(function (s) { return counts[s]; }).map(function (s) {
      var on = _sev.indexOf(s) >= 0;
      return '<button type="button" class="fw-chip fw-sev-' + esc(s) + (on ? ' is-on' : '') +
        '" data-sev="' + esc(s) + '" aria-pressed="' + (on ? 'true' : 'false') + '">' +
        esc(s) + ' <span class="fw-chip-n">' + esc(counts[s]) + '</span></button>';
    }).join('');

    if (!chips) return '';
    return '<div class="fw-chips-row"><span class="fw-chips-l">Severity</span>' +
      chips + '</div>';
  }

  /**
   * What the filters are currently hiding, and the way out.
   *
   * Shown whenever a filter is active — including when it happens to hide
   * nothing — because the cost of a stale filter is an analyst concluding a
   * firewall is clean when they are looking at one category of it.
   */
  function filterNote(shown, total) {
    if (!anyFilter()) return '';
    var parts = [];
    if (String(_q).trim()) parts.push('matching &ldquo;' + esc(String(_q).trim()) + '&rdquo;');
    if (_sev.length) parts.push(esc(_sev.join(', ')));
    if (_cat) parts.push('in ' + esc(categoryLabel(_cat)));
    return '<div class="fw-filter-note">Showing ' + esc(shown) + ' of ' + esc(total) +
      ' &middot; ' + parts.join(' &middot; ') +
      ' <button type="button" class="fw-clear" id="fw-clear">Clear filters</button></div>';
  }

  function listBlock(a) {
    var all = a.findings || [];
    var shown = applyFilters(all, filterState()).sort(bySeverity);
    var totalInTab = all.filter(function (f) { return f.status === _status; }).length;

    var body;
    if (shown.length) {
      body = groupByCategory(shown, a.byCategory).map(function (g) {
        return '<h4 class="fw-cat-h">' + esc(g.label) +
          ' <span class="fw-cat-n">' + esc(g.rows.length) + '</span></h4>' +
          g.rows.map(function (f) { return findingRow(f); }).join('');
      }).join('');
    } else if (anyFilter()) {
      body = '<div class="fw-note">Nothing here matches these filters. ' +
        '<button type="button" class="fw-clear" id="fw-clear-2">Clear filters</button></div>';
    } else if (_status === 'fail') {
      body = '<div class="fw-note fw-good">Every check that could be evaluated passed.</div>';
    } else if (_status === 'not-assessable') {
      body = '<div class="fw-note fw-good">Every check could be evaluated against ' +
        'this configuration.</div>';
    } else {
      body = '<div class="fw-note">No checks passed.</div>';
    }

    /*
     * The standing caveat on the not-assessable tab. It rides with the list
     * rather than sitting in the page header, so it is on screen exactly when
     * someone is reading the rows it explains.
     */
    var caveat = _status === 'not-assessable'
      ? '<p class="fw-note">Excluded from the score rather than counted against ' +
        'it — not passed, and not evidence that the firewall is configured ' +
        'correctly. Confirm these on the device.</p>'
      : '';

    return caveat + filterNote(shown.length, totalInTab) + body;
  }

  function controlsBlock(a) {
    var all = a.findings || [];
    return '<div class="fw-seg" role="tablist" id="fw-seg">' + segBlock(all) + '</div>' +
      '<div class="fw-toolbar">' +
        '<label class="fw-q-wrap">' +
          '<span class="fw-sr">Search findings</span>' +
          '<input type="search" id="fw-q" class="fw-q" autocomplete="off" ' +
            'placeholder="Search title, detail, fix, evidence, CIS ref…" value="' +
            esc(_q) + '">' +
        '</label>' +
        '<div class="fw-chips" id="fw-chips">' + chipsBlock(all) + '</div>' +
        '<div class="fw-tools">' +
          '<button type="button" class="fw-tool" id="fw-expand">Expand all</button>' +
          '<button type="button" class="fw-tool" id="fw-collapse">Collapse all</button>' +
        '</div>' +
      '</div>' +
      '<div id="fw-list">' + listBlock(a) + '</div>';
  }

  // ── Rendering: upload, messages, history ──────────────────────────────────

  /*
   * Collapsed once an audit exists, so the thing an analyst opened the page for
   * is the thing at the top of it. Open when there is nothing to read yet,
   * because then uploading IS the page.
   *
   * The "not stored" promise is in the summary, not only in the body: it has to
   * be answerable while the card is shut.
   */
  function uploadBlock() {
    if (!canUpload()) return '';
    return '<details class="admin-card fw-upload"' + (_audit ? '' : ' open') + '>' +
        '<summary class="fw-up-sum">' +
          '<span class="admin-card-title">' +
            (_audit ? 'Upload a new configuration' : 'Upload a configuration') + '</span>' +
          '<span class="fw-up-hint">The file is not stored</span>' +
        '</summary>' +
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
      '</details>';
  }

  /*
   * Rendered once by render(), not inside the upload card — a delete confirmation
   * has to be visible to someone who cannot upload, and a message that only
   * appears when another control happens to be on screen is a message that will
   * one day not appear at all.
   */
  function msgBlock() {
    if (!_msg) return '';
    return '<p class="fw-note ' + (_msg.bad ? 'fw-bad' : 'fw-good') + '">' +
      esc(_msg.text) + '</p>';
  }

  /* How an audit is named in a confirmation prompt and in the message after. */
  function auditLabel(a) {
    var when = a.uploadedAt ? new Date(a.uploadedAt).toLocaleDateString() : 'unknown date';
    return ((a.device && a.device.name) || 'Unnamed device') + ' (' + when + ')';
  }

  function deleteButton(a) {
    if (!canDelete()) return '';
    return '<button type="button" class="fw-h-del" data-del="' + esc(a.id) +
      '" data-label="' + esc(auditLabel(a)) + '" title="Delete this audit">Delete</button>';
  }

  /**
   * Score movement against the audit before it.
   *
   * Two audits a month apart, both reading 68, is a different conversation from
   * 51 then 68 — and the history list was the one place that comparison was
   * free to make and was not being made. Null scores produce no arrow rather
   * than a fabricated zero-point move.
   */
  function scoreDelta(a, older) {
    if (!older || a.score == null || older.score == null) return '';
    var d = a.score - older.score;
    if (!d) return '<span class="fw-h-d fw-flat" title="No change since the previous audit">&mdash;</span>';
    var up = d > 0;
    return '<span class="fw-h-d ' + (up ? 'fw-up' : 'fw-down') + '" title="' +
      (up ? 'Up ' : 'Down ') + Math.abs(d) + ' since the previous audit">' +
      (up ? '&uarr;' : '&darr;') + Math.abs(d) + '</span>';
  }

  function historyBlock() {
    if (!_history.length) return '<p class="fw-note">No previous audits.</p>';
    return '<div class="fw-hist">' + _history.map(function (a, i) {
      var isOpen = _audit && String(_audit.id) === String(a.id);
      // Sibling buttons, not nested: a <button> inside a <button> is invalid
      // HTML, and browsers resolve it by dropping one — usually the delete.
      return '<div class="fw-h-item">' +
        '<button type="button" class="fw-h-row' + (isOpen ? ' is-on' : '') +
          '" data-audit="' + esc(a.id) + '">' +
          '<span class="fw-h-when">' +
            esc(a.uploadedAt ? new Date(a.uploadedAt).toLocaleDateString() : '') + '</span>' +
          '<span class="fw-h-dev">' + esc((a.device && a.device.name) || 'Unnamed') +
            (i === 0 ? '<span class="fw-h-tag">Latest</span>' : '') +
            (isOpen ? '<span class="fw-h-tag fw-h-tag-on">On screen</span>' : '') + '</span>' +
          '<span class="fw-h-score">' +
            (a.score == null ? '<span class="fw-nd">n/a</span>' : esc(a.score)) +
            scoreDelta(a, _history[i + 1]) + '</span>' +
          '<span class="fw-h-sub">' + plural(a.failed, 'finding') + ' &middot; ' +
            esc(a.coverage) + '% coverage</span>' +
        '</button>' +
        deleteButton(a) +
      '</div>';
    }).join('') + '</div>';
  }

  // ── Rendering: the page ───────────────────────────────────────────────────

  function render() {
    var host = document.getElementById('tab-firewall');
    if (!host) return;

    var body;
    if (_loading) {
      body = '<div class="fw-note">Loading the latest audit…</div>';
    } else if (_view === 'history') {
      body = historyBlock();
    } else if (_audit) {
      body = scoreBlock(_audit) + categoryBlock(_audit) + controlsBlock(_audit) +
        (canDelete() ? '<div class="fw-actions">' + deleteButton(_audit) + '</div>' : '');
    } else {
      body = '<div class="fw-note">No configuration has been audited for this ' +
        'client yet.' + (canUpload() ? ' Upload one above.' : '') + '</div>';
    }

    host.innerHTML =
      '<div class="page-head"><h2>Firewall Configuration Review</h2>' +
        '<p class="page-sub">A FortiGate backup audited against the CIS FortiGate ' +
        'Benchmark and Reflex\'s own checks.</p></div>' +
      uploadBlock() +
      msgBlock() +
      '<div class="fw-tabs">' +
        '<button type="button" class="fw-tab' + (_view === 'current' ? ' is-on' : '') +
          '" data-view="current">Latest audit</button>' +
        '<button type="button" class="fw-tab' + (_view === 'history' ? ' is-on' : '') +
          '" data-view="history">History' +
          (_history.length ? ' <span class="fw-st-n">' + esc(_history.length) + '</span>' : '') +
        '</button>' +
      '</div>' +
      '<div class="fw-body">' + body + '</div>';

    wire();
  }

  /**
   * Re-render the list and the controls that count it, leaving the search box
   * alone.
   *
   * Rebuilding the whole page on every keystroke took the caret out of the
   * search field, which made the field unusable for anything longer than one
   * character. The input is therefore never re-rendered while the user is in
   * it; only what depends on it is.
   */
  function refreshList() {
    if (!_audit) return;
    var all = _audit.findings || [];
    var seg = document.getElementById('fw-seg');
    var chips = document.getElementById('fw-chips');
    var list = document.getElementById('fw-list');
    if (seg)   seg.innerHTML = segBlock(all);
    if (chips) chips.innerHTML = chipsBlock(all);
    if (list)  list.innerHTML = listBlock(_audit);
    wireList();
  }

  function clearFilters() {
    _q = '';
    _sev = [];
    _cat = null;
    var q = document.getElementById('fw-q');
    if (q) q.value = '';
    // The category cards live outside the refreshed region, so their pressed
    // state is cleared by hand rather than by a re-render.
    document.querySelectorAll('#tab-firewall .fw-cat').forEach(function (b) {
      b.classList.remove('is-on');
      b.setAttribute('aria-pressed', 'false');
    });
    refreshList();
  }

  /* Handlers for the parts refreshList() replaces. */
  function wireList() {
    document.querySelectorAll('#tab-firewall .fw-st').forEach(function (b) {
      b.onclick = function () {
        _status = b.dataset.status;
        // Severity chips are counted within a tab, so a severity that exists in
        // one tab and not the next would otherwise leave an invisible filter
        // hiding every row. Drop them with the tab.
        _sev = [];
        refreshList();
      };
    });
    document.querySelectorAll('#tab-firewall .fw-chip').forEach(function (b) {
      b.onclick = function () {
        var s = b.dataset.sev;
        var at = _sev.indexOf(s);
        if (at >= 0) _sev.splice(at, 1); else _sev.push(s);
        refreshList();
      };
    });
    ['fw-clear', 'fw-clear-2'].forEach(function (id) {
      var el = document.getElementById(id);
      if (el) el.onclick = clearFilters;
    });
  }

  function wire() {
    document.querySelectorAll('#tab-firewall .fw-tab').forEach(function (b) {
      b.onclick = function () { _view = b.dataset.view; render(); };
    });
    document.querySelectorAll('#tab-firewall .fw-h-row').forEach(function (b) {
      b.onclick = function () { openAudit(b.dataset.audit); };
    });
    document.querySelectorAll('#tab-firewall .fw-h-del').forEach(function (b) {
      b.onclick = function () { doDelete(b.dataset.del, b.dataset.label); };
    });
    document.querySelectorAll('#tab-firewall .fw-cat').forEach(function (b) {
      b.onclick = function () {
        // A second click on the same card is the way back out — the card is the
        // filter's only control, so it has to be able to release it.
        _cat = _cat === b.dataset.cat ? null : b.dataset.cat;
        document.querySelectorAll('#tab-firewall .fw-cat').forEach(function (o) {
          var on = _cat === o.dataset.cat;
          o.classList.toggle('is-on', on);
          o.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        refreshList();
      };
    });

    var q = document.getElementById('fw-q');
    if (q) q.oninput = function () { _q = q.value; refreshList(); };

    var ex = document.getElementById('fw-expand');
    if (ex) ex.onclick = function () { _expand = 'all'; refreshList(); };
    var col = document.getElementById('fw-collapse');
    if (col) col.onclick = function () { _expand = 'none'; refreshList(); };

    var up = document.getElementById('fw-upload');
    if (up) up.onclick = doUpload;

    wireList();
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  /* A different audit is a different set of findings; its filters are not ours. */
  function resetFilters() {
    _q = '';
    _sev = [];
    _cat = null;
    _status = 'fail';
    _expand = 'auto';
  }

  async function openAudit(id) {
    try {
      var j = await get('firewall/audits/' + encodeURIComponent(id) + tenantParam('?'));
      _audit = j.audit;
      _view = 'current';
      resetFilters();
      // The parse note describes the file that was just uploaded, not this
      // audit. Carrying it across would attribute a quoting repair to a
      // configuration it never touched.
      _parseNote = null;
      render();
    } catch (err) {
      _msg = { text: 'Could not load that audit: ' + err.message, bad: true };
      render();
    }
  }

  /**
   * Delete one audit.
   *
   * Irreversible and it says so: the configuration was never stored, so a
   * deleted audit cannot be regenerated from anything we hold. Re-auditing means
   * asking the client for a fresh backup — and it would be a fresh backup, not
   * this one, so the historical record of what the firewall looked like on that
   * date is gone for good.
   */
  async function doDelete(id, label) {
    if (!id) return;
    if (!confirm('Delete the audit for ' + (label || 'this device') + '?\n\n' +
      'This deletes the findings and cannot be undone. The configuration itself ' +
      'was never stored, so this audit cannot be recreated — only replaced by a ' +
      'new backup from the client.')) return;

    try {
      var res = await fetch(
        apiUrl('firewall/audits/' + encodeURIComponent(id) + tenantParam('?')),
        { method: 'DELETE', credentials: 'same-origin' });
      var j = await res.json().catch(function () { return {}; });
      if (!res.ok) {
        _msg = { text: j.error || ('Delete failed (HTTP ' + res.status + ').'), bad: true };
        render();
        return;
      }

      _msg = { text: 'Deleted the audit for ' + (label || 'that device') + '.', bad: false };

      /*
       * If the audit on screen is the one that just went, do not keep rendering
       * it. Re-fetch rather than blanking: deleting the latest audit promotes
       * the one before it, and the page should show the posture that now
       * stands — not an empty state that reads as "this client has no firewall
       * review".
       */
      if (_audit && String(_audit.id) === String(id)) {
        _audit = null;
        _parseNote = null;
        resetFilters();
        try {
          var latest = await get('firewall/audits/latest' + tenantParam('?'));
          _audit = latest.audit;
        } catch (err) { /* the message above still stands; the view falls back */ }
      }

      await loadHistory();
      render();
    } catch (err) {
      _msg = { text: 'Delete failed: ' + err.message, bad: true };
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
      resetFilters();
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
    // A blank panel while two requests run reads as "this client has no
    // firewall review", which is a different answer from "not yet loaded".
    _loading = true;
    resetFilters();
    render();
    try {
      var j = await get('firewall/audits/latest' + tenantParam('?'));
      _audit = j.audit;
      await loadHistory();
      _loading = false;
      render();
    } catch (err) {
      _loading = false;
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
    _historyBlock: historyBlock,
    _canDelete: canDelete,
    _setAudit: function (a) { _audit = a; },
    _setHistory: function (h) { _history = h; },
    _applyFilters: applyFilters,
    _evidenceValue: evidenceValue,
    _evidenceLabel: evidenceLabel,
    _segBlock: function (all) { return segBlock(all); },
    _listBlock: function (a) { return listBlock(a); },
    _setFilters: function (f) {
      if (!f) return resetFilters();
      if ('q' in f) _q = f.q;
      if ('sev' in f) _sev = f.sev;
      if ('cat' in f) _cat = f.cat;
      if ('status' in f) _status = f.status;
      if ('expand' in f) _expand = f.expand;
    },
  };
})();
