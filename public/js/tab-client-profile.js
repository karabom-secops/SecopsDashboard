/* tab-client-profile.js — who this client is, in one place.
 *
 * WHY THIS TAB EXISTS
 *
 * The estate was seven blank number boxes on the Admin tab, and the service mix
 * was a checkbox list beside it. Between them they decide which yardstick the
 * Secure Score uses, how it is weighted, and which sections a client's board
 * report contains — up to about forty-five points of a number that is printed
 * and handed to a board. Nothing on that form said what was missing, what it
 * was costing, whether it was still true, or whether it agreed with the
 * telemetry sitting one table away.
 *
 * So the page is organised around the questions an analyst actually has, and
 * it answers back:
 *
 *   What they buy      the service mix
 *   What they have     asset counts, each shown NEXT TO what we can see
 *   What we protect    managed patching, awareness programme
 *   What this means    gaps, conflicts, and the history of who changed what
 *
 * NOTHING ON THIS PAGE CHANGES A SCORE BY ITSELF. The gaps and conflicts panels
 * report; the score moves only when somebody edits a value and saves it, and
 * that movement is recorded. See the header of lib/estate.js.
 */

window.ClientProfileTab = (function () {
  'use strict';

  var COUNT_FIELDS = [
    { key: 'servers',        label: 'Servers' },
    { key: 'publicAssets',   label: 'Public-facing assets / apps' },
    { key: 'endpoints',      label: 'Endpoints' },
    { key: 'cloudTenancies', label: 'Cloud tenancies' },
    { key: 'users',          label: 'Users' },
  ];

  // Hints that explain a field's CONSEQUENCE, not its name. "Public-facing
  // assets" needs no gloss; what a typed value does to the score does.
  var FIELD_HINTS = {
    publicAssets: 'Leave blank to follow the scan. A number here is a challenge ' +
                  'to it — say 10 when the scan reached 6 and the score stays ' +
                  'capped until the missing four are in scope.',
    users:        'Drives how much of the score belongs to human risk.',
    endpoints:    'Leave blank to follow EDR. A number here is what reveals ' +
                  'machines with no agent on them.',
  };

  var _data = null;

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function apiUrl(p) {
    return (typeof window.apiUrl === 'function') ? window.apiUrl(p) : ('/api/' + p);
  }

  /** Superadmins act on the globally selected client; everyone else on their own. */
  function tenantQS() {
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return '?tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  function tenantBody() {
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return {};
    return { tenantId: window.globalTenantId };
  }

  // window.canWrite comes from auth.js and answers off the resolved access map
  // that GET /api/auth/me returns. Read-only here is cosmetic only — the real
  // refusal is pageGate on the server.
  function canWriteProfile() {
    return typeof window.canWrite === 'function'
      ? window.canWrite('client-profile') : true;
  }

  function msg(text, isError) {
    var el = document.getElementById('cp-msg');
    if (!el) return;
    el.hidden = !text;
    el.textContent = text || '';
    el.className = 'admin-form-msg ' + (isError ? 'admin-form-error' : 'admin-form-success');
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  /**
   * One number box, with what the telemetry says beside it.
   *
   * The ghost value is the point of this whole block. Typing a headcount into
   * an empty box is guessing; typing it next to "EDR sees 118" is a decision.
   */
  function countField(f, d) {
    var declared = d.declared || {};
    var eff      = d.effective || {};
    var derived  = (eff.derived || {})[f.key];
    var v = declared[f.key];

    var ghost = '';
    if (derived !== null && derived !== undefined) {
      var src = f.key === 'publicAssets' ? 'the scan reached' : 'we can see';
      ghost = '<small class="cp-ghost">' + esc(src + ' ' + derived) + '</small>';
    }

    return '<div class="form-group">' +
        '<label class="modal-label" for="cp-' + f.key + '">' + esc(f.label) + '</label>' +
        '<input id="cp-' + f.key + '" type="number" min="0" step="1" ' +
               'class="modal-status-select" placeholder="not recorded" ' +
               'autocomplete="off" value="' +
               (v === null || v === undefined ? '' : esc(v)) + '">' +
        ghost +
        (FIELD_HINTS[f.key]
          ? '<small class="admin-field-hint">' + esc(FIELD_HINTS[f.key]) + '</small>'
          : '') +
      '</div>';
  }

  function servicesBlock(d) {
    var cat = d.catalogue || [];
    var on  = Array.isArray(d.services) ? d.services : [];
    var includes = d.includes || {};

    // A service delivered inside another one is shown as included rather than
    // as an unticked box, which would read as a gap in something they have.
    var impliedBy = {};
    on.forEach(function (k) {
      (includes[k] || []).forEach(function (i) { impliedBy[i] = k; });
    });

    var rows = cat.map(function (s) {
      var parent = impliedBy[s.key];
      var implied = !!parent && on.indexOf(s.key) < 0;
      var parentLabel = parent
        ? (cat.filter(function (x) { return x.key === parent; })[0] || {}).label
        : '';
      return '<label class="rpt-section-row' + (implied ? ' rpt-section-na' : '') + '">' +
          '<span class="integration-toggle">' +
            '<input type="checkbox" class="cp-svc" value="' + esc(s.key) + '"' +
              (on.indexOf(s.key) >= 0 ? ' checked' : '') +
              (implied || !canWriteProfile() ? ' disabled' : '') + '>' +
            '<span class="int-toggle-slider"></span>' +
          '</span>' +
          '<span class="rpt-section-name">' + esc(s.label) +
            '<small class="rpt-section-hint">' + esc(s.hint || '') + '</small>' +
          '</span>' +
          (implied
            ? '<span class="rpt-section-tag" title="Delivered as part of ' +
              esc(parentLabel) + '">included</span>'
            : '') +
        '</label>';
    }).join('');

    // null and [] both render as all-clear boxes, so the note is the only thing
    // that can tell them apart. It is not decoration.
    var note = !Array.isArray(d.services)
      ? 'Not recorded yet — every report section is still offered for this client, ' +
        'and the Secure Score is not scoped to any service.'
      : (!d.services.length
          ? 'Recorded as buying nothing. Only the always-on report sections are ' +
            'pre-selected.'
          : '');

    return '<div class="admin-card">' +
        '<h3 class="admin-card-title">What they buy</h3>' +
        '<div class="rpt-section-list">' + rows + '</div>' +
        (note ? '<p class="admin-card-hint">' + esc(note) + '</p>' : '') +
      '</div>';
  }

  function gapsBlock(d) {
    var gaps = d.gaps || [];
    if (!gaps.length) {
      return '<div class="cp-panel cp-ok">Nothing missing — every input the score ' +
             'needs has been recorded.</div>';
    }
    return '<div class="cp-panel">' +
        '<h4 class="cp-panel-h">What is missing, and what it costs</h4>' +
        gaps.map(function (g) {
          return '<div class="cp-item cp-' + esc(g.severity) + '">' +
              '<div class="cp-item-t">' + esc(g.title) + '</div>' +
              '<div class="cp-item-b">' + esc(g.cost) + '</div>' +
              '<div class="cp-item-a">' + esc(g.action) + '</div>' +
            '</div>';
        }).join('') +
      '</div>';
  }

  function conflictsBlock(d) {
    var cs = d.conflicts || [];
    if (!cs.length) return '';
    return '<div class="cp-panel">' +
        '<h4 class="cp-panel-h">Where the record and the telemetry disagree</h4>' +
        cs.map(function (c) {
          return '<div class="cp-item cp-' + esc(c.severity) + '">' +
              '<div class="cp-item-t">' + esc(c.label) +
                ' &mdash; recorded ' + esc(c.declared) +
                ', we see ' + esc(c.derived) + '</div>' +
              '<div class="cp-item-b">' + esc(c.meaning) + '</div>' +
            '</div>';
        }).join('') +
        '<p class="cp-note">The recorded figure is still the one the score uses. ' +
          'Nothing here changes it — it is shown so somebody can decide which ' +
          'number is right.</p>' +
      '</div>';
  }

  function historyBlock(d) {
    if (!(d.available || {}).history) {
      return '<div class="cp-panel"><p class="cp-note">Change history is not ' +
             'available yet. Run db/migrate-client-profile.sql.</p></div>';
    }
    var h = d.history || [];
    if (!h.length) {
      return '<div class="cp-panel"><p class="cp-note">No changes recorded yet.</p></div>';
    }

    return '<div class="cp-panel">' +
        '<h4 class="cp-panel-h">Change history</h4>' +
        h.map(function (e) {
          var when = e.changedAt ? new Date(e.changedAt).toLocaleString() : '';
          var who  = e.changedBy || 'unknown';

          if (e.kind === 'review') {
            return '<div class="cp-h-row"><span class="cp-h-when">' + esc(when) +
              '</span><span class="cp-h-what">Confirmed unchanged by ' + esc(who) +
              '</span></div>';
          }

          var fields = Object.keys(e.diff || {}).map(function (k) {
            var v = e.diff[k];
            return esc(k) + ' ' + esc(fmt(v.from)) + ' &rarr; ' + esc(fmt(v.to));
          }).join(', ');

          // Labelled as a snapshot on purpose: these were computed when the
          // edit was saved and are NOT a recomputed history. Presented bare,
          // an old row reads as an authoritative past score.
          var move = (e.scoreBefore == null || e.scoreAfter == null)
            ? ''
            : '<span class="cp-h-move' +
              (e.scoreAfter < e.scoreBefore ? ' down' : (e.scoreAfter > e.scoreBefore ? ' up' : '')) +
              '" title="Composite score as computed at the time of this change">' +
              esc(e.scoreBefore + ' → ' + e.scoreAfter) + '</span>';

          return '<div class="cp-h-row">' +
              '<span class="cp-h-when">' + esc(when) + '</span>' +
              '<span class="cp-h-what">' + fields + ' &middot; ' + esc(who) + '</span>' +
              move +
            '</div>';
        }).join('') +
        '<p class="cp-note">Score movements are snapshots taken when each change ' +
          'was saved, not a recalculated history.</p>' +
      '</div>';
  }

  function fmt(v) {
    if (v === null || v === undefined) return 'not recorded';
    if (Array.isArray(v)) return v.length ? v.join('+') : 'none';
    if (v === '') return 'blank';
    return String(v);
  }

  function staleBanner(d) {
    var age = d.age || {};
    if (!age.stale) return '';
    return '<div class="cp-stale">' +
        'This profile was last confirmed ' + esc(age.days) + ' days ago. ' +
        'It is still being used exactly as recorded — nothing has been ' +
        'discounted — but it is worth checking before the next board report.' +
      '</div>';
  }

  function render(d) {
    var host = document.getElementById('tab-client-profile');
    if (!host) return;

    var avail = d.available || {};
    var ro = !canWriteProfile();

    host.innerHTML =
      '<div class="page-head"><h2>Client Profile</h2>' +
        '<p class="page-sub">What this client buys and what they have. Both ' +
        'decide how the Secure Score is measured and which sections their ' +
        'board report contains.</p></div>' +

      (avail.estate ? '' :
        '<div class="cp-stale">The estate table is not available. ' +
        'Run db/migrate-tenant-estate.sql.</div>') +
      staleBanner(d) +

      servicesBlock(d) +

      '<div class="admin-card">' +
        '<h3 class="admin-card-title">What they have</h3>' +
        '<p class="admin-card-hint">Leave a field <em>blank</em> for "not ' +
          'recorded". That is not the same as <em>0</em>, which is a positive ' +
          'statement that they have none — and 0 across servers, public assets ' +
          'and cloud is what moves them onto the endpoint measure.</p>' +
        '<div class="admin-form-row">' +
          COUNT_FIELDS.map(function (f) { return countField(f, d); }).join('') +
        '</div>' +
      '</div>' +

      '<div class="admin-card">' +
        '<h3 class="admin-card-title">What we protect</h3>' +
        '<div class="admin-form-row">' +
          countField({ key: 'serversPatched', label: 'Servers under managed patching' }, d) +
          '<div class="form-group" style="grid-column: span 2">' +
            '<label class="modal-label" for="cp-awarenessProgram">Security awareness programme</label>' +
            awarenessSelect(d) +
          '</div>' +
          '<div class="form-group" style="grid-column: span 2">' +
            '<label class="modal-label" for="cp-notes">Notes</label>' +
            '<input id="cp-notes" type="text" class="modal-status-select" maxlength="2000" ' +
              'autocomplete="off" placeholder="e.g. two legacy servers excluded from scanning" ' +
              'value="' + esc((d.declared || {}).notes || '') + '">' +
          '</div>' +
        '</div>' +
        '<div class="admin-form-row">' +
          '<div class="form-group admin-form-submit">' +
            '<button id="cp-save" type="button" class="btn btn-primary"' +
              (ro ? ' disabled' : '') + '>Save Profile</button>' +
          '</div>' +
          '<div class="form-group admin-form-submit">' +
            '<button id="cp-review" type="button" class="btn"' +
              (ro || !d.declared ? ' disabled' : '') + '>Confirm still correct</button>' +
          '</div>' +
        '</div>' +
        '<p id="cp-msg" class="admin-form-msg" hidden></p>' +
      '</div>' +

      '<div class="admin-card">' +
        '<h3 class="admin-card-title">What this means</h3>' +
        '<p class="admin-card-hint">' + esc('In effect: ' + (d.summary || 'not recorded')) + '</p>' +
        gapsBlock(d) +
        conflictsBlock(d) +
        historyBlock(d) +
      '</div>';

    wire();
  }

  function awarenessSelect(d) {
    var v = (d.declared || {}).awarenessProgram || '';
    var opts = [
      ['',         'Not recorded'],
      ['platform', 'Run through this platform'],
      ['internal', 'Client runs their own programme'],
      ['none',     'No programme in place'],
    ];
    return '<select id="cp-awarenessProgram" class="modal-status-select"' +
      (canWriteProfile() ? '' : ' disabled') + '>' +
      opts.map(function (o) {
        return '<option value="' + esc(o[0]) + '"' +
          (v === o[0] ? ' selected' : '') + '>' + esc(o[1]) + '</option>';
      }).join('') + '</select>';
  }

  // ── Wiring ────────────────────────────────────────────────────────────────

  function wire() {
    var save = document.getElementById('cp-save');
    if (save) save.onclick = handleSave;
    var rev = document.getElementById('cp-review');
    if (rev) rev.onclick = handleReview;
  }

  function collect() {
    var body = Object.assign({}, tenantBody());

    var fields = COUNT_FIELDS.map(function (f) { return f.key; }).concat(['serversPatched']);
    for (var i = 0; i < fields.length; i++) {
      var el = document.getElementById('cp-' + fields[i]);
      var raw = el ? String(el.value).trim() : '';
      // An empty box must send null, never 0. They are different claims and
      // only one of them changes which yardstick the client is measured on.
      if (raw === '') { body[fields[i]] = null; continue; }
      var n = Number(raw);
      if (!isFinite(n) || n < 0 || Math.floor(n) !== n) {
        msg('Enter a whole number of zero or more for each field.', true);
        return null;
      }
      body[fields[i]] = n;
    }

    var prog = document.getElementById('cp-awarenessProgram');
    body.awarenessProgram = (prog && prog.value) ? prog.value : null;

    var notes = document.getElementById('cp-notes');
    body.notes = notes ? notes.value : '';

    // Services are sent only when the catalogue actually rendered. Sending []
    // from a page that failed to draw its checkboxes would record "this client
    // buys nothing" — a claim nobody made.
    var boxes = document.querySelectorAll('.cp-svc');
    if (boxes.length) {
      body.services = Array.prototype.slice.call(boxes)
        .filter(function (b) { return b.checked; })
        .map(function (b) { return b.value; });
    }

    return body;
  }

  async function handleSave() {
    var btn = document.getElementById('cp-save');
    var body = collect();
    if (!body) return;

    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      var res = await fetch(apiUrl('client-profile') + tenantQS(), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      var j = await res.json().catch(function () { return {}; });
      if (!res.ok) { msg(j.error || ('Save failed (HTTP ' + res.status + ').'), true); return; }

      _data = j.profile;
      render(_data);

      if (j.changed === false) {
        msg('Nothing had changed, so nothing was recorded.', false);
      } else if (j.scoreBefore != null && j.scoreAfter != null &&
                 j.scoreBefore !== j.scoreAfter) {
        // Told immediately rather than discovered in next month's board pack.
        msg('Saved. The Secure Score moved from ' + j.scoreBefore +
            ' to ' + j.scoreAfter + '.', false);
      } else {
        msg('Saved.', false);
      }
    } catch (err) {
      msg('Save failed: ' + err.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Save Profile'; }
    }
  }

  async function handleReview() {
    var btn = document.getElementById('cp-review');
    if (btn) btn.disabled = true;
    try {
      var res = await fetch(apiUrl('client-profile/review') + tenantQS(), {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(tenantBody()),
      });
      var j = await res.json().catch(function () { return {}; });
      if (!res.ok) { msg(j.error || ('Could not confirm (HTTP ' + res.status + ').'), true); return; }
      _data = j.profile;
      render(_data);
      msg('Confirmed. Nothing was changed.', false);
    } catch (err) {
      msg('Could not confirm: ' + err.message, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function loadAndRender() {
    var host = document.getElementById('tab-client-profile');
    if (!host) return;
    try {
      var res = await fetch(apiUrl('client-profile') + tenantQS(),
        { credentials: 'same-origin' });
      if (!res.ok) {
        var j = await res.json().catch(function () { return {}; });
        host.innerHTML = '<div class="cp-stale">' +
          esc(j.error || ('Could not load the client profile (HTTP ' + res.status + ').')) +
          '</div>';
        return;
      }
      _data = await res.json();
      render(_data);
    } catch (err) {
      host.innerHTML = '<div class="cp-stale">Could not load the client profile: ' +
        esc(err.message) + '</div>';
    }
  }

  return { loadAndRender: loadAndRender, _render: render };
})();
