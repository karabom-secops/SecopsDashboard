/* tab-training.js — the SOC analyst training portal.
 *
 * Four views: the playbook reference, the module catalogue, a module (lessons
 * then knowledge check), and my own record.
 *
 * TWO THINGS THIS FILE IS CAREFUL ABOUT
 *
 * 1. It renders content as DATA, never as markup. Lesson bodies arrive as typed
 *    blocks and every value goes through esc() before it reaches the page. An
 *    unrecognised block type is skipped rather than passed through — the closed
 *    set is the security boundary, so widening it is a deliberate act.
 *
 * 2. It never knows the answers. The quiz arrives without them; submitting
 *    posts to the server, and the correct option and its explanation come back
 *    in the graded result. Grading here would have been simpler and would have
 *    made every recorded score meaningless.
 */

window.TrainingTab = (function () {
  'use strict';

  /*
   * The app is served under /secops/ and nginx strips the prefix, so every
   * request has to be built from <base href> — see the note in
   * tab-client-profile.js about the afternoon lost to getting this wrong.
   */
  var BASE = (function () {
    var base = document.querySelector('base');
    return base ? base.href : '/';
  })();

  function apiUrl(path) { return BASE + 'api/' + path; }

  var _view = 'modules';     // 'modules' | 'playbooks' | 'module' | 'record'
  var _moduleId = null;
  var _data = null;          // catalogue payload
  var _module = null;        // open module payload
  var _playbooks = null;
  var _result = null;        // last graded result

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function canManage() {
    return typeof window.canWrite === 'function' ? window.canWrite('training') : false;
  }

  async function get(path) {
    var res = await fetch(apiUrl(path), { credentials: 'same-origin' });
    var j = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(j.error || ('HTTP ' + res.status));
    return j;
  }

  async function post(path, body) {
    var res = await fetch(apiUrl(path), {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body || {}),
    });
    var j = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(j.error || ('HTTP ' + res.status));
    return j;
  }

  // ── Block rendering ───────────────────────────────────────────────────────

  /**
   * One lesson block.
   *
   * THE CLOSED SET IS THE SECURITY BOUNDARY. Every branch escapes its input,
   * and anything not matched returns '' rather than being rendered. There is no
   * `else` that falls back to raw output, deliberately: that fallback is how a
   * content pipeline acquires an XSS hole years after anyone reviewed it.
   */
  function renderBlock(b, playbooks) {
    if (!b || typeof b !== 'object') return '';

    if (typeof b.p === 'string')  return '<p class="tr-p">' + esc(b.p) + '</p>';
    if (typeof b.h === 'string')  return '<h4 class="tr-h">' + esc(b.h) + '</h4>';

    if (Array.isArray(b.list)) {
      return '<ul class="tr-list">' +
        b.list.map(function (i) { return '<li>' + esc(i) + '</li>'; }).join('') +
        '</ul>';
    }
    if (Array.isArray(b.steps)) {
      return '<ol class="tr-steps">' +
        b.steps.map(function (i) { return '<li>' + esc(i) + '</li>'; }).join('') +
        '</ol>';
    }
    if (typeof b.code === 'string') {
      return '<pre class="tr-code">' + esc(b.code) + '</pre>';
    }
    if (b.callout && typeof b.callout.text === 'string') {
      // Tone is an attribute value, so it is constrained to a known set rather
      // than escaped — escaping would keep it safe but would still let content
      // invent classes.
      var tone = ['info', 'warn', 'good'].indexOf(b.callout.tone) >= 0
        ? b.callout.tone : 'info';
      return '<div class="tr-callout tr-' + tone + '">' +
        esc(b.callout.text) + '</div>';
    }
    if (typeof b.playbook === 'string') {
      var pb = (playbooks || {})[b.playbook];
      // A playbook block whose data did not arrive renders as nothing rather
      // than as an empty frame implying the playbook has no steps.
      return pb ? playbookCard(pb, true) : '';
    }

    return '';
  }

  function renderBody(body, playbooks) {
    return (body || []).map(function (b) { return renderBlock(b, playbooks); }).join('');
  }

  // ── Playbooks ─────────────────────────────────────────────────────────────

  function playbookCard(pb, embedded) {
    return '<div class="tr-playbook' + (embedded ? ' tr-embedded' : '') + '">' +
        '<div class="tr-pb-head">' + esc(pb.label) +
          '<span class="tr-pb-tag">live playbook</span></div>' +
        pb.phases.map(function (ph) {
          return '<div class="tr-phase">' +
              '<div class="tr-phase-h">' + esc(ph.label) + '</div>' +
              '<ol class="tr-steps">' +
                ph.tasks.map(function (t) { return '<li>' + esc(t) + '</li>'; }).join('') +
              '</ol>' +
            '</div>';
        }).join('') +
        '<p class="tr-note">These are the tasks that populate the board when an ' +
          'incident of this type is opened &mdash; not a summary of them. ' +
          'Change the playbook and this changes with it.</p>' +
      '</div>';
  }

  function renderPlaybooks() {
    if (!_playbooks) return '<p class="tr-note">Loading&hellip;</p>';
    return '<div class="tr-intro">' +
        '<p>Every incident type and the tasks it seeds, straight from the ' +
        'response playbooks. This is a reference &mdash; nothing here can be ' +
        'edited, and nothing here differs from what you will be handed during ' +
        'a live incident.</p>' +
      '</div>' +
      _playbooks.map(function (p) { return playbookCard(p, false); }).join('');
  }

  // ── Modules ───────────────────────────────────────────────────────────────

  function moduleCard(m, progress, best) {
    var p = (progress || {})['module:' + m.id];
    var b = (best || {})[m.id];

    var state = '';
    if (p && p.status === 'completed') {
      state = '<span class="tr-state tr-done">Completed</span>';
    } else if (p) {
      state = '<span class="tr-state tr-started">In progress</span>';
    }

    var quiz = '';
    if (b) {
      quiz = '<span class="tr-state ' + (b.passed ? 'tr-pass' : 'tr-fail') + '">' +
        esc(b.score + '/' + b.total) + (b.passed ? ' passed' : ' — not yet passed') +
        '</span>';
    }

    return '<button type="button" class="tr-card" data-module="' + esc(m.id) + '">' +
        '<div class="tr-card-top">' +
          '<span class="tr-level tr-lv-' + esc(m.level) + '">' + esc(m.levelLabel) + '</span>' +
          '<span class="tr-mins">' + esc(m.estimateMins) + ' min</span>' +
        '</div>' +
        '<div class="tr-card-title">' + esc(m.title) + '</div>' +
        '<div class="tr-card-sum">' + esc(m.summary) + '</div>' +
        '<div class="tr-card-foot">' +
          esc(m.lessonCount) + ' lesson' + (m.lessonCount === 1 ? '' : 's') +
          (m.quizCount ? ' &middot; ' + esc(m.quizCount) + '-question check' : '') +
          state + quiz +
        '</div>' +
      '</button>';
  }

  function renderModules() {
    if (!_data) return '<p class="tr-note">Loading&hellip;</p>';

    var byLevel = (_data.levels || []).map(function (lv) {
      var mods = _data.modules.filter(function (m) { return m.level === lv; });
      if (!mods.length) return '';
      return '<h3 class="tr-level-h">' + esc((_data.levelLabels || {})[lv] || lv) + '</h3>' +
        '<div class="tr-grid">' +
          mods.map(function (m) {
            return moduleCard(m, _data.progress, _data.best);
          }).join('') +
        '</div>';
    }).join('');

    var warn = _data.available === false
      ? '<div class="tr-callout tr-warn">Progress cannot be saved yet &mdash; ' +
        'run db/migrate-training.sql. Everything is still readable.</div>'
      : '';

    return warn + byLevel;
  }

  // ── One module ────────────────────────────────────────────────────────────

  function renderModule() {
    if (!_module) return '<p class="tr-note">Loading&hellip;</p>';
    var m = _module.module;
    var done = (_module.progress || {})['module:' + m.id];

    return '<button type="button" class="btn tr-back" id="tr-back">&larr; All modules</button>' +
      '<div class="tr-mod-head">' +
        '<span class="tr-level tr-lv-' + esc(m.level) + '">' + esc(m.levelLabel) + '</span>' +
        '<h2>' + esc(m.title) + '</h2>' +
        '<p class="tr-card-sum">' + esc(m.summary) + '</p>' +
      '</div>' +
      m.lessons.map(function (l) {
        return '<section class="tr-lesson">' +
            '<h3 class="tr-lesson-h">' + esc(l.title) + '</h3>' +
            renderBody(l.body, _module.playbooks) +
          '</section>';
      }).join('') +
      renderQuiz(m) +
      '<div class="tr-mod-foot">' +
        '<button type="button" class="btn btn-primary" id="tr-complete"' +
          (done && done.status === 'completed' ? ' disabled' : '') + '>' +
          (done && done.status === 'completed' ? 'Completed' : 'Mark as complete') +
        '</button>' +
      '</div>';
  }

  function renderQuiz(m) {
    if (!m.quiz || !m.quiz.length) return '';

    // After grading, show the result instead of the form — including WHY, which
    // is the part that teaches.
    if (_result && _result.moduleId === m.id) {
      return '<section class="tr-quiz">' +
          '<h3 class="tr-lesson-h">Knowledge check</h3>' +
          '<div class="tr-result ' + (_result.passed ? 'tr-pass' : 'tr-fail') + '">' +
            esc(_result.score + ' of ' + _result.total) + ' &middot; ' +
            esc(_result.pct) + '% &middot; ' +
            (_result.passed ? 'passed' : 'not passed — ' +
              esc(Math.round(_result.passMark * 100)) + '% needed') +
          '</div>' +
          m.quiz.map(function (q, i) {
            var r = (_result.results || []).filter(function (x) { return x.id === q.id; })[0];
            if (!r) return '';
            return '<div class="tr-q ' + (r.correct ? 'tr-ok' : 'tr-no') + '">' +
                '<div class="tr-q-t">' + esc((i + 1) + '. ' + q.q) + '</div>' +
                '<div class="tr-q-a">Your answer: ' +
                  esc(r.picked == null ? 'not answered' : q.options[r.picked]) + '</div>' +
                (r.correct ? '' : '<div class="tr-q-c">Correct: ' +
                  esc(q.options[r.answer]) + '</div>') +
                '<div class="tr-q-w">' + esc(r.why) + '</div>' +
              '</div>';
          }).join('') +
          '<button type="button" class="btn" id="tr-retry">Try again</button>' +
        '</section>';
    }

    return '<section class="tr-quiz">' +
        '<h3 class="tr-lesson-h">Knowledge check</h3>' +
        m.quiz.map(function (q, i) {
          return '<div class="tr-q">' +
              '<div class="tr-q-t">' + esc((i + 1) + '. ' + q.q) + '</div>' +
              q.options.map(function (o, oi) {
                return '<label class="tr-opt">' +
                    '<input type="radio" name="' + esc(q.id) + '" value="' + oi + '">' +
                    '<span>' + esc(o) + '</span>' +
                  '</label>';
              }).join('') +
            '</div>';
        }).join('') +
        '<button type="button" class="btn btn-primary" id="tr-submit">Submit answers</button>' +
        '<p id="tr-quiz-msg" class="tr-note" hidden></p>' +
      '</section>';
  }

  // ── My record ─────────────────────────────────────────────────────────────

  function renderRecord() {
    if (!_data) return '<p class="tr-note">Loading&hellip;</p>';
    var attempts = _data.attempts || [];
    var titles = {};
    (_data.modules || []).forEach(function (m) { titles[m.id] = m.title; });

    var completed = Object.keys(_data.progress || {})
      .filter(function (k) { return (_data.progress[k] || {}).status === 'completed'; });

    return '<div class="tr-intro"><p>Your own record. Attempts are kept in ' +
        'full, including the ones that did not pass &mdash; a record that shows ' +
        'only successes cannot tell you where you improved.</p></div>' +
      '<div class="tr-panel"><h4 class="tr-panel-h">Completed</h4>' +
        (completed.length
          ? '<ul class="tr-list">' + completed.map(function (k) {
              return '<li>' + esc(titles[k.replace('module:', '')] || k) + '</li>';
            }).join('') + '</ul>'
          : '<p class="tr-note">Nothing completed yet.</p>') +
      '</div>' +
      '<div class="tr-panel"><h4 class="tr-panel-h">Attempt history</h4>' +
        (attempts.length
          ? attempts.map(function (a) {
              return '<div class="tr-h-row">' +
                  '<span class="tr-h-when">' +
                    esc(a.attemptedAt ? new Date(a.attemptedAt).toLocaleDateString() : '') +
                  '</span>' +
                  '<span class="tr-h-what">' + esc(titles[a.moduleId] || a.moduleId) + '</span>' +
                  '<span class="tr-state ' + (a.passed ? 'tr-pass' : 'tr-fail') + '">' +
                    esc(a.score + '/' + a.total) + '</span>' +
                '</div>';
            }).join('')
          : '<p class="tr-note">No attempts yet.</p>') +
      '</div>';
  }

  // ── Shell ─────────────────────────────────────────────────────────────────

  var TABS = [
    { id: 'modules',   label: 'Modules' },
    { id: 'playbooks', label: 'Playbooks' },
    { id: 'record',    label: 'My record' },
  ];

  function render() {
    var host = document.getElementById('tab-training');
    if (!host) return;

    var body = _view === 'playbooks' ? renderPlaybooks()
             : _view === 'module'    ? renderModule()
             : _view === 'record'    ? renderRecord()
             : renderModules();

    host.innerHTML =
      '<div class="page-head"><h2>Training</h2>' +
        '<p class="page-sub">Playbooks and upskilling for the SOC. Your ' +
        'progress is yours &mdash; nobody else sees your answers.</p></div>' +
      (_view === 'module' ? '' :
        '<div class="tr-tabs">' +
          TABS.map(function (t) {
            return '<button type="button" class="tr-tab' +
              (t.id === _view ? ' is-on' : '') + '" data-view="' + esc(t.id) + '">' +
              esc(t.label) + '</button>';
          }).join('') +
        '</div>') +
      '<div class="tr-body">' + body + '</div>';

    wire();
  }

  function wire() {
    document.querySelectorAll('#tab-training .tr-tab').forEach(function (b) {
      b.onclick = function () { show(b.dataset.view); };
    });
    document.querySelectorAll('#tab-training .tr-card').forEach(function (b) {
      b.onclick = function () { openModule(b.dataset.module); };
    });

    var back = document.getElementById('tr-back');
    if (back) back.onclick = function () { _result = null; show('modules'); };

    var submit = document.getElementById('tr-submit');
    if (submit) submit.onclick = submitQuiz;

    var retry = document.getElementById('tr-retry');
    if (retry) retry.onclick = function () { _result = null; render(); };

    var complete = document.getElementById('tr-complete');
    if (complete) complete.onclick = markComplete;
  }

  async function show(view) {
    _view = view;
    if (view === 'playbooks' && !_playbooks) {
      render();
      try { _playbooks = (await get('training/playbooks')).playbooks; }
      catch (err) { _playbooks = []; }
    }
    if (view === 'record' && _data && !_data.attempts) {
      try { _data.attempts = (await get('training/attempts')).attempts; }
      catch (err) { _data.attempts = []; }
    }
    render();
  }

  async function openModule(id) {
    _moduleId = id;
    _result = null;
    _view = 'module';
    render();
    try {
      _module = await get('training/modules/' + encodeURIComponent(id));
      render();
      // Opening a module marks it started. Best effort: a failure here must not
      // stop somebody reading it.
      post('training/progress', { itemKey: 'module:' + id, status: 'started' })
        .catch(function () {});
    } catch (err) {
      _module = null;
      render();
    }
  }

  async function submitQuiz() {
    if (!_module) return;
    var m = _module.module;
    var answers = {};
    m.quiz.forEach(function (q) {
      var picked = document.querySelector('#tab-training input[name="' + q.id + '"]:checked');
      // Integers only. The server treats anything else as wrong, and sending a
      // string would rely on that rather than being correct here.
      if (picked) answers[q.id] = parseInt(picked.value, 10);
    });

    var msg = document.getElementById('tr-quiz-msg');
    if (Object.keys(answers).length < m.quiz.length) {
      if (msg) {
        msg.hidden = false;
        msg.textContent = 'Answer every question — an unanswered one is marked wrong.';
      }
      return;
    }

    var btn = document.getElementById('tr-submit');
    if (btn) { btn.disabled = true; btn.textContent = 'Marking…'; }
    try {
      var j = await post('training/quiz/' + encodeURIComponent(m.id), { answers: answers });
      _result = j.result;
      render();
    } catch (err) {
      if (msg) { msg.hidden = false; msg.textContent = 'Could not submit: ' + err.message; }
      if (btn) { btn.disabled = false; btn.textContent = 'Submit answers'; }
    }
  }

  async function markComplete() {
    if (!_module) return;
    var btn = document.getElementById('tr-complete');
    if (btn) btn.disabled = true;
    try {
      await post('training/progress',
        { itemKey: 'module:' + _module.module.id, status: 'completed' });
      _module.progress = _module.progress || {};
      _module.progress['module:' + _module.module.id] = { status: 'completed' };
      _data = null;          // catalogue is stale now
      render();
    } catch (err) {
      if (btn) { btn.disabled = false; }
    }
  }

  async function loadAndRender() {
    var host = document.getElementById('tab-training');
    if (!host) return;
    try {
      if (!_data) _data = await get('training/modules');
      render();
    } catch (err) {
      host.innerHTML = '<div class="tr-callout tr-warn">Could not load training: ' +
        esc(err.message) + '</div>';
    }
  }

  return {
    loadAndRender: loadAndRender,
    // Seams. renderBlock in particular: it is the escaping boundary for all
    // lesson content, and a test that cannot call it directly can only check
    // escaping through whatever path it happens to exercise.
    _renderBlock: renderBlock,
    _renderBody: renderBody,
    _apiUrl: apiUrl,
    _canManage: canManage,
  };
})();
