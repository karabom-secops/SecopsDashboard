/* tab-awareness.js — Security Awareness Training tab renderer */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  var _data           = null;  // { upload, users }
  var _chartDist      = null;
  var _chartType      = null;
  var _chartTrend     = null;


  // ── XSS helper ─────────────────────────────────────────────────────────────
  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /**
   * Did this person click? true, false, or null when the export did not say.
   *
   * `clicked` is authoritative when present; `clicked_at` is a fallback for
   * rows written before db/migrate-awareness-clicked.sql, and only ever proves
   * a click — its absence there proves nothing, because the old parser left it
   * NULL both for a genuine non-click and for a value it could not read.
   *
   * The tri-state is the point. Counting "not reported" as "did not click" is
   * how a broken import reports a perfect score.
   */
  function clickState(s) {
    if (!s) return null;
    if (s.clicked === true || s.clicked === false) return s.clicked;
    if (s.clicked_at) return true;
    return null;
  }

  // ── Tenant query param helper ───────────────────────────────────────────────
  function tenantParam(sep) {
    var isSA = window.currentUser && window.currentUser.role === 'superadmin';
    if (!isSA || !window.globalTenantId) return '';
    return sep + 'tenantId=' + encodeURIComponent(window.globalTenantId);
  }

  // ── Public entry point ──────────────────────────────────────────────────────
  window.renderAwareness = async function renderAwareness() {
    var contentEl = document.getElementById('awarenessContent');
    var emptyEl   = document.getElementById('awarenessEmpty');
    var spinEl    = document.getElementById('awarenessLoading');
    if (spinEl)    spinEl.hidden   = false;
    if (contentEl) contentEl.hidden = true;
    if (emptyEl)   emptyEl.hidden   = true;

    try {
      var res = await fetch('api/awareness' + tenantParam('?'), { credentials: 'same-origin' });
      _data = res.ok ? await res.json() : { upload: null, users: [] };
    } catch (_) {
      _data = { upload: null, users: [] };
    }

    if (spinEl) spinEl.hidden = true;
    _renderAll();
  };

  // ── Full render ─────────────────────────────────────────────────────────────
  function _renderAll() {
    var hasData = _data && _data.upload;
    var emptyEl   = document.getElementById('awarenessEmpty');
    var contentEl = document.getElementById('awarenessContent');
    if (emptyEl)   emptyEl.hidden   = !!hasData;
    if (contentEl) contentEl.hidden = !hasData;

    // Upload metadata & delete button
    var metaEl  = document.getElementById('awarenessUploadedAt');
    var delBtn  = document.getElementById('awarenessDeleteBtn');

    if (metaEl) {
      if (hasData && _data.upload.uploaded_at) {
        var d = new Date(_data.upload.uploaded_at);
        metaEl.textContent = 'Uploaded ' + d.toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' });
      } else {
        metaEl.textContent = '';
      }
    }

    if (delBtn) {
      var isAdmin = window.canWrite('awareness');
      delBtn.hidden = !hasData || !isAdmin;
      if (!delBtn.dataset.handlerSet) {
        delBtn.dataset.handlerSet = '1';
        delBtn.addEventListener('click', function () {
          if (!confirm('Delete all awareness data for this tenant?')) return;
          _deleteData();
        });
      }
    }

    // The manual-entry card is a write action, so it follows the same gate as
    // the delete button rather than being shown to read-only viewers.
    var manualCard = document.getElementById('awarenessManualCard');
    if (manualCard) {
      manualCard.hidden = !window.canWrite('awareness');
      var mForm = document.getElementById('awarenessManualForm');
      if (mForm && !mForm.dataset.handlerSet) {
        mForm.dataset.handlerSet = '1';
        mForm.addEventListener('submit', _saveManual);
      }
      // Prefill from figures already recorded, so an edit starts from what is
      // there rather than from blank boxes that look like nothing was saved.
      if (hasData && (_data.upload.upload_type === 'manual')) {
        var t = parseInt(_data.upload.total_users, 10) || 0;
        var i = parseInt(_data.upload.total_incomplete, 10) || 0;
        var tEl = document.getElementById('awarenessManualTotal');
        var cEl = document.getElementById('awarenessManualCompleted');
        if (tEl && !tEl.value) tEl.value = t;
        if (cEl && !cEl.value) cEl.value = Math.max(0, t - i);
      }
    }

    if (!hasData) return;

    var type      = _data.upload.upload_type || 'summary';
    var isHistory = (type === 'history');
    var isManual  = (type === 'manual');
    var summaryEl = document.getElementById('awarenessSummaryContent');
    var historyEl = document.getElementById('awarenessHistoryContent');
    var manualEl  = document.getElementById('awarenessManualContent');
    if (summaryEl) summaryEl.hidden = isHistory || isManual;
    if (historyEl) historyEl.hidden = !isHistory;
    if (manualEl)  manualEl.hidden  = !isManual;

    var exportBtn = document.getElementById('awarenessExportCsvBtn');

    if (isManual) {
      // Deliberately NOT the summary path: manual figures carry no per-user
      // rows, and the distribution chart and offender tables would render as
      // empty boxes that read as missing data rather than as absent detail.
      if (exportBtn) exportBtn.hidden = true;
      _renderManualCards();
    } else if (isHistory) {
      _renderHistoryStatCards();
      _renderTypeBreakdownChart();
      _renderMonthlyTrendChart();
      _renderPhishingClickTable();
      _renderUserCompletionTable(); // also shows exportBtn
    } else {
      if (exportBtn) exportBtn.hidden = true;
      _renderStatCards();
      _renderChart();
      _renderManagerTable();
      _renderTopTable();
    }
  }

  // ── Delete ──────────────────────────────────────────────────────────────────
  async function _deleteData() {
    try {
      var r = await fetch('api/awareness' + tenantParam('?'), {
        method: 'DELETE', credentials: 'same-origin',
      });
      if (!r.ok) { var d = await r.json(); alert(d.error || 'Delete failed.'); return; }
      _data = { upload: null, users: [] };
      _renderAll();
    } catch (err) {
      alert('Network error: ' + err.message);
    }
  }

  function _manualMsg(text, isError) {
    var el = document.getElementById('awarenessManualMsg');
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ''; return; }
    el.hidden = false;
    el.textContent = text;
    el.className = isError ? 'admin-form-error' : 'admin-form-success';
  }

  /** Save client-supplied completion figures, replacing whatever is recorded. */
  async function _saveManual(e) {
    if (e) e.preventDefault();
    var btn = document.getElementById('awarenessManualSaveBtn');
    var tEl = document.getElementById('awarenessManualTotal');
    var cEl = document.getElementById('awarenessManualCompleted');

    var total     = tEl ? Number(tEl.value.trim()) : NaN;
    var completed = cEl ? Number(cEl.value.trim()) : NaN;

    function whole(n) { return Number.isFinite(n) && n >= 0 && Math.floor(n) === n; }
    if (!whole(total) || total < 1) {
      _manualMsg('Staff covered must be a whole number of one or more.', true); return;
    }
    if (!whole(completed)) {
      _manualMsg('Staff completed must be a whole number of zero or more.', true); return;
    }
    // Checked here as well as on the server: clamping this silently would turn a
    // typo into a 100% completion rate on a board report.
    if (completed > total) {
      _manualMsg('Staff completed cannot exceed staff covered.', true); return;
    }

    if (btn) { btn.disabled = true; btn.textContent = 'Saving…'; }
    try {
      var body = { totalUsers: total, completedUsers: completed };
      if (window.currentUser && window.currentUser.role === 'superadmin' && window.globalTenantId) {
        body.tenantId = window.globalTenantId;
      }
      var r = await fetch('api/awareness/manual', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(body),
      });
      var data = await r.json().catch(function () { return {}; });
      if (!r.ok) { _manualMsg(data.error || ('Save failed (HTTP ' + r.status + ').'), true); return; }
      _manualMsg('Figures saved. The Secure Score will use them on next refresh.', false);
      await window.renderAwareness();
    } catch (err) {
      _manualMsg('Save failed: ' + err.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Save Figures'; }
    }
  }

  // ── Manually recorded figures ───────────────────────────────────────────────
  function _renderManualCards() {
    var el = document.getElementById('awareness-manual-stat-cards');
    var up = _data && _data.upload;
    if (!el || !up) return;

    var total      = parseInt(up.total_users, 10) || 0;
    var incomplete = parseInt(up.total_incomplete, 10) || 0;
    var completed  = Math.max(0, total - incomplete);
    var pct        = total > 0 ? Math.round((completed / total) * 100) : 0;

    el.innerHTML =
      _card('Staff Covered', total, 'accent-blue', '') +
      _card('Completed', completed, 'accent-blue', '') +
      _card('Outstanding', incomplete, incomplete > 0 ? 'accent-amber' : 'accent-blue', '') +
      _card('Completion Rate', pct + '%', pct >= 90 ? 'accent-blue' : 'accent-amber', '');

    var prov = document.getElementById('awarenessManualProvenance');
    if (prov) {
      prov.textContent = 'Client-supplied figures from an internally run awareness ' +
        'programme. These are scored at full weight but have not been verified ' +
        'against training records held by this platform.';
    }
  }

  // ── Stat cards ──────────────────────────────────────────────────────────────
  function _renderStatCards() {
    var el = document.getElementById('awareness-stat-cards');
    if (!el || !_data) return;

    var users     = _data.users || [];
    var upload    = _data.upload;
    var total     = upload ? upload.total_users      : users.length;
    var incomplete = upload ? upload.total_incomplete : users.reduce(function (s, u) { return s + u.incomplete_sessions; }, 0);
    var avg       = total > 0 ? (incomplete / total).toFixed(1) : '0.0';
    var highCount = users.filter(function (u) { return u.incomplete_sessions >= 10; }).length;

    el.innerHTML =
      _card('Total Employees Tracked', total,            'accent-blue',  '') +
      _card('Total Incomplete Sessions', incomplete,     'accent-red',   '') +
      _card('Avg Incomplete / Employee', avg,            'accent-amber', '') +
      _card('Employees with 10+ Incomplete', highCount,  'accent-purple', '');
  }

  function _card(label, value, accent, sub) {
    return '<div class="stat-card ' + esc(accent) + '">' +
      '<div class="stat-value">' + esc(String(value)) + '</div>' +
      '<div class="stat-label">' + esc(label) + '</div>' +
      (sub ? '<div class="stat-sub">' + esc(sub) + '</div>' : '') +
      '</div>';
  }

  // ── Distribution bar chart (Chart.js) ──────────────────────────────────────
  function _renderChart() {
    var canvas = document.getElementById('chartAwarenessDistrib');
    if (!canvas || !_data) return;
    if (_chartDist) { _chartDist.destroy(); _chartDist = null; }

    var users   = _data.users || [];
    var buckets = [
      { label: '1–5',   min: 1,  max: 5  },
      { label: '6–10',  min: 6,  max: 10 },
      { label: '11–15', min: 11, max: 15 },
      { label: '16–20', min: 16, max: 20 },
      { label: '20+',        min: 21, max: Infinity },
    ];
    var counts = buckets.map(function (b) {
      return users.filter(function (u) {
        return u.incomplete_sessions >= b.min && u.incomplete_sessions <= b.max;
      }).length;
    });

    _chartDist = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: buckets.map(function (b) { return b.label; }),
        datasets: [{
          label: 'Employees',
          data: counts,
          backgroundColor: 'rgba(37,99,235,0.75)',
          borderColor: '#2563eb',
          borderWidth: 1,
          borderRadius: 4,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a9bb0', precision: 0 }, grid: { color: 'rgba(0,0,0,0.06)' } },
          x: { title: { display: true, text: 'Incomplete Sessions Range', color: '#7a9bb0', font: { size: 11 } }, ticks: { color: '#7a9bb0' }, grid: { display: false } },
        },
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: function (ctx) { return ' ' + ctx.parsed.y + ' employee' + (ctx.parsed.y !== 1 ? 's' : ''); } } },
        },
      },
    });
  }

  // ── Manager breakdown table ─────────────────────────────────────────────────
  function _renderManagerTable() {
    var table = document.getElementById('awarenessManagerTable');
    if (!table || !_data) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;

    var users = _data.users || [];

    // Group by manager email (null/empty → 'No Manager')
    var groups = {};
    users.forEach(function (u) {
      var key  = u.manager_email || '';
      var name = key
        ? ((u.manager_first_name || '') + ' ' + (u.manager_last_name || '')).trim() || key
        : 'No Manager';
      if (!groups[key]) {
        groups[key] = { managerName: name, managerEmail: key, total: 0, users: [] };
      }
      groups[key].total += u.incomplete_sessions;
      groups[key].users.push(u);
    });

    var rows = Object.values(groups).sort(function (a, b) { return b.total - a.total; });

    tbody.innerHTML = rows.map(function (g) {
      // Worst offender = user with most incomplete sessions in this group
      var worst = g.users.reduce(function (max, u) {
        return u.incomplete_sessions > max.incomplete_sessions ? u : max;
      }, g.users[0]);
      var worstName = worst ? ((worst.user_first_name || '') + ' ' + (worst.user_last_name || '')).trim() : '';

      return '<tr>' +
        '<td>' + esc(g.managerName) + (g.managerEmail ? '<br><small class="muted">' + esc(g.managerEmail) + '</small>' : '') + '</td>' +
        '<td class="col-num">' + esc(String(g.users.length)) + '</td>' +
        '<td class="col-num"><strong>' + esc(String(g.total)) + '</strong></td>' +
        '<td>' + esc(worstName) + '</td>' +
        '<td class="col-num">' + esc(String(worst ? worst.incomplete_sessions : 0)) + '</td>' +
        '</tr>';
    }).join('');
  }

  // ── Top offenders table ─────────────────────────────────────────────────────
  function _renderTopTable() {
    var table = document.getElementById('awarenessTopTable');
    if (!table || !_data) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;

    var top = (_data.users || []).slice(0, 10);

    tbody.innerHTML = top.map(function (u, i) {
      var fullName    = ((u.user_first_name || '') + ' ' + (u.user_last_name || '')).trim();
      var managerName = u.manager_email
        ? ((u.manager_first_name || '') + ' ' + (u.manager_last_name || '')).trim() || u.manager_email
        : '\u2014';

      return '<tr>' +
        '<td class="col-num">' + esc(String(i + 1)) + '</td>' +
        '<td>' + esc(fullName) + '</td>' +
        '<td><small>' + esc(u.user_email || '') + '</small></td>' +
        '<td>' + esc(managerName) + '</td>' +
        '<td class="col-num"><strong>' + esc(String(u.incomplete_sessions)) + '</strong></td>' +
        '</tr>';
    }).join('');
  }

  // ── History: stat cards ─────────────────────────────────────────────────────
  function _renderHistoryStatCards() {
    var el = document.getElementById('awareness-history-stat-cards');
    if (!el || !_data) return;

    var sessions = _data.sessions || [];

    // Unique employees
    var userEmails = new Set(sessions.map(function (s) { return (s.user_email || '').toLowerCase(); }));
    var totalUsers = userEmails.size;

    // Completion rate: Awareness Session + Quiz + Phishing Remediation Session (exclude raw Phishing Simulation)
    var trainSessions = sessions.filter(function (s) {
      return s.session_type !== 'Phishing Simulation';
    });
    var completedTrain = trainSessions.filter(function (s) { return s.status === 'Complete'; }).length;
    var compRate = trainSessions.length > 0
      ? Math.round(completedTrain / trainSessions.length * 100)
      : 0;

    /* Phishing click rate: unique users who clicked / unique users sent a sim.
     *
     * `clicked` is the fact and `clicked_at` is only the time, so the fact is
     * what gets counted. Reading a click as !!clicked_at was half of why this
     * card once showed 99%: the parser was manufacturing timestamps out of a
     * yes/no column, and the value meaning "no" produced the year 1999.
     *
     * A row whose click state is unknown is excluded from BOTH sides rather
     * than counted as a non-click, so a reporting gap cannot masquerade as
     * good news. */
    var phishingSims = sessions.filter(function (s) { return s.session_type === 'Phishing Simulation'; });
    var knownSims = phishingSims.filter(function (s) { return clickState(s) !== null; });

    var sentPhishEmails = new Set(knownSims.map(function (s) {
      return (s.user_email || '').toLowerCase();
    }));
    var clickedPhishEmails = new Set(
      knownSims
        .filter(function (s) { return clickState(s) === true; })
        .map(function (s) { return (s.user_email || '').toLowerCase(); })
    );
    var unknownSims = phishingSims.length - knownSims.length;
    var phishClickRate = sentPhishEmails.size > 0
      ? Math.round(clickedPhishEmails.size / sentPhishEmails.size * 100)
      : null;

    // Avg quiz score (only rows where quiz_score is a number)
    var quizRows = sessions.filter(function (s) { return s.quiz_score !== null && s.quiz_score !== undefined; });
    var avgQuiz  = quizRows.length > 0
      ? (quizRows.reduce(function (sum, s) { return sum + parseFloat(s.quiz_score); }, 0) / quizRows.length).toFixed(1)
      : 'N/A';

    el.innerHTML =
      _card('Total Employees',          totalUsers,                       'accent-blue',   '') +
      _card('Training Completion Rate', compRate + '%',                   'accent-green',  completedTrain + ' / ' + trainSessions.length + ' sessions') +
      _card('Phishing Click Rate',
            phishClickRate === null ? 'Not reported' : phishClickRate + '%',
            'accent-red',
            phishClickRate === null
              ? (phishingSims.length
                  ? 'This export carried no click result'
                  : 'No phishing simulations in this export')
              : clickedPhishEmails.size + ' / ' + sentPhishEmails.size + ' employees' +
                (unknownSims ? ' · ' + unknownSims + ' not reported' : '')) +
      _card('Avg Quiz Score',           avgQuiz + (avgQuiz !== 'N/A' ? '%' : ''), 'accent-amber', quizRows.length + ' quiz attempts');
  }

  // ── History: training type breakdown chart (Chart.js) ─────────────────────
  function _renderTypeBreakdownChart() {
    var canvas = document.getElementById('chartAwarenessTypeBreakdown');
    if (!canvas || !_data) return;
    if (_chartType) { _chartType.destroy(); _chartType = null; }

    var sessions = _data.sessions || [];
    var types    = ['Awareness Session', 'Quiz', 'Phishing Remediation Session'];
    var labels   = ['Awareness', 'Quiz', 'Phishing Remediation'];

    var completed  = types.map(function (t) {
      return sessions.filter(function (s) { return s.session_type === t && s.status === 'Complete'; }).length;
    });
    var notStarted = types.map(function (t) {
      return sessions.filter(function (s) { return s.session_type === t && s.status === 'Not Started'; }).length;
    });

    _chartType = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [
          { label: 'Completed',  data: completed,  backgroundColor: 'rgba(22,163,74,0.8)',  borderColor: '#16a34a', borderWidth: 1, borderRadius: 4 },
          { label: 'Not Started', data: notStarted, backgroundColor: 'rgba(220,38,38,0.8)', borderColor: '#dc2626', borderWidth: 1, borderRadius: 4 },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a9bb0', precision: 0 }, grid: { color: 'rgba(0,0,0,0.06)' } },
          x: { ticks: { color: '#7a9bb0' }, grid: { display: false } },
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#7a9bb0', boxWidth: 12, padding: 16 } },
          tooltip: { mode: 'index', intersect: false },
        },
      },
    });
  }

  // ── History: monthly trend chart (Chart.js) ──────────────────────────────
  function _renderMonthlyTrendChart() {
    var canvas = document.getElementById('chartAwarenessTrend');
    if (!canvas || !_data) return;
    if (_chartTrend) { _chartTrend.destroy(); _chartTrend = null; }

    var sessions = _data.sessions || [];

    var monthMap = {};
    sessions.forEach(function (s) {
      if (!s.sent_date || s.session_type === 'Phishing Simulation') return;
      var d   = new Date(s.sent_date);
      var key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
      if (!monthMap[key]) monthMap[key] = { assigned: 0, completed: 0 };
      monthMap[key].assigned++;
      if (s.status === 'Complete') monthMap[key].completed++;
    });

    var keys = Object.keys(monthMap).sort();
    var labelsFmt = keys.map(function (k) {
      var parts = k.split('-');
      return new Date(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, 1)
        .toLocaleDateString('en-US', { month: 'short', year: '2-digit' });
    });

    if (keys.length === 0) {
      var ctx2 = canvas.getContext('2d');
      ctx2.clearRect(0, 0, canvas.width, canvas.height);
      return;
    }

    _chartTrend = new Chart(canvas, {
      type: 'line',
      data: {
        labels: labelsFmt,
        datasets: [
          { label: 'Assigned',  data: keys.map(function (k) { return monthMap[k].assigned; }),  borderColor: '#93c5fd', backgroundColor: 'rgba(147,197,253,0.08)', tension: 0.3, pointRadius: 4, fill: false },
          { label: 'Completed', data: keys.map(function (k) { return monthMap[k].completed; }), borderColor: '#16a34a', backgroundColor: 'rgba(22,163,74,0.08)',   tension: 0.3, pointRadius: 4, fill: false },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a9bb0', precision: 0 }, grid: { color: 'rgba(0,0,0,0.06)' } },
          x: { ticks: { color: '#7a9bb0', maxTicksLimit: 12 }, grid: { display: false } },
        },
        plugins: {
          legend: { position: 'bottom', labels: { color: '#7a9bb0', boxWidth: 12, padding: 16 } },
          tooltip: { mode: 'index', intersect: false },
        },
      },
    });
  }

  // ── History: phishing click table ───────────────────────────────────────────
  function _renderPhishingClickTable() {
    var table = document.getElementById('awarenessPhishingTable');
    if (!table || !_data) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;

    var sessions = _data.sessions || [];
    // A click is a click whether or not the export dated it.
    var phishing = sessions.filter(function (s) {
      return s.session_type === 'Phishing Simulation' && clickState(s) === true;
    });

    // Group by user email — count clicks
    var byUser = {};
    phishing.forEach(function (s) {
      var key = (s.user_email || '').toLowerCase();
      if (!byUser[key]) {
        byUser[key] = {
          name:    ((s.user_first_name || '') + ' ' + (s.user_last_name || '')).trim(),
          email:   s.user_email || '',
          manager: s.manager_email
            ? ((s.manager_first_name || '') + ' ' + (s.manager_last_name || '')).trim() || s.manager_email
            : '\u2014',
          clicks:   0,
          lastSim:  null,
          // Kept as a Date so the comparison below is date-to-date. It used to
          // compare against lastSim, which holds a TITLE — so the comparison
          // was always false and the column showed the first sim, not the last.
          lastClickAt: null,
        };
      }
      byUser[key].clicks++;
      // Only a dated click can order the list; a flag-only row still counts
      // toward the total but cannot claim to be the most recent one.
      if (s.clicked_at) {
        var cd = new Date(s.clicked_at);
        if (!byUser[key].lastClickAt || cd > byUser[key].lastClickAt) {
          byUser[key].lastClickAt = cd;
          byUser[key].lastSim = s.title || '';
        }
      } else if (!byUser[key].lastSim) {
        byUser[key].lastSim = s.title || '';
      }
    });

    var rows = Object.values(byUser).sort(function (a, b) { return b.clicks - a.clicks; });

    if (rows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="muted" style="text-align:center">No phishing clicks recorded.</td></tr>';
      return;
    }

    tbody.innerHTML = rows.map(function (r, i) {
      return '<tr>' +
        '<td class="col-num">' + esc(String(i + 1)) + '</td>' +
        '<td>' + esc(r.name) + '</td>' +
        '<td><small>' + esc(r.email) + '</small></td>' +
        '<td>' + esc(r.manager) + '</td>' +
        '<td class="col-num"><strong>' + esc(String(r.clicks)) + '</strong></td>' +
        '<td><small>' + esc(r.lastSim || '\u2014') + '</small></td>' +
        '</tr>';
    }).join('');
  }

  // ── History: per-user completion table ─────────────────────────────────────
  // Sort state for the user completion table
  var _ucSort = { col: 'pct', dir: 'asc' };

  function _renderUserCompletionTable() {
    var table = document.getElementById('awarenessUserCompletionTable');
    if (!table || !_data) return;
    var tbody = table.querySelector('tbody');
    if (!tbody) return;

    var sessions = _data.sessions || [];
    // Only include types that count toward training completion
    var trainSessions = sessions.filter(function (s) {
      return s.session_type !== 'Phishing Simulation';
    });

    var byUser = {};
    trainSessions.forEach(function (s) {
      var key = (s.user_email || '').toLowerCase();
      if (!byUser[key]) {
        byUser[key] = {
          name:    ((s.user_first_name || '') + ' ' + (s.user_last_name || '')).trim(),
          email:   s.user_email || '',
          manager: s.manager_email
            ? ((s.manager_first_name || '') + ' ' + (s.manager_last_name || '')).trim() || s.manager_email
            : '\u2014',
          assigned:  0,
          completed: 0,
          missing:   [],
        };
      }
      byUser[key].assigned++;
      if (s.status === 'Complete') {
        byUser[key].completed++;
      } else if (s.status === 'Not Started') {
        byUser[key].missing.push({
          type:  s.session_type || '',
          title: s.title        || '',
          date:  s.sent_date    || null,
        });
      }
    });

    var allRows = Object.values(byUser);

    function _sortRows(rows) {
      var col = _ucSort.col;
      var dir = _ucSort.dir === 'asc' ? 1 : -1;
      return rows.slice().sort(function (a, b) {
        var va, vb;
        if (col === 'manager') {
          va = (a.manager || '').toLowerCase();
          vb = (b.manager || '').toLowerCase();
          return dir * (va < vb ? -1 : va > vb ? 1 : 0);
        } else if (col === 'assigned') {
          return dir * (a.assigned - b.assigned);
        } else if (col === 'completed') {
          return dir * (a.completed - b.completed);
        } else { // pct
          var ra = a.assigned > 0 ? a.completed / a.assigned : 1;
          var rb = b.assigned > 0 ? b.completed / b.assigned : 1;
          return dir * (ra - rb);
        }
      });
    }

    function _updateSortIndicators() {
      table.querySelectorAll('.sortable-col').forEach(function (th) {
        var ind = th.querySelector('.sort-indicator');
        if (!ind) return;
        if (th.dataset.sortCol === _ucSort.col) {
          ind.textContent = _ucSort.dir === 'asc' ? ' \u25b2' : ' \u25bc';
        } else {
          ind.textContent = '';
        }
      });
    }

    function _rebuildCompletionBody(tbodyEl, sortedRows, searchEl) {
      var html = '';
      sortedRows.forEach(function (r, i) {
        var pct      = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
        var pctClass = pct >= 80 ? 'accent-green' : pct >= 50 ? 'accent-amber' : 'accent-red';
        var detailId  = 'uc-detail-' + i;
        var missCount = r.missing.length;

        html += '<tr>' +
          '<td>' + esc(r.name) + '</td>' +
          '<td><small>' + esc(r.email) + '</small></td>' +
          '<td>' + esc(r.manager) + '</td>' +
          '<td class="col-num">' + esc(String(r.assigned)) + '</td>' +
          '<td class="col-num">' + esc(String(r.completed)) + '</td>' +
          '<td class="col-num"><strong class="' + esc(pctClass) + '">' + esc(String(pct)) + '%</strong></td>' +
          '<td class="col-num">' +
            (missCount > 0
              ? '<button class="btn-link awareness-missing-toggle" data-target="' + esc(detailId) + '" aria-expanded="false">' +
                  '&#9654; ' + esc(String(missCount)) +
                '</button>'
              : '<span class="muted">\u2014</span>') +
          '</td>' +
          '</tr>';

        if (missCount > 0) {
          var items = r.missing.map(function (m) {
            var dateStr = m.date
              ? new Date(m.date).toLocaleDateString('en-ZA', { day: 'numeric', month: 'short', year: 'numeric' })
              : '';
            var typeTag = m.type === 'Quiz'
              ? '<span class="badge badge-amber">Quiz</span>'
              : m.type === 'Phishing Remediation Session'
                ? '<span class="badge badge-red">Phishing Remediation</span>'
                : '<span class="badge badge-blue">Awareness</span>';
            return '<li>' + typeTag + ' ' + esc(m.title) +
              (dateStr ? ' <span class="muted">(' + esc(dateStr) + ')</span>' : '') + '</li>';
          }).join('');

          html += '<tr id="' + esc(detailId) + '" class="awareness-missing-detail" hidden>' +
            '<td colspan="7" style="padding:0.5rem 1rem 0.75rem 2rem;background:var(--surface-alt,#f5f6f8)">' +
            '<ul class="awareness-missing-list">' + items + '</ul>' +
            '</td></tr>';
        }
      });

      tbodyEl.innerHTML = html;

      // Re-apply search filter if there's an active term
      if (searchEl && searchEl.value.trim()) {
        var term = searchEl.value.trim().toLowerCase();
        tbodyEl.querySelectorAll('tr').forEach(function (tr) {
          if (tr.classList.contains('awareness-missing-detail')) return;
          var show = tr.textContent.toLowerCase().indexOf(term) !== -1;
          tr.hidden = !show;
          var toggleBtn = tr.querySelector('.awareness-missing-toggle');
          if (toggleBtn && !show) {
            var dr = document.getElementById(toggleBtn.getAttribute('data-target'));
            if (dr) dr.hidden = true;
          }
        });
      }
    }

    var searchInput = document.getElementById('awarenessCompletionSearch');

    // Attach sort click handlers once (guard with dataset flag)
    if (!table.dataset.sortBound) {
      table.dataset.sortBound = '1';
      table.querySelectorAll('.sortable-col').forEach(function (th) {
        th.addEventListener('click', function () {
          var col = th.dataset.sortCol;
          if (_ucSort.col === col) {
            _ucSort.dir = _ucSort.dir === 'asc' ? 'desc' : 'asc';
          } else {
            _ucSort.col = col;
            _ucSort.dir = 'asc';
          }
          _updateSortIndicators();
          _rebuildCompletionBody(tbody, _sortRows(allRows), searchInput);
        });
      });
    }

    _updateSortIndicators();
    _rebuildCompletionBody(tbody, _sortRows(allRows), searchInput);

    // Delegate toggle clicks on the tbody (works after innerHTML replacement)
    tbody.addEventListener('click', function (e) {
      var btn = e.target.closest('.awareness-missing-toggle');
      if (!btn) return;
      var detailRow = document.getElementById(btn.getAttribute('data-target'));
      if (!detailRow) return;
      var expanded = btn.getAttribute('aria-expanded') === 'true';
      detailRow.hidden = expanded;
      btn.setAttribute('aria-expanded', String(!expanded));
      btn.innerHTML = (expanded ? '&#9654; ' : '&#9660; ') + esc(String(detailRow.querySelectorAll('li').length));
    });

    // Live search filter
    if (searchInput) {
      searchInput.value = '';
      searchInput.oninput = function () {
        var term = searchInput.value.trim().toLowerCase();
        tbody.querySelectorAll('tr').forEach(function (tr) {
          if (tr.classList.contains('awareness-missing-detail')) return;
          var text = tr.textContent.toLowerCase();
          var show = !term || text.indexOf(term) !== -1;
          tr.hidden = !show;
          var toggleBtn = tr.querySelector('.awareness-missing-toggle');
          if (toggleBtn) {
            var detailRow = document.getElementById(toggleBtn.getAttribute('data-target'));
            if (detailRow && !show) detailRow.hidden = true;
          }
        });
      };
    }

    // CSV export button
    var exportBtn = document.getElementById('awarenessExportCsvBtn');
    if (exportBtn) {
      exportBtn.hidden = false;
      exportBtn.onclick = function () {
        var csvRows = [['Name', 'Email', 'Manager', 'Assigned', 'Completed', '%']];
        _sortRows(allRows).forEach(function (r) {
          var pct = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
          csvRows.push([r.name, r.email, r.manager, r.assigned, r.completed, pct + '%']);
        });
        // Shared helper: it attaches the anchor to the document before clicking
        // it, which a detached <a download> requires in order to fire at all.
        window.ReportShell.downloadFile(
          'awareness-completion.csv',
          window.ReportShell.toCsv(csvRows),
          'text/csv;charset=utf-8'
        );
      };
    }

    // Export <70% users button
    var exportLowBtn = document.getElementById('awarenessExportLowBtn');
    if (exportLowBtn) {
      exportLowBtn.hidden = false;
      exportLowBtn.onclick = function () {
        var lowRows = allRows.filter(function (r) {
          return r.assigned > 0 && Math.round(r.completed / r.assigned * 100) < 70;
        });
        if (!lowRows.length) {
          alert('Every employee is at or above 70% completion — nothing to export.');
          return;
        }
        var csvRows = [['Name', 'Email', 'Manager', 'Assigned', 'Completed', '%', 'Missing Sessions']];
        lowRows.forEach(function (r) {
          var pct = Math.round(r.completed / r.assigned * 100);
          var missing = (r.missing || []).map(function (m) { return m.title || m.type; }).join('; ');
          csvRows.push([r.name, r.email, r.manager, r.assigned, r.completed, pct + '%', missing]);
        });
        window.ReportShell.downloadFile(
          'awareness-below-70pct.csv',
          window.ReportShell.toCsv(csvRows),
          'text/csv;charset=utf-8'
        );
      };
    }

    // Manager Report button
    var mgrReportBtn = document.getElementById('awarenessManagerReportBtn');
    if (mgrReportBtn) {
      mgrReportBtn.hidden = false;
      mgrReportBtn.onclick = function () {
        // The popup MUST be opened synchronously here. _generateManagerReport
        // awaits the logo fetch before building its HTML, and a window opened
        // after an await has lost the page's transient user activation, so the
        // browser blocks it as unrequested — which is why this button appeared
        // to do nothing at all.
        var handle = window.ReportShell.reserveReportWindow({
          width: 960, height: 700, title: 'Manager Compliance Report',
        });
        if (!handle) return;
        _generateManagerReport(allRows, handle).catch(function () {
          handle.fail('The manager report could not be generated.');
        });
      };
    }
  }

  // ── Manager compliance report (printable popup) ─────────────────────────────
  async function _logoToDataUri() {
    return window.ReportShell.logoToDataUri();
  }

  async function _generateManagerReport(rows, handle) {
    var logoDataUri = await _logoToDataUri();
    // Group users below 70% by manager
    var byManager = {};
    var managerOrder = [];
    rows.forEach(function (r) {
      var pct = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
      if (pct >= 70) return;
      // Derive manager key from the raw session data for email, fall back to display name
      var sessions = (_data && _data.sessions) || [];
      var managerEmail = '';
      var managerName  = r.manager && r.manager !== '—' ? r.manager : '';
      // Find manager email from sessions for this user
      var userKey = r.email.toLowerCase();
      for (var i = 0; i < sessions.length; i++) {
        if ((sessions[i].user_email || '').toLowerCase() === userKey && sessions[i].manager_email) {
          managerEmail = sessions[i].manager_email;
          if (!managerName) {
            managerName = (
              ((sessions[i].manager_first_name || '') + ' ' + (sessions[i].manager_last_name || '')).trim()
            ) || managerEmail;
          }
          break;
        }
      }
      var key = managerEmail || managerName || 'Unknown Manager';
      if (!byManager[key]) {
        byManager[key] = { name: managerName || key, email: managerEmail, users: [], totalTeam: 0 };
        managerOrder.push(key);
      }
      byManager[key].users.push({ name: r.name, email: r.email, assigned: r.assigned, completed: r.completed, pct: pct, missing: r.missing });
    });

    // Count each manager's total team size from all rows (not just below-70%)
    rows.forEach(function (r) {
      var sessions = (_data && _data.sessions) || [];
      var userKey = r.email.toLowerCase();
      var managerEmail = '';
      var managerName  = r.manager && r.manager !== '—' ? r.manager : '';
      for (var i = 0; i < sessions.length; i++) {
        if ((sessions[i].user_email || '').toLowerCase() === userKey && sessions[i].manager_email) {
          managerEmail = sessions[i].manager_email;
          if (!managerName) {
            managerName = (
              ((sessions[i].manager_first_name || '') + ' ' + (sessions[i].manager_last_name || '')).trim()
            ) || managerEmail;
          }
          break;
        }
      }
      var key = managerEmail || managerName || 'Unknown Manager';
      if (byManager[key]) byManager[key].totalTeam++;
    });

    if (managerOrder.length === 0) {
      alert('All employees have met or exceeded the 70% training threshold.');
      return;
    }

    var reportDate = new Date().toLocaleDateString('en-ZA', { day: 'numeric', month: 'long', year: 'numeric' });
    var totalNonCompliant = managerOrder.reduce(function (s, k) { return s + byManager[k].users.length; }, 0);

    var sectionsHtml = managerOrder.map(function (key) {
      var g = byManager[key];
      var teamLabel = g.totalTeam > 0 ? g.users.length + ' of ' + g.totalTeam + ' team members' : g.users.length + ' team member(s)';
      var rowsHtml = g.users.map(function (u) {
        var pctColor = u.pct < 50 ? '#dc2626' : '#d97706';
        var missingList = u.missing.length > 0
          ? u.missing.map(function (m) { return esc(m.title || m.type); }).join(', ')
          : '—';
        return '<tr>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0">' + esc(u.name) + '</td>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0;color:#64748b;font-size:0.82rem">' + esc(u.email) + '</td>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0;text-align:center">' + esc(String(u.assigned)) + '</td>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0;text-align:center">' + esc(String(u.completed)) + '</td>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0;text-align:center;font-weight:700;color:' + pctColor + '">' + esc(String(u.pct)) + '%</td>' +
          '<td style="padding:8px 10px;border-bottom:1px solid #e8ecf0;font-size:0.8rem;color:#64748b">' + missingList + '</td>' +
          '</tr>';
      }).join('');

      return '<div style="page-break-inside:avoid;break-inside:avoid;margin-bottom:2rem;border:1px solid #dde4ed;border-radius:8px;overflow:hidden">' +
        '<div style="background:#1565C0;color:#fff;padding:14px 18px;display:flex;justify-content:space-between;align-items:center">' +
          '<div>' +
            '<div style="font-size:1rem;font-weight:700">' + esc(g.name) + '</div>' +
            (g.email ? '<div style="font-size:0.78rem;opacity:0.85;margin-top:2px">' + esc(g.email) + '</div>' : '') +
          '</div>' +
          '<div style="background:rgba(255,255,255,0.2);border-radius:20px;padding:4px 14px;font-size:0.85rem;font-weight:600">' +
            esc(teamLabel) + ' below 70%' +
          '</div>' +
        '</div>' +
        '<table style="width:100%;border-collapse:collapse;font-size:0.88rem;font-family:Segoe UI,Arial,sans-serif">' +
          '<thead>' +
            '<tr style="background:#f1f5f9">' +
              '<th style="padding:9px 10px;text-align:left;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">Name</th>' +
              '<th style="padding:9px 10px;text-align:left;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">Email</th>' +
              '<th style="padding:9px 10px;text-align:center;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">Assigned</th>' +
              '<th style="padding:9px 10px;text-align:center;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">Completed</th>' +
              '<th style="padding:9px 10px;text-align:center;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">%</th>' +
              '<th style="padding:9px 10px;text-align:left;font-weight:600;color:#374151;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em">Missing Sessions</th>' +
            '</tr>' +
          '</thead>' +
          '<tbody>' + rowsHtml + '</tbody>' +
        '</table>' +
      '</div>';
    }).join('');

    var logoHtml = logoDataUri
      ? '<img src="' + logoDataUri + '" alt="Reflex" style="height:52px;width:auto">'
      : '<div style="font-size:1.3rem;font-weight:800;color:#1565C0">reflex</div>';

    var html = '<!DOCTYPE html><html><head><meta charset="utf-8">' +
      '<title>Manager Training Compliance Report</title>' +
      '<style>' +
        'body{margin:0;padding:2rem;font-family:Segoe UI,Arial,sans-serif;color:#1e293b;background:#fff}' +
        '@media print{body{padding:1rem}.no-print{display:none!important}@page{margin:1.5cm}}' +
      '</style>' +
      '</head><body>' +
      '<div style="border-bottom:3px solid #1565C0;padding-bottom:1.5rem;margin-bottom:2rem">' +
        '<div style="display:flex;justify-content:space-between;align-items:flex-start">' +
          '<div style="display:flex;align-items:center;gap:1.2rem">' +
            logoHtml +
            '<div>' +
              '<div style="font-size:0.75rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#1565C0;margin-bottom:4px">Security Awareness Training</div>' +
              '<h1 style="margin:0 0 6px;font-size:1.6rem;font-weight:800;color:#0d2d6b">Manager Compliance Report</h1>' +
              '<div style="font-size:0.85rem;color:#64748b">Training completion — employees below 70% threshold</div>' +
            '</div>' +
          '</div>' +
          '<div style="text-align:right;font-size:0.8rem;color:#64748b">' +
            '<div>' + esc(reportDate) + '</div>' +
            '<div style="margin-top:4px"><span style="background:#fee2e2;color:#dc2626;padding:3px 10px;border-radius:20px;font-weight:700">' +
              esc(String(totalNonCompliant)) + ' employee' + (totalNonCompliant !== 1 ? 's' : '') + ' below 70%' +
            '</span></div>' +
          '</div>' +
        '</div>' +
      '</div>' +
      sectionsHtml +
      '<div style="margin-top:2.5rem;padding-top:1rem;border-top:1px solid #e2e8f0;font-size:0.75rem;color:#94a3b8;text-align:center">' +
        'Generated by SecopsDashboard &nbsp;·&nbsp; Confidential &nbsp;·&nbsp; ' + esc(reportDate) +
      '</div>' +
      '<div class="no-print" style="position:fixed;bottom:20px;right:20px;display:flex;gap:8px">' +
        '<button onclick="window.print()" style="padding:10px 20px;background:#1565C0;color:#fff;border:none;border-radius:6px;font-size:0.9rem;cursor:pointer;font-weight:600">Print / Save as PDF</button>' +
        '<button onclick="window.close()" style="padding:10px 20px;background:#e2e8f0;color:#374151;border:none;border-radius:6px;font-size:0.9rem;cursor:pointer">Close</button>' +
      '</div>' +
      '</body></html>';

    // Written into the window the click handler reserved. Opening one here
    // instead would be blocked: this function has already awaited the logo.
    handle.write(html);
  }

  // Shared: fetch awareness data and build per-user completion rows (history mode)
  async function _fetchAndBuildRows() {
    var res = await fetch('api/awareness', { credentials: 'same-origin' });
    if (!res.ok) throw new Error('Could not load awareness data.');
    _data = await res.json();
    if (!_data || !_data.upload) throw new Error('No awareness data has been uploaded yet.');

    var sessions = (_data.sessions || []).filter(function (s) {
      return s.session_type !== 'Phishing Simulation';
    });
    var byUser = {};
    sessions.forEach(function (s) {
      var key = (s.user_email || '').toLowerCase();
      if (!byUser[key]) {
        byUser[key] = {
          name:      ((s.user_first_name || '') + ' ' + (s.user_last_name || '')).trim(),
          email:     s.user_email || '',
          manager:   s.manager_email
            ? ((s.manager_first_name || '') + ' ' + (s.manager_last_name || '')).trim() || s.manager_email
            : '—',
          managerEmail: s.manager_email || '',
          assigned:  0,
          completed: 0,
          missing:   [],
        };
      }
      byUser[key].assigned++;
      if (s.status === 'Complete') {
        byUser[key].completed++;
      } else if (s.status === 'Not Started') {
        byUser[key].missing.push({ type: s.session_type || '', title: s.title || '', date: s.sent_date || null });
      }
    });
    return Object.values(byUser).sort(function (a, b) {
      var ratA = a.assigned > 0 ? a.completed / a.assigned : 1;
      var ratB = b.assigned > 0 ? b.completed / b.assigned : 1;
      return ratA - ratB;
    });
  }

  // Exposed: fetch awareness data and return rows — for manager.html team table
  window.getAwarenessRows = async function getAwarenessRows() {
    return _fetchAndBuildRows();
  };

  // Exposed: generate the printable manager report popup
  window.generateManagerReport = async function generateManagerReport(rows) {
    // Reserved here, synchronously, because this is called straight from a
    // click handler in manager.html. _fetchAndBuildRows() and the logo fetch
    // below both await, and a popup opened after an await is blocked.
    var handle = window.ReportShell.reserveReportWindow({
      width: 960, height: 700, title: 'Manager Compliance Report',
    });
    if (!handle) return;
    try {
      var r = rows || (await _fetchAndBuildRows());
      if (r.length === 0) {
        handle.fail('No session data available. Please ensure a history-format CSV has been uploaded.');
        return;
      }
      await _generateManagerReport(r, handle);
    } catch (err) {
      handle.fail(err.message || 'Failed to generate report.');
    }
  };

})();
