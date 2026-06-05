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
      var isAdmin = window.currentUser &&
        (window.currentUser.role === 'admin' || window.currentUser.role === 'superadmin');
      delBtn.hidden = !hasData || !isAdmin;
      if (!delBtn.dataset.handlerSet) {
        delBtn.dataset.handlerSet = '1';
        delBtn.addEventListener('click', function () {
          if (!confirm('Delete all awareness data for this tenant?')) return;
          _deleteData();
        });
      }
    }

    if (!hasData) return;

    var isHistory = (_data.upload.upload_type === 'history');
    var summaryEl = document.getElementById('awarenessSummaryContent');
    var historyEl = document.getElementById('awarenessHistoryContent');
    if (summaryEl) summaryEl.hidden = isHistory;
    if (historyEl) historyEl.hidden = !isHistory;

    var exportBtn = document.getElementById('awarenessExportCsvBtn');

    if (isHistory) {
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

    // Phishing click rate: unique users clicked / unique users sent at least one phishing sim
    var phishingSims = sessions.filter(function (s) { return s.session_type === 'Phishing Simulation'; });
    var sentPhishEmails   = new Set(phishingSims.map(function (s) { return (s.user_email || '').toLowerCase(); }));
    var clickedPhishEmails = new Set(
      phishingSims
        .filter(function (s) { return s.clicked_at; })
        .map(function (s) { return (s.user_email || '').toLowerCase(); })
    );
    var phishClickRate = sentPhishEmails.size > 0
      ? Math.round(clickedPhishEmails.size / sentPhishEmails.size * 100)
      : 0;

    // Avg quiz score (only rows where quiz_score is a number)
    var quizRows = sessions.filter(function (s) { return s.quiz_score !== null && s.quiz_score !== undefined; });
    var avgQuiz  = quizRows.length > 0
      ? (quizRows.reduce(function (sum, s) { return sum + parseFloat(s.quiz_score); }, 0) / quizRows.length).toFixed(1)
      : 'N/A';

    el.innerHTML =
      _card('Total Employees',          totalUsers,                       'accent-blue',   '') +
      _card('Training Completion Rate', compRate + '%',                   'accent-green',  completedTrain + ' / ' + trainSessions.length + ' sessions') +
      _card('Phishing Click Rate',      phishClickRate + '%',             'accent-red',    clickedPhishEmails.size + ' / ' + sentPhishEmails.size + ' employees') +
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
    var phishing = sessions.filter(function (s) {
      return s.session_type === 'Phishing Simulation' && s.clicked_at;
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
        };
      }
      byUser[key].clicks++;
      var cd = new Date(s.clicked_at);
      if (!byUser[key].lastSim || cd > new Date(byUser[key].lastSim)) {
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

    var rows = Object.values(byUser).sort(function (a, b) {
      var ratA = a.assigned > 0 ? a.completed / a.assigned : 1;
      var ratB = b.assigned > 0 ? b.completed / b.assigned : 1;
      return ratA - ratB; // worst (lowest %) first
    });

    var html = '';
    rows.forEach(function (r, i) {
      var pct      = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
      var pctClass = pct >= 80 ? 'accent-green' : pct >= 50 ? 'accent-amber' : 'accent-red';
      var detailId  = 'uc-detail-' + i;
      var missCount = r.missing.length;

      // Main row
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

      // Expandable detail row listing specific missing sessions
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

    tbody.innerHTML = html;

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
    var searchInput = document.getElementById('awarenessCompletionSearch');
    if (searchInput) {
      // Clear any previous value when re-rendering
      searchInput.value = '';
      searchInput.oninput = function () {
        var term = searchInput.value.trim().toLowerCase();
        var allRows = tbody.querySelectorAll('tr');
        allRows.forEach(function (tr) {
          if (tr.classList.contains('awareness-missing-detail')) return; // handled via parent
          var text = tr.textContent.toLowerCase();
          var show = !term || text.indexOf(term) !== -1;
          tr.hidden = !show;
          // Keep the associated detail row hidden when parent is hidden
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
        rows.forEach(function (r) {
          var pct = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
          csvRows.push([r.name, r.email, r.manager, r.assigned, r.completed, pct + '%']);
        });
        var csv = csvRows.map(function (row) {
          return row.map(function (v) { return '"' + String(v).replace(/"/g, '""') + '"'; }).join(',');
        }).join('\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'awareness-completion.csv';
        a.click();
      };
    }

    // Export <70% users button
    var exportLowBtn = document.getElementById('awarenessExportLowBtn');
    if (exportLowBtn) {
      exportLowBtn.hidden = false;
      exportLowBtn.onclick = function () {
        var lowRows = rows.filter(function (r) {
          return r.assigned > 0 && Math.round(r.completed / r.assigned * 100) < 70;
        });
        var csvRows = [['Name', 'Email', 'Manager', 'Assigned', 'Completed', '%', 'Missing Sessions']];
        lowRows.forEach(function (r) {
          var pct = Math.round(r.completed / r.assigned * 100);
          var missing = r.missing.map(function (m) { return m.title || m.type; }).join('; ');
          csvRows.push([r.name, r.email, r.manager, r.assigned, r.completed, pct + '%', missing]);
        });
        var csv = csvRows.map(function (row) {
          return row.map(function (v) { return '"' + String(v ?? '').replace(/"/g, '""') + '"'; }).join(',');
        }).join('\r\n');
        var blob = new Blob([csv], { type: 'text/csv' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'awareness-below-70pct.csv';
        a.click();
        URL.revokeObjectURL(a.href);
      };
    }
  }

})();
