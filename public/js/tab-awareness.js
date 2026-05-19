/* tab-awareness.js — Security Awareness Training tab renderer */

(function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────────────────
  var _data           = null;  // { upload, users }


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
    try {
      var res = await fetch('api/awareness' + tenantParam('?'), { credentials: 'same-origin' });
      _data = res.ok ? await res.json() : { upload: null, users: [] };
    } catch (_) {
      _data = { upload: null, users: [] };
    }

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

    if (isHistory) {
      _renderHistoryStatCards();
      _renderTypeBreakdownChart();
      _renderMonthlyTrendChart();
      _renderPhishingClickTable();
      _renderUserCompletionTable();
    } else {
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

  // ── Distribution bar chart ──────────────────────────────────────────────────
  function _renderChart() {
    var canvas = document.getElementById('chartAwarenessDistrib');
    if (!canvas || !_data) return;

    var users   = _data.users || [];
    var buckets = [
      { label: '1\u20135',   min: 1,  max: 5  },
      { label: '6\u201310',  min: 6,  max: 10 },
      { label: '11\u201315', min: 11, max: 15 },
      { label: '16\u201320', min: 16, max: 20 },
      { label: '20+',       min: 21, max: Infinity },
    ];

    var counts = buckets.map(function (b) {
      return users.filter(function (u) {
        return u.incomplete_sessions >= b.min && u.incomplete_sessions <= b.max;
      }).length;
    });
    var labels = buckets.map(function (b) { return b.label; });

    var DPR   = window.devicePixelRatio || 1;
    var W     = (canvas.parentElement.clientWidth || 400);
    var H     = 220;
    canvas.width  = W * DPR;
    canvas.height = H * DPR;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';

    var ctx   = canvas.getContext('2d');
    ctx.scale(DPR, DPR);

    var textColor  = '#374151';
    var gridColor  = '#e5e7eb';
    var barColor   = '#2563eb';

    var padL = 50, padR = 20, padT = 20, padB = 40;
    var chartW = W - padL - padR;
    var chartH = H - padT - padB;

    ctx.clearRect(0, 0, W, H);

    var maxVal = Math.max.apply(null, counts.concat([1]));

    // Grid lines
    ctx.strokeStyle = gridColor;
    ctx.lineWidth   = 1;
    var gridLines = 4;
    for (var g = 0; g <= gridLines; g++) {
      var y = padT + chartH - (g / gridLines) * chartH;
      ctx.beginPath();
      ctx.moveTo(padL, y);
      ctx.lineTo(padL + chartW, y);
      ctx.stroke();

      ctx.fillStyle = textColor;
      ctx.font = '11px system-ui, sans-serif';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((g / gridLines) * maxVal), padL - 6, y + 4);
    }

    // Bars
    var barW = chartW / counts.length * 0.6;
    var gap  = chartW / counts.length;

    ctx.fillStyle = barColor;
    counts.forEach(function (val, i) {
      var bh = (val / maxVal) * chartH;
      var x  = padL + i * gap + (gap - barW) / 2;
      var y  = padT + chartH - bh;
      ctx.fillRect(x, y, barW, bh);

      // Value label above bar
      if (val > 0) {
        ctx.fillStyle = textColor;
        ctx.font = 'bold 11px system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(val, x + barW / 2, y - 4);
        ctx.fillStyle = barColor;
      }
    });

    // X-axis labels
    ctx.fillStyle = textColor;
    ctx.font = '11px system-ui, sans-serif';
    ctx.textAlign = 'center';
    labels.forEach(function (lbl, i) {
      var x = padL + i * gap + gap / 2;
      ctx.fillText(lbl, x, padT + chartH + 18);
    });

    // Axis label
    ctx.fillStyle = textColor;
    ctx.font = '11px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Incomplete Sessions Range', padL + chartW / 2, H - 4);
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

  // ── History: training type breakdown chart ──────────────────────────────────
  function _renderTypeBreakdownChart() {
    var canvas = document.getElementById('chartAwarenessTypeBreakdown');
    if (!canvas || !_data) return;

    var sessions = _data.sessions || [];
    var types    = ['Awareness Session', 'Quiz', 'Phishing Remediation Session'];
    var labels   = ['Awareness', 'Quiz', 'Phishing Remediation'];
    var colors   = { completed: '#16a34a', notStarted: '#dc2626', na: '#9ca3af' };

    var counts = types.map(function (t) {
      var rows      = sessions.filter(function (s) { return s.session_type === t; });
      var completed = rows.filter(function (s) { return s.status === 'Complete'; }).length;
      var pending   = rows.filter(function (s) { return s.status === 'Not Started'; }).length;
      return { total: rows.length, completed: completed, pending: pending };
    });

    var DPR = window.devicePixelRatio || 1;
    var W   = canvas.parentElement.clientWidth || 500;
    var H   = 240;
    canvas.width  = W * DPR; canvas.height = H * DPR;
    canvas.style.width  = W + 'px'; canvas.style.height = H + 'px';

    var ctx = canvas.getContext('2d');
    ctx.scale(DPR, DPR);

    var textColor = '#374151', gridColor = '#e5e7eb';
    var padL = 55, padR = 20, padT = 20, padB = 45;
    var chartW = W - padL - padR, chartH = H - padT - padB;

    ctx.clearRect(0, 0, W, H);

    var maxVal = Math.max.apply(null, counts.map(function (c) { return c.total; }).concat([1]));
    var gridLines = 4;
    for (var g = 0; g <= gridLines; g++) {
      var y = padT + chartH - (g / gridLines) * chartH;
      ctx.strokeStyle = gridColor; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + chartW, y); ctx.stroke();
      ctx.fillStyle = textColor; ctx.font = '11px system-ui, sans-serif'; ctx.textAlign = 'right';
      ctx.fillText(Math.round((g / gridLines) * maxVal), padL - 6, y + 4);
    }

    var groupW  = chartW / counts.length;
    var barW    = groupW * 0.28;
    var barGap  = groupW * 0.04;

    counts.forEach(function (c, i) {
      var gx = padL + i * groupW + groupW * 0.1;

      // Completed bar
      var bh1 = c.completed > 0 ? Math.max(2, (c.completed / maxVal) * chartH) : 0;
      ctx.fillStyle = colors.completed;
      ctx.fillRect(gx, padT + chartH - bh1, barW, bh1);
      if (c.completed > 0) {
        ctx.fillStyle = textColor; ctx.font = 'bold 10px system-ui, sans-serif'; ctx.textAlign = 'center';
        ctx.fillText(c.completed, gx + barW / 2, padT + chartH - bh1 - 3);
      }

      // Not-started bar
      var bh2 = c.pending > 0 ? Math.max(2, (c.pending / maxVal) * chartH) : 0;
      ctx.fillStyle = colors.notStarted;
      ctx.fillRect(gx + barW + barGap, padT + chartH - bh2, barW, bh2);
      if (c.pending > 0) {
        ctx.fillStyle = textColor; ctx.font = 'bold 10px system-ui, sans-serif'; ctx.textAlign = 'center';
        ctx.fillText(c.pending, gx + barW + barGap + barW / 2, padT + chartH - bh2 - 3);
      }

      // X label
      ctx.fillStyle = textColor; ctx.font = '11px system-ui, sans-serif'; ctx.textAlign = 'center';
      ctx.fillText(labels[i], padL + i * groupW + groupW / 2, padT + chartH + 16);
    });

    // Legend
    var lx = padL, ly = H - 14;
    [[colors.completed, 'Completed'], [colors.notStarted, 'Not Started']].forEach(function (item) {
      ctx.fillStyle = item[0];
      ctx.fillRect(lx, ly - 9, 12, 10);
      ctx.fillStyle = textColor; ctx.font = '11px system-ui, sans-serif'; ctx.textAlign = 'left';
      ctx.fillText(item[1], lx + 15, ly);
      lx += 100;
    });
  }

  // ── History: monthly trend chart ────────────────────────────────────────────
  function _renderMonthlyTrendChart() {
    var canvas = document.getElementById('chartAwarenessTrend');
    if (!canvas || !_data) return;

    var sessions = _data.sessions || [];

    // Group completions by YYYY-MM from sent_date
    var monthMap = {};
    sessions.forEach(function (s) {
      if (!s.sent_date || s.session_type === 'Phishing Simulation') return;
      var d   = new Date(s.sent_date);
      var key = d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
      if (!monthMap[key]) monthMap[key] = { assigned: 0, completed: 0 };
      monthMap[key].assigned++;
      if (s.status === 'Complete') monthMap[key].completed++;
    });

    var keys    = Object.keys(monthMap).sort();
    var labels  = keys.map(function (k) {
      var parts = k.split('-');
      return new Date(parseInt(parts[0], 10), parseInt(parts[1], 10) - 1, 1)
        .toLocaleDateString('en-ZA', { month: 'short', year: '2-digit' });
    });
    var assignedData  = keys.map(function (k) { return monthMap[k].assigned; });
    var completedData = keys.map(function (k) { return monthMap[k].completed; });

    var DPR = window.devicePixelRatio || 1;
    var W   = canvas.parentElement.clientWidth || 600;
    var H   = 240;
    canvas.width  = W * DPR; canvas.height = H * DPR;
    canvas.style.width  = W + 'px'; canvas.style.height = H + 'px';

    var ctx = canvas.getContext('2d');
    ctx.scale(DPR, DPR);

    var textColor = '#374151', gridColor = '#e5e7eb';
    var colAssigned  = '#93c5fd', colCompleted = '#16a34a';
    var padL = 50, padR = 20, padT = 20, padB = 45;
    var chartW = W - padL - padR, chartH = H - padT - padB;

    ctx.clearRect(0, 0, W, H);
    if (keys.length === 0) {
      ctx.fillStyle = textColor; ctx.font = '13px system-ui, sans-serif'; ctx.textAlign = 'center';
      ctx.fillText('No data', W / 2, H / 2);
      return;
    }

    var maxVal = Math.max.apply(null, assignedData.concat([1]));
    var gridLines = 4;
    for (var g = 0; g <= gridLines; g++) {
      var y = padT + chartH - (g / gridLines) * chartH;
      ctx.strokeStyle = gridColor; ctx.lineWidth = 1;
      ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(padL + chartW, y); ctx.stroke();
      ctx.fillStyle = textColor; ctx.font = '11px system-ui, sans-serif'; ctx.textAlign = 'right';
      ctx.fillText(Math.round((g / gridLines) * maxVal), padL - 6, y + 4);
    }

    function drawLine(dataArr, color) {
      ctx.strokeStyle = color; ctx.lineWidth = 2;
      ctx.beginPath();
      dataArr.forEach(function (val, i) {
        var x = padL + (keys.length > 1 ? i / (keys.length - 1) : 0.5) * chartW;
        var yp = padT + chartH - (val / maxVal) * chartH;
        i === 0 ? ctx.moveTo(x, yp) : ctx.lineTo(x, yp);
      });
      ctx.stroke();
      // Dots
      ctx.fillStyle = color;
      dataArr.forEach(function (val, i) {
        var x = padL + (keys.length > 1 ? i / (keys.length - 1) : 0.5) * chartW;
        var yp = padT + chartH - (val / maxVal) * chartH;
        ctx.beginPath(); ctx.arc(x, yp, 3, 0, Math.PI * 2); ctx.fill();
      });
    }

    drawLine(assignedData,  colAssigned);
    drawLine(completedData, colCompleted);

    // X-axis labels (show every N-th if too many)
    var step = Math.max(1, Math.ceil(keys.length / 10));
    ctx.fillStyle = textColor; ctx.font = '10px system-ui, sans-serif'; ctx.textAlign = 'center';
    keys.forEach(function (k, i) {
      if (i % step !== 0) return;
      var x = padL + (keys.length > 1 ? i / (keys.length - 1) : 0.5) * chartW;
      ctx.fillText(labels[i], x, padT + chartH + 16);
    });

    // Legend
    var lx = padL, ly = H - 8;
    [[colAssigned, 'Assigned'], [colCompleted, 'Completed']].forEach(function (item) {
      ctx.fillStyle = item[0]; ctx.fillRect(lx, ly - 9, 12, 10);
      ctx.fillStyle = textColor; ctx.font = '11px system-ui, sans-serif'; ctx.textAlign = 'left';
      ctx.fillText(item[1], lx + 15, ly);
      lx += 100;
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
        };
      }
      byUser[key].assigned++;
      if (s.status === 'Complete') byUser[key].completed++;
    });

    var rows = Object.values(byUser).sort(function (a, b) {
      var ratA = a.assigned > 0 ? a.completed / a.assigned : 1;
      var ratB = b.assigned > 0 ? b.completed / b.assigned : 1;
      return ratA - ratB; // worst (lowest %) first
    });

    tbody.innerHTML = rows.map(function (r) {
      var pct = r.assigned > 0 ? Math.round(r.completed / r.assigned * 100) : 0;
      var pctClass = pct >= 80 ? 'accent-green' : pct >= 50 ? 'accent-amber' : 'accent-red';
      return '<tr>' +
        '<td>' + esc(r.name) + '</td>' +
        '<td><small>' + esc(r.email) + '</small></td>' +
        '<td>' + esc(r.manager) + '</td>' +
        '<td class="col-num">' + esc(String(r.assigned)) + '</td>' +
        '<td class="col-num">' + esc(String(r.completed)) + '</td>' +
        '<td class="col-num"><strong class="' + esc(pctClass) + '">' + esc(String(pct)) + '%</strong></td>' +
        '</tr>';
    }).join('');
  }

})();
