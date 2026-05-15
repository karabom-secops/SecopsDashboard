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

    _renderStatCards();
    _renderChart();
    _renderManagerTable();
    _renderTopTable();
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

})();
